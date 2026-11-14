// Property and plumbing tests for the classic OpenVPN key derivation: argument
// order, slot offsets, the odd-length secret split, and the error paths a
// malformed caller reaches. None of it is evidence that the PRF is right —
// length, determinism and label-sensitivity hold for any plausible wrong PRF,
// and the known answers are in vectors_test.go.
package prf_test

import (
	"bytes"
	"testing"

	"github.com/buengese/go-openvpn/internal/prf"
)

// -------------------------------------------------------------------------
// TLS1PRF — properties, not proof
// -------------------------------------------------------------------------

// TestTLS1PRFLength checks that TLS1PRF returns exactly n bytes, including
// lengths that are no multiple of either digest's block size: MD5 emits 16
// bytes per round and SHA-1 20, so both streams must be truncated to the same
// point before the XOR.
func TestTLS1PRFLength(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 48)
	seed := bytes.Repeat([]byte{0xA5}, 64)
	for _, n := range []int{1, 15, 16, 17, 19, 20, 21, 32, 48, 64, 100, 256, 257} {
		if got := len(prf.TLS1PRF(secret, "OpenVPN master secret", seed, n)); got != n {
			t.Errorf("n=%d: got %d bytes", n, got)
		}
	}
}

// TestTLS1PRFNonPositiveN checks the documented nil return rather than a panic
// or an empty non-nil slice.
func TestTLS1PRFNonPositiveN(t *testing.T) {
	for _, n := range []int{0, -1, -256} {
		if got := prf.TLS1PRF(nil, "", nil, n); got != nil {
			t.Errorf("n=%d: got %v, want nil", n, got)
		}
	}
}

// TestTLS1PRFDeterministic checks that the same inputs always produce the same
// output — the weakest possible property.
func TestTLS1PRFDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 48)
	seed := bytes.Repeat([]byte{0xCD}, 64)
	a := prf.TLS1PRF(secret, "OpenVPN master secret", seed, 256)
	b := prf.TLS1PRF(secret, "OpenVPN master secret", seed, 256)
	if !bytes.Equal(a, b) {
		t.Fatal("non-deterministic output")
	}
}

// TestTLS1PRFInputSensitivity checks that the label, the seed and the secret
// each reach the output. An implementation that ignored the label would still
// be deterministic and still be the right length.
func TestTLS1PRFInputSensitivity(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, 48)
	seed := bytes.Repeat([]byte{0x02}, 64)
	base := prf.TLS1PRF(secret, "OpenVPN master secret", seed, 64)

	otherSecret := append(bytes.Repeat([]byte{0x01}, 47), 0x02)
	otherSeed := append(bytes.Repeat([]byte{0x02}, 63), 0x03)

	for _, tc := range []struct {
		name string
		got  []byte
	}{
		{"label", prf.TLS1PRF(secret, "OpenVPN key expansion", seed, 64)},
		{"label differing in one character", prf.TLS1PRF(secret, "OpenVPN master secrey", seed, 64)},
		{"seed", prf.TLS1PRF(secret, "OpenVPN master secret", otherSeed, 64)},
		{"secret", prf.TLS1PRF(otherSecret, "OpenVPN master secret", seed, 64)},
	} {
		if bytes.Equal(base, tc.got) {
			t.Errorf("changing the %s left the output unchanged", tc.name)
		}
	}
}

// TestTLS1PRFTruncationIsAPrefix checks that a short request is a prefix of a
// long one, because P_hash truncates the concatenated stream. Re-seeding per
// request, or padding the final block, breaks it.
func TestTLS1PRFTruncationIsAPrefix(t *testing.T) {
	secret := bytes.Repeat([]byte{0x3C}, 48)
	seed := bytes.Repeat([]byte{0xC3}, 64)
	long := prf.TLS1PRF(secret, "OpenVPN key expansion", seed, 256)
	for _, n := range []int{1, 16, 20, 48, 100, 255} {
		if short := prf.TLS1PRF(secret, "OpenVPN key expansion", seed, n); !bytes.Equal(short, long[:n]) {
			t.Errorf("n=%d: output is not a prefix of the 256-byte stream", n)
		}
	}
}

// TestTLS1PRFOddSecretSharesTheMiddleByte pins the RFC 2246 Section 5 rule that
// S1 and S2 are each ceil(len/2) bytes. Duplicating the middle byte yields an
// even-length secret whose two exact halves are S1 and S2 of the odd one, so
// the two calls must agree; a wrong split one byte shorter fails it.
func TestTLS1PRFOddSecretSharesTheMiddleByte(t *testing.T) {
	seed := bytes.Repeat([]byte{0x9E}, 64)
	for _, n := range []int{1, 3, 5, 47, 49} {
		odd := make([]byte, n)
		for i := range odd {
			odd[i] = byte(i*7 + 1)
		}
		half := (n + 1) / 2

		// S1 = odd[:half], S2 = odd[n-half:] = odd[half-1:]. Concatenating
		// them duplicates the shared middle byte and gives an even-length
		// secret that splits into exactly the same two halves.
		expanded := make([]byte, 0, 2*half)
		expanded = append(expanded, odd[:half]...)
		expanded = append(expanded, odd[n-half:]...)

		got := prf.TLS1PRF(odd, "OpenVPN master secret", seed, 48)
		want := prf.TLS1PRF(expanded, "OpenVPN master secret", seed, 48)
		if !bytes.Equal(got, want) {
			t.Errorf("len(secret)=%d: halves do not share the middle byte\n got: %x\nwant: %x", n, got, want)
		}
	}
}

// -------------------------------------------------------------------------
// Split — asserted against a recorded key block, not against itself
// -------------------------------------------------------------------------

// TestSplitMapsVectorKeyBlockToSlots checks the slot layout against ground
// truth: the four slots must be the recorded key block sliced at 0, 64, 128 and
// 192. Slicing the vector rather than re-deriving it keeps the test to the
// mapping alone.
func TestSplitMapsVectorKeyBlockToSlots(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			block := mustHex(t, "key_block", v.KeyBlock, 256)
			slots, err := prf.Split(block)
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			for _, tc := range []struct {
				name   string
				got    []byte
				lo, hi int
			}{
				{"CipherEncrypt", slots.CipherEncrypt, 0, 64},
				{"HMACEncrypt", slots.HMACEncrypt, 64, 128},
				{"CipherDecrypt", slots.CipherDecrypt, 128, 192},
				{"HMACDecrypt", slots.HMACDecrypt, 192, 256},
			} {
				if len(tc.got) != 64 {
					t.Errorf("%s: %d bytes, want 64", tc.name, len(tc.got))
					continue
				}
				if !bytes.Equal(tc.got, block[tc.lo:tc.hi]) {
					t.Errorf("%s: does not match key_block[%d:%d]\n got: %x\nwant: %x",
						tc.name, tc.lo, tc.hi, tc.got, block[tc.lo:tc.hi])
				}
			}

			// The slots must be copies. A sub-slice of the block would carry a
			// capacity running to byte 256, so appending to one slot would
			// overwrite the head of the next.
			slots.CipherEncrypt[0] ^= 0xFF
			if block[0] == slots.CipherEncrypt[0] {
				t.Error("slots alias the caller's key block")
			}
		})
	}
}

// TestSplitRejectsWrongLength checks that a key block of any other size is an
// error rather than a panic in a slice expression.
func TestSplitRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 128, 192, 255, 257, 512} {
		if _, err := prf.Split(make([]byte, n)); err == nil {
			t.Errorf("len=%d: Split accepted a key block that is not 256 bytes", n)
		}
	}
	if _, err := prf.Split(nil); err == nil {
		t.Error("Split accepted a nil key block")
	}
}

// -------------------------------------------------------------------------
// Error paths — wrong-sized material must be reported, never sliced
// -------------------------------------------------------------------------

// validMaterial returns a well-formed set of derivation inputs. Its bytes are
// fixed rather than random: these tests are about lengths, and a failure
// should be reproducible from the source alone.
func validMaterial() (client, server prf.KeySource, clientSID, serverSID []byte) {
	client = prf.KeySource{
		PreMaster: bytes.Repeat([]byte{0x11}, 48),
		Random1:   bytes.Repeat([]byte{0x22}, 32),
		Random2:   bytes.Repeat([]byte{0x33}, 32),
	}
	server = prf.KeySource{
		Random1: bytes.Repeat([]byte{0x44}, 32),
		Random2: bytes.Repeat([]byte{0x55}, 32),
	}
	return client, server, bytes.Repeat([]byte{0x66}, 8), bytes.Repeat([]byte{0x77}, 8)
}

// TestDeriveRejectsMalformedMaterial checks that every fixed-width input is
// length-checked, and that a wrong length is an error rather than a panic.
//
// stageOneToo marks the cases DeriveMasterSecret must reject on its own;
// DeriveKeyBlock must reject all of them, since it runs stage one first.
func TestDeriveRejectsMalformedMaterial(t *testing.T) {
	tests := []struct {
		name        string
		stageOneToo bool
		mutate      func(client, server *prf.KeySource, clientSID, serverSID *[]byte)
	}{
		{"nil client pre-master", true, func(c, _ *prf.KeySource, _, _ *[]byte) { c.PreMaster = nil }},
		{"short client pre-master", true, func(c, _ *prf.KeySource, _, _ *[]byte) { c.PreMaster = c.PreMaster[:47] }},
		{"long client pre-master", true, func(c, _ *prf.KeySource, _, _ *[]byte) { c.PreMaster = append(c.PreMaster, 0) }},
		{"nil client random1", true, func(c, _ *prf.KeySource, _, _ *[]byte) { c.Random1 = nil }},
		{"short client random1", true, func(c, _ *prf.KeySource, _, _ *[]byte) { c.Random1 = c.Random1[:31] }},
		{"nil server random1", true, func(_, s *prf.KeySource, _, _ *[]byte) { s.Random1 = nil }},
		{"long server random1", true, func(_, s *prf.KeySource, _, _ *[]byte) { s.Random1 = append(s.Random1, 0) }},
		{"server carries a pre-master", true, func(_, s *prf.KeySource, _, _ *[]byte) {
			s.PreMaster = bytes.Repeat([]byte{0x88}, 48)
		}},
		{"nil client random2", false, func(c, _ *prf.KeySource, _, _ *[]byte) { c.Random2 = nil }},
		{"short server random2", false, func(_, s *prf.KeySource, _, _ *[]byte) { s.Random2 = s.Random2[:16] }},
		{"nil client session ID", false, func(_, _ *prf.KeySource, cs, _ *[]byte) { *cs = nil }},
		{"short client session ID", false, func(_, _ *prf.KeySource, cs, _ *[]byte) { *cs = (*cs)[:7] }},
		{"both session IDs in one argument", false, func(_, _ *prf.KeySource, _, ss *[]byte) {
			*ss = bytes.Repeat([]byte{0x99}, 16)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server, clientSID, serverSID := validMaterial()
			tc.mutate(&client, &server, &clientSID, &serverSID)

			if _, err := prf.DeriveKeyBlock(client, server, clientSID, serverSID); err == nil {
				t.Error("DeriveKeyBlock accepted malformed material")
			}
			if _, err := prf.DeriveMasterSecret(client, server); tc.stageOneToo != (err != nil) {
				t.Errorf("DeriveMasterSecret error = %v, want error: %v", err, tc.stageOneToo)
			}
		})
	}
}

// TestDeriveMasterSecretIgnoresStageTwoMaterial checks that stage one is
// callable with stage-one material alone: it is exported so a vector mismatch
// can be localised before the rest of the exchange has arrived.
func TestDeriveMasterSecretIgnoresStageTwoMaterial(t *testing.T) {
	client, server, _, _ := validMaterial()
	full, err := prf.DeriveMasterSecret(client, server)
	if err != nil {
		t.Fatalf("DeriveMasterSecret: %v", err)
	}
	client.Random2, server.Random2 = nil, nil
	partial, err := prf.DeriveMasterSecret(client, server)
	if err != nil {
		t.Fatalf("DeriveMasterSecret without random2: %v", err)
	}
	if !bytes.Equal(full, partial) {
		t.Error("stage one consumed random2, which belongs to stage two")
	}
	if len(full) != 48 {
		t.Errorf("master secret is %d bytes, want 48", len(full))
	}
}

// TestDeriveKeyBlockConsumesEveryStageTwoInput checks that random2 and both
// session IDs actually reach the key block. A derivation with nowhere to put
// them produces a well-formed 256-byte block regardless.
func TestDeriveKeyBlockConsumesEveryStageTwoInput(t *testing.T) {
	client, server, clientSID, serverSID := validMaterial()
	base, err := prf.DeriveKeyBlock(client, server, clientSID, serverSID)
	if err != nil {
		t.Fatalf("DeriveKeyBlock: %v", err)
	}
	if len(base) != 256 {
		t.Fatalf("key block is %d bytes, want 256", len(base))
	}

	for _, tc := range []struct {
		name string
		run  func() ([]byte, error)
	}{
		{"client random2", func() ([]byte, error) {
			c, s, cs, ss := validMaterial()
			c.Random2[0] ^= 0xFF
			return prf.DeriveKeyBlock(c, s, cs, ss)
		}},
		{"server random2", func() ([]byte, error) {
			c, s, cs, ss := validMaterial()
			s.Random2[31] ^= 0xFF
			return prf.DeriveKeyBlock(c, s, cs, ss)
		}},
		{"client session ID", func() ([]byte, error) {
			c, s, cs, ss := validMaterial()
			cs[0] ^= 0xFF
			return prf.DeriveKeyBlock(c, s, cs, ss)
		}},
		{"server session ID", func() ([]byte, error) {
			c, s, cs, ss := validMaterial()
			ss[7] ^= 0xFF
			return prf.DeriveKeyBlock(c, s, cs, ss)
		}},
		{"session IDs swapped", func() ([]byte, error) {
			c, s, cs, ss := validMaterial()
			return prf.DeriveKeyBlock(c, s, ss, cs)
		}},
	} {
		got, err := tc.run()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if bytes.Equal(base, got) {
			t.Errorf("changing the %s left the key block unchanged", tc.name)
		}
	}
}
