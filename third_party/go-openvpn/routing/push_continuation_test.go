package routing

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestPushAccumulator_SingleFragment pins that a reply the server did not split
// survives the accumulator byte for byte: the raw string is what the session
// report records and what dns.ParsePushReply and parsePeerID are handed.
func TestPushAccumulator_SingleFragment(t *testing.T) {
	const msg = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.6 255.255.255.0," +
		"route-gateway 10.8.0.1,cipher AES-256-GCM\x00"

	var acc PushAccumulator
	complete, err := acc.AddFragment(msg)
	if err != nil {
		t.Fatalf("AddFragment: %v", err)
	}
	if !complete {
		t.Fatal("a reply with no push-continuation directive must be complete")
	}
	if acc.Fragments() != 1 {
		t.Errorf("Fragments() = %d, want 1", acc.Fragments())
	}
	if got, want := acc.Reply(), strings.TrimRight(msg, "\x00"); got != want {
		t.Errorf("Reply() = %q, want the message verbatim %q", got, want)
	}
}

// TestPushAccumulator_SplitReply covers a reply the server split. A reply
// longer than PUSH_BUNDLE_SIZE (1024 bytes, openvpn-2.6.22
// src/openvpn/common.h:88) crosses several control messages, every fragment but
// the last closing with "push-continuation 2" and the last with
// "push-continuation 1" (push.c:718-735, push.c:795-806). Taking the first
// fragment alone yields one route out of three.
func TestPushAccumulator_SplitReply(t *testing.T) {
	fragments := []string{
		"PUSH_REPLY,topology subnet,ifconfig 10.8.0.6 255.255.255.0," +
			"route-gateway 10.8.0.1,route 10.10.0.0 255.255.0.0,push-continuation 2",
		"PUSH_REPLY,route 10.20.0.0 255.255.0.0,route 10.30.0.0 255.255.0.0," +
			"push-continuation 2",
		"PUSH_REPLY,route 10.40.0.0 255.255.0.0,cipher AES-256-GCM," +
			"push-continuation 1\x00",
	}

	var acc PushAccumulator
	for i, f := range fragments {
		complete, err := acc.AddFragment(f)
		if err != nil {
			t.Fatalf("AddFragment(%d): %v", i, err)
		}
		if want := i == len(fragments)-1; complete != want {
			t.Fatalf("AddFragment(%d) complete = %v, want %v", i, complete, want)
		}
	}
	if acc.Fragments() != 3 {
		t.Errorf("Fragments() = %d, want 3", acc.Fragments())
	}

	// The reassembled reply must parse as one configuration: four routes, not
	// the single route the first fragment carried, and the cipher that only
	// the last fragment named.
	opts, err := ParsePushReply(acc.Reply())
	if err != nil {
		t.Fatalf("ParsePushReply(%q): %v", acc.Reply(), err)
	}
	if len(opts.Routes) != 4 {
		t.Errorf("routes: got %d, want 4 — %q", len(opts.Routes), acc.Reply())
	}
	if opts.Cipher != "AES-256-GCM" {
		t.Errorf("cipher: got %q, want AES-256-GCM (it is only in the last fragment)", opts.Cipher)
	}
	if opts.Ifconfig == nil || opts.Ifconfig.Gateway == nil {
		t.Fatal("ifconfig and route-gateway from the first fragment were lost")
	}
	// No push-continuation directive may survive into the reassembled reply.
	if strings.Contains(acc.Reply(), "push-continuation") {
		t.Errorf("Reply() still carries a push-continuation directive: %q", acc.Reply())
	}
}

// TestPushAccumulator_ContinuationOnlyFragment covers a fragment whose entire
// content is the continuation marker: the reassembled reply must not grow a
// stray empty option list from it.
func TestPushAccumulator_ContinuationOnlyFragment(t *testing.T) {
	var acc PushAccumulator
	if _, err := acc.AddFragment("PUSH_REPLY,push-continuation 2"); err != nil {
		t.Fatalf("AddFragment: %v", err)
	}
	complete, err := acc.AddFragment("PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 1")
	if err != nil {
		t.Fatalf("AddFragment: %v", err)
	}
	if !complete {
		t.Fatal("push-continuation 1 must complete the reply")
	}
	if got, want := acc.Reply(), "PUSH_REPLY,route 10.1.0.0 255.255.0.0"; got != want {
		t.Errorf("Reply() = %q, want %q", got, want)
	}
}

// TestPushAccumulator_Rejects covers the fragment shapes that are a protocol
// fault rather than a continuation, so that a peer cannot keep the client in
// the push stage or append to a reply it has already finished.
func TestPushAccumulator_Rejects(t *testing.T) {
	t.Run("not a PUSH_REPLY", func(t *testing.T) {
		var acc PushAccumulator
		if _, err := acc.AddFragment("AUTH_FAILED"); err == nil {
			t.Error("a non-PUSH_REPLY fragment must be refused")
		}
	})

	t.Run("keyword prefix only", func(t *testing.T) {
		var acc PushAccumulator
		if _, err := acc.AddFragment("PUSH_REPLY_LATER,route 10.1.0.0 255.255.0.0"); err == nil {
			t.Error("a message that merely starts with the keyword must be refused")
		}
	})

	t.Run("unknown continuation value", func(t *testing.T) {
		var acc PushAccumulator
		if _, err := acc.AddFragment("PUSH_REPLY,push-continuation 7"); err == nil {
			t.Error("an unknown push-continuation value must be refused")
		}
	})

	t.Run("unparseable continuation value", func(t *testing.T) {
		var acc PushAccumulator
		if _, err := acc.AddFragment("PUSH_REPLY,push-continuation later"); err == nil {
			t.Error("a non-numeric push-continuation value must be refused")
		}
	})

	t.Run("fragment after the last", func(t *testing.T) {
		var acc PushAccumulator
		if _, err := acc.AddFragment("PUSH_REPLY,route 10.1.0.0 255.255.0.0"); err != nil {
			t.Fatalf("AddFragment: %v", err)
		}
		_, err := acc.AddFragment("PUSH_REPLY,route 10.2.0.0 255.255.0.0")
		if !errors.Is(err, ErrPushComplete) {
			t.Errorf("second fragment after a complete reply: got %v, want ErrPushComplete", err)
		}
	})

	t.Run("unbounded continuation", func(t *testing.T) {
		var acc PushAccumulator
		for i := range MaxPushFragments {
			complete, err := acc.AddFragment(fmt.Sprintf(
				"PUSH_REPLY,route 10.%d.0.0 255.255.0.0,push-continuation 2", i))
			if err != nil {
				t.Fatalf("AddFragment(%d): %v", i, err)
			}
			if complete {
				t.Fatalf("AddFragment(%d) completed early", i)
			}
		}
		if _, err := acc.AddFragment("PUSH_REPLY,push-continuation 2"); err == nil {
			t.Errorf("a server that never stops continuing must be cut off at %d fragments",
				MaxPushFragments)
		}
	})
}
