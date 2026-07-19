package softether

import "encoding/binary"

type sha0Digest struct {
	count uint64
	block [64]byte
	state [5]uint32
}

func newSHA0() *sha0Digest {
	return &sha0Digest{state: [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}}
}

func (digest *sha0Digest) write(data []byte) {
	index := int(digest.count & 63)
	digest.count += uint64(len(data))
	for _, value := range data {
		digest.block[index] = value
		index++
		if index == len(digest.block) {
			digest.transform()
			index = 0
		}
	}
}

func (digest *sha0Digest) transform() {
	var words [80]uint32
	for index := 0; index < 16; index++ {
		words[index] = binary.BigEndian.Uint32(digest.block[index*4 : index*4+4])
	}
	for index := 16; index < 80; index++ {
		words[index] = words[index-3] ^ words[index-8] ^ words[index-14] ^ words[index-16]
	}
	a, b, c, d, e := digest.state[0], digest.state[1], digest.state[2], digest.state[3], digest.state[4]
	for index := 0; index < 80; index++ {
		value := rotateLeft(a, 5) + e + words[index]
		switch {
		case index < 20:
			value += (d ^ (b & (c ^ d))) + 0x5a827999
		case index < 40:
			value += (b ^ c ^ d) + 0x6ed9eba1
		case index < 60:
			value += ((b & c) | (d & (b | c))) + 0x8f1bbcdc
		default:
			value += (b ^ c ^ d) + 0xca62c1d6
		}
		e, d, c, b, a = d, c, rotateLeft(b, 30), a, value
	}
	digest.state[0] += a
	digest.state[1] += b
	digest.state[2] += c
	digest.state[3] += d
	digest.state[4] += e
}

func (digest *sha0Digest) sum() [20]byte {
	bitCount := digest.count * 8
	digest.write([]byte{0x80})
	for digest.count&63 != 56 {
		digest.write([]byte{0})
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], bitCount)
	digest.write(length[:])
	var result [20]byte
	for index, value := range digest.state {
		binary.BigEndian.PutUint32(result[index*4:index*4+4], value)
	}
	return result
}

func sha0(data []byte) [20]byte {
	digest := newSHA0()
	digest.write(data)
	return digest.sum()
}

func rotateLeft(value uint32, bits uint) uint32 {
	return value<<bits | value>>(32-bits)
}
