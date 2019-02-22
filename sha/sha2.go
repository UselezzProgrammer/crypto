package sha

var sha2K = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// used by sha1, sha256, sha224
func sha2PrepareData(rawData []byte) []byte {

	// padding
	var lenData, padLen uint32
	lenData = uint32(len(rawData))
	padLen = 0
	if lenData%64 < 56 {
		padLen = 56 - (lenData % 64)
	} else {
		padLen = 64 + 56 - (lenData % 64)
	}
	pad := make([]byte, padLen)
	pad[0] = 0x80
	rawData = append(rawData, pad...)

	// append length
	bitLenBytes := make([]byte, 8)
	lenData = lenData << 3
	for i := uint32(0); i < 8; i++ {
		bitLenBytes[i] = byte(lenData >> (8 * (7 - i)))
	}
	rawData = append(rawData, bitLenBytes...)
	return rawData
}

func bigEndianBytesUint32(val uint32) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte((val & 0xFF000000) >> 24)
	bytes[1] = byte((val & 0xFF0000) >> 16)
	bytes[2] = byte((val & 0xFF00) >> 8)
	bytes[3] = byte(val & 0xFF)
	return bytes
}

func sha2Digest(algType int, m []byte) [8]uint32 {
	m = sha2PrepareData(m)

	var h0, h1, h2, h3, h4, h5, h6, h7 uint32
	if algType == algSHA224 {
		h0, h1, h2, h3, h4, h5, h6, h7 = uint32(0xc1059ed8), uint32(0x367cd507), uint32(0x3070dd17), uint32(0xf70e5939),
			uint32(0xffc00b31), uint32(0x68581511), uint32(0x64f98fa7), uint32(0xbefa4fa4)
	} else {
		h0, h1, h2, h3, h4, h5, h6, h7 = uint32(0x6a09e667), uint32(0xbb67ae85), uint32(0x3c6ef372), uint32(0xa54ff53a),
			uint32(0x510e527f), uint32(0x9b05688c), uint32(0x1f83d9ab), uint32(0x5be0cd19)
	}

	var r [8]uint32
	chunk := len(m) / 64
	for k := 0; k < chunk; k++ {
		var W [64]uint32

		for t := 0; t < 64; t++ {
			if t <= 15 {
				j := t * 4
				W[t] = uint32(m[(k*64)+j])<<24 | uint32(m[(k*64)+j+1])<<16 | uint32(m[(k*64)+j+2])<<8 | uint32(m[(k*64)+j+3])
			} else {
				tmp1 := (W[t-2]>>17 | W[t-2]<<15) ^ (W[t-2]>>19 | W[t-2]<<13) ^ (W[t-2] >> 10)
				tmp0 := (W[t-15]>>7 | W[t-15]<<25) ^ (W[t-15]>>18 | W[t-15]<<14) ^ (W[t-15] >> 3)
				W[t] = tmp1 + W[t-7] + tmp0 + W[t-16]
			}
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		var tmp1, tmp2 uint32
		for t := 0; t < 64; t++ {
			tmp1 = h + ((e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)) + ((e & f) ^ (^e & g)) + sha2K[t] + W[t]
			tmp2 = ((a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)) + ((a & b) ^ (a & c) ^ (b & c))

			h, g, f, e, d, c, b, a = g, f, e, d+tmp1, c, b, a, tmp1+tmp2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h
	}

	r[0] = h0
	r[1] = h1
	r[2] = h2
	r[3] = h3
	r[4] = h4
	r[5] = h5
	r[6] = h6
	r[7] = h7
    return r
}
