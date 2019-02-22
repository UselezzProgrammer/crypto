package sha

var sha5K = []uint64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

func sha5PrepareData(rawData []byte) []byte {

    // padding
    var lenData, padLen uint64
    lenData = uint64(len(rawData))
    padLen = 0
    if lenData%128 < 112 {
        padLen = 112 - (lenData % 128)
    } else {
        padLen = 128 + 112 - (lenData % 128)
    }
    pad := make([]byte, padLen)
    pad[0] = 0x80
    rawData = append(rawData, pad...)

    // append length
    bitLenBytes := make([]byte, 16)
    lenData = lenData << 3
    for i := uint32(8); i < 16; i++ {
        bitLenBytes[i] = byte(lenData >> (8 * (15 - i)))
    }
    rawData = append(rawData, bitLenBytes...)
    return rawData
}

func bigEndianBytesUint64(val uint64) []byte {
    bytes := make([]byte, 8)
    bytes[0] = byte((val & 0xFF00000000000000) >> 56)
    bytes[1] = byte((val & 0xFF000000000000) >> 48)
    bytes[2] = byte((val & 0xFF0000000000) >> 40)
    bytes[3] = byte((val & 0xFF00000000) >> 32)
    bytes[4] = byte((val & 0xFF000000) >> 24)
    bytes[5] = byte((val & 0xFF0000) >> 16)
    bytes[6] = byte((val & 0xFF00) >> 8)
    bytes[7] = byte(val & 0xFF)
    return bytes
}

func sha5Digest(algType int, m []byte) [8]uint64 {
    m = sha5PrepareData(m)

    var h0, h1, h2, h3, h4, h5, h6, h7 uint64
    if algType == algSHA512 {
        h0, h1, h2, h3, h4, h5, h6, h7 = uint64(0x6a09e667f3bcc908), uint64(0xbb67ae8584caa73b),
            uint64(0x3c6ef372fe94f82b), uint64(0xa54ff53a5f1d36f1), uint64(0x510e527fade682d1),
            uint64(0x9b05688c2b3e6c1f), uint64(0x1f83d9abfb41bd6b), uint64(0x5be0cd19137e2179)
    } else if algType == algSHA384 {
        h0, h1, h2, h3, h4, h5, h6, h7 = uint64(0xcbbb9d5dc1059ed8), uint64(0x629a292a367cd507),
            uint64(0x9159015a3070dd17), uint64(0x152fecd8f70e5939), uint64(0x67332667ffc00b31),
            uint64(0x8eb44a8768581511), uint64(0xdb0c2e0d64f98fa7), uint64(0x47b5481dbefa4fa4)
    } else if algType == algSHA512224 {
        h0, h1, h2, h3, h4, h5, h6, h7 = uint64(0x8C3D37C819544DA2), uint64(0x73E1996689DCD4D6),
            uint64(0x1DFAB7AE32FF9C82), uint64(0x679DD514582F9FCF), uint64(0x0F6D2B697BD44DA8),
            uint64(0x77E36F7304C48942), uint64(0x3F9D85A86A1D36C8), uint64(0x1112E6AD91D692A1)
    } else if algType == algSHA512256 {
        h0, h1, h2, h3, h4, h5, h6, h7 = uint64(0x22312194FC2BF72C), uint64(0x9F555FA3C84C64C2),
            uint64(0x2393B86B6F53B151), uint64(0x963877195940EABD), uint64(0x96283EE2A88EFFE3),
            uint64(0xBE5E1E2553863992), uint64(0x2B0199FC2C85B8AA), uint64(0x0EB72DDC81C52CA2)
    }

    var r [8]uint64
    chunk := len(m) / 128 // block size is 1024 bit
    for k := 0; k < chunk; k++ {
        var W [80]uint64

        for t := 0; t < 80; t++ {
            if t <= 15 {
                j := t * 8
                W[t] = uint64(m[(k*128)+j])<<56 | uint64(m[(k*128)+j+1])<<48 | uint64(m[(k*128)+j+2])<<40 | uint64(m[(k*128)+j+3])<<32 |
                    uint64(m[(k*128)+j+4])<<24 | uint64(m[(k*128)+j+5])<<16 | uint64(m[(k*128)+j+6])<<8 | uint64(m[(k*128)+j+7])
            } else {
                tmp1 := (W[t-2]>>19 | W[t-2]<<45) ^ (W[t-2]>>61 | W[t-2]<<3) ^ (W[t-2] >> 6)
                tmp0 := (W[t-15]>>1 | W[t-15]<<63) ^ (W[t-15]>>8 | W[t-15]<<56) ^ (W[t-15] >> 7)
                W[t] = tmp1 + W[t-7] + tmp0 + W[t-16]
            }
        }

        a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

        var tmp1, tmp2 uint64
        for t := 0; t < 80; t++ {
            tmp1 = h + ((e>>14 | e<<50) ^ (e>>18 | e<<46) ^ (e>>41 | e<<23)) + ((e & f) ^ (^e & g)) + sha5K[t] + W[t]
            tmp2 = ((a>>28 | a<<36) ^ (a>>34 | a<<30) ^ (a>>39 | a<<25)) + ((a & b) ^ (a & c) ^ (b & c))

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