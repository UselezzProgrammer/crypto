package sha

func littleEndianBytesUint32(val uint32) []byte {
    bytes := make([]byte, 4)
    bytes[0]   = byte((val & 0xFF000000) >> 24)
    bytes[1]   = byte((val & 0xFF0000) >> 16)
    bytes[2]   = byte((val & 0xFF00) >> 8)
    bytes[3]   = byte(val & 0xFF)
    return bytes
}

func sha1Digest(m []byte) [5]uint32 {
    var r [5]uint32
    m = sha2PrepareData(m)
    h0, h1, h2, h3, h4 :=  uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476), uint32(0xc3d2e1f0)
    chunk := len(m) / 64
    for k := 0; k < chunk; k++ {
        var W [80]uint32

        for t := 0; t < 80; t++ {
            if t <= 15 {
                j := t * 4
                W[t] =  uint32(m[(k*64)+j])<<24 | uint32(m[(k*64)+j+1])<<16 | uint32(m[(k*64)+j+2])<<8 | uint32(m[(k*64)+j+3])
            } else {
                W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
                W[t] = W[t]<<1|W[t]>>31
            }
        }

        a, b, c, d, e := h0, h1, h2, h3, h4
        var tmp uint32
        for t := 0; t < 80; t++ {
            if t < 20 {
                tmp = (a<<5|a>>27) + (b&c|(^b)&d) + e + W[t] + uint32(0x5a827999)
            } else if t < 40 {
                tmp = (a<<5|a>>27) + (b^c^d) + e + W[t] + uint32(0x6ed9eba1)
            } else if t < 60 {
                tmp = (a<<5|a>>27) + ((b&c)^(b&d)^(c&d)) + e + W[t] + uint32(0x8f1bbcdc)
            } else {
                tmp = (a<<5|a>>27) + (b^c^d) + e + W[t] + uint32(0xca62c1d6)
            }
            e, d, c, b, a = d, c, b<<30|b>>2, a, tmp
        }

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
    }

    r[0] = h0
    r[1] = h1
    r[2] = h2
    r[3] = h3
    r[4] = h4
    return r
}

