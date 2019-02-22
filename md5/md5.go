package md5

import "encoding/hex"

const (
    A = uint32(0x67452301)
    B = uint32(0xEFCDAB89)
    C = uint32(0x98BADCFE)
    D = uint32(0x10325476)
)

type MD5 struct {
    r [4]uint32 // result
}

func (md5 *MD5) prepareData(rawData []byte) []byte {

    // padding
    var lenData, padLen uint32
    lenData = uint32(len(rawData))
    padLen = 0
    if lenData % 64 < 56 {
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
        bitLenBytes[i] = byte(lenData >> (8 * i))
    }
    rawData = append(rawData, bitLenBytes...)
    return rawData
}

func (md5 *MD5) Digest(m []byte) {
    m = md5.prepareData(m)
    a, b, c, d := A, B, C, D
    chunk := len(m) / 64 // process the data as 16-word block
    for k := 0; k < chunk; k++ {
        /* Copy block i into X. */
        // For j = 0 to 15 do
        //     Set X[j] to M[i*16+j].
        // end /* of loop on j */

        var X [16]uint32

        j := 0
        for i := 0; i < 16; i++ {
            X[i] = uint32(m[(k*64)+j]) | uint32(m[(k*64)+j+1])<<8 | uint32(m[(k*64)+j+2])<<16 | uint32(m[(k*64)+j+3])<<24
            j += 4
        }

        /* Save A as AA, B as BB, C as CC, and D as DD. */
        AA, BB, CC, DD := a, b, c, d

        /* Round 1. */
        /* Let [abcd k s i] denote the operation
        a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
        /* Do the following 16 operations. */
        // [ABCD 0 7 1] [DABC 1 12 2] [CDAB 2 17 3] [BCDA 3 22 4]
        a += (((c ^ d) & b) ^ d) + X[0] + 3614090360
        a = a<<7 | a>>(32-7) + b
        d += (((b ^ c) & a) ^ c) + X[1] + 3905402710
        d = d<<12 | d>>(32-12) + a
        c += (((a ^ b) & d) ^ b) + X[2] + 606105819
        c = c<<17 | c>>(32-17) + d
        b += (((d ^ a) & c) ^ a) + X[3] + 3250441966
        b = b<<22 | b>>(32-22) + c

        // [ABCD 4 7 5] [DABC 5 12 6] [CDAB 6 17 7] [BCDA 7 22 8]
        a += (((c ^ d) & b) ^ d) + X[4] + 4118548399
        a = a<<7 | a>>(32-7) + b
        d += (((b ^ c) & a) ^ c) + X[5] + 1200080426
        d = d<<12 | d>>(32-12) + a
        c += (((a ^ b) & d) ^ b) + X[6] + 2821735955
        c = c<<17 | c>>(32-17) + d
        b += (((d ^ a) & c) ^ a) + X[7] + 4249261313
        b = b<<22 | b>>(32-22) + c

        // [ABCD 8 7 9] [DABC 9 12 10] [CDAB 10 17 11] [BCDA 11 22 12]
        a += (((c ^ d) & b) ^ d) + X[8] + 1770035416
        a = a<<7 | a>>(32-7) + b
        d += (((b ^ c) & a) ^ c) + X[9] + 2336552879
        d = d<<12 | d>>(32-12) + a
        c += (((a ^ b) & d) ^ b) + X[10] + 4294925233
        c = c<<17 | c>>(32-17) + d
        b += (((d ^ a) & c) ^ a) + X[11] + 2304563134
        b = b<<22 | b>>(32-22) + c

        // [ABCD 12 7 13] [DABC 13 12 14] [CDAB 14 17 15] [BCDA 15 22 16]
        a += (((c ^ d) & b) ^ d) + X[12] + 1804603682
        a = a<<7 | a>>(32-7) + b
        d += (((b ^ c) & a) ^ c) + X[13] + 4254626195
        d = d<<12 | d>>(32-12) + a
        c += (((a ^ b) & d) ^ b) + X[14] + 2792965006
        c = c<<17 | c>>(32-17) + d
        b += (((d ^ a) & c) ^ a) + X[15] + 1236535329
        b = b<<22 | b>>(32-22) + c

        /* Round 2. */
        /* Let [abcd k s i] denote the operation
        a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
        /* Do the following 16 operations. */
        // [ABCD 1 5 17] [DABC 6 9 18] [CDAB 11 14 19] [BCDA 0 20 20]
        a += (((b ^ c) & d) ^ c) + X[(1+5*0)&15] + 4129170786
        a = a<<5 | a>>(32-5) + b
        d += (((a ^ b) & c) ^ b) + X[(1+5*1)&15] + 3225465664
        d = d<<9 | d>>(32-9) + a
        c += (((d ^ a) & b) ^ a) + X[(1+5*2)&15] + 643717713
        c = c<<14 | c>>(32-14) + d
        b += (((c ^ d) & a) ^ d) + X[(1+5*3)&15] + 3921069994
        b = b<<20 | b>>(32-20) + c

        // [ABCD 5 5 21] [DABC 10 9 22] [CDAB 15 14 23] [BCDA 4 20 24]
        a += (((b ^ c) & d) ^ c) + X[(1+5*4)&15] + 3593408605
        a = a<<5 | a>>(32-5) + b
        d += (((a ^ b) & c) ^ b) + X[(1+5*5)&15] + 38016083
        d = d<<9 | d>>(32-9) + a
        c += (((d ^ a) & b) ^ a) + X[(1+5*6)&15] + 3634488961
        c = c<<14 | c>>(32-14) + d
        b += (((c ^ d) & a) ^ d) + X[(1+5*7)&15] + 3889429448
        b = b<<20 | b>>(32-20) + c

        // [ABCD 9 5 25] [DABC 14 9 26] [CDAB 3 14 27] [BCDA 8 20 28]
        a += (((b ^ c) & d) ^ c) + X[(1+5*8)&15] + 568446438
        a = a<<5 | a>>(32-5) + b
        d += (((a ^ b) & c) ^ b) + X[(1+5*9)&15] + 3275163606
        d = d<<9 | d>>(32-9) + a
        c += (((d ^ a) & b) ^ a) + X[(1+5*10)&15] + 4107603335
        c = c<<14 | c>>(32-14) + d
        b += (((c ^ d) & a) ^ d) + X[(1+5*11)&15] + 1163531501
        b = b<<20 | b>>(32-20) + c

        //[ABCD 13 5 29] [DABC 2 9 30] [CDAB 7 14 31] [BCDA 12 20 32]
        a += (((b ^ c) & d) ^ c) + X[(1+5*12)&15] + 2850285829
        a = a<<5 | a>>(32-5) + b
        d += (((a ^ b) & c) ^ b) + X[(1+5*13)&15] + 4243563512
        d = d<<9 | d>>(32-9) + a
        c += (((d ^ a) & b) ^ a) + X[(1+5*14)&15] + 1735328473
        c = c<<14 | c>>(32-14) + d
        b += (((c ^ d) & a) ^ d) + X[(1+5*15)&15] + 2368359562
        b = b<<20 | b>>(32-20) + c

        /* Round 3. */
        /* Let [abcd k s t] denote the operation
        a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
        /* Do the following 16 operations. */
        // [ABCD 5 4 33] [DABC 8 11 34] [CDAB 11 16 35] [BCDA 14 23 36]
        a += (b ^ c ^ d) + X[(5+3*0)&15] + 4294588738
        a = a<<4 | a>>(32-4) + b
        d += (a ^ b ^ c) + X[(5+3*1)&15] + 2272392833
        d = d<<11 | d>>(32-11) + a
        c += (d ^ a ^ b) + X[(5+3*2)&15] + 1839030562
        c = c<<16 | c>>(32-16) + d
        b += (c ^ d ^ a) + X[(5+3*3)&15] + 4259657740
        b = b<<23 | b>>(32-23) + c

        // [ABCD 1 4 37] [DABC 4 11 38] [CDAB 7 16 39] [BCDA 10 23 40]
        a += (b ^ c ^ d) + X[(5+3*4)&15] + 2763975236
        a = a<<4 | a>>(32-4) + b
        d += (a ^ b ^ c) + X[(5+3*5)&15] + 1272893353
        d = d<<11 | d>>(32-11) + a
        c += (d ^ a ^ b) + X[(5+3*6)&15] + 4139469664
        c = c<<16 | c>>(32-16) + d
        b += (c ^ d ^ a) + X[(5+3*7)&15] + 3200236656
        b = b<<23 | b>>(32-23) + c

        // [ABCD 13 4 41] [DABC 0 11 42] [CDAB 3 16 43] [BCDA 6 23 44]
        a += (b ^ c ^ d) + X[(5+3*8)&15] + 681279174
        a = a<<4 | a>>(32-4) + b
        d += (a ^ b ^ c) + X[(5+3*9)&15] + 3936430074
        d = d<<11 | d>>(32-11) + a
        c += (d ^ a ^ b) + X[(5+3*10)&15] + 3572445317
        c = c<<16 | c>>(32-16) + d
        b += (c ^ d ^ a) + X[(5+3*11)&15] + 76029189
        b = b<<23 | b>>(32-23) + c

        // [ABCD 9 4 45] [DABC 12 11 46] [CDAB 15 16 47] [BCDA 2 23 48]
        a += (b ^ c ^ d) + X[(5+3*12)&15] + 3654602809
        a = a<<4 | a>>(32-4) + b
        d += (a ^ b ^ c) + X[(5+3*13)&15] + 3873151461
        d = d<<11 | d>>(32-11) + a
        c += (d ^ a ^ b) + X[(5+3*14)&15] + 530742520
        c = c<<16 | c>>(32-16) + d
        b += (c ^ d ^ a) + X[(5+3*15)&15] + 3299628645
        b = b<<23 | b>>(32-23) + c

        /* Round 4. */
        /* Let [abcd k s t] denote the operation
        a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
        /* Do the following 16 operations. */
        // [ABCD 0 6 49] [DABC 7 10 50] [CDAB 14 15 51] [BCDA 5 21 52]
        a += (c ^ (b | ^d)) + X[(7*0)&15] + 4096336452
        a = a<<6 | a>>(32-6) + b
        d += (b ^ (a | ^c)) + X[(7*1)&15] + 1126891415
        d = d<<10 | d>>(32-10) + a
        c += (a ^ (d | ^b)) + X[(7*2)&15] + 2878612391
        c = c<<15 | c>>(32-15) + d
        b += (d ^ (c | ^a)) + X[(7*3)&15] + 4237533241
        b = b<<21 | b>>(32-21) + c

        // [ABCD 12 6 53] [DABC 3 10 54] [CDAB 10 15 55] [BCDA 1 21 56]
        a += (c ^ (b | ^d)) + X[(7*4)&15] + 1700485571
        a = a<<6 | a>>(32-6) + b
        d += (b ^ (a | ^c)) + X[(7*5)&15] + 2399980690
        d = d<<10 | d>>(32-10) + a
        c += (a ^ (d | ^b)) + X[(7*6)&15] + 4293915773
        c = c<<15 | c>>(32-15) + d
        b += (d ^ (c | ^a)) + X[(7*7)&15] + 2240044497
        b = b<<21 | b>>(32-21) + c

        // [ABCD 8 6 57] [DABC 15 10 58] [CDAB 6 15 59] [BCDA 13 21 60]
        a += (c ^ (b | ^d)) + X[(7*8)&15] + 1873313359
        a = a<<6 | a>>(32-6) + b
        d += (b ^ (a | ^c)) + X[(7*9)&15] + 4264355552
        d = d<<10 | d>>(32-10) + a
        c += (a ^ (d | ^b)) + X[(7*10)&15] + 2734768916
        c = c<<15 | c>>(32-15) + d
        b += (d ^ (c | ^a)) + X[(7*11)&15] + 1309151649
        b = b<<21 | b>>(32-21) + c

        // [ABCD 4 6 61] [DABC 11 10 62] [CDAB 2 15 63] [BCDA 9 21 64]
        a += (c ^ (b | ^d)) + X[(7*12)&15] + 4149444226
        a = a<<6 | a>>(32-6) + b
        d += (b ^ (a | ^c)) + X[(7*13)&15] + 3174756917
        d = d<<10 | d>>(32-10) + a
        c += (a ^ (d | ^b)) + X[(7*14)&15] + 718787259
        c = c<<15 | c>>(32-15) + d
        b += (d ^ (c | ^a)) + X[(7*15)&15] + 3951481745
        b = b<<21 | b>>(32-21) + c

        a = AA + a
        b = BB + b
        c = CC + c
        d = DD + d
    }

    md5.r[0] = a
    md5.r[1] = b
    md5.r[2] = c
    md5.r[3] = d
}

func (md5 *MD5) Binary() []byte {
    bytes := make([]byte, 16)
    bytes[0]  = byte(md5.r[0] & 0xFF)
    bytes[1]  = byte((md5.r[0] & 0xFF00) >> 8)
    bytes[2]  = byte((md5.r[0] & 0xFF0000) >> 16)
    bytes[3]  = byte((md5.r[0] & 0xFF000000) >> 24)
    bytes[4]  = byte(md5.r[1] & 0xFF)
    bytes[5]  = byte((md5.r[1] & 0xFF00) >> 8)
    bytes[6]  = byte((md5.r[1] & 0xFF0000) >> 16)
    bytes[7]  = byte((md5.r[1] & 0xFF000000) >> 24)
    bytes[8]  = byte(md5.r[2] & 0xFF)
    bytes[9]  = byte((md5.r[2] & 0xFF00) >> 8)
    bytes[10] = byte((md5.r[2] & 0xFF0000) >> 16)
    bytes[11] = byte((md5.r[2] & 0xFF000000) >> 24)
    bytes[12] = byte(md5.r[3] & 0xFF)
    bytes[13] = byte((md5.r[3] & 0xFF00) >> 8)
    bytes[14] = byte((md5.r[3] & 0xFF0000) >> 16)
    bytes[15] = byte((md5.r[3] & 0xFF000000) >> 24)
    return bytes
}

func (md5 *MD5) Hex() string {
    return hex.EncodeToString(md5.Binary())
}

// Size returns the length of MD5 message digest in bytes
func (md5 *MD5) Size() int {
    return 16 // 128 bits
}


// BlockSize returns block size of MD5 message digest algorithm in bytes
func (md5 *MD5) BlockSize() int {
    return 64 // 16-Word block = 64 bytes
}
