package sha

import "encoding/hex"

func NewSHA1() *SHA {
    return &SHA{alg:algSHA1}
}

func NewSHA224() *SHA {
    return &SHA{alg:algSHA224}
}

func NewSHA256() *SHA {
    return &SHA{alg:algSHA256}
}


func NewSHA384() *SHA {
    return &SHA{alg:algSHA384}
}

func NewSHA512() *SHA {
    return &SHA{alg:algSHA512}
}

func NewSHA512t(t string) *SHA {
    if t == "224" {
        return &SHA{alg:algSHA512224}
    } else if t == "256" {
        return &SHA{alg:algSHA512256}
    } else {
        return NewSHA512()
    }

}


const (
    algSHA1       = 0
    algSHA224     = 1
    algSHA256     = 2
    algSHA384     = 3
    algSHA512     = 4
    algSHA512224  = 5
    algSHA512256  = 6
)


const (
    digestLenSHA1      = 5 // five uint32
    digestLenSHA224    = 7 // seven uint32
    digestLenSHA256    = 8 // eight uint32
    digestLenSHA384    = 6 // six uint64
    digestLenSHA512    = 8 // eight uint64
    digestLenSHA512224 = 4 // 224 bits only take four uint64
    digestLenSHA512256 = 4 // 256 bits only take four uint64
)

type SHA struct {
    alg int

    digest1 [5]uint32 // for sha1
    digest2 [8]uint32 // for sha256, sha224
    digest3 [8]uint64 // for other algorithms
}


func (sha *SHA) Digest(m []byte) {
    switch sha.alg {
    case algSHA1:
        sha.digest1 = sha1Digest(m)
    case algSHA224:
        sha.digest2 = sha2Digest(algSHA224, m)
    case algSHA256:
        sha.digest2 = sha2Digest(algSHA256, m)
    case algSHA384:
        sha.digest3 = sha5Digest(algSHA384, m)
    case algSHA512:
        sha.digest3 = sha5Digest(algSHA512, m)
    case algSHA512224:
        sha.digest3 = sha5Digest(algSHA512224, m)
    case algSHA512256:
        sha.digest3 = sha5Digest(algSHA512256, m)
    }
}


func (sha *SHA) Hex() string {
    return hex.EncodeToString(sha.Binary())
}

func (sha *SHA) Binary() []byte {
    var dig []byte
    switch sha.alg {
    case algSHA1:
        for i := 0; i < digestLenSHA1; i++ {
            dig = append(dig, littleEndianBytesUint32(sha.digest1[i])...)
        }
    case algSHA224:
        for i := 0; i < digestLenSHA224; i++ {
            dig = append(dig, bigEndianBytesUint32(sha.digest2[i])...)
        }
    case algSHA256:
        for i := 0; i < digestLenSHA256; i++ {
            dig = append(dig, bigEndianBytesUint32(sha.digest2[i])...)
        }
    case algSHA384:
        for i := 0; i < digestLenSHA384; i++ {
            dig = append(dig, bigEndianBytesUint64(sha.digest3[i])...)
        }
    case algSHA512:
        for i := 0; i < digestLenSHA512; i++ {
            dig = append(dig, bigEndianBytesUint64(sha.digest3[i])...)
        }
    case algSHA512224:
        for i := 0; i < digestLenSHA512224; i++ {
            dig = append(dig, bigEndianBytesUint64(sha.digest3[i])...)
        }
        dig = dig[0:28] // left-most 224 bits
    case algSHA512256:
        for i := 0; i < digestLenSHA512256; i++ {
            dig = append(dig, bigEndianBytesUint64(sha.digest3[i])...)
        }
        dig = dig[0:32] // left-most 256 bits
    }
    return dig
}


// Size returns the length of specific SHA message digest algorithm in bytes
func (sha *SHA) Size() int {
    switch sha.alg {
    case algSHA1:
        return 20 // 160 bits
    case algSHA224:
        return 28 //224 bits
    case algSHA256:
        return 32 // 256 bits
    case algSHA384:
        return 48 // 384 bits
    case algSHA512:
        return 64 // 512 bits
    case algSHA512224:
        return 28 // 224 bits
    case algSHA512256:
        return 32 // 256 bits
    default:
        return 0
    }
}

// BlockSize returns block size of specific SHA message digest algorithm in bytes
func (sha *SHA) BlockSize() int {
    switch sha.alg {
    case algSHA1, algSHA224, algSHA256:
        return 64
    case algSHA384, algSHA512,  algSHA512224, algSHA512256:
        return 128
    default:
        return 0
    }
}


