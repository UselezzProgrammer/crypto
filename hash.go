package mycrypto



type Hash interface {
    // Size returns the length of hash algorithm in bytes
    Size() int

    // BlockSize returns block size of hash algorithm in bytes
    BlockSize() int

    // Digest() compute the message digest on the input data
    Digest(m []byte)

    // Binary() returns the binary message digest
    Binary() []byte
}

