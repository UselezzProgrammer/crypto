package hmac

import (
    "encoding/hex"
    "errors"
    "fmt"
    "mycrypto"
    "mycrypto/md5"
    "mycrypto/sha"
)

type Hmac struct {
    hashAlg string
    key []byte
    hash mycrypto.Hash
    ipad, opad []byte
}

func New(hashAlg string, key []byte) (*Hmac, error) {
    hmac := &Hmac{}
    if err := hmac.setHash(hashAlg); err != nil {
        return nil, err
    }
    hmac.hashAlg = hashAlg

    if len(key) > hmac.hash.BlockSize() {
        hmac.hash.Digest(key)
        hmac.key = hmac.hash.Binary()
    } else {
        hmac.key = key
    }

    hmac.ipad = make([]byte, hmac.hash.BlockSize())
    hmac.opad = make([]byte, hmac.hash.BlockSize())
    copy(hmac.ipad, hmac.key)
    copy(hmac.opad, hmac.key)
    for i := 0; i < hmac.hash.BlockSize(); i++ {
        hmac.ipad[i] ^= 0x36
        hmac.opad[i] ^= 0x5C
    }

    return hmac, nil
}

func (hmac *Hmac) setHash(hashAlg string) error {
    switch hashAlg {
    case "md5":
        hmac.hash = &md5.MD5{}
    case "sha1":
        hmac.hash = sha.NewSHA1()
    case "sha224":
        hmac.hash = sha.NewSHA224()
    case "sha256":
        hmac.hash = sha.NewSHA256()
    case "sha384":
        hmac.hash = sha.NewSHA384()
    case "sha512":
        hmac.hash = sha.NewSHA512()
    default:
        return errors.New(fmt.Sprintf("unsupported hash algorithm: %s", hashAlg))
    }
    return nil
}

func (hmac *Hmac) Digest(m []byte) {
    m = append(hmac.ipad, m...)
    hmac.hash.Digest(m)
    m = append(hmac.opad, hmac.hash.Binary()...)
    hmac.hash.Digest(m)
}

func (hmac *Hmac) Binary() []byte {
    return hmac.hash.Binary()
}

func (hmac *Hmac) Hex() string {
    return hex.EncodeToString(hmac.Binary())
}