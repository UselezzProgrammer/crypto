package sha

import (
    "testing"
)

var sha1Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha1Output = [7]string{
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "c12252ceda8be8994d5fa0290a47231c1d16aae3",
    "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
    "761c457bf73b14d27e9e9265c46f4b4dda11f940",
    "50abf5706a150990a08b2c5ea40fa0e585554732",
}

var sha224Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha224Output = [7]string{
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
    "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
    "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
    "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e",
}

var sha256Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha256Output = [7]string{
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
    "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
}


var sha384Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha384Output = [7]string{
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
    "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
    "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
    "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
}

var sha512Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha512Output = [7]string{
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
    "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
    "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
    "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
}

var sha512224Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha512224Output = [7]string{
    "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    "ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564",
    "ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8",
    "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3",
    "ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2",
}

var sha512256Input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var sha512256Output = [7]string{
    "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    "0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb",
    "fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26",
    "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8",
    "2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148",
}

func TestSHA1(t *testing.T) {
    sha1 := NewSHA1()

    l := len(sha1Input)
    for i := 0; i < l; i++ {
        sha1.Digest([]byte(sha1Input[i]))
        if sha1.Hex() != sha1Output[i]  {
            t.FailNow()
        }
    }
}

func TestSHA224(t *testing.T) {
    sha224 := NewSHA224()

    l := len(sha224Input)
    for i := 0; i < l; i++ {
        sha224.Digest([]byte(sha224Input[i]))
        if sha224.Hex() != sha224Output[i]  {
            t.FailNow()
        }
    }
}

func TestSHA256(t *testing.T) {
    sha256 := NewSHA256()

    l := len(sha256Input)
    for i := 0; i < l; i++ {
        sha256.Digest([]byte(sha256Input[i]))
        if sha256.Hex() != sha256Output[i]  {
            t.FailNow()
        }
    }
}

func TestSHA384(t *testing.T) {
    sha384 := NewSHA384()

    l := len(sha384Input)
    for i := 0; i < l; i++ {
        sha384.Digest([]byte(sha384Input[i]))
        if sha384.Hex() != sha384Output[i] {
            t.FailNow()
        }
    }
}

func TestSHA512(t *testing.T) {
    sha512 := NewSHA512()

    l := len(sha512Input)
    for i := 0; i < l; i++ {
        sha512.Digest([]byte(sha512Input[i]))
        if sha512.Hex() != sha512Output[i] {
            t.FailNow()
        }
    }
}

func TestSHA512224(t *testing.T) {
    sha5 := NewSHA512t("224")

    l := len(sha512224Input)
    for i := 0; i < l; i++ {
        sha5.Digest([]byte(sha512224Input[i]))
        if sha5.Hex() != sha512224Output[i] {
            t.FailNow()
        }
    }
}

func TestSHA512256(t *testing.T) {
    sha5 := NewSHA512t("256")

    l := len(sha512256Input)
    for i := 0; i < l; i++ {
        sha5.Digest([]byte(sha512256Input[i]))
        if sha5.Hex() != sha512256Output[i] {
            t.FailNow()
        }
    }
}