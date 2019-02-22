package md5

import (
    "fmt"
    "testing"
)

var input = [7]string{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}
var md5s = [7]string{
    "d41d8cd98f00b204e9800998ecf8427e",
    "0cc175b9c0f1b6a831c399e269772661",
    "900150983cd24fb0d6963f7d28e17f72",
    "f96b697d7cb7938d525a2f31aaf161d0",
    "c3fcd3d76192e4007dfb496cca67e13b",
    "d174ab98d277d9f5a5611c2c9f419d9f",
    "57edf4a22be3c955ac49da2e2107b67a",
}

func TestAll(t *testing.T) {
    md5 := MD5{}

    l := len(input)
    for i := 0; i < l; i++ {
        md5.Digest([]byte(input[i]))
        if md5.Hex() != md5s[i]  {
            fmt.Println(input[i], " ", md5s[i], " ", md5.Hex())
            t.FailNow()
        }
    }

}