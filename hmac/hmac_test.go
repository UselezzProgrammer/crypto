package hmac

import "testing"

var hmac_key = []byte("123456")
var input = [6]string{
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
}

var hmac_md5_output = [6]string{
    "6eadbbfbad43007b4c73cf3f228de890",
    "31c7c3659be95cd3c7c024a14751cf0c",
    "017074ea675740f49f8544a4c8e02337",
    "14e1f34a37e325ad0d2ae20ea4d0bfca",
    "c11930c66cac95d913d90f91395fca6c",
    "c825e0fcb1857643cf496a4e988f7111",
}

var hmac_sha1_output = [6]string{
    "ae2fa0c621e69ae63821e90ffb428ddbfb031031",
    "f1ae6a48d467345aa63e72a8cbd8baba92417ce5",
    "b5d5da50163feb7a85f8b21fdcb218499523e1ee",
    "fd08ccbbbbdcbb90780e703ba16442a5b26165c8",
    "89f413e55fc45fc3e1766d4a5e4cdaa54004148e",
    "fd80b4422788d2e568abb98e336c6bb6c2977b32",
}

var hmac_sha224_output = [6]string{
    "55feecc2ba9e9e094be614413fda89fa05b1cd5001bfcba851edab6b",
    "a1083990356121fb87ecfb5c8204792ffb2b94be951714c771fcd2c7",
    "822a59e4f5454067193c1b0ce8ffa2fbd8465f2738ce2eb431276708",
    "acb575db98b110427ba2269ead2128f685334c4fbdfe123df858a861",
    "21a1e348f7b5cbe7c096c74dc860beba4520667422751c9d4a9f522a",
    "02ee955603ebd227afd652645bb558007acff688bc7542f9c1018a04",
}

var hmac_sha256_output = [6]string{
    "e67ccd2d2cfeb5f41765acb9b717565bedc585b841aa370221a912e609107148",
    "f6ced6f4883ffc0981a6b9945819f680102b43097ad8ef7a0df9bde06fb3d2e4",
    "a67b92fad10d2d2cac8f319f69287afe8a0f0c87137bdf69893011b2f01269ab",
    "49e3b5f4ee3cb7deb6731efe975f4f214986cc64766dd58d1532e9dbcd0ec2ec",
    "0ced729477d8658fdda9ef2cb308a765e5da58a9cc354d79a74ae313e9e2e883",
    "d700efab9ab2e545fb587347155dd1e34adc688f01ce34c8c68a4c74d201f08e",
}

var hmac_sha384_output = [6]string{
    "aede47889e61d7de7a1bc34bf97e43ad122d0b50a8769777f9103d965ccfd5d1d6a1fc0a31b9b8efaa74348e119ff50f",
    "bd31dbd1073ceca7cb43c96a7cbd02e1df33e6ce276601bdc6178ba8e20b18323b29422de92a9180932ef8f49a4873fe",
    "cc56a6f4c058eb82fb388c389a5ca2986e255c99f9a757bb9b02f503ac215926b55b10c7be9e48bccc340758b442aea7",
    "f7d8e7694e0e98d3743fff710af5edaffd39b8e0f43cb03c4c50aaaea55d9a2d80a27a56ea4f091d9c8e6da7931b5ca3",
    "23f639dbd01ec6b2a5a18f4b1de51cce6e36b531beafc083f327e7f8539762eb1595be97a3efe69af33b41b02748e85a",
    "f936935ef170e9e8de244bb603bf55e9c747c435e59b7fd19540dc52f95d9805f6073441008759f23ce8e00abd019d0f",
}

var hmac_sha512_output = [6]string{
    "fabb661d28eb8920a80e1320cf3b6a7f75a33cd3f86dfe10fc1e82b04cbd184628bdbd800c60b9446134b9b4a82653422dfa874f0bf50150c4248fc55c4d09df",
    "7842485b1a55745a9823c3e155986ec9bde5b140691678c5d202a4e1f4664f130ac4fc4dc75c8a51d47b9a8fb43bdcf30652143da696fe79407032ce48aba2f8",
    "d740af8249f463a94755e6b68da81e1ea84ebd3cc57c055f6a35d683e7af0d048bcae2b9fb453ebde73c9e617709614da8be875887bed17f637f1f4074edb5c7",
    "225c0c6f817e96122d1dfb3dd7b64808ec2fed941f0233e8785831285f985a09a62bad2a7347e67598d9c64391d73aec78f19dbfde43a4189fb0769405b6289c",
    "fb973c0df1b355220428b9ca1afbec10a8c2cc27f745e57f8eef4d82cdc747f9a082c79e6c8b0c0dc2d98d6e66293edc3abdbfb2eb7ee70da6f56219f5b2dfe5",
    "02f9ad298340bfe05a518bd599d6b46e4087f23ae62f45dc7d269b53143fa0e0663965c3bea181b932b701ae8757f0dabaccb7898e2b0dbff8cc618d272ba887",
}



func TestHMAC_MD5(t *testing.T) {
    hmac, err := New("md5", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_md5_output[i] {
            t.FailNow()
        }
    }
}

func TestHMAC_SHA1(t *testing.T) {
    hmac, err := New("sha1", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_sha1_output[i] {
            t.FailNow()
        }
    }
}

func TestHMAC_SHA224(t *testing.T) {
    hmac, err := New("sha224", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_sha224_output[i] {
            t.FailNow()
        }
    }
}

func TestHMAC_SHA256(t *testing.T) {
    hmac, err := New("sha256", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_sha256_output[i] {
            t.FailNow()
        }
    }
}

func TestHMAC_SHA384(t *testing.T) {
    hmac, err := New("sha384", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_sha384_output[i] {
            t.FailNow()
        }
    }
}

func TestHMAC_SHA512(t *testing.T) {
    hmac, err := New("sha512", hmac_key)
    if err != nil {
        t.FailNow()
    }

    l := len(input)
    for i := 0; i < l; i++ {
        hmac.Digest([]byte(input[i]))
        if hmac.Hex() != hmac_sha512_output[i] {
            t.FailNow()
        }
    }
}