rule iceloaderpacker {
    meta:
        author      = "4rchib4ld"
        description = "Iceloader"
        reference   = "https://4rchib4ld.github.io/blog/HoneymoonOnIceloader/"
        type        = "malware.loader"
        created     = "2021-05-14"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $obfuscationCode = {89 DA [0-7] B? FF 44 30 [0-17] C2 44 30 [0-8] 20 ?? 08 D0 [0-8] 88 84} // This code is used for deobfuscation
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and // We only want PE files
        all of them
    }