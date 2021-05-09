rule iceLoaderPacker {
    strings:
        $obfuscationCode = {89 DA [0-7] B? FF 44 30 [0-17] C2 44 30 [0-8] 20 ?? 08 D0 [0-8] 88 84}
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and
        all of them
    }