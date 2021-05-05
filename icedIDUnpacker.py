from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from pathlib import PurePath
import pickle
import yara
import binascii
import pefile
import argparse

def extractRdataSect(pe):
    # Extracting the payload from the .rdata section
    print("[+] Extracting rdata...")
    startOfDebugDirectory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]].VirtualAddress
    for section in pe.sections:
        if ".rdata" in str(section.Name):
            rdata = section.get_data()
            rdata = rdata[0x80:]
            RdataVirtualAddress = section.VirtualAddress
            endOfPayload = startOfDebugDirectory - RdataVirtualAddress - 0x80
            return rdata[:endOfPayload]
            
def extractDataSect(pe):
    # Extracting the payload from the .data section
    for section in pe.sections:
        if ".data" in str(section.Name):
            print("[+] Done !")
            data = section.get_data()
            # OK this one is hardcoded, maybe I can do something about it
            return data[16:16400]

def rdataDecode(rdata):
    # First round on the .rdata section.
    decodedRdata = bytearray()
    for i in range(0, len(rdata), 2):
        decodedRdata.append(rdata[i])
    return decodedRdata

def rdataDecrypt(decodedRdata):
    # OK this one is pretty annoying. Starting from the end for the data, and a byte every 20 bytes. Then it loops again, but from len(data)-1 and so on
    payload = bytearray()
    decrem = decodedRdata[-1] # That's where the value is located
    count = 0
    scount = 0
    lenRdata = len(decodedRdata) - 1
    i = lenRdata
    while scount != decrem:
        payload.append(decodedRdata[i])
        i -= decrem
        count = count + 1
        if count == 512:
            i = len(decodedRdata) - 1
            count = 0
            scount += 1
            i = lenRdata - scount
    return payload[::-1]

def gettingObfuscationCode(file):
    rules = yara.compile(source='''rule IceLoaderPacker {
    strings:
        $IceLoaderPacker = {89 DA [0-7] B? FF 44 30 [0-17] C2 44 30 [0-8] 20 ?? 08 D0 [0-8] 88 84}
    condition:
        all of them
    }''')
    with open(file, "rb") as f:
        sample = f.read()
        matches = rules.match(data=sample)
        start = int(matches[0].strings[0][0])
        end = start + len(matches[0].strings[0][2])
        return sample[start:end]

def runObfuscationCode(decodedRdata, encrCode):
    X86_CODE64 = encrCode
    ADDRESS = 0x1000000
    try:
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)
        firstDecr = bytearray()
        count = 0
        key = 1 # Maybe this will change ?
        for byte in decodedRdata:
            if count == 512:
                key += 1
                count = 0
            # initialize machine registers
            mu.reg_write(UC_X86_REG_RAX, byte)
            mu.reg_write(UC_X86_REG_RBX, key)
            mu.reg_write(UC_X86_REG_RDX, 0x0)

            try:
                # emulate machine code in infinite time
                mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64))
            except UcError as e:
                print("ERROR: %s" % e)

            result = mu.reg_read(UC_X86_REG_RAX)
            count += 1
            firstDecr.append(result)
        return firstDecr[::1]

    except UcError as e:
        print("ERROR: %s" % e)

def decryptSecondStage(encryptedPayload, dataSect):
    # The final decryption. Loop throught the data section and take two bytes at a time, adding them and getting the corresponding char in the decrypted payload from .rdata
    secondStage = bytearray()
    count = 0
    step = 512
    padding = 0
    for i in range(0, len(encryptedPayload) * 2, 2):
        try:
            currentChar = encryptedPayload[int.from_bytes(bytes([dataSect[i % len(dataSect)]]) + bytes([dataSect[(i+1) % len(dataSect)]]), "little") + padding]
            secondStage.append(currentChar)
        except IndexError:
            pass   
        count += 1
        if count == step:
            padding += step
            count = 0
    return secondStage

def extractPayload(file):
    # Extracting the payload from the .data section
    print("[+] Extracting the payload...")
    pe = pefile.PE(data=file)
    for section in pe.sections:
        if ".data" in str(section.Name):
            print("[+] Done !")
            return section.get_data()

def decodePayload(payload):
    decrypted = ""
    for i in range(32):
        decrypted += chr(payload[i+64] ^ payload[i])
    return decrypted.split("\x00")[0]

def main():
    parser = argparse.ArgumentParser(description='Decrypt the IcedID config')
    parser.add_argument('-f', '--file', help='Path of the binary file', required=True)
    args = parser.parse_args()
    pe = pefile.PE(args.file)
    rdata = extractRdataSect(pe)
    data = extractDataSect(pe)
    decryptedRdata = rdataDecrypt(rdataDecode(rdata))
    obfCode = gettingObfuscationCode(args.file)
    obfCode = obfCode[:-2]
    encryptedPayload = runObfuscationCode(decryptedRdata, obfCode)
    secondStage = decryptSecondStage(encryptedPayload, data)
    payload = extractPayload(secondStage)
    config = decodePayload(payload[4:]) #skipping the first 4 bytes
    print(f"The C2 config is : {config}")
    filename = PurePath(args.file).parts
    filename = filename[-1]
    with open(f"unpacked_{filename}", "wb") as f:
        f.write(secondStage)

if __name__ == "__main__":
    main()