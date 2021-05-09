from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from pathlib import PurePath
import pickle
import yara
import binascii
import pefile
import argparse
import logging
import hexdump
from icecream import ic

log = logging.getLogger(__name__)


def extractRdataSect(pe):
    """ 
    Extracting the payload from the .rdata section
    """
    startOfDebugDirectory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]].VirtualAddress
    for section in pe.sections:
        if ".rdata" in str(section.Name):
            rdata = section.get_data()
            rdata = rdata[0x80:]
            RdataVirtualAddress = section.VirtualAddress
            endOfPayload = startOfDebugDirectory - RdataVirtualAddress - 0x80
            if debug:
                log.debug('EXTRACTED RDATA section:')
                hexdump.hexdump(rdata[:endOfPayload])
            return rdata[:endOfPayload]
            
def extractDataSect(pe):
    """
    Extracting the payload from the .data section
    """
    for section in pe.sections:
        if ".data" in str(section.Name):
            data = section.get_data()
            # OK this one is hardcoded, maybe I can do something about it
            if debug is True:
                log.debug('EXTRACTED DATA section:')
                hexdump.hexdump(data[16:16400])
            return data[16:16400]

def rdataDecode(rdata):
    """
    Decoding .rdata. Making it ready for the next stage
    """
    decodedRdata = bytearray()
    for i in range(0, len(rdata), 2):
        decodedRdata.append(rdata[i])
    if debug:
        log.debug('Decoded RDATA section:')
        hexdump.hexdump(decodedRdata)
    return decodedRdata

def rdataDecrypt(decodedRdata):
    """
    Starting from the end for the data, and a byte every 20 bytes. Then it loops again, but from len(data)-1 and so on
    """
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
    if debug:
        log.debug('Decrypted RDATA section:')
        hexdump.hexdump(payload[::-1])
    return payload[::-1]

def gettingObfuscationCode(file, yaraRule):
    """
    Retrieving the code used for obfuscation using a Yara rule
    """
    rules = yara.compile(filepath=yaraRule)
    f = open(file, "rb")
    matches = rules.match(data=f.read())
    f.close()
    obfuscationCode = matches[0].strings[0][2]
    if debug:
        log.debug("Obfuscation code :", obfuscationCode)

    return obfuscationCode

def runObfuscationCode(decodedRdata, obfuscationCode):
    """
    Treat the obfuscation code as a shellcode (could have used the code offset instead) and run it in a loop
    """
    X86_CODE64 = obfuscationCode
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
        deobfuscatedPayload = bytearray()
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
            deobfuscatedPayload.append(result)
        if debug:
            log.debug('Deobfuscated Payload :')
            hexdump.hexdump(deobfuscatedPayload[::1])
        return deobfuscatedPayload[::1]

    except UcError as e:
        log.error("Something is wrong with Unicorn : %s" % e)

def decryptSecondStage(encryptedPayload, dataSect):
    """
    The final decryption. Loop throught the data section and take two bytes at a time, adding them and getting the corresponding char in the decrypted payload from .rdata
    """
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
    if debug:
        log.debug('Second Stage :')
        hexdump.hexdump(secondStage)
    return secondStage

def extractPayloadFromUnpackedData(file):
    """
    Extracting the payload from the .data section of the unpacked executable
    """
    MAX_STRING_SIZE = 128
    pe = pefile.PE(data=file)
    for section in pe.sections:
        if ".data" in str(section.Name):
            data = section.get_data()
            payload = data[4:MAX_STRING_SIZE].split(b"\0")[0]
            if debug:
                log.debug('Extracted Payload from the second stage:')
                hexdump.hexdump(payload) 
            return payload

def decodePayloadFromUnpackedData(payload, obfuscationCode):
    """
    Decode the payload from the .data section of the unpacked executable using dynamic values
    """
    xorCountValue = obfuscationCode[3] ## Getting this values dynamically because... you never know
    countValue = obfuscationCode[-1]
    decrypted = ""
    for i in range(countValue):
        try:
            decrypted += chr(payload[i+xorCountValue] ^ payload[i])
        except IndexError:
            pass
    config = decrypted.split("\x00")[0]
    return config

def main():
    global debug
    parser = argparse.ArgumentParser(description='Decrypt the IcedID config')
    parser.add_argument('-f', '--file', help='Path of the binary file', required=True)
    parser.add_argument('--debug', help='Debug', type=bool, default=False, required=False)
    args = parser.parse_args()
    debug = args.debug
    pe = pefile.PE(args.file)
    rdata = extractRdataSect(pe)
    data = extractDataSect(pe)
    decryptedRdata = rdataDecrypt(rdataDecode(rdata))
    obfuscationCode = gettingObfuscationCode(args.file, "iceLoaderPacker.yar")
    obfuscationCode = obfuscationCode[:-2] # Removing the last two bytes because I use them as markor for the end of the code
    encryptedPayload = runObfuscationCode(decryptedRdata, obfuscationCode)
    unpackedExecutable = decryptSecondStage(encryptedPayload, data)
    filename = PurePath(args.file).parts
    filename = filename[-1]
    unpackedFileName = "unpacked_" + filename
    log.info(f"Writing the unpacked data to {unpackedFileName}")
    with open(unpackedFileName, "wb") as f:
        f.write(unpackedExecutable)
    payload = extractPayloadFromUnpackedData(unpackedExecutable)
    secondStageObfuscationCode = gettingObfuscationCode(unpackedFileName, "icedid.yar")
    config = decodePayloadFromUnpackedData(payload[4:], secondStageObfuscationCode) #skipping the first 4 bytes
    print(f"The C2 config is : {config}")

if __name__ == "__main__":
    main()