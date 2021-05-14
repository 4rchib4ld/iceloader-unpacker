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


log = logging.getLogger(__name__)

def extractPayloadFromSect(pe, sectionName):
    """ 
    Extracting the payload from the pe section. Different routines because of the different section that can be used
    """
    for section in pe.sections:
        if sectionName == section.Name:
            if ".rdata" in str(sectionName):
                startOfDebugDirectory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]].VirtualAddress
                rdata = section.get_data()
                RdataVirtualAddress = section.VirtualAddress
                endOfPayload = startOfDebugDirectory - RdataVirtualAddress
                return rdata[:endOfPayload]
            data = section.get_data()
            log.debug(f"Size of extracted payload section : {len(data)}")
            return data
            
def extractDecryptionSect(pe, sectionName):
    """
    Extracting the payload from the pe section

    """
    for section in pe.sections:
        if sectionName == section.Name:
            data = section.get_data()
            endoffset = 16400 # hardcoded value, but it's always the same
            extractedValue = int.from_bytes(data[:4], 'little')
            data =  data[16:endoffset]
            log.debug(f"Size of the extracted decryption section : {len(data)}\nExtracted value : {extractedValue}")
            return data, extractedValue

def payloadDecode(data):
    """
    Decoding the payload. Making it ready for the next stage
    """
    decodedData = bytearray()
    for i in range(0, len(data), 2):
        decodedData.append(data[i])
    log.debug(f"Size decoded payload section: {len(decodedData)}")
    return decodedData

def payloadDecrypt(decodedPayload, decrementationCounter):
    """
    Starting from the end for the decodedPayload, and a byte every n bytes. Then it loops again, but from len(data)-1 and so on
    """
    payload = bytearray()
    count = 0
    scount = 0
    payloadSize = len(decodedPayload) - 1
    i = payloadSize
    while scount != decrementationCounter:
        try:
            payload.append(decodedPayload[i])
        except:
            pass
        i -= decrementationCounter
        count = count + 1
        if count == 512:
            count = 0
            scount += 1
            i = payloadSize - scount

    log.debug(f"Size of the decrypted payload section : {len(payload)}")
    return payload[::-1]

def gettingObfuscationCode(file, yaraRule):
    """
    Retrieving the code used for obfuscation using a Yara rule
    """
    rules = yara.compile(filepath=yaraRule)
    f = open(file, "rb")
    matches = rules.match(data=f.read())
    f.close()
    if matches:
        obfuscationCode = matches[0].strings[0][2]
    else:
        obfuscationCode = 0
    log.debug(f"Obfuscation code : {obfuscationCode}")
    return obfuscationCode

def runObfuscationCode(obfuscatedPayload, obfuscationCode):
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
        for byte in obfuscatedPayload:
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
        log.debug(f"Size of deobfuscated payload : {len(deobfuscatedPayload)}")
        return deobfuscatedPayload[::1]

    except UcError as e:
        log.error("Something is wrong with Unicorn : %s" % e)

def decryptSecondStage(deobfuscatedPayload, dataSect):
    """
    The final decryption. Loop throught the data section and take two bytes at a time, adding them and getting the corresponding char in the deobfuscated payload
    """
    secondStage = bytearray()
    count = 0
    step = 512
    padding = 0
    for i in range(0, len(deobfuscatedPayload) * 2, 2):
        try:
            currentChar = deobfuscatedPayload[int.from_bytes(bytes([dataSect[i % len(dataSect)]]) + bytes([dataSect[(i+1) % len(dataSect)]]), "little") + padding]
            secondStage.append(currentChar)
        except IndexError:
            pass   
        count += 1
        if count == step:
            padding += step
            count = 0
    log.debug(f"Size of the decrypted second stage : {len(secondStage)}")
    return secondStage

def selectingSections(pe):
    """
    Sorting the biggest region of the file. The biggest is the packed executable, the second one the data used for decryption
    """
    sort = {}
    for section in pe.sections:
        if not ".text" in str(section.Name) and not ".data" in str(section.Name): # we don't care about .text
            sort[section.Name] = section.Misc_VirtualSize
        if ".data" in str(section.Name):
            dataSectionSize = section.Misc_VirtualSize
            dataSectionName = section.Name
    sortedSection = sorted(sort.items(), key=lambda x: x[1], reverse=True)
    payloadSection = sortedSection[0][0]
    payloadSectionSize = sortedSection[0][1]
    log.debug(f"Biggest section is : {payloadSection} with size {payloadSectionSize}")
    if dataSectionSize > (payloadSectionSize * 5): #means that everything is in .data
        log.debug("Everything is in .data")
        dataSect = extractPayloadFromSect(pe, dataSectionName)
        extractedPayload, extractedDecryptionSection, extractedValue = scanningData(dataSect)
    else:
        extractedPayload = extractPayloadFromSect(pe, payloadSection)
        extractedDecryptionSection, extractedValue  = extractDecryptionSect(pe, dataSectionName)
    
    return extractedPayload, extractedDecryptionSection, extractedValue

def scanningData(data):
    """
    Sometimes everything is in the .data section, so we need to parse it in order to get the data we want. I use a Yara rule in order to find the markor
    """
    markorYara = """
    rule  findMarkor
    {
    strings:
        $markor = { 00 ?? ?? 00 ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        all of them
    }
    """
    yarac = yara.compile(source=markorYara)
    matches = yarac.match(data=data)
    extractedValue = int.from_bytes(matches[0].strings[0][2][:4], 'little')
    offset = matches[0].strings[0][0]
    payload = data[:offset]
    dataSect = data[offset+16:offset+16400] #skipping the 16bytes that are used as a delimeter
    log.debug(f"extracted payload size : {payload}\n extracted data section size : {dataSect} \n extracted value : {extractedValue}")
    return payload, dataSect, extractedValue

def extractPayloadFromUnpackedData(file):
    """
    Extracting the payload from the .data section of the unpacked executable
    """
    MAX_STRING_SIZE = 128
    pe = pefile.PE(data=file)
    for section in pe.sections:
        if ".data" in str(section.Name):
            data = section.get_data()
            #payload = data[4:MAX_STRING_SIZE].split(b"\0")[0]
            payload = data[4:]
            log.debug(f"Size of extracted payload : {len(payload)}")
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
    log.debug(f"Decrypted config : {decrypted}")
    config = decrypted.split("\x00")[0]
    return config

def main():
    parser = argparse.ArgumentParser(description='Decrypt the IcedID config')
    parser.add_argument('-f', '--file', help='Path of the binary file', required=True)
    parser.add_argument('-d', '--debug', help='Debug', action="store_true", default=False, required=False)
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level = logging.DEBUG)
    else:
        logging.basicConfig(level = logging.INFO)

    file = args.file
    pe = pefile.PE(args.file)
    extractedPayload, extractedDecryptionSection, extractedValue = selectingSections(pe)
    decrementationCounter = extractedValue // 512 # that's how it is calculated
    obfuscatedPayload   = payloadDecrypt(payloadDecode(extractedPayload), decrementationCounter)
    obfuscationCode     = gettingObfuscationCode(file, "iceloader.yar")
    obfuscationCode     = obfuscationCode[:-2] # Removing the last two bytes because I use them as markor for the end of the code
    deobfuscatedPayload = runObfuscationCode(obfuscatedPayload, obfuscationCode)
    unpackedExecutable  = decryptSecondStage(deobfuscatedPayload, extractedDecryptionSection)
    filename = PurePath(args.file).parts
    filename = filename[-1]
    unpackedFileName = "unpacked_" + filename
    log.info(f"Writing the unpacked data to {unpackedFileName}")
    with open(unpackedFileName, "wb") as f:
        f.write(unpackedExecutable)
    secondStageObfuscationCode = gettingObfuscationCode(unpackedFileName, "icedid.yar")
    if secondStageObfuscationCode == 0:
        log.info("IcedID yara didn't match !")
    else:
        payload = extractPayloadFromUnpackedData(unpackedExecutable)
        config = decodePayloadFromUnpackedData(payload, secondStageObfuscationCode)
        print(f"The C2 config is : {config}")

if __name__ == "__main__":
    main()