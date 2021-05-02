import binascii
import pefile
import argparse

def extractRdataSect(pe):
    # Extracting the payload from the .rdata section
    print("[+] Extracting rdata...")
    for section in pe.sections:
        if ".rdata" in str(section.Name):
            rdata = section.get_data()
            rdata = rdata[0x80:]
            for i in range(len(rdata)):
                # Searching for the end of the chunk. Better than a hardcoded value
                if rdata[i] == 0 and rdata[i+1] == 0 and rdata[i+2] == 0 and rdata[i+3] == 0:
                    print("[+] Done !")
                    return rdata[:i]
            
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
    decrem = 0x14 # Maybe this will change ?
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

def firstDecrypt(decodedRdata):
    # Pretty straight forward. There is a key, there is a byte, a bunch of bitwise operations
    firstDecr = bytearray()
    count=0
    key = 1 # Maybe this will change ?
    for byte in decodedRdata:
        if count == 512:
            key += 1
            count = 0
        result = ((~byte & 0xC) | (byte & 0xf3)) ^ ((~key & 0xC) | (key & 0xF3))
        count += 1
        firstDecr.append(result)
    return firstDecr[::1]

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
    encryptedPayload = firstDecrypt(decryptedRdata)
    secondStage = decryptSecondStage(encryptedPayload, data)
    payload = extractPayload(secondStage)
    config = decodePayload(payload[4:]) #skipping the first 4 bytes
    print(f"The C2 config is : {config}")
    with open("unpackedIcedID.bin", "wb") as f:
        f.write(secondStage)

if __name__ == "__main__":
    main()

