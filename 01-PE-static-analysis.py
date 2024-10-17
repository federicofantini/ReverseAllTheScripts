import struct
import sys
import os

import json
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

WORD_SIZE = 4
FILE_HEADER_SIZE = (4 * 4) * WORD_SIZE
OPTIONAL_HEADER_SIZE = (15 * 4 + 2) * WORD_SIZE
SECTION_HEADER_SIZE = 10 * WORD_SIZE
SECTION_START_ADDRESS = (32 * 4) * WORD_SIZE
IMAGE_IMPORT_DESCRIPTOR_SIZE = 5 * WORD_SIZE

PE = {
    "NT_HEADER": {},
    "SECTIONS": {},
    "IMPORTS": {},
    "EXPORTS": {},
}



def check_args():
    if len(sys.argv) != 2:
        print("Error: this script accept only one filepath argument")
        exit()

    if not os.path.isfile(sys.argv[1]):
        print("Error: the file does not exist")
        exit()

def check_mz_signature(f) -> None:
    f.seek(0)
    MZSignature = b"".join(struct.unpack('=cc', f.read(2)))
    if MZSignature != b"MZ":
        print("Warning: invalid MZ signature")

def get_nt_header_address(f) -> int:
    f.seek(FILE_HEADER_SIZE - WORD_SIZE) # last word = e_lfanew
    NtHeader = b"".join(struct.unpack('=cccc', f.read(4)))
    return int.from_bytes(NtHeader, "little")

def get_nt_header(f) -> bytes:
    NtHeaderAddress = get_nt_header_address(f)
    f.seek(NtHeaderAddress)
    NtHeader = f.read(OPTIONAL_HEADER_SIZE)
    return NtHeader

def check_nt_signature(input_bytes: bytes):
    NTSignature = b"".join(struct.unpack('=cccc', input_bytes))
    if NTSignature != b"PE\x00\x00":
        print("Warning: invalid PE signature")

def get_entry_point(input_bytes: bytes) -> int:
    EntryPoint = b"".join(struct.unpack('=cccc', input_bytes))
    EntryPoint = format(int.from_bytes(EntryPoint, "little"), '04X')
    return EntryPoint

def get_image_base(input_bytes: bytes) -> int:
    ImageBase = b"".join(struct.unpack('=cccc', input_bytes))
    ImageBase = format(int.from_bytes(ImageBase, "little"), '04X')
    return ImageBase

def get_export_virtual_address(input_bytes: bytes) -> int:
    VirtualAddress = b"".join(struct.unpack('=cccc', input_bytes[0:4]))
    VirtualAddress = format(int.from_bytes(VirtualAddress, "little"), '04X')
    Size = b"".join(struct.unpack('=cccc', input_bytes[4:8]))
    Size = format(int.from_bytes(Size, "little"), '04X')
    return VirtualAddress, Size

def get_import_virtual_address(input_bytes: bytes) -> int:
    VirtualAddress = b"".join(struct.unpack('=cccc', input_bytes[0:4]))
    VirtualAddress = format(int.from_bytes(VirtualAddress, "little"), '04X')
    Size = b"".join(struct.unpack('=cccc', input_bytes[4:8]))
    Size = format(int.from_bytes(Size, "little"), '04X')
    return VirtualAddress, Size

def extract_sections(f, input_bytes: bytes) -> None:
    TotalSections = b"".join(struct.unpack('=cc', input_bytes))
    TotalSections = format(int.from_bytes(TotalSections, "little"), '04X')

    f.seek(SECTION_START_ADDRESS)
    for s in range(int(TotalSections)):
        section = f.read(SECTION_HEADER_SIZE)

        name = b"".join(struct.unpack('=cccccccc', section[:8])).decode().replace(f"\x00", "")
        VirtualAddress = b"".join(struct.unpack('=cccc', section[12:16]))
        VirtualAddress = format(int.from_bytes(VirtualAddress, "little"), '04X')
        SizeOfRawData = b"".join(struct.unpack('=cccc', section[16:20]))
        SizeOfRawData = format(int.from_bytes(SizeOfRawData, "little"), '04X')
        PointerToRawData = b"".join(struct.unpack('=cccc', section[20:24]))
        PointerToRawData = format(int.from_bytes(PointerToRawData, "little"), '04X')

        PE["SECTIONS"][name] = {
            "VirtualAddress": f"0x{VirtualAddress}",
            "SizeOfRawData": f"0x{SizeOfRawData}",
            "PointerToRawData": f"0x{PointerToRawData}",
        }

def locate_address_in_sections_ranges(address: int) -> str:
    prev = None
    for k,v in PE["SECTIONS"].items():
        if int(address, 16) < int(v["VirtualAddress"], 16):
            if prev is None:
                return k
            return prev
        prev = k

def locate_virtual_address_on_disk(
    virtual: str,
    section_name: str
) -> int:
    offset = hex(int(virtual, 16) - int(PE["SECTIONS"][section_name]["VirtualAddress"], 16))
    offset_disk = hex(int(offset, 16) + int(PE["SECTIONS"][section_name]["PointerToRawData"], 16))
    return offset_disk

def extract_imports(f, Import_VirtualAddress, Import_Size):
    # determine in which section Import_VirtualAddress is located
    import_section_name = locate_address_in_sections_ranges(Import_VirtualAddress)
    offset_disk = locate_virtual_address_on_disk(Import_VirtualAddress, import_section_name)
    f.seek(int(offset_disk, 16))
    
    # read the retrived address
    imports = f.read(int(Import_Size, 16))
    number_of_imports = int(Import_Size, 16) // int(hex(IMAGE_IMPORT_DESCRIPTOR_SIZE), 16) - 1 # last one is zeros
    for i in range(number_of_imports):
        offset = int(hex(IMAGE_IMPORT_DESCRIPTOR_SIZE), 16) * i

        # retrieve the library name from file
        nameVirtualAddress = b"".join(struct.unpack('=cccc', imports[offset+12:offset+16]))
        nameVirtualAddress = format(int.from_bytes(nameVirtualAddress, "little"), '04X')
        nameDiskAddress = locate_virtual_address_on_disk(nameVirtualAddress, import_section_name)
        f.seek(int(nameDiskAddress, 16))
        name = []
        while (b := f.read(1)) != b"\x00":
            name.append(b)
        name = b"".join(name).decode()
        PE["IMPORTS"][name] = [] # library name

        OriginalFirstThunkVirtualAddress = b"".join(struct.unpack('=cccc', imports[offset:offset+4]))
        OriginalFirstThunkVirtualAddress = format(int.from_bytes(OriginalFirstThunkVirtualAddress, "little"), '04X')
        OriginalFirstThunkDiskAddress = locate_virtual_address_on_disk(OriginalFirstThunkVirtualAddress, import_section_name)
        f.seek(int(OriginalFirstThunkDiskAddress, 16))
        
        # read the OriginalFirstThunk pointers to IMAGE_IMPORT_BY_NAME structures
        addresses = []
        while (address := f.read(4)) != b"\x00\x00\x00\x00":
            addresses.append(address)
        
        for address in addresses:
            # retrive function names from file
            ImportByNameVirtualAddress = b"".join(struct.unpack('=cccc', address))
            ImportByNameVirtualAddress = format(int.from_bytes(ImportByNameVirtualAddress, "little"), '04X')
            ImportByNameDiskAddress = locate_virtual_address_on_disk(ImportByNameVirtualAddress, import_section_name)
            f.seek(int(ImportByNameDiskAddress, 16))

            funname = []
            f.read(2) # skip hint
            while (b := f.read(1)) != b"\x00":
                funname.append(b)
            funname = b"".join(funname).decode()
            PE["IMPORTS"][name].append(funname)


def main():
    check_args()
    with open(sys.argv[1], 'rb') as f:
        check_mz_signature(f)
        
        nt_header = get_nt_header(f)
        check_nt_signature(nt_header[0:4])
        
        PE["NT_HEADER"]["AddressOfEntryPoint"] = f"0x{get_entry_point(nt_header[10*WORD_SIZE : 11*WORD_SIZE])}"
        PE["NT_HEADER"]["ImageBase"] = f"0x{get_image_base(nt_header[13*WORD_SIZE : 14*WORD_SIZE])}"
        
        Export_VirtualAddress, Export_Size = get_export_virtual_address(nt_header[30 * WORD_SIZE : 32 * WORD_SIZE])
        Import_VirtualAddress, Import_Size = get_import_virtual_address(nt_header[32 * WORD_SIZE : 34 * WORD_SIZE])
        PE["EXPORTS"]["VirtualAddress"] = f"0x{Export_VirtualAddress}"
        PE["EXPORTS"]["Size"] = f"0x{Export_Size}"
        PE["IMPORTS"]["VirtualAddress"] = f"0x{Import_VirtualAddress}"
        PE["IMPORTS"]["Size"] = f"0x{Import_Size}"
        
        extract_sections(f, nt_header[WORD_SIZE + 2 : 2 * WORD_SIZE])

        extract_imports(f, PE["IMPORTS"]["VirtualAddress"], PE["IMPORTS"]["Size"])

        print(highlight(json.dumps(PE, indent=4), JsonLexer(), TerminalFormatter()))

if __name__ == "__main__":
    main()