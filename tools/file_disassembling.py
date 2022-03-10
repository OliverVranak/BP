import time
import pefile
from elftools.elf.elffile import ELFFile
from capstone import *


def opcodes_frequency(list_of_opcodes):
    dictionary = dict()
    length = len(list_of_opcodes)
    # counting number of ocurrencies
    for i in list_of_opcodes:
        if i in dictionary:
            dictionary[i] += 1
        else:
            dictionary[i] = 1
    # sorting ocurrencies
    dictionary = sorted(dictionary.items(), key=lambda v: v[1], reverse=True)
    dic3 = dict(dictionary)
    for i, j in dic3.items():
        print(f"{i} : {j * 100 / length}%")

# function takes list of file section and the adrres of the first section
def get_main_code_section(sections, base_of_code):
    section_addresses = list()
    # get addresses of all sections
    for section in sections:
        section_addresses.append(section.VirtualAddress)

    # this section is the main part of code
    if base_of_code in section_addresses:
        return sections[section_addresses.index(base_of_code)]
    # otherwise, sort addresses and look for the interval to which the base of code
    # belongs
    # if not, look for the interval which the main part belongs to
    else:
        section_addresses.append(base_of_code)
        section_addresses.sort()
        if section_addresses.index(base_of_code) != 0:
            return sections[section_addresses.index(base_of_code) - 1]
        else:
            # this means we failed to locate it
            return sections[section_addresses.index(base_of_code)]


def disassemble(exe):
    # getting the main part of code excluding header
    main_code = get_main_code_section(exe.sections, exe.OPTIONAL_HEADER.BaseOfCode)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    last_address = 0
    last_size = 0
    # defining the beginning of main part of code
    start = main_code.PointerToRawData
    # defining the end of main part
    end = start + main_code.SizeOfRawData
    list_of_opcode = list()
    while True:
        # parse section with main code
        data = exe.get_memory_mapped_image()[start:end]
        for i in md.disasm(data, start):
            print(i)
            last_address = int(i.address)
            last_size = i.size
            list_of_opcode.append(i.mnemonic)
        start = max(int(last_address), start) + last_size + 1
        if start >= end:
            opcodes_frequency(list_of_opcode)
            break


# inspired by
# https://isleem.medium.com/create-your-own-disassembler-in-python-pefile-capstone-754f863b2e1c
def disassembling_analysis():
    file_to_analyze = 'secret_file'
    time.sleep(2)
    try:
        # if file is of type PE
        exe = pefile.PE(file_to_analyze)
        try:
            disassemble(exe)
        except:
            print('Error occurred while disassembling the file\n')
    except:
        # ELF file header
        header = b"\x7f\x45\x4c\x46"
        list_of_opcodes = list()
        with open(file_to_analyze, "rb") as f:
            output = f.read()
            # checks if our output contains ELF header
            if output.startswith(header):
                # parsing elf file
                elf = ELFFile(f)
                code = elf.get_section_by_name('.text')
                ops = code.data()
                addr = code['sh_addr']
                # defining architecture we want to use
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.syntax = CS_OPT_SYNTAX_INTEL
                # disassembling file from addr till end of file
                for i in md.disasm(ops, addr):
                    print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
                    list_of_opcodes.append(i.mnemonic)

                opcodes_frequency(list_of_opcodes)
            # if file is of different type
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.syntax = CS_OPT_SYNTAX_INTEL
                # disassembling from the begging of file
                for i in md.disasm(output, 0x0000000):
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                    list_of_opcodes.append(i.mnemonic)
                opcodes_frequency(list_of_opcodes)
