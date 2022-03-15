import pickle
import pefile
from elftools.elf.elffile import ELFFile
from capstone import *

def capstone_predict(predict):
    with open("pickle_model_capstone.pkl", 'rb') as file:
        pickle_model = pickle.load(file)

    file_predict = pickle_model.predict([predict])
    if file_predict[0] == 0:
        print("Capstone Goodware")
        return 0
    else:
        print("Capstone Malware")
        return 1




def opcodes_frequency_capstone(list_of_opcodes):
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
    return dic3

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
            last_address = int(i.address)
            last_size = i.size
            list_of_opcode.append(i.mnemonic)
        start = max(int(last_address), start) + last_size + 1
        if start >= end:
            return list_of_opcode
            break


# inspired by
# https://isleem.medium.com/create-your-own-disassembler-in-python-pefile-capstone-754f863b2e1c
def disassembling_analysis(name):
    file_to_analyze = name
    try:
        # if file is of type PE
        exe = pefile.PE(file_to_analyze)
        try:
            list_of_opcodes = disassemble(exe)
            return list_of_opcodes
        except:
            print('[+] Error occurred while disassembling the file\n')
    except:
        print("File is of different type than PE")
        exit()

