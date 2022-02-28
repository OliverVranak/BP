import hashlib
import sys
from tools.reveal_file import *
from tools.virus_total import *
import time
from tools.file_signatures import *
import pandas as pd
from tools.file_disassembling import *

def opcodes_frequency(output):
    #reading csv file with pandas module
    df = pd.read_csv('opcodes.csv')

    list_of_opcodes = list()
    opcodes = dict()
    #saving opcodes from csv to dictionary
    for i in range(len(df)):
        opcodes[df.iloc[i]['po']] = df.iloc[i]['mnemonic']

    for i in output:
        # iterating through each byte
        byte = hex(i)
        byte = byte[2:]
        byte = byte.upper()
        # searching if given byte has a match with opcode from opcodes dictionary
        for j in opcodes:
            if j == byte:
                list_of_opcodes.append(opcodes[j])

    dictionary = dict()
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
        print(f"{i} : {j * 100 / len(output)}%")

def analyze():
    image = input("Enter image: ")
    print("Extracting file...")
    time.sleep(2)
    try:
        output = lsb.reveal(image)
        if output != None:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file

            print("\n -> File extracted as secret_file <-")
            with open("secret_file", "wb") as file:
                file.write(output)
            file.close()

            print("\n->Analyzing secret_file<-")

            check_file_header(output)

            time.sleep(1)

            VT_hash_scan(output)
            print()
            print("=> Calculating frequency of opcodes...\n")
            time.sleep(1)
            opcodes_frequency(output)
            print()
            print("=> Disassembling...\n\n")

            disassembling_analysis()

        else:
            print("\n-> No file found <-")
    except FileNotFoundError:
        print("\nError, while extracting file!\n")




