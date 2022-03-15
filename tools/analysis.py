from machine_learning.predict import tramsform_list_for_prediction, comparing_predict, capstone_predict
from tools.reveal_file import *
from tools.virus_total import *
from tools.file_signatures import *
from tools.file_disassembling import *
from tools.compare_opcodes import *

def compare_technique(output):
    list_of_opcodes = opcodes_frequency(output)
    len_list_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    print("[*] Predicting...")
    transformed_list = tramsform_list_for_prediction(dictionary_of_opcode_freq, len_list_opcodes)
    comparing_predict(transformed_list)

def capstone_technique():
    list_of_opcodes = disassembling_analysis()
    len_list_of_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    print("[*] Predicting...")
    transformed_list = tramsform_list_for_prediction(dictionary_of_opcode_freq,len_list_of_opcodes)
    capstone_predict(transformed_list)

def analyze():
    image = input("[->] Enter image: ")
    print("[*] Extracting file...")
    time.sleep(2)
    try:
        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            print("[+] File Not Found\n")
            print("[+] Bytes exctracted from empty image.\n")
            output = bytes(output, 'utf-8')

        print("\n[+] Saved as secret_file")
        with open("secret_file", "wb") as file:
            file.write(output)
        file.close()

        print("\n[*] Analyzing secret_file")

        check_file_header(output)
        time.sleep(1)

        VT_hash_scan(output)
        print()
        print("[*] Calculating frequency of opcodes...\n")
        time.sleep(1)
        compare_technique(output)
        print()
        print("[*] Disassembling...\n\n")
        capstone_technique()

    except FileNotFoundError:
        print("\n[+] Error, while extracting file!\n")




