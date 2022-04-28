from machine_learning.predict import transform_list_for_prediction, comparing_predict, capstone_predict
from tools.reveal_file import *
from tools.virus_total import *
from tools.file_signatures import *
from tools.file_disassembling import *
from tools.compare_opcodes import *
from datetime import datetime
from os.path import exists
import imghdr


def compare_technique(output):
    list_of_opcodes = opcodes_frequency(output)
    len_list_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    print("[*] Predicting...")
    transformed_list = transform_list_for_prediction(dictionary_of_opcode_freq, len_list_opcodes)
    comparing_predict(transformed_list)


def capstone_technique(output):
    list_of_opcodes = disassembling_analysis(output)
    len_list_of_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = opcodes_frequency_capstone(list_of_opcodes)

    print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Predicting...")
    transformed_list = transform_list_for_prediction(dictionary_of_opcode_freq, len_list_of_opcodes)
    capstone_predict(transformed_list)


def analyze():
    image = input("\n[->] Enter picture: ")
    if not exists(image):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Image was not found!")
        return

    if imghdr.what(image) != "png":
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Wrong type, please enter PNG image.")
        return
    print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Extracting...")
    try:

        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Nothing has been found!\n")
            return

        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] File saved as secret_file")
        name_of_file = "secret_file"
        with open(name_of_file, "wb") as file:
            file.write(output)
        file.close()

        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Analyzing secret_file...")
        # checking for filetypes
        # in case it is an executable or unknown filetype, we continue with analysis
        if check_filetype(output):
            VT_hash_scan(output)

            # this algorithm was not that effective at the end so we will not use it anymore
            #compare_technique(output)

            print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Disassembling...")
            capstone_technique(name_of_file)
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Report saved as report")
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] End of Analysis")
        else:
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] End of Analysis")

    except Exception as e:
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Error while extracting file!")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] " + str(e))
        return




