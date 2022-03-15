import os
from tools.analysis import compare_technique, capstone_technique
from tools.reveal_file import *
from machine_learning_caps import *
from machine_learning_comp import *
import pandas as pd

def tramsform_list_for_prediction(dictionary,length):
    attributes = ['mov','push','call','lea','add','jae','inc','cmp','sub','jmp','dec','shl','pop','xchg','je','jne','xor','test','ret','jo','imul','and','in','jge','outsb','fstp','sbb','adc','jp','insb','other']
    values = list()
    sum = 0
    found = 0
    for i in attributes:
        if i == 'other':
            pass
        else:
            for opcode, percentage in dictionary.items():
                if opcode.lower() == i:
                    values.append(percentage / length)
                    found = 1
                    break
            if found == 0:
                values.append(0.0)
            else:
                found = 0
    for i,j in dictionary.items():
        c = i.lower()
        if c not in attributes:
            sum += j

    values.append(sum/length)
    return values


def calculate_freq(list_of_opcodes):
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
    return dic3

def compare_technique(output):
    list_of_opcodes = opcodes_frequency(output)
    len_list_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    transformed_list = tramsform_list_for_prediction(dictionary_of_opcode_freq, len_list_opcodes)
    return comparing_predict(transformed_list)

def capstone_technique(output):
    list_of_opcodes = disassembling_analysis(output)
    len_list_of_opcodes = len(list_of_opcodes)
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    transformed_list = tramsform_list_for_prediction(dictionary_of_opcode_freq,len_list_of_opcodes)
    return capstone_predict(transformed_list)

def analyze(file):
    image = "pure_images/"+file
    prediction1 = 0
    prediction2 = 0
    try:
        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            output = bytes(output, 'utf-8')
        name = "exctracted/secret_" + file
        # to strip .png
        name = name[:-4]
        with open(name, "wb") as file:
            file.write(output)
        file.close()
        prediction1 = compare_technique(output)
        prediction2 = capstone_technique(name)
        return prediction1,prediction2

    except FileNotFoundError:
        print("\n[+] Error, while extracting file!\n")

if __name__ == "__main__":
    count = 0
    comp = 0
    cap = 0
    for i in os.listdir("pure_images"):
        print("["+str(count)+"] "+i)
        prediction1,prediction2 = analyze(i)
        if prediction1 == 0:
            comp += 1
        if prediction2 == 0:
            cap += 1
        print()
        count += 1

    print("Compare opcodes technique")
    print("Goodware: " + str(comp) + "/30")
    print("Malware: " + str(30 - comp) + "/30")
    print()
    print("Capstone technique")
    print("Goodware: " + str(cap) + "/30")
    print("Malware: " + str(30 - cap) + "/30")




