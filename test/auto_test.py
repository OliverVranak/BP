import os
from tools.reveal_file import *
from machine_learning_caps import *
from machine_learning_comp import *
import math
from collections import Counter
from scipy import stats

def eta(data, unit='natural'):
    base = {
        'shannon': 2.,
        'natural': math.exp(1),
        'hartley': 10.
        }
    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    ent = 0
    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])
    return ent

def entropy(labels):
    return stats.entropy(list(Counter(labels).values()), base=2)

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
    comparing_predict(transformed_list)

def capstone_technique(output):
    list_of_opcodes = disassembling_analysis(output)
    len_list_of_opcodes = len(list_of_opcodes)
    if len_list_of_opcodes == 0:
        capstone_success_counter()
        return
    dictionary_of_opcode_freq = calculate_freq(list_of_opcodes)

    transformed_list = tramsform_list_for_prediction(dictionary_of_opcode_freq,len_list_of_opcodes)
    capstone_predict(transformed_list)

def analyze(file):
    image = "image_goodware/"+file
    try:
        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            output = bytes(output, 'utf-8')

        # calculate entropy of bytes
        #print(eta(output))
        #print(entropy(output))

        name = "exctracted/secret_" + file
        # to strip .png
        name = name[:-4]
        with open(name, "wb") as file:
            file.write(output)
        file.close()
        #compare_technique(output)
        capstone_technique(name)

    except FileNotFoundError:
        print("\n[+] Error, while extracting file!\n")

if __name__ == "__main__":
    count = 0
    comp = 0
    cap = 0
    for i in os.listdir("image_goodware"):
        print("["+str(count)+"] "+i)
        analyze(i)
        count += 1

capstone_goodware = capstone_success_counter() - 1
#compare_goodware = comparing_success_counter() - 1
print("Capstone Goodware ratio: {} / 30".format(capstone_goodware))
#print("Comparing Goodware ratio: {} / 30".format(compare_goodware))



