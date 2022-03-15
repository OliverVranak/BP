import pandas as pd


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
    return list_of_opcodes

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
    for i, j in dic3.items():
        print(f"{i} : {j * 100 / len(list_of_opcodes)}%")

    return dic3