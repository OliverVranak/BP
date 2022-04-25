import pickle

import pandas as pd

def comparing_success_counter():
    if not hasattr(comparing_success_counter,"counter"):
        comparing_success_counter.counter = 0
    comparing_success_counter.counter += 1
    return comparing_success_counter.counter

def comparing_predict(predict):
    with open("pickle_model_comparing_random_forest.pkl", 'rb') as file:
        pickle_model = pickle.load(file)

    file_predict = pickle_model.predict([predict])
    if file_predict[0] == 0:
        comparing_success_counter()

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



