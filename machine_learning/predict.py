import pickle


def capstone_predict(predict):
    with open("machine_learning/pickle_model_capstone.pkl", 'rb') as file:
        pickle_model = pickle.load(file)

    file_predict = pickle_model.predict([predict])
    if file_predict[0] == 0:
        print("[->] Goodware")
    else:
        print("[->] Malware")
    print(file_predict)

def comparing_predict(predict):
    with open("machine_learning/pickle_model_comparing.pkl", 'rb') as file:
        pickle_model = pickle.load(file)

    file_predict = pickle_model.predict([predict])
    if file_predict[0] == 0:
        print("[->] Goodware")
    else:
        print("[->] Malware")
    print(file_predict)



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




