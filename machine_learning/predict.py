import os
import pickle
from datetime import datetime

from machine_learning.train_model import capstone_machine_learning


def capstone_predict(predict):

    capstone_machine_learning()

    with open("machine_learning/pickle_model_capstone_svc_rbf.pkl", 'rb') as file1:
        pickle_model_rbf = pickle.load(file1)
    with open("machine_learning/pickle_model_capstone_svc_poly.pkl", 'rb') as file2:
        pickle_model_poly = pickle.load(file2)
    with open("machine_learning/pickle_model_capstone_decision_tree.pkl", 'rb') as file3:
        pickle_model_decision_tree = pickle.load(file3)
    with open("machine_learning/pickle_model_capstone_random_forest.pkl", 'rb') as file4:
        pickle_model_random_forest = pickle.load(file4)
    with open("machine_learning/pickle_model_capstone_gradient_boosting.pkl", 'rb') as file5:
        pickle_model_gradient_boosting = pickle.load(file5)

    file_predict_rbf = pickle_model_rbf.predict([predict])
    file_predict_poly = pickle_model_poly.predict([predict])
    file_predict_decision_tree = pickle_model_decision_tree.predict([predict])
    file_predict_random_forest = pickle_model_random_forest.predict([predict])
    file_predict_gradient_boosting = pickle_model_gradient_boosting.predict([predict])

    count_malware = 0
    a = file_predict_gradient_boosting[0]
    b = file_predict_decision_tree[0]
    c = file_predict_random_forest[0]
    d = file_predict_poly[0]
    e = file_predict_rbf[0]

    count_malware = count_malware + 1 if file_predict_rbf[0] == 1 else count_malware
    count_malware = count_malware + 1 if file_predict_decision_tree[0] == 1 else count_malware
    count_malware = count_malware + 1 if file_predict_poly[0] == 1 else count_malware
    count_malware = count_malware + 1 if file_predict_random_forest[0] == 1 else count_malware
    count_malware = count_malware + 1 if file_predict_gradient_boosting[0] == 1 else count_malware
    if count_malware > 2:
        print("\n\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Your file is -> UNSAFE <-")
    else:
        print("\n\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Your file is -> SAFE <-")

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




