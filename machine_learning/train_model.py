from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
import pandas as pd
import pickle

def capstone_machine_learning():
    data = pd.read_csv("malware_goodware_capstone_opcode_freq.csv",sep=',')
    data_in = data.drop(['Malicious'],axis=1).values

    label = data['Malicious'].values
    x_train,x_test,y_train,y_test = train_test_split(data_in,label,test_size=0.2,random_state=42)

    clf = svm.SVC()
    clf.fit(x_train,y_train)

    y_pred = clf.predict(x_test)
    print("[+] Accuracy: ",metrics.accuracy_score(y_test, y_pred))
    print("[*] Saving as pickle_model_capstone.pkl")
    pkl_filename = "pickle_model_capstone.pkl"
    with open(pkl_filename, 'wb') as file:
        pickle.dump(clf, file)

def comparing_machine_learning():
    data = pd.read_csv("malware_goodware_comparing_opcode_freq.csv", sep=',')
    data_in = data.drop(['Malicious'], axis=1).values

    label = data['Malicious'].values

    x_train, x_test, y_train, y_test = train_test_split(data_in, label, test_size=0.2, random_state=42)

    clf = svm.SVC()
    clf.fit(x_train, y_train)

    y_pred = clf.predict(x_test)
    print("[+] Accuracy: ", metrics.accuracy_score(y_test, y_pred))
    print("[*] Saving as pickle_model_comparing.pkl")
    pkl_filename = "pickle_model_comparing.pkl"
    with open(pkl_filename, 'wb') as file:
        pickle.dump(clf, file)

