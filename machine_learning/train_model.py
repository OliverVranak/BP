from datetime import datetime

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
import pandas as pd
import pickle
from sklearn.tree import DecisionTreeClassifier
from os.path import exists

def capstone_svc_rbf():
    if not exists("machine_learning/pickle_model_capstone_svc_rbf.pkl"):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] SVC rbf model not found!")
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Training model...")
        if not exists("machine_learning/malware_goodware_capstone_opcode_freq.csv"):
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Dataset Not Found!!!")
            return
        data = pd.read_csv("machine_learning/malware_goodware_capstone_opcode_freq.csv",sep=',')

        data_in = data.drop(['Malicious'],axis=1)

        data_in = data_in.values
        label = data['Malicious']
        x_train, x_test, y_train, y_test = train_test_split(data_in, label, test_size=0.2, random_state=42)

        clf = svm.SVC(kernel='rbf', C=1.0)
        model = clf.fit(x_train, y_train)

        y_pred = clf.predict(x_test)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Accuracy: ", metrics.accuracy_score(y_test, y_pred)*100)

        conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Positive: ", conf_matrix[0][1]/sum(conf_matrix[0])*100 )
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Negative: ", conf_matrix[1][0]/sum(conf_matrix[1]) *100)


        pkl_filename = "machine_learning/pickle_model_capstone_svc_rbf.pkl"
        with open(pkl_filename, 'wb') as file:
            pickle.dump(model, file)

def capstone_svc_poly():
    if not exists("machine_learning/pickle_model_capstone_svc_poly.pkl"):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] SVC poly model not found!")
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Training model...")
        if not exists("machine_learning/malware_goodware_capstone_opcode_freq.csv"):
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Dataset Not Found!!!")
            return
        data = pd.read_csv("machine_learning/malware_goodware_capstone_opcode_freq.csv",sep=',')
        data_in = data.drop(['Malicious'],axis=1).values

        label = data['Malicious']
        x_train,x_test,y_train,y_test = train_test_split(data_in,label,test_size=0.2,random_state=42)

        clf = svm.SVC(kernel='poly',degree=8,C=1.0)
        model = clf.fit(x_train,y_train)

        y_pred = clf.predict(x_test)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Accuracy: ", metrics.accuracy_score(y_test, y_pred)*100)

        conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Positive: ",conf_matrix[0][1] / sum(conf_matrix[0])*100 )
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Negative: ",conf_matrix[1][0] / sum(conf_matrix[1])*100 )

        pkl_filename = "machine_learning/pickle_model_capstone_svc_poly.pkl"
        with open(pkl_filename, 'wb') as file:
            pickle.dump(model, file)

def capstone_random_forest():
    if not exists("machine_learning/pickle_model_capstone_random_forest.pkl"):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Random Forest model not found!")
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Training model...")
        if not exists("machine_learning/malware_goodware_capstone_opcode_freq.csv"):
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Dataset Not Found!!!")
            return
        data = pd.read_csv("machine_learning/malware_goodware_capstone_opcode_freq.csv", sep=',')
        data_in = data.drop(['Malicious'], axis=1).values

        label = data['Malicious']
        forest = RandomForestClassifier(n_estimators=100, random_state=100)
        x_train, x_test, y_train, y_test = train_test_split(data_in, label, test_size=0.2, random_state=42)
        forest.fit(x_train,y_train)
        prediction = forest.predict(x_test)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Accuracy: ", metrics.accuracy_score(y_test, prediction)*100)
        conf_matrix = confusion_matrix(y_test, prediction, labels=[0, 1])
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Positive: ",conf_matrix[0][1] / sum(conf_matrix[0])*100)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Negative: ",conf_matrix[1][0] / sum(conf_matrix[1])*100)

        pkl_filename = "machine_learning/pickle_model_capstone_random_forest.pkl"
        with open(pkl_filename, 'wb') as file:
            pickle.dump(forest, file)

def capstone_gradient_boosting():
    if not exists("machine_learning/pickle_model_capstone_gradient_boosting.pkl"):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Gradient Boosting model not found!")
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Training model...")
        if not exists("machine_learning/malware_goodware_capstone_opcode_freq.csv"):
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Dataset Not Found!!!")
            return
        data = pd.read_csv("machine_learning/malware_goodware_capstone_opcode_freq.csv", sep=',')
        data_in = data.drop(['Malicious'], axis=1).values

        label = data['Malicious']

        x_train, x_test, y_train, y_test = train_test_split(data_in, label, test_size=0.2, random_state=42)

        clf = GradientBoostingClassifier(n_estimators=50)
        clf.fit(x_train, y_train)
        y_pred = clf.predict(x_test)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Accuracy: ", metrics.accuracy_score(y_test, y_pred)*100)

        conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Positive: ",conf_matrix[0][1] / sum(conf_matrix[0])*100)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Negative: ",conf_matrix[1][0] / sum(conf_matrix[1])*100)

        pkl_filename = "machine_learning/pickle_model_capstone_gradient_boosting.pkl"
        with open(pkl_filename, 'wb') as file:
            pickle.dump(clf, file)

def capstone_decission_tree():
    if not exists("machine_learning/pickle_model_capstone_decision_tree.pkl"):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Decision Tree model not found!")
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Training model...")
        if not exists("machine_learning/malware_goodware_capstone_opcode_freq.csv"):
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Dataset Not Found!!!")
            return
        data = pd.read_csv("machine_learning/malware_goodware_capstone_opcode_freq.csv", sep=',')
        data_in = data.drop(['Malicious'], axis=1).values

        label = data['Malicious']
        x_train, x_test, y_train, y_test = train_test_split(data_in, label, test_size=0.2, random_state=42)
        clf = DecisionTreeClassifier(max_leaf_nodes=8,class_weight='balanced')
        clf.fit(x_train,y_train)
        y_pred = clf.predict(x_test)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Accuracy: ", metrics.accuracy_score(y_test, y_pred)*100)

        conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Positive: ",conf_matrix[0][1] / sum(conf_matrix[0])*100)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] False Negative: ",conf_matrix[1][0] / sum(conf_matrix[1])*100)

        pkl_filename = "machine_learning/pickle_model_capstone_decision_tree.pkl"
        with open(pkl_filename, 'wb') as file:
            pickle.dump(clf, file)

def capstone_machine_learning():

    capstone_svc_rbf()
    capstone_svc_poly()
    capstone_random_forest()
    capstone_gradient_boosting()
    capstone_decission_tree()

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

