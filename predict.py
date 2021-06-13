#! /usr/bin/env python3

##############################################################################################
#                        BCAST_IDS: A NETWORK INTRUSION DETECTION SYSTEM
#                           PREDICT WITH ISOLATION FOREST ALGORITHM
#
#                                      Dpto de Redes
#                               Gestion Tributaria Territorial
#                                           2020
##############################################################################################

import argparse
import sys
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import warnings

#name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARP','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']
name_columns = ['MAC', 'UCAST', 'MCAST', 'BCAST','ARP','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']
# Type the columns you want to delete in the detection phase
delete_columns = ['MAC', 'IP_ICMP']


""" Load the model from disk """
def load_model(filename):
    try:
        loaded_model = pickle.load(open(filename, 'rb'))
        return loaded_model
    except:
        return None

# TODO
# ISOLATION FOREST
""" Prediction of the activity of a set of MAC addresses. Returns a list of abnormal MACs in the current capture """
def predict_capture(dataset):
    global name_columns
    loaded_model = load_model("./model_randforest")
    macs_atacando = list()
    if loaded_model != None:
        try:
            # Read the captured data
            dataFrame = pd.DataFrame(dataset,columns=name_columns)

            # Prepare the data
            to_model_columns=dataFrame.columns[1:19]
            dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)

            # We delete the columns that we do not want
            dataFrame_aux = dataFrame.drop(delete_columns, axis=1)

            # Prediction
            prediction = loaded_model.predict(dataFrame_aux)
            dataFrame_aux['IF']=prediction

            # List of MACs with abnormal activity
            macs_atacando = dataFrame.loc[dataFrame_aux['IF']==1]['MAC'].tolist()

        except FileNotFoundError:
            msg = "Dataset does not exist or there was a problem in reading it".format(dataset)
            print(msg)

        finally:
            return macs_atacando

    else:
        return macs_atacando

def predict_if(cad, filename):
    name_columns = "MAC;UCAST;MCAST;BCAST;ARP;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP;SSDP;ICMPv6"
    # Cabecera:
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename)

    if loaded_model != None:
        # Convertimos los datos a un DataFrame para poder predecir el resultado:
        d = dict()
        for i in range(len(name_columns.split(";"))):
            if i == 0:
                d[name_columns.split(";")[i]]=[(cad.split(";"))[i]]
            else:
                d[name_columns.split(";")[i]]=[round(float(cad.split(";")[i]),6)]
        df = pd.DataFrame(data=d)

        traff_dif = df.drop(delete_columns, axis=1)
        try:
            # Resultado de la prediccion:
            prediction = loaded_model.predict(traff_dif)
            print(prediction)
        except:
            print("ERROR! The prediction could not made")
    else:
        print(f"ERROR! Model not found in the current directory {os.getcwd()}")


def predict_dataset_if(dataset, filename):
    global name_columns
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename)

    if loaded_model != None:
        try:
            dataFrame=pd.read_csv(dataset,sep=';',names=name_columns)
            dataFrame= dataFrame.fillna(0)
            to_model_columns=dataFrame.columns[1:19]
            dataFrame[to_model_columns] = dataFrame[to_model_columns]
            dataFrame_aux = dataFrame.drop(delete_columns, axis=1)
            #print(dataFrame_aux)
            prediction = loaded_model.predict(dataFrame_aux)
            count_normal = 0;
            count_anomaly = 0;
            #print(prediction)
            for p in prediction:
                if p == 0:
                    count_normal += 1
                else:
                    count_anomaly += 1

            #print(f"Prediction bear in mind these columns: {(dataFrame_aux.columns.tolist())}")
            #print("------------------------------------")
            print(f"Quantity of normal MAC activity: {count_normal}")
            print(f"Quantity of abnormal MAC activity: {count_anomaly}")
            #print("------------------------------------")

            # Imprimimos las anomalias detectadas en pantalla
            outliers=dataFrame.loc[prediction==1]
            print("\t\nANOMALIES:")
            print(outliers.to_string())

        except FileNotFoundError:
            msg = "Dataset does not exist or there were a problem in reading the columns {0}.".format(dataset)
            print(msg)
    else:
        print(f"ERROR! Model not found in the current directory {os.getcwd()}")

if __name__ == '__main__':
    text_help= "Script to predict the activity of a MAC address or dataset using the Isolation Forest algorithm"
    text_help += "\n\t./predict.py -s \"MAC;0.0;0.001976;0.998024;0.998024;0.021739;0.0;0.0;0.0;0.0;0.001976;0.0;0.480237;0.0;0.001976\""
    text_help += "\n\t./predict.py -s \"MAC;0.0;0.001976;0.998024;0.998024;0.021739;0.0;0.0;0.0;0.0;0.001976;0.0;0.480237;0.0;0.001976\" -m [MODEL]"
    text_help += "\n\t./predict.py -d dataset.csv"
    text_help += "\n\t./predict.py -d dataset.csv -m [MODEL]"
    text_help += "\nSALIDA"
    text_help += "\n\t[+]  1 -> normal activity \n"
    text_help += "\t[+] -1 -> abnormal activity \n\n"
    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-s", "--actividadMAC", required=False, help="Activity of a single MAC address")
    ap.add_argument("-d", "--datasetMAC", required=False, help="Dataset")
    ap.add_argument("-m", "--model", required=False, help="Machine Learning model")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.actividadMAC:
        model_file = vars(ap.parse_args())["model"]
        cad = vars(ap.parse_args())["actividadMAC"]
        predict_if(cad,model_file)
    if args.datasetMAC:
        model_file = vars(ap.parse_args())["model"]
        dataset = vars(ap.parse_args())["datasetMAC"]
        predict_dataset_if(dataset,model_file)
