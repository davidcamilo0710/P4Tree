# Data treatment
# ------------------------------------------------------------------------------
# python Tree.py -a DT -w 10 -d ../datasets/UNI1.csv
import numpy as np
import pandas as pd

# Preprocessing and modeling
# ------------------------------------------------------------------------------
from sklearn.metrics import matthews_corrcoef
import pickle as pickle
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import argparse
# Warning configuration
# ------------------------------------------------------------------------------
import warnings
warnings.filterwarnings('once')
parser = argparse.ArgumentParser(
    description='Trair Decition Tree or Random Forest.')
parser.add_argument('-a', '--algorithm', action='store', dest="algorithm",
                    default="DT", required=False, help="Input Pcap File.")
parser.add_argument('-d', '--dataset', action='store', dest="dataset",
                    default="../datasets/UNI1.csv", required=False, help="Test dataset.")
parser.add_argument('-w', '--weigth', action='store', dest="wt",
                    default=10, required=False, help="Window Time Off Flow.")

args = parser.parse_args()
algoritmo = args.algorithm
dataset1 = args.dataset
w = args.wt

dataset1 = pd.read_csv(r''+dataset1+'')

# Import dataset
dataset1['Elephant'] = np.where(dataset1.tot_size > 100000, 1, 0)
drop_elements = ["tot_size"]
X = dataset1.drop(drop_elements, axis=1)
Num = dataset1.groupby('Elephant').size()

# Seperamos los unos y ceros para poder comparar las predicciones por seperado
data0 = X[X['Elephant'] == 0]
data1 = X[X['Elephant'] == 1]

dataT0 = data0.drop(columns='Elephant')
datat0 = data0["Elephant"]
dataT1 = data1.drop(columns='Elephant')
datat1 = data1["Elephant"]

# We separate the ones and zeros to be able to compare the predictions separately
# ------------------------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X.drop(columns='Elephant'), X['Elephant'], random_state=0)

if algoritmo == "RF":
    # Create the model
    modelo = RandomForestClassifier(
        n_estimators=5,
        max_depth=14,
        n_jobs=2,
        min_samples_leaf=9,
        max_leaf_nodes=200,
        class_weight={1: w}
    )
elif (algoritmo == "DT"):
    modelo = DecisionTreeClassifier(
        max_depth=14,
        min_samples_leaf=9,
        max_leaf_nodes=200,
        class_weight={1: w}
    )
else:
    print("Only DT (Desicion Tree) or RF (Randon Forest)")

# Model Training
modelo.fit(X_train, y_train)

# predictions are made
predicciones = modelo.predict(X_test)  # Predccion Total

mcc = matthews_corrcoef(y_test, predicciones)
pre0 = modelo.predict(dataT0)  # Prediction of 0
pre1 = modelo.predict(dataT1)  # Prediction of 1

# The percentage of Success of each prediction is printed

# Prediction of 1's
accurac1 = accuracy_score(y_true=datat1,
                          y_pred=pre1,
                          normalize=True)

if algoritmo == "RF":
    print('Random Forest')
elif algoritmo == "DT":
    print('Decision Tree')

print("TPR: {:.2f} %".format(100 * accurac1))


accurac0 = accuracy_score(
    y_true=datat0,
    y_pred=pre0,
    normalize=True
)

print("FPR: {:.2f} %".format(100 * (1-accurac0)))

# Total
accurac2 = accuracy_score(
    y_true=y_test,
    y_pred=predicciones,
    normalize=True
)

print("MCC: {:.2f} \n".format(mcc))

if algoritmo == "RF":
    filename = open('tree_RF.sav', 'wb')
    pickle.dump(modelo, filename)
    filename.close()
elif algoritmo == "DT":
    filename = open('tree_DT.sav', 'wb')
    pickle.dump(modelo, filename)
    filename.close()
