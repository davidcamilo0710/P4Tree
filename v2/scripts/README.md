# Scripts

## datasetGenerator.py
To generate the dataset in CSV format, run:

`python datasetGenerator.py -i ../PCAPs/UNI1.pcap -w 5.45 -c UNI1 -d ../datasets`

Where:
`-i` Input PCAP Path
`-w` Time window between flows with equal 5-tuples
`-c` Name of the new dataset
`-d` Folder where the CSV will be saved

## Algorithm modeling
### Tree.py
To generate and save the trained model run:

`python Tree.py -a DT -w 10 -d ../datasets/UNI1.csv`

Where:
`-a` Algorithm, decision tree (DT) or random forest (RF)
`-w` Weight to balance dataset
`-d` Folder where the model (.sav file) will be saved

### Tree.ipynb

Visualize the process of modeling and evaluating the algorithms in [this](https://nbviewer.org/github/davidcamilo0710/Elephant_flows/blob/master/scripts/Tree.ipynb) notebook.

## Decision Tree and Random Forest to P4

To transform the trained model (.sav file) to tables (which understands the P4 language) run:

`python DTtoP4.py` if the model is from a DT or `python RFtoP4.py`  if it is an RF. The tables are saved in the file commands.txt.

