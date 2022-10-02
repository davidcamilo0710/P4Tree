## Installation

As each component under this repository is independent, installation instructions and dependencies are listed separately under each folder

## Structure

The repository is structured as follows:

### PCAPs

This folder stores the real traffic traces used for algorithm evaluation, plus instructions for downloading the original training traces.

### scripts

Contains all the tools to generate the training dataset from the real traffic traces, a Notebook to generate the prediction model using Decision Trees or Random Forest and two scripts to transform the model into P4 tables.

### datasets

This folder saves the training datasets in CSV format.

### simulation

The version of our algorithm in python to corroborate and compare the results.

### P4-Desicion-Tree and P4-Random-Forest

Contain all the necessary files to run the emulation of our algorithm on P4, with a decision tree or with a random forest, plus a quick start guide.

## Citation

When referencing this work, please use the following citation:

An open access version of the paper is available at:
