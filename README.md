# Elephant_flows

In-Network detection of attacks using Random Forests

Please cite this paper if you use this code:

`Jong-Hyouk Lee and Kamal Singh, "SwitchTree: In-network Computing and Traffic Analyses with Random Forests", Neural Computing and Applications (2020)`

## Introduction
We perform in-network analysis of the network data by exploiting the power of programmable data planes. 
SwitchTree coded in P4 embeds Random Forest algorithm inside a programmable switch such that the 
Random Forest is configurable and re-configurable at runtime. We show how some flow level 
stateful features can be estimated, such as the round trip time and bitrate of each flow. 
Main references for this work are [IISY](https://github.com/cucl-srg/IIsy) and [pForest](https://arxiv.org/abs/1909.05680).

## Installation

As each component under this repository is independent, installation instructions and dependencies are listed separately under each folder

## Structure

The repository is structured as follows:

### PCAPs

### scripts

### datasets

### simulation

### P4-Desicion-Tree and P4-Random-Forest

## Citation

When referencing this work, please use the following citation:

An open access version of the paper is available at:
