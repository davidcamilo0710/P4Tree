# P4Tree
## Introduction

The classification of flows plays an essential traffic engineering role in improving network perfor-
mance. Novel approaches based on Software-Defined Networking classify elephant/mice flows to
process them separately, aiming to improve network performance. Some flow classification methods
use Machine Learning either at the Control Plane, network servers, or Data Plane. However, these
methods lead to traffic overhead, low scalability, and high classification time. This paper introduces
P4Tree, a novel approach based on Random Forests that quickly and accurately identifies elephant
flows in programmable Data Planes. P4Tree trains an offline Random Forest model at the Knowledge
Plane and deploys it on the Data Plane to classify flows at line speed. P4Tree enables updating
the Random Forest model at runtime and supports a flexible configuration of the number of trees
depending on the switches’ performance and the traffic conditions. We evaluated P4Tree extensively
using real traffic traces and different Random Forest configurations. The evaluation results show that
P4Tree is accurate and achieves a low classification time.

<p align="center">
  <img src="https://user-images.githubusercontent.com/60159274/193469294-26d17833-8840-430e-8746-a868323b2059.png")
</p>

Main references for this work are [IISY](https://github.com/cucl-srg/IIsy) and [SwitchTree](https://www.researchgate.net/publication/344827700_SwitchTree_In-network_Computing_and_Traffic_Analyses_with_Random_Forests).

## V1

This version was made in the virtual machine ubuntu 16 ...

## V2

This version incorporating an API that facilitates the communication between the controller and the switch using python. This version was made on the ubuntu 18 virtual machine...

Note: This version only works for small or low speed traffic traces.
