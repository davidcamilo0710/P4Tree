# P4Tree
## Introduction


Traditional multipath routing approaches such as Equal Cost Multi-Path (ECMP) and Weighted Cost Multi-Path (WCMP), tend to generate congested links (hot-spots) since they lack discriminating large, long-lived flows (elephants) from small, short-lived flows (mice). Congestion (hot-spots) compromises the quality and performance of applications and services, particularly those framed in 5G and beyond use cases. Novel approaches based on Software-Defined Networking classify elephant/mice flows to process them separately, aiming to improve network performance. Some flow classification methods use Machine Learning either at the Control Plane, network servers, or Data Plane. However, these methods lead to traffic overhead, low scalability, and high classification time. This repository stores the prototype and datasets of P4Tree, a novel approach based on Random Forests that quickly and accurately identifies elephant flows in programmable Data Planes. P4Tree trains an offline Random Forest model at the Knowledge Plane and deploys it on the Data Plane to classify flows at line speed. P4Tree enables updating the Random Forest model at runtime and supports a flexible configuration of the number of trees depending on the switches’ performance and the traffic conditions. We evaluated P4Tree extensively using real traffic traces and different Random Forest configurations. The evaluation results show that P4Tree is accurate and achieves a low classification time.

<p align="center">
  <img src="https://user-images.githubusercontent.com/60159274/193469294-26d17833-8840-430e-8746-a868323b2059.png")
</p>

## Code and Resources Used

* P4 Emulation: [bmv2](https://github.com/p4lang/behavioral-model)
* P4 Utils (only for version 2): [p4-utils](https://github.com/nsg-ethz/p4-utils)
* Python Version: 2.7
* Python Packages: Pandas, NumPy, Sklearn
* Data: [UNIV1 and UNIV2](https://pages.cs.wisc.edu/~tbenson/IMC10_Data.html)

## V1

The initial version is made with [bmv2](https://github.com/p4lang/behavioral-model) on Ubuntu 16.

## V2

This version incorporates [p4-utils](https://github.com/nsg-ethz/p4-utils), which makes P4 networks easier to build and is made with Ubuntu 18.

Note: This version only works for small or low speed traffic traces.

## Authors

* [David Camilo Muñoz Garcia](https://github.com/davidcamilo0710)
* [Freddy Andres Saavedra Hoyos](https://github.com/freddysaav)

## Citation

When referencing this work, please use the following citation:

An open access version of the paper is available at:
