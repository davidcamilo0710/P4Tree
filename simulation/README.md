# Simulation

You can run the simulation in python to verify the veracity of the emulation results in P4:
`python simulation.py -w 5 -i ../PCAPs/fast_test.pcap -t ../scripts/tree_DT.sav`  

where:
`-i` Input PCAP Path
`-w` Weight to balance dataset
`-t` Trained model path
