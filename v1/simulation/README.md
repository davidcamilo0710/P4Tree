# Simulation

You can run the simulation in python to verify the veracity of the emulation results in P4:

`python simulation.py -w 5 -i ../PCAPs/fast_test.pcap -t ../scripts/tree_DT.sav`  

Where:
`-i` Input PCAP Path
`-w` Time window between flows with equal 5-tuples
`-t` Trained model path
