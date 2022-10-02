# Quick Start Guide

To run the code
1. Use the machine...

2. cd /home/vagrant/tutorials/exercises/P4Tree/P4-Random-Forest-5

3. `sudo make`

4.  In another terminal in the same path run:

`simple_switch_CLI < s1-commands\(uni1\).txt` 

This is done to embed the trained tree of the UNIV1 dataset

If you want to embed the UNIV2 trained tree, run:

`simple_switch_CLI < s1-commands\(uni2\).txt` 

5. In the mininet CLI open a new terminal on host 1 `xterm h1`.

6. Send traffic from `h1` to `h2` using tcpreplay. A quick test file of the UNIV1 dataset (< 10 minutes) containing 100k packets in the PCAP folder is provided. 

`sudo tcpreplay -i h1-eth0 ../PCAPs/fast_test.pcap`

7. To display the results, in another terminal run:

`simple_switch_CLI < get_results.txt`

8. To restart the program, the following command is executed in the same path:

`sudo make clean`

Return to step 1

9. In case you want to do performance evaluations and heavy tests: debugging and logging should be disabled otherwise several packets will be lost during real-time tests. This can be done by recompiling bmv2 using the options that disable logging.

`cd /home/vagrant/behavioral-model`

`sudo ./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger`

`sudo make`

`sudo make install`

10. If you want to train your own decison trees and random forests then please see the scripts folder.
