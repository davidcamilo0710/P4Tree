# Quick Start Guide

To run the code
1. Use or Create a BMV2 VM or machine. You can download our ready-to-use machine [here](https://drive.google.com/drive/folders/122pO1naACjXhwBUpNBiYIfDq9REoIMp-?usp=sharing), or you can create it yourself [here](https://nsg-ethz.github.io/p4-utils/installation.html).

2. Clone the repository in your home folder

3. cd to P4-Desicion-Tree folder 

4. `sudo p4run`

5. In the mininet CLI open a new terminal on host 1 `xterm h1`.

6. Send the traffic from `h1` to `h2` using tcpreplay. A fast test file (< 10 minutes) containing 100k packets is provided in PCAPs folder. 

`sudo tcpreplay -i h1-eth0 ../PCAPs/fast_test.pcap`

7. To display the results, in another terminal run:

`python mycontroller.py`

8. Note you may need to exit and type `sudo p4run` again to reinitialize and do a new test with new data. 

9. In case you want to do performance evaluations and heavy tests: debugging and logging should be disabled otherwise several packets will be lost during real-time tests. This can be done by recompiling bmv2 using the options that disable logging.

`cd p4-tools/bmv2/`

`sudo ./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger`

`sudo make`

`sudo make install`

10. If you want to train your own decison trees and random forests then please see the scripts folder.
