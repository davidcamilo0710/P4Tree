#! /usr/bin/python
# -*- coding:utf8 -*-

# python datasetGenerator.py -i ../PCAPs/UNI1.pcap -w 5.45 -c UNI1 -d ../datasets
import os
from scapy.all import *
from scapy.utils import RawPcapReader
import pandas as pd
import numpy as np
import argparse
import os.path
import datetime
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

pesototal = 0


def segundos_entre(ts1, ts2):
    #timeStamp = packet.time
    ts1 = datetime.datetime.utcfromtimestamp(int(ts1))
    ts2 = datetime.datetime.utcfromtimestamp(int(ts2))

    TS1 = 3600*ts1.hour + 60*ts1.minute + ts1.second + 0.000001*ts1.microsecond
    TS2 = 3600*ts2.hour + 60*ts2.minute + ts2.second + 0.000001*ts2.microsecond
    # ts2..microsecond
    diff = abs(TS2 - TS1)
    return diff


parser = argparse.ArgumentParser(
    description='Process pcap and generate Dataset. NOTE: Only output first sub pcap.')
parser.add_argument('-i', '--input', action='store', dest="pcap_in",
                    default="../PCAPs/UNI1.pcap", required=True, help="Input Pcap File.")
parser.add_argument('-w', '--window', action='store', dest="window_size",
                    default=5.45, required=False, help="Window Time Off Flow.")
parser.add_argument('-d', '--outdir', action='store', dest="dir_out",
                    default="../datasets", required=False, help="Output Directory.")
parser.add_argument('-l', '--log', action='store', dest="pcap_out",
                    default="log", required=False, help="Output log File.")
parser.add_argument('-c', '--csv', action='store', dest="csv_out",
                    default="dataset", required=False, help="Output dataset .csv File.")


args = parser.parse_args()
pcap_input = args.pcap_in
timeOff = args.window_size
timeOff = float(timeOff)
dir_output = args.dir_out
pcap_output = args.pcap_out
csv_output = args.csv_out

max_count = 0xfffffffffffff

folder = os.path.exists(dir_output)
if not folder:
    os.makedirs(dir_output)
dir_output = dir_output + "/"

# TO statistic these data.
pcap_statistics = {
    'pkt_num': 0,
    'ipv4_num': 0,
    'ipv6_num': 0,
    # Only for ipv4
    'tcp_num': 0,
    'udp_num': 0,
    'flow_set_5_tuple': {},     # (ipv4_dst, ipv4_src, dport, sport, protocol)
    'flow_set_5_tuple_bandera': {},
    'flow_num_5_tuple': 0,
    'flow_num_5_tuple_bandera': 0,
    'count_elephants': 0,
    'count_nellys': 0,
    '5_tuple_pkt_cnt_table': dict(),    # <5-tuple : pkt_count>
    'time_last_pkt': dict(),
    'n_subflows': dict(),
    '5_tuple_flow_size_table': dict(),   # <5-tuple : flow_size>
    'elephant__cnt_table': dict(),
    'count__by_nelly': dict(),
    'packt1': dict(),
    'packt2': dict(),
    'packt3': dict(),
    'packt4': dict(),
    'packt5': dict(),
    'packt6': dict(),
    'packt7': dict()
}

# read pcap
print("Begin to process %s" % pcap_input)
pause = 0
for packet, (sec, usec, wirelen, caplen) in RawPcapReader(pcap_input):
    pause += 1
    print(pause)
    try:
        if pause >= max_count:
            print("top")
            break
        pcap_statistics['pkt_num'] += 1
        ether_packet = Ether(packet)
        a = 0

        if ether_packet[IP]:
            pcap_statistics['ipv4_num'] += 1
            # <<<< Assuming Ethernet + IPv4 here
            ip_packet = ether_packet[IP]
            protocol = ip_packet.fields['proto']
            ipv4_src = ip_packet.src
            ipv4_dst = ip_packet.dst
            sport = 0
            dport = 0

            if protocol == 17:
                udp_packet = ip_packet[UDP]
                sport = udp_packet.sport
                dport = udp_packet.dport
                pcap_statistics["udp_num"] += 1
            if protocol == 6:
                tcp_packet = ip_packet[TCP]
                sport = tcp_packet.sport
                dport = tcp_packet.dport
                pcap_statistics["tcp_num"] += 1

            five_tuple_bandera = (ipv4_dst, ipv4_src, dport, sport, protocol)
            first_packt = 0
            if five_tuple_bandera not in pcap_statistics["flow_set_5_tuple_bandera"]:
                pcap_statistics['flow_set_5_tuple_bandera'][five_tuple_bandera] = 1
                pcap_statistics['flow_num_5_tuple_bandera'] += 1
                pcap_statistics['time_last_pkt'][five_tuple_bandera] = 0
                pcap_statistics['n_subflows'][five_tuple_bandera] = 1
                first_packt = 1

            ActualTimestep = sec

            if (segundos_entre(ActualTimestep, pcap_statistics['time_last_pkt'][five_tuple_bandera]) > timeOff and first_packt == 0):
                pcap_statistics['n_subflows'][five_tuple_bandera] += 1

            five_tuple_key = (ipv4_dst, ipv4_src, dport, sport, protocol,
                              pcap_statistics['n_subflows'][five_tuple_bandera])
            pkt_len = wirelen
            pesototal = pesototal+pkt_len
            pcap_statistics['time_last_pkt'][five_tuple_bandera] = ActualTimestep

            if five_tuple_key not in pcap_statistics["flow_set_5_tuple"]:

                pcap_statistics['flow_set_5_tuple'][five_tuple_key] = 1
                pcap_statistics['flow_num_5_tuple'] += 1
                pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] = 0
                pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] = 0
                pcap_statistics['elephant__cnt_table'][five_tuple_key] = 0
                pcap_statistics['count__by_nelly'][five_tuple_key] = 0
                pcap_statistics['packt1'][five_tuple_key] = 0
                pcap_statistics['packt2'][five_tuple_key] = 0
                pcap_statistics['packt3'][five_tuple_key] = 0
                pcap_statistics['packt4'][five_tuple_key] = 0
                pcap_statistics['packt5'][five_tuple_key] = 0
                pcap_statistics['packt6'][five_tuple_key] = 0
                pcap_statistics['packt7'][five_tuple_key] = 0

            pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] += 1
            if pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] <= 7:
                pcap_statistics['packt'+str(pcap_statistics['5_tuple_pkt_cnt_table']
                                            [five_tuple_key])][five_tuple_key] = pkt_len

            pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] += pkt_len

            if (pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] > 10000):
                if pcap_statistics['count__by_nelly'][five_tuple_key] == 0:
                    pcap_statistics['count_nellys'] += 1

                pcap_statistics['count__by_nelly'][five_tuple_key] = 1

            if (pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] > 100000 and pcap_statistics['elephant__cnt_table'][five_tuple_key] == 0):
                pcap_statistics['count_elephants'] += 1
                pcap_statistics['elephant__cnt_table'][five_tuple_key] = 1
    except:
        print("+1 paquete no valido (%d)" % pause)

# Conclude the Result.
print("pkt_num : %d" % pcap_statistics["pkt_num"])
print("Total Bytes : %d" % pesototal)
print("tcp_num(ipv4) : %d" % pcap_statistics["tcp_num"])
print("udp_num(ipv4) : %d" % pcap_statistics["udp_num"])
print("flow_num_5_tuple : %d" % pcap_statistics["flow_num_5_tuple"])
print("largest to 10Mb : %d" % pcap_statistics['count_nellys'])
print("Elephants_flow > 100Mb : %d" % pcap_statistics['count_elephants'])
print("For detail please see result.txt.")


# Write txt Result.F
of = open(dir_output + pcap_output + ".txt", "w")
of.write("==============================================================================================================\n")
of.write("Overview:\n")
of.write("==============================================================================================================\n")
of.write("pkt_num : %d \n" % pcap_statistics["pkt_num"])
of.write("tcp_num(ipv4) : %d \n" % pcap_statistics["tcp_num"])
of.write("udp_num(ipv4) : %d \n" % pcap_statistics["udp_num"])
of.write("flow_num_5_tuple(ipv4)  : %d \n" %
         pcap_statistics["flow_num_5_tuple"])
of.write("Elephants_flow > 100Mb : %d \n" % pcap_statistics['count_elephants'])
of.write("largest to 10Mb : %d \n" % pcap_statistics['count_nellys'])
of.write("==============================================================================================================\n")
of.write("5-tuple flow count table:\n")
five_tuple_sorted_pkt_cnt = sorted(pcap_statistics["5_tuple_pkt_cnt_table"].items(
), key=lambda item: item[1], reverse=True)
tplt2 = "[{0:<16}:{2:<5} => {1:<16}:{3:<5} | {4:<4}]\t Packet Count = {5:<10}\t Flow Size (Bytes) = {6:<10}  Largest to 10Mb = {7:<10} Elephant = {8:<10}\n"

toCSV = np.zeros(((pcap_statistics['count_nellys']), 12))

count = 0
for five_tuple in five_tuple_sorted_pkt_cnt:
    pkt_cnt = pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple[0]]
    flow_size = pcap_statistics["5_tuple_flow_size_table"][five_tuple[0]]
    Elephant = pcap_statistics["elephant__cnt_table"][five_tuple[0]]
    Nelly = pcap_statistics["count__by_nelly"][five_tuple[0]]

    if Nelly == 1:
        toCSV[count, :] = [five_tuple[0][4], five_tuple[0][3], five_tuple[0][2], pcap_statistics['packt1'][five_tuple[0]], pcap_statistics['packt2'][five_tuple[0]], pcap_statistics['packt3'][five_tuple[0]],
                           pcap_statistics['packt4'][five_tuple[0]], pcap_statistics['packt5'][five_tuple[0]], pcap_statistics['packt6'][five_tuple[0]], pcap_statistics['packt7'][five_tuple[0]], flow_size, Elephant]
    if Nelly == 1:
        count += 1

    of.write(tplt2.format(five_tuple[0][1], five_tuple[0][0], five_tuple[0][3],
             five_tuple[0][2], five_tuple[0][4], pkt_cnt, flow_size, Nelly, Elephant))
of.write("==============================================================================================================\n")
of.close()


# Export dataset csv.
DF = pd.DataFrame(toCSV, columns=["ip_proto", "port_src", "port_dst", "size_pkt1", "size_pkt2",
                  "size_pkt3", "size_pkt4", "size_pkt5", "size_pkt6", "size_pkt7", "tot_size", "Elephant"])
DF.to_csv(dir_output+csv_output+".csv", index=False)
