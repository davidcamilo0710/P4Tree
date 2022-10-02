#! /usr/bin/python
# -*- coding:utf8 -*-
# python .\simulation.py -w 5 -i ../PCAPs/fast_test.pcap -t ../scripts/tree_DT.sav
from scapy.all import *
from scapy.utils import RawPcapReader
import numpy as np
import argparse
import datetime
import time
import pickle as pickle
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
import math as m
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
    description='Process pcap file and split into subfile. NOTE: Only output first sub pcap.')
parser.add_argument('-i', '--input', action='store', dest="pcap_in",
                    default="../PCAPs/fast_test.pcap", required=False, help="Input Pcap File.")
parser.add_argument('-t', '--tree', action='store', dest="tree",
                    default="../scripts/tree_DT.sav", required=False, help="Input Tree .sav file.")
parser.add_argument('-w', '--window', action='store', dest="window_size",
                    default=5, required=False, help="Window Time Off Flow.")
parser.add_argument('-c', '--count', action='store', dest="max_count",
                    default=0x1f1f1f1f, type=int, required=False, help="Read Packet Count.")
args = parser.parse_args()

pcap_input = args.pcap_in
timeOff = args.window_size
timeOff = float(timeOff)
max_count = args.max_count
direction = args.tree

filename = open(direction, 'rb')
rf = pickle.load(filename)
filename.close()

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
    'count_predictions': 0,
    'count_elephants': 0,
    'count_nellys': 0,
    'count_elephants_BP': 0,
    'count_mices_BP': 0,
    'count_time7': 0,
    'time7_pkt': 0,
    'src_ip_pkt_cnt_table': dict(),
    'src_ip_flow_size_table': dict(),
    'dst_ip_pkt_cnt_table': dict(),
    'dst_ip_flow_size_table': dict(),
    'ip_pair_pkt_cnt_table': dict(),    # <ip_pair : pkt_count>
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
    'packt7': dict(),
    'predictions': dict(),
    'elephant_bad_prediction': dict(),
    'mice_bad_prediction': dict(),
    'dataPredict': dict(),

}

# read pcap
print("Begin to process %s" % pcap_input)
pause = 0

for packet, (sec, usec, wirelen, caplen) in RawPcapReader(pcap_input):
    try:
        pause += 1
        if pause >= max_count:
            break
        pcap_statistics['pkt_num'] += 1
        ether_packet = Ether(packet)
        a = 0

        if ether_packet[IP]:
            pcap_statistics['ipv4_num'] += 1
            # <<<< Assuming Ethernet + IPv4 herez
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
                pcap_statistics['predictions'][five_tuple_key] = 0
                #pcap_statistics['predictions_only_7'][five_tuple_key] = 0
                pcap_statistics['packt1'][five_tuple_key] = 0
                pcap_statistics['packt2'][five_tuple_key] = 0
                pcap_statistics['packt3'][five_tuple_key] = 0
                pcap_statistics['packt4'][five_tuple_key] = 0
                pcap_statistics['packt5'][five_tuple_key] = 0
                pcap_statistics['packt6'][five_tuple_key] = 0
                pcap_statistics['packt7'][five_tuple_key] = 0
                pcap_statistics['elephant_bad_prediction'][five_tuple_key] = 0
                pcap_statistics['mice_bad_prediction'][five_tuple_key] = 0
                pcap_statistics['dataPredict'][five_tuple_key] = [
                    6, 9404, 1987, 60, 162, 134, 138, 230, 1434, 491]

            pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] += 1
            if pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] <= 7:
                pcap_statistics['packt'+str(pcap_statistics['5_tuple_pkt_cnt_table']
                                            [five_tuple_key])][five_tuple_key] = pkt_len

            if pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] == 7:

                flow_test = [protocol, sport, dport, pcap_statistics['packt1'][five_tuple_key], pcap_statistics['packt2'][five_tuple_key], pcap_statistics['packt3'][five_tuple_key],
                             pcap_statistics['packt4'][five_tuple_key], pcap_statistics['packt5'][five_tuple_key], pcap_statistics['packt6'][five_tuple_key], pcap_statistics['packt7'][five_tuple_key]]
                pcap_statistics['dataPredict'][five_tuple_key] = flow_test
                flow_test = np.array(flow_test)
                flow_test = flow_test.reshape(1, -1)
                prediction = rf.predict(flow_test)
                prediction = prediction[0]
                pcap_statistics['predictions'][five_tuple_key] = prediction
                pcap_statistics['count_predictions'] += 1
                if prediction == 1:
                    pcap_statistics['count_mices_BP'] += 1

            pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] += pkt_len

            if (pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] > 10000):

                if pcap_statistics['count__by_nelly'][five_tuple_key] == 0:
                    pcap_statistics['count_nellys'] += 1
                pcap_statistics['count__by_nelly'][five_tuple_key] = 1

            if (pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] > 100000 and pcap_statistics['elephant__cnt_table'][five_tuple_key] == 0):

                pcap_statistics['count_elephants'] += 1
                pcap_statistics['elephant__cnt_table'][five_tuple_key] = 1

                if pcap_statistics['predictions'][five_tuple_key] == 0:
                    pcap_statistics['count_elephants_BP'] += 1
                else:
                    pcap_statistics['count_mices_BP'] -= 1
    except:
        print("+1 paquete no valido (%d)" % pause)

matriz = pcap_statistics["dataPredict"]
matriz = list(matriz.values())
matriz = np.array(matriz)

vector = pcap_statistics['elephant__cnt_table']
vector = list(vector.values())
vector = np.array(vector)

init_time = time.time()
prediccion = rf.predict(matriz)
end_time = time.time()
delta_time = end_time - init_time
TC = 1000000*delta_time/(pcap_statistics['count_predictions'])

Mices = pcap_statistics["flow_num_5_tuple"] - \
    pcap_statistics['count_elephants']
TPR = 100*(pcap_statistics['count_elephants'] -
           pcap_statistics['count_elephants_BP'])/pcap_statistics['count_elephants']
FPR = 100*pcap_statistics['count_mices_BP'] / \
    (pcap_statistics["flow_num_5_tuple"] - pcap_statistics['count_elephants'])

FP = pcap_statistics['count_mices_BP']
TN = Mices - FP
FN = pcap_statistics['count_elephants_BP']
TP = pcap_statistics['count_elephants'] - pcap_statistics['count_elephants_BP']

round(1.4756, 2)
MCC = ((TP*TN) - (FP*FN))/(m.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN)))


# Conclude the Result.
print("pkt_num : %d" % pcap_statistics["pkt_num"])
print("Total Bytes : %d" % pesototal)
print("tcp_num(ipv4) : %d" % pcap_statistics["tcp_num"])
print("udp_num(ipv4) : %d" % pcap_statistics["udp_num"])
print("flow_num_5_tuple : %d" % pcap_statistics["flow_num_5_tuple"])
print("largest to 10Mb : %d" % pcap_statistics['count_nellys'])
print("Elephants_flow > 100Mb : %d" % pcap_statistics['count_elephants'])
print("TPR: {:.1f} %".format(TPR))
print("FPR: {:.1f} %".format(FPR))
print("MCC: {:.2f}".format(MCC))
print("tiempo de clasificacion: {:.1f} microsegundos".format(TC))
