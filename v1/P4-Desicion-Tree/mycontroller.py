import sys
import math as m
from xml.dom.minidom import Element
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


class ReadCounters(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

    def read(self):
        self.controller.counter_read('counter_pkts', 0)
        self.controller.counter_read('counter_hash_collisions', 0)
        totalflows = self.controller.counter_read('counter_flows', 0)
        elephants = self.controller.counter_read('counter_Flow_Elephant', 0)
        elephants_BP = self.controller.counter_read(
            'counter_false_detection_Elephant', 0)
        mice_BD_sum = self.controller.counter_read(
            'counter_false_detection_mice', 0)
        mice_BD_rest = self.controller.counter_read(
            'counter_false_detection_mice_rest', 0)

        N_muestras = self.controller.register_read('reg_count_muestras', 1)
        N_muestras7 = self.controller.register_read('reg_count_muestras7', 1)
        muestras = self.controller.register_read('reg_muestras', 1)
        muestras7 = self.controller.register_read('reg_muestras7', 1)

        try:
            mice_BD = mice_BD_sum[1] - mice_BD_rest[1]
            TPR = (elephants[1] - elephants_BP[1]) * 100 / elephants[1]
            print("TPR: {:.1f} %".format(TPR))
            FPR = mice_BD * 100 / (totalflows[1] - elephants[1])
            print("FPR: {:.1f} %".format(FPR))

            FP = mice_BD
            TN = totalflows[1] - elephants[1] - FP
            FN = elephants_BP[1]
            TP = elephants[1] - FN
            MCC = ((TP*TN) - (FP-FN))/(m.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN)))
            tiempo_promedio_IngressProcesing_normal_paquete = muestras / N_muestras
            tiempo_promedio_IngressProcesing_paquete_7 = muestras7 / N_muestras7
            tc = tiempo_promedio_IngressProcesing_paquete_7 - \
                tiempo_promedio_IngressProcesing_normal_paquete

            print("MCC: {:.2f}".format(MCC))
            print("Tiempo promedio IP paquete normal: {:.1f} microS".format(
                tiempo_promedio_IngressProcesing_normal_paquete))
            print("Tiempo promedio IP paquete clasificado: {:.1f} microS".format(
                tiempo_promedio_IngressProcesing_paquete_7))
            print("Tiempo Clasificación: {:.1f} microS".format(tc))
        except:
            print("TPR: -·-")
            print("FPR: -·-")
            print("MCC: -·-")
            print("Tiempo Clasificación: -·-")


if __name__ == '__main__':
    ReadCounters('s1').read()
