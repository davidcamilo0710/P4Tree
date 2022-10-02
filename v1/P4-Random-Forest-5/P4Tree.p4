/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define MAX_REGISTER_ENTRIES 4800000
#define CLASS_NOT_SET 10000// A big number
#define FLOW_TIMEOUT 5450000 //5 seconds
#define THRESHOLD 100000 // Umbral


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {



    //Registros
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_BanderaR;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_class;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_Flow_length;
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_Npkts;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_srcip;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_srcport;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dstport;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature4;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature5;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature6;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature7;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature8;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature9;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_feature10;

    //Contadores
    counter(1, CounterType.packets) counter_pkts;
    counter(1, CounterType.packets) counter_flows;
    counter(1, CounterType.packets) counter_timeout;
    counter(1, CounterType.packets) counter_hash_collisions;
    counter(1, CounterType.packets) counter_Flow_Elephant;
    counter(1, CounterType.packets) counter_false_detection_Elephant;
    counter(1, CounterType.packets) counter_false_detection_mice;
    counter(1, CounterType.packets) counter_false_detection_mice_rest;

    action init_register() {
	//intialise the registers to 0
    reg_time_last_pkt.write(meta.register_index, 0);
    reg_Npkts.write(meta.register_index, 0);
    reg_srcip.write(meta.register_index, 0);
    reg_srcport.write(meta.register_index, 0);
    reg_dstport.write(meta.register_index, 0);
    reg_Flow_length.write(meta.register_index, 0x0);
    reg_BanderaR.write(meta.register_index, 0);
    reg_feature4.write(meta.register_index, 0x0);
    reg_feature5.write(meta.register_index, 0x0);
    reg_feature6.write(meta.register_index, 0x0);
    reg_feature7.write(meta.register_index, 0x0);
    reg_feature8.write(meta.register_index, 0x0);
    reg_feature9.write(meta.register_index, 0x0);
    reg_feature10.write(meta.register_index, 0x0);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }


   action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    action get_register_index_tcp() {
    //Get register position
        hash(meta.register_index, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                            hdr.ipv4.dstAddr,
                			hdr.tcp.srcPort,
                            hdr.tcp.dstPort,
               				hdr.ipv4.protocol},
                			(bit<32>)MAX_REGISTER_ENTRIES);

    }

    action get_register_index_udp() {
            hash(meta.register_index, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

    }

    action init_class() {
	meta.class = CLASS_NOT_SET;
	meta.class1 = CLASS_NOT_SET;
	meta.class2 = CLASS_NOT_SET;
	meta.class3 = CLASS_NOT_SET;
 	meta.class4 = CLASS_NOT_SET;
	meta.class5 = CLASS_NOT_SET;
    }

    action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<32> threshold) {

	bit<32> feature = 0;
    bit<32> th = threshold;
	bit<16> f = f_inout + 1;

	if (f == 1) feature = meta.feature1;
	else if (f == 2) feature = meta.feature2;
	else if (f == 3) feature = meta.feature3;
	else if (f == 4) feature = meta.feature4;
	else if (f == 5) feature = meta.feature5;
	else if (f == 6) feature = meta.feature6;
	else if (f == 7) feature = meta.feature7;
	else if (f == 8) feature = meta.feature8;
	else if (f == 9) feature = meta.feature9;
	else if (f == 10) feature = meta.feature10;

	if (feature <= th) meta.isTrue = 1;
	else meta.isTrue = 0;

	meta.prevFeature = f - 1;

	meta.node_id = node_id;
    }

    action SetClass1(bit<16> node_id, bit<16> class) {
	meta.class1 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass2(bit<16> node_id, bit<16> class) {
	meta.class2 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass3(bit<16> node_id, bit<16> class) {
	meta.class3 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass4(bit<16> node_id, bit<16> class) {
	meta.class4 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass5(bit<16> node_id, bit<16> class) {
	meta.class5 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }


    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

	table level_1_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}
	table level_1_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_12{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_13{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_14{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_1_15{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass1;
	    }
	    size = 1024;
	}

	table level_2_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}
	table level_2_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_12{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_13{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_14{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_15{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_3_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}
	table level_3_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_12{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_13{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_14{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_15{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_4_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}
	table level_4_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_12{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_13{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_14{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_4_15{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass4;
	    }
	    size = 1024;
	}

	table level_5_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}
	table level_5_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_12{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_13{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_14{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table level_5_15{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass5;
	    }
	    size = 1024;
	}

	table debug{
	    key = {
		meta.feature1: exact;
		meta.feature2: exact;
		meta.feature3: exact;
		meta.feature4: exact;
		meta.feature5: exact;
		meta.feature6: exact;
		meta.feature7: exact;
		meta.feature8: exact;
		meta.feature9: exact;
		meta.feature10: exact;
		meta.is_first: exact;
		hdr.ipv4.dstAddr: exact;
		hdr.ipv4.totalLen: exact;
		meta.hdr_srcport: exact;
		meta.hdr_dstport: exact;
		standard_metadata.ingress_global_timestamp: exact;
		meta.register_index: exact;
		meta.is_hash_collision: exact;
		meta.class: exact;
	    }
	    actions = {
		NoAction;
	    }
	    size = 1024;
	}

    apply {

        //apply sketch

        counter_pkts.count(0);

        if (hdr.ipv4.isValid()){


        if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {//We treat only TCP or UDP packets


         if (hdr.ipv4.protocol == 6) {
            get_register_index_tcp();
            meta.hdr_srcport = hdr.tcp.srcPort;
            meta.hdr_dstport = hdr.tcp.dstPort;
        }
         else {
            get_register_index_udp();
            meta.hdr_srcport = hdr.udp.srcPort;
            meta.hdr_dstport = hdr.udp.dstPort;

         }

        //read_reg_to_check_collision srcip, srcport, dstport
		reg_srcip.read(meta.srcip, meta.register_index);
		reg_srcport.read(meta.srcport, meta.register_index);
		reg_dstport.read(meta.dstport, meta.register_index);
        reg_time_last_pkt.read(meta.time_last_pkt, (bit<32>)meta.register_index);

        if (meta.srcip == 0) {//It was an empty register
            meta.is_first = 1;
        }
        else if ((standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
            /*We havent heard from this flow it has been FLOW_TIMEOUT
              We will initialse the register space
              TODO check if init_register() is initialising all and only those needed. ;
             */
            init_register();
            counter_timeout.count(0);
            meta.is_first = 1;
        }
        else if (meta.srcip != hdr.ipv4.srcAddr || meta.srcport != meta.hdr_srcport
        || meta.dstport != meta.hdr_dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
            counter_hash_collisions.count(0);
        }

        if (meta.is_hash_collision == 0) {

        if (meta.is_first == 1) {
            meta.time_first_pkt = standard_metadata.ingress_global_timestamp;
            reg_time_first_pkt.write((bit<32>)meta.register_index, meta.time_first_pkt);
	    reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
	    reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
	    reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
            counter_flows.count(0);
        }

		reg_Npkts.read(meta.Npkts, (bit<32>)meta.register_index);
		meta.Npkts = meta.Npkts + 1;
		reg_Npkts.write((bit<32>)meta.register_index, meta.Npkts);

        reg_time_last_pkt.write((bit<32>)meta.register_index, standard_metadata.ingress_global_timestamp);


        if (meta.Npkts == 1){
            meta.feature4 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature4.write((bit<32>)meta.register_index, meta.feature4);
        }
        if (meta.Npkts == 2){
            meta.feature5 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature5.write((bit<32>)meta.register_index, meta.feature5);
        }
        if (meta.Npkts == 3){
            meta.feature6 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature6.write((bit<32>)meta.register_index, meta.feature6);
        }
        if (meta.Npkts == 4){
            meta.feature7 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature7.write((bit<32>)meta.register_index, meta.feature7);
        }
        if (meta.Npkts == 5){
            meta.feature8 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature8.write((bit<32>)meta.register_index, meta.feature8);
        }
        if (meta.Npkts == 6){
            meta.feature9 = (bit<32>)hdr.ipv4.totalLen;
            reg_feature9.write((bit<32>)meta.register_index, meta.feature9);
        }
        if (meta.Npkts == 7){
            meta.feature10= (bit<32>)hdr.ipv4.totalLen;
            reg_feature10.write((bit<32>)meta.register_index, meta.feature10);
        }


        if (meta.Npkts ==7){
			// feature initialization
            meta.feature1 = (bit<32>)hdr.ipv4.protocol;
            meta.feature2 = (bit<32>)meta.hdr_srcport;
            meta.feature3 = (bit<32>)meta.hdr_dstport;
            reg_feature4.read(meta.feature4, (bit<32>)meta.register_index);
            reg_feature5.read(meta.feature5, (bit<32>)meta.register_index);
            reg_feature6.read(meta.feature6, (bit<32>)meta.register_index);
            reg_feature7.read(meta.feature7, (bit<32>)meta.register_index);
            reg_feature8.read(meta.feature8, (bit<32>)meta.register_index);
            reg_feature9.read(meta.feature9, (bit<32>)meta.register_index);
            reg_feature10.read(meta.feature10, (bit<32>)meta.register_index);

            init_class();
            //debug.apply();

		meta.prevFeature = 0;
		meta.isTrue = 1;

		// Desicion tree 1
		level_1_1.apply();

		if (meta.class1 == CLASS_NOT_SET) {
		  level_1_2.apply();
		  if (meta.class1 == CLASS_NOT_SET) {
		    level_1_3.apply();
		    if (meta.class1 == CLASS_NOT_SET) {
			    level_1_4.apply();
			    if (meta.class1 == CLASS_NOT_SET) {
			        level_1_5.apply();
			        if (meta.class1 == CLASS_NOT_SET) {
			            level_1_6.apply();
			            if (meta.class1 == CLASS_NOT_SET) {
			                level_1_7.apply();
			                if (meta.class1 == CLASS_NOT_SET) {
				                level_1_8.apply();
				                if (meta.class1 == CLASS_NOT_SET) {
				                    level_1_9.apply();
				                    if (meta.class1 == CLASS_NOT_SET) {
				                        level_1_10.apply();
			                                if (meta.class1 == CLASS_NOT_SET){
					                    level_1_11.apply();
                                                            if (meta.class1 == CLASS_NOT_SET){
					                        level_1_12.apply();
								if (meta.class1 == CLASS_NOT_SET) {
				                		    level_1_13.apply();
				                		    if (meta.class1 == CLASS_NOT_SET) {
				                    			level_1_14.apply();
				                    			if (meta.class1 == CLASS_NOT_SET) {
				                        		    level_1_15.apply();
        }}}}}}}}}}}}}}

		// desicion tree 2
		meta.node_id = 399;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_2_1.apply();

		if (meta.class2 == CLASS_NOT_SET) {
		  level_2_2.apply();
		  if (meta.class2 == CLASS_NOT_SET) {
		    level_2_3.apply();
		    if (meta.class2 == CLASS_NOT_SET) {
			    level_2_4.apply();
			    if (meta.class2 == CLASS_NOT_SET) {
			        level_2_5.apply();
			        if (meta.class2 == CLASS_NOT_SET) {
			            level_2_6.apply();
			            if (meta.class2 == CLASS_NOT_SET) {
			                level_2_7.apply();
			                if (meta.class2 == CLASS_NOT_SET) {
				                level_2_8.apply();
				                if (meta.class2 == CLASS_NOT_SET) {
				                    level_2_9.apply();
				                    if (meta.class2 == CLASS_NOT_SET) {
				                        level_2_10.apply();
			                                if (meta.class2 == CLASS_NOT_SET){
					                    level_2_11.apply();
                                                            if (meta.class2 == CLASS_NOT_SET){
					                        level_2_12.apply();
								if (meta.class2 == CLASS_NOT_SET) {
				               			    level_2_13.apply();
				                		    if (meta.class2 == CLASS_NOT_SET) {
				                    			level_2_14.apply();
				                    			if (meta.class2 == CLASS_NOT_SET) {
				                        		    level_2_15.apply();
        }}}}}}}}}}}}}}

		// desicion tree 3
		meta.node_id = 798;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_3_1.apply();

		if (meta.class3 == CLASS_NOT_SET) {
		  level_3_2.apply();
		  if (meta.class3 == CLASS_NOT_SET) {
		    level_3_3.apply();
		    if (meta.class3 == CLASS_NOT_SET) {
			    level_3_4.apply();
			    if (meta.class3 == CLASS_NOT_SET) {
			        level_3_5.apply();
			        if (meta.class3 == CLASS_NOT_SET) {
			            level_3_6.apply();
			            if (meta.class3 == CLASS_NOT_SET) {
			                level_3_7.apply();
			                if (meta.class3 == CLASS_NOT_SET) {
				                level_3_8.apply();
				                if (meta.class3 == CLASS_NOT_SET) {
				                    level_3_9.apply();
				                    if (meta.class3 == CLASS_NOT_SET) {
				                        level_3_10.apply();
			                                if (meta.class3 == CLASS_NOT_SET){
					                    level_3_11.apply();
                                                            if (meta.class3 == CLASS_NOT_SET){
					                        level_3_12.apply();
								if (meta.class3 == CLASS_NOT_SET) {
				                		    level_3_13.apply();
				                		    if (meta.class3 == CLASS_NOT_SET) {
				                    			level_3_14.apply();
				                    			if (meta.class3 == CLASS_NOT_SET) {
				                        		    level_3_15.apply();
        }}}}}}}}}}}}}}

		// desicion tree 4
		meta.node_id = 1197;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_4_1.apply();

		if (meta.class4 == CLASS_NOT_SET) {
		  level_4_2.apply();
		  if (meta.class4 == CLASS_NOT_SET) {
		    level_4_3.apply();
		    if (meta.class4 == CLASS_NOT_SET) {
			    level_4_4.apply();
			    if (meta.class4 == CLASS_NOT_SET) {
			        level_4_5.apply();
			        if (meta.class4 == CLASS_NOT_SET) {
			            level_4_6.apply();
			            if (meta.class4 == CLASS_NOT_SET) {
			                level_4_7.apply();
			                if (meta.class4 == CLASS_NOT_SET) {
				                level_4_8.apply();
				                if (meta.class4 == CLASS_NOT_SET) {
				                    level_4_9.apply();
				                    if (meta.class4 == CLASS_NOT_SET) {
				                        level_4_10.apply();
			                                if (meta.class4 == CLASS_NOT_SET){
					                    level_4_11.apply();
                                                            if (meta.class4 == CLASS_NOT_SET){
					                        level_4_12.apply();
								if (meta.class4 == CLASS_NOT_SET) {
				               			    level_4_13.apply();
				                		    if (meta.class4 == CLASS_NOT_SET) {
				                    			level_4_14.apply();
				                    			if (meta.class4 == CLASS_NOT_SET) {
				                        		    level_4_15.apply();
        }}}}}}}}}}}}}}

		// desicion tree 5
		meta.node_id = 1596;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_5_1.apply();

		if (meta.class5 == CLASS_NOT_SET) {
		  level_5_2.apply();
		  if (meta.class5 == CLASS_NOT_SET) {
		    level_5_3.apply();
		    if (meta.class5 == CLASS_NOT_SET) {
			    level_5_4.apply();
			    if (meta.class5 == CLASS_NOT_SET) {
			        level_5_5.apply();
			        if (meta.class5 == CLASS_NOT_SET) {
			            level_5_6.apply();
			            if (meta.class5 == CLASS_NOT_SET) {
			                level_5_7.apply();
			                if (meta.class5 == CLASS_NOT_SET) {
				                level_5_8.apply();
				                if (meta.class5 == CLASS_NOT_SET) {
				                    level_5_9.apply();
				                    if (meta.class5 == CLASS_NOT_SET) {
				                        level_5_10.apply();
			                                if (meta.class5 == CLASS_NOT_SET){
					                    level_5_11.apply();
                                                            if (meta.class5 == CLASS_NOT_SET){
					                        level_5_12.apply();
								if (meta.class5 == CLASS_NOT_SET) {
				               			    level_5_13.apply();
				                		    if (meta.class5 == CLASS_NOT_SET) {
				                    			level_5_14.apply();
				                    			if (meta.class5 == CLASS_NOT_SET) {
				                        		    level_5_15.apply();
        }}}}}}}}}}}}}}

		//voting from results of different trees
		if (meta.class1 == CLASS_NOT_SET) meta.class1 = 0; //TODO to check why this can happen!
		if (meta.class2 == CLASS_NOT_SET) meta.class2 = 0;
		if (meta.class3 == CLASS_NOT_SET) meta.class3 = 0;
		if (meta.class4 == CLASS_NOT_SET) meta.class4 = 0;
		if (meta.class5 == CLASS_NOT_SET) meta.class5 = 0;


		meta.class = meta.class1 + meta.class2 + meta.class3 + meta.class4 + meta.class5;

		if (meta.class < 3) meta.class = 0;
		else meta.class = 1;

        reg_class.write((bit<32>)meta.register_index, meta.class);

        if (meta.class == 1) counter_false_detection_mice.count(0);

        } //End Npkts ==7

        reg_Flow_length.read(meta.Flow_length, (bit<32>)meta.register_index);
        meta.Flow_length = meta.Flow_length + (bit<32>)hdr.ipv4.totalLen;
        reg_Flow_length.write((bit<32>)meta.register_index, meta.Flow_length);


        reg_BanderaR.read(meta.BanderaR, (bit<32>)meta.register_index);

        if (meta.Flow_length > THRESHOLD && meta.BanderaR == 0) {

            meta.BanderaR = 1;
            reg_BanderaR.write((bit<32>)meta.register_index, meta.BanderaR);
            counter_Flow_Elephant.count(0);
            reg_class.read(meta.class, (bit<32>)meta.register_index);

            if (meta.class == 0) counter_false_detection_Elephant.count(0);
	    else counter_false_detection_mice_rest.count(0);

        }


        } //End Hash_Colision

      }  //End of if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17)

        forwarding.apply();

  }//End of if hdr.ipv4.isValid()
 }//End of apply
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_muestras;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_muestras7;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_count_muestras;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_count_muestras7;

    table debug2{
 	    key = {
         meta.count_muestras: exact;
         meta.muestras: exact;
         meta.count_muestras7: exact;
         meta.muestras7: exact;
 	    }
 	    actions = {
 		NoAction;
 	    }
 	    size = 1024;
 	}


    apply {
        reg_count_muestras7.read(meta.count_muestras7, 1);
        reg_muestras7.read(meta.muestras7, 1);
        reg_count_muestras.read(meta.count_muestras, 1);
        reg_muestras.read(meta.muestras, 1);

        if (meta.Npkts == 7 && meta.count_muestras7 < 300){
            meta.muestras7 = meta.muestras7 + standard_metadata.packet_length;
            meta.count_muestras7 = meta.count_muestras7 +1;
            reg_count_muestras7.write(1, meta.count_muestras7);
            reg_muestras7.write(1, meta.muestras7);

        } else if(meta.Npkts != 7 && meta.count_muestras < 500){
            meta.muestras = meta.muestras + standard_metadata.packet_length;
            meta.count_muestras = meta.count_muestras +1;
            reg_count_muestras.write(1, meta.count_muestras);
            reg_muestras.write(1, meta.muestras);

        }

     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
