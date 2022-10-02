/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<32> feature1;
    bit<32> feature2;
    bit<32> feature3;
    bit<32> feature4;
    bit<32> feature5;
    bit<32> feature6;
    bit<32> feature7;
    bit<32> feature8;
    bit<32> feature9;
    bit<32> feature10;

    bit<16> class;
    bit<16> class1;
    bit<16> class2;
    bit<16> class3;
    bit<16> class4;
    bit<16> class5;
    bit<16> node_id;

    bit<16> prevFeature;
    bit<16> isTrue;

    bit<48> time_last_pkt;
    bit<48> time_first_pkt;
    bit<32> srcip;
    bit<32> register_index;
    bit<32> Flow_length;
    bit<32> Npkts;
    bit<16> srcport;
    bit<16> dstport;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<1> is_hash_collision;
    bit<1> is_first;
    bit<1> BanderaR;

    bit<16> count_muestras7;
    bit<16> count_muestras;
    bit<32> muestras7;
    bit<32> muestras;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t	     udp;
}
