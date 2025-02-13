

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/




#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"
#include "standard_h.p4" // Eth, IP, TCP/UDP
#include "int_report_h.p4"
#include "int_tcp_udp_h.p4"



@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _pad;
}

struct headers_t {
    //Packet IN/OUT
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    // Telemetry report outer standard headers
    ethernet_t report_ethernet;
    ipv4_t report_ipv4;
    tcp_t report_tcp;
    udp_t report_udp;
    // Telemetry INT report header
    int_report_header_t int_report_header;
    //Standard headers
    ethernet_t ethernet;
    ipv4_t ipv4;
    icmp_t icmp;
    tcp_t tcp;
    udp_t udp;
    //INT header for TCP/UDP (Shim+Meta+Stack)
    int_shim_t int_shim;
    int_meta_t int_meta;
    int_switch_id_t int_switch_id;
    int_level1_port_ids_t int_level1_port_ids;
    int_hop_latency_t int_hop_latency;
    int_q_occupancy_t int_q_occupancy;
    int_ingress_tstamp_t int_ingress_tstamp;
    int_egress_tstamp_t int_egress_tstamp;
    int_level2_port_ids_t int_level2_port_ids;
    int_egress_port_tx_util_t int_egress_port_tx_util;
    int_metadata_stack_t int_metadata_stack;
}

struct empty_metadata_t {

}

struct int_metadata_t {
    bit<1>  flowmon;
    bit<1>  first_hop;
    bit<1>  last_hop;
    bit<16> insert_byte_cnt;
    bit<16> flow_id;
    bit<8>  metadata_len;
    bit<32> switch_id;
    bit<8>  int_hdr_word_len;
    bit<8>  int_data_len;
    bit<9>  egress_port;
    bit<32> ingress_tstamp;
}

struct fwd_metadata_t {
    bit<16>  l3_mtu;
}

struct metadata {
    int_metadata_t int_metadata;
    fwd_metadata_t fwd_metadata;
    bool update_udp_checksum;
}

error {
    BadIPv4HeaderChecksum
}

#endif
