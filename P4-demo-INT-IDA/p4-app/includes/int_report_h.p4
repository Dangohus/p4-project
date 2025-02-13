#ifndef __TELEMETRY_REPORT_HEADER__
#define __TELEMETRY_REPORT_HEADER__

// Report Telemetry Headers
header int_report_header_t {
    bit<4> ver;
    bit<4> len;
    bit<3> nProt;
    bit<6> repMdBits;
    bit<6> rsvd;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<6> hw_id;
    bit<32> switch_id;
    bit<32> seq_no;
    bit<32> ingress_tstamp;
}

header int_q_drop_t {
    bit<8> queue_id;
    bit<8> drop_reason; // see possible values below
    bit<16> pad;
}

#endif

/*
 This report might include additional (optional) data like hop latency
 The headers for the optional and additional data are mostly already
 defined in the int_tcp_udp_h file

 Depending which bit is set in repMdBits:
 bit 0: int_level1_port_ids_t
 bit 1: int_hop_latency_t
 bit 2: int_q_occupancy_t
 bit 3: int_egress_tstamp_t
 bit 4: queue_id + drop_reason + padding (missing needs definition here)
 bit 5: int_egress_port_tx_util_t

DROP REASON (bit 4)
https://github.com/p4lang/switch/blob/master/p4src/includes/drop_reason_codes.h

#define DROP_UNKNOWN                       0

#define DROP_OUTER_SRC_MAC_ZERO            10
#define DROP_OUTER_SRC_MAC_MULTICAST       11
#define DROP_OUTER_DST_MAC_ZERO            12
#define DROP_OUTER_ETHERNET_MISS           13
#define DROP_SRC_MAC_ZERO                  14
#define DROP_SRC_MAC_MULTICAST             15
#define DROP_DST_MAC_ZERO                  16

#define DROP_OUTER_IP_VERSION_INVALID      25
#define DROP_OUTER_IP_TTL_ZERO             26
#define DROP_OUTER_IP_SRC_MULTICAST        27
#define DROP_OUTER_IP_SRC_LOOPBACK         28
#define DROP_OUTER_IP_MISS                 29
#define DROP_IP_VERSION_INVALID            30
#define DROP_IP_TTL_ZERO                   31
#define DROP_IP_SRC_MULTICAST              32
#define DROP_IP_SRC_LOOPBACK               33

#define DROP_PORT_VLAN_MAPPING_MISS        40
#define DROP_STP_STATE_LEARNING            41
#define DROP_STP_STATE_BLOCKING            42
#define DROP_SAME_IFINDEX                  43
#define DROP_MULTICAST_SNOOPING_ENABLED    44

#define DROP_MTU_CHECK_FAIL                50
#define DROP_TRAFFIC_MANAGER               51

#define DROP_ACL_DENY                      60
#define DROP_RACL_DENY                     61
#define DROP_URPF_CHECK_FAIL               62
#define DROP_IPSG_MISS                     63
#define DROP_IFINDEX                       64

*/
