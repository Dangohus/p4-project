
/********************************************************************
 PARSER & DEPARSER
 *******************************************************************/




parser ParserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            TYPE_TCP : parse_tcp;
            TYPE_UDP : parse_udp;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT: parse_int_shim;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
            // &&& is a mask operator in p4_16
            // why DSCP_INT &&& DSCP_INT
            DSCP_INT: parse_int_shim;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT: parse_int_shim;
            default: accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition parse_int_meta;
    }

    state parse_int_meta {
        packet.extract(hdr.int_meta);
        /*If we cannot extract varbit, then ..*/
        /*What about the array of INT data? Like in the source routing example?*/
        transition parse_int_metadata_stack;
    }

    state parse_int_metadata_stack { //P4apps, Joghwan
        // Parse INT metadata, not INT header and INT shim header (length in bits)
        packet.extract(hdr.int_metadata_stack, (bit<32>) ((hdr.int_shim.len - 3) << 5));
        transition accept;
    }

}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {

        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.int_report_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_meta);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_port_tx_util);
        packet.emit(hdr.int_metadata_stack);
    }
}
