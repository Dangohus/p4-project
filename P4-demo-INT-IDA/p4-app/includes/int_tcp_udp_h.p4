
#ifndef __INT_TCP_UDP_HEADER__
#define __INT_TCP_UDP_HEADER__
/* INT shim header:
   In-band Network Telemetry (INT) Dataplane Specification
   Working draft, 2018-05-08, Page 10
*/

/* INT shim header for TCP/UDP */
header int_shim_t {
    bit<8>  int_type;   // hop-by-hop or destination header
    bit<8>  rsvd1;
    bit<8>  len;  // Total length of INT metadata header
    bit<6>  dscp; // Store original DSCP value (if DSCP is used) else reserved
    // Will use this field in the paper
    // if 0x1 and remaining_hop_cnt is >1 then broadcast, else send to CPU
    bit<2>  rsvd2;
} // 4 bytes

/* INT header */
/* 16 instruction bits are defined in four 4b fields to allow concurrent
lookups of the bits without listing 2^16 combinations */
header int_meta_t {
    bit<4> ver;
    bit<2> rep;
    bit<1> c;
    bit<1> e;
    bit<1> m;
    bit<7> rsvd1;
    bit<3> rsvd2;
    bit<5> hop_metadata_len;
    bit<8> remaining_hop_cnt;
    bit<4> instruction_mask_0003; // check instructions from bit 0 to bit 3
    bit<4> instruction_mask_0407; // check instructions from bit 4 to bit 7
    bit<4> instruction_mask_0811; // check instructions from bit 8 to bit 11
    bit<4> instruction_mask_1215; // check instructions from bit 12 to bit 15
    bit<16> rsvd3;
} // 8 bytes


//HEADERS USED IN BiTS 0-3
/* INT meta-value headers - different header for each value type */

// bit 0:
header int_switch_id_t {
    bit<32> switch_id;
}

// bit 1:
header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

// bit 2: deq_timedelta
// the time, in microseconds, that the packet spent in the queue.
header int_hop_latency_t {
    // (bit<32>) standard_metadata.deq_timedelta;
    bit<32> hop_latency;
}

// bit 3: deq_qdepth;
// https://github.com/p4lang/behavioral-model/issues/311
// https://github.com/p4lang/behavioral-model/issues/493
// the depth of queue when the packet was dequeued.
header int_q_occupancy_t {
    bit<8>  q_id; // looks like not supported
    // (bit<24>) standard_metadata.deq_qdepth;
    bit<24> q_occupancy;
}

//HEADERS USED IN BiTS 4-7

// bit 4
// a timestamp, in microseconds, set when the packet shows up on ingress.
// The clock is set to 0 every time the switch starts. This field can be read
// directly from either pipeline (ingress and egress) but should not be
// written to.
// ingress_global_timestamp
header int_ingress_tstamp_t {
    bit<32> ingress_tstamp;
}

// bit 5
// egress_global_timestamp
header int_egress_tstamp_t {
    bit<32> egress_tstamp;
}

// bit 6:
header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

// bit 7
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

// Other INT standard_metadata based headers
// deq_qdepth;
// the depth of queue when the packet was enqueued.
header int_enqueue_occupancy_t {
    bit<32> enq_occupancy;
}

header int_enqueue_tstamp_t {
    bit<32> enq_timestamp;
}

/* switch internal variables for INT logic implementation */
header int_metadata_stack_t {
    // Maximum int metadata stack size in bits:
    // (0xFF - 3) * 32 (excluding INT shim header and INT metadata header)
    // EDER: Can we express this as a function of max_hop or should we
    // just consider 8064?
    // I think this is (MAX_shim.len - 3) * TO_BITS
    // (255 - 3) * 32 = 8064
    // - MAX field value for shim.len (8 bits) = 255
    // - shim and metadata header length (in 4 byte words) = 3
    // - WORD_TO_BITS = * 32
    varbit<8064> data;
}

/* switch internal variables for INT logic implementation */
struct int_local_metadata_t {
    bit<16>  insert_byte_cnt;
    bit<8>   int_hdr_word_len;
    bit<32>  switch_id;
    bit<1>   source;
    bit<1>   first_hop;
    bit<1>   last_hop;
    // Supposed to be used in egress parser.
    bit<1>   int_check;
}

#endif


// Some info sources:
// https://github.com/p4lang/behavioral-model/blob/master/docs/simple_switch.md
//

// standard_metadata
/*
struct standard_metadata_t {
    bit<9> ingress_port; x 0-3bits
    bit<9> egress_spec;
    bit<9> egress_port; x 0-3bits
    bit<32> clone_spec;
    bit<32> instance_type;
    bit<1> drop;
    bit<16> recirculate_port;
    bit<32> packet_length;
    bit<32> enq_timestamp; x 4-7bits
    bit<19> enq_qdepth; x 4-7bits
    bit<32> deq_timedelta; x 4-7bits
    bit<19> deq_qdepth;  x 4-7bits
    bit<48> ingress_global_timestamp; x 0-3bits
    bit<48> egress_global_timestamp; x 0-3bits
    bit<32> lf_field_list;
    bit<16> mcast_grp; x
    bit<32> resubmit_flag;
    bit<16> egress_rid;
    bit<1> checksum_error;
    bit<32> recirculate_flag;
}
*/
