
control Int_ingress(inout headers_t hdr,
                    inout metadata meta,
                    in    standard_metadata_t standard_metadata)
{

    direct_counter(CounterType.packets_and_bytes) counter_set_last_hop;

    action int_set_first_hop () {
        meta.int_metadata.first_hop = 1;
        meta.int_metadata.ingress_tstamp =
            (bit<32>) standard_metadata.ingress_global_timestamp;
    }
    action int_monitor_flow () {
        //If tb_set_source matches then we
        //indicate this is a flow to monitor
        meta.int_metadata.flowmon = 1;
    }
    action int_set_last_hop() {
        meta.int_metadata.last_hop = 1;
    }

    // Table for checking where the packet comes from
    // If packet comes from port which is a port for hosts
    // flag it (meta.int_metadata.first_hop) as first hop
    table tb_set_first_hop {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            int_set_first_hop;
        }
    }

    table tb_set_last_hop {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            int_set_last_hop;
        }
        counters = counter_set_last_hop;
        size = 256;
    }


    table tb_monitor_flow {
        key = {
            hdr.ipv4.srcAddr:  ternary;
            hdr.ipv4.dstAddr:  ternary;
            hdr.ipv4.protocol: ternary;
            hdr.icmp.tp:       ternary;
            hdr.tcp.srcPort:   ternary;
            hdr.tcp.dstPort:   ternary;
            hdr.udp.srcPort:   ternary;
            hdr.udp.dstPort:   ternary;
        }
        actions = {
            int_monitor_flow;
        }
    }
    apply{
        // Determine whether this switch acts as a source or not for a given packet.
        // (Acts as a source when a packet is coming from a host.)
        if(hdr.int_shim.isValid() && hdr.int_meta.isValid()){
            meta.int_metadata.flowmon = 1;
        }else{
            tb_monitor_flow.apply();
        }

        if (meta.int_metadata.flowmon == 1) {
            // Specify traffic slice to apply INT, as a 5-tuple. (isn't it 6?)
            tb_set_first_hop.apply();
            tb_set_last_hop.apply();
        }
     }

 }


control Int_report(inout headers_t hdr,
                   inout metadata meta,
                   in       standard_metadata_t standard_metadata)
{

    action add_telemetry_report_header() {
        /* Device should include its own INT metadata as embedded,
         * we'll not use local_report_header for this purpose.
         */
        hdr.int_report_header.setValid();
        hdr.int_report_header.ver = 1; //Latest spec
        hdr.int_report_header.len = 4;
        hdr.int_report_header.nProt = NEXT_PROTO_ETHERNET;
        // I guess repMdBits must be in if-else to check kind of report
        hdr.int_report_header.repMdBits = 0x0; // No additional metadata
        hdr.int_report_header.rsvd = 0;
        hdr.int_report_header.d = 0;
        hdr.int_report_header.q = 0;
        hdr.int_report_header.f = 1;
        hdr.int_report_header.hw_id = HW_ID;
        hdr.int_report_header.switch_id = meta.int_metadata.switch_id;
        hdr.int_report_header.seq_no = 0;
        hdr.int_report_header.ingress_tstamp =
            meta.int_metadata.ingress_tstamp;

    }

    action create_int_report(macAddr_t src_mac, macAddr_t mon_server_mac,
                                ip4Addr_t src_ip, ip4Addr_t mon_server_ip,
                                udp_port_t mon_server_port)
    {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr = mon_server_mac;
        hdr.report_ethernet.srcAddr = src_mac;
        hdr.report_ethernet.etherType = TYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4; // ipv4
        hdr.report_ipv4.ihl = 5; //i.e. 20 bytes
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 0;

        /* Total Len in outer IP header is:
         - report_ipv4_len +
         - report_udp_len  +
         - report_fixed_hdr_len +
         - ethernet_len +
         - ipv4_totalLen */
        hdr.report_ipv4.totalLen =
            (bit<16>)((bit<8>) hdr.report_ipv4.ihl * WORD_TO_BYTES +
            UDP_HEADER_SIZE_BYTES +
            (FIXED_INT_REPORT_LENGTH * WORD_TO_BYTES) +
            ETHERNET_HEADER_SIZE_BYTES) +
            hdr.ipv4.totalLen;

        /* Dont Fragment bit should be set */
        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl = 0xFF;
        hdr.report_ipv4.protocol = TYPE_UDP;
        hdr.report_ipv4.srcAddr = src_ip;
        hdr.report_ipv4.dstAddr = mon_server_ip;

        //Report UDP Header
        hdr.report_udp.setValid();
        hdr.report_udp.srcPort = 0;
        hdr.report_udp.dstPort = mon_server_port;
        /* Length in outer UDP header is:
         - report_udp_len  +
         - report_fixed_hdr_len +
         - ethernet_len +
         - ipv4_totalLen */
        hdr.report_udp.length_ =
            (bit<16>)(UDP_HEADER_SIZE_BYTES +
            FIXED_INT_REPORT_LENGTH * WORD_TO_BYTES +
            ETHERNET_HEADER_SIZE_BYTES) +
            hdr.ipv4.totalLen;

        add_telemetry_report_header();

    }

    /* Cloned packet instance_type is PKT_INSTANCE_TYPE_INGRESS_CLONE=1
     * Packet is forwarded according to the mirroring_add command
     */
    table tb_generate_report {
        key = {
            standard_metadata.instance_type: exact;
        }
        actions = {
            create_int_report;
        }
    }

    apply {
        tb_generate_report.apply();
    }
}

/* EGRESS */
control Int_source_sink(inout headers_t hdr,
                        inout metadata meta,
                        in    standard_metadata_t standard_metadata)
{

    action send_postcard() {
        // Placeholder for postcard report generation.
        NoAction();
    }

    action int_sink() {
        // Restore length fields of IPv4 header
        // Oh, ok. I think I got it. << 2 in order to multiply by four since length
        // in shim header is in 4 byte words and we need it in bytes
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)(hdr.int_shim.len << 2);
        hdr.ipv4.dscp = (bit<6>)hdr.int_shim.dscp;
        // Restore TCP/UDP
        hdr.udp.length_ = hdr.udp.length_ - (bit<16>)(hdr.int_shim.len << 2);
        // remove all the INT information from the packet
        hdr.int_shim.setInvalid();
        hdr.int_meta.setInvalid();
        hdr.int_switch_id.setInvalid();
        hdr.int_level1_port_ids.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_level2_port_ids.setInvalid();
        hdr.int_egress_port_tx_util.setInvalid();
        hdr.int_metadata_stack.setInvalid();
    }

    action int_first_hop(bit<8> remaining_hop_cnt, bit<5> hop_metadata_len,
        bit<4> ins_mask0003, bit<4> ins_mask0407, bit<4> ins_mask1215)
    {
        // All parameters came as parameters introduced from the SDN controller
        // in the table tb_int_source

        // insert INT shim header for TCP/UDP
        hdr.int_shim.setValid();

        // TODO: check the exact value for this field.
        // int_type: Hop-by-hop type (1) , destination type (2)
        // Destination type is not defined, therefore not supported in this implementation.
        hdr.int_shim.int_type = 1;

        /* Default INT header length in 4-byte words.
        (4 byte INT shim header + 8 byte INT metadata header) */

        /*Length: This is the total length of INT metadata header, INT stack
        and the shim header in 4-byte words. A non-INT device may read this
        field and skip over INT headers.*/

        /*The Fixed INT Header Length is the sum of INT metadata header length
        (8B) and the size of encapsulation-specific shim/option header (4B) as
        defined in section 4.6.
        */
        hdr.int_shim.len = 3; // in 4 byte words, so 3 * 4 = 12 bytes

        hdr.int_shim.dscp = hdr.ipv4.dscp; // save original DSCP from IP header

        // insert INT hop-by-hop metadata header
        hdr.int_meta.setValid();
        // 1 for INT version 1.0
        hdr.int_meta.ver = 1;
        hdr.int_meta.rep = 0;
        hdr.int_meta.c = 0;
        hdr.int_meta.e = 0;
        hdr.int_meta.m = 0;
        hdr.int_meta.rsvd1 = 0;
        hdr.int_meta.rsvd2 = 0;
        hdr.int_meta.hop_metadata_len = hop_metadata_len;
        hdr.int_meta.remaining_hop_cnt = remaining_hop_cnt;
        hdr.int_meta.instruction_mask_0003 = ins_mask0003;
        hdr.int_meta.instruction_mask_0407 = ins_mask0407;
        hdr.int_meta.instruction_mask_0811 = 0; // not supported
        hdr.int_meta.instruction_mask_1215 = ins_mask1215; // only checksum complement (bit 15) is supported

        // add the header len to total len
        // * Looks like we update length (3 words as 4 byte words introduced in
        // shim header length). So take that and update ipv4/udp/tcp lengths

        // So add 12 bytes as a result of adding shim header and metadata header
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
        // INT_HEADER_LEN_WORD (3)  * INT_WORD_SIZE (4);
        hdr.udp.length_ = hdr.udp.length_ + 12;
        // INT_HEADER_LEN_WORD (3) * INT_WORD_SIZE (4);

        // Set DSCP field to indicate the existance of INT header
        hdr.ipv4.dscp = DSCP_INT;
    }

    table tb_int_first_hop {
        // key = {}
        key = {
             hdr.int_meta.ver: exact;
        }
        actions = {
            int_first_hop;
        }
    }

    apply {
        if (meta.int_metadata.first_hop == 1 && meta.int_metadata.last_hop == 1) {
            // This is 1-hop source/sink case, we can't add INT.
            // Generate postcard report instead.
            send_postcard();
        } else if (meta.int_metadata.first_hop == 1){
            // This is source. Add INT header.
            tb_int_first_hop.apply();
        } else if (hdr.int_meta.isValid() && meta.int_metadata.last_hop == 1) {
            int_sink();
        }
    }
}

control Int_metadata_insert(inout headers_t hdr,
                            in    metadata meta,
                            in    standard_metadata_t standard_metadata)
{
    /* This implementation covers INT instructions 0-3 and 4-7*/

    /************************************************************
    ********************INT instructions 0-3*********************
    ************************************************************/

    /* this reference implementation covers only INT instructions 0-3 */
    action int_set_header_0() {
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = meta.int_metadata.switch_id;
    }
    action int_set_header_1() {
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id =
            (bit<16>) standard_metadata.ingress_port;
        hdr.int_level1_port_ids.egress_port_id =
            (bit<16>) standard_metadata.egress_port;
    }

    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency =
            (bit<32>) standard_metadata.deq_timedelta;
    }
    action int_set_header_3() {
        hdr.int_q_occupancy.setValid();
        // q_id not supported in v1model.
        hdr.int_q_occupancy.q_id = 0xff;
            // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_occupancy.q_occupancy =
            (bit<24>) standard_metadata.deq_qdepth;
    }

    /* action functions for bits 0-3 combinations, 0 is msb, 3 is lsb */
    /* Each bit set indicates that corresponding INT header should be added */
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }

    /* Table to process instruction bits 0-3 */
    table int_inst_0003 {
        key = {
            hdr.int_meta.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        default_action = int_set_header_0003_i0();
        const entries = {
            0 : int_set_header_0003_i0();
            1 : int_set_header_0003_i1();
            2 : int_set_header_0003_i2();
            3 : int_set_header_0003_i3();
            4 : int_set_header_0003_i4();
            5 : int_set_header_0003_i5();
            6 : int_set_header_0003_i6();
            7 : int_set_header_0003_i7();
            8 : int_set_header_0003_i8();
            9 : int_set_header_0003_i9();
            10 : int_set_header_0003_i10();
            11 : int_set_header_0003_i11();
            12 : int_set_header_0003_i12();
            13 : int_set_header_0003_i13();
            14 : int_set_header_0003_i14();
            15 : int_set_header_0003_i15();
        }
    }

    /************************************************************
    ********************INT instructions 4-7*********************
    ************************************************************/

    //ingress_tstamp
    action int_set_header_4() {
        hdr.int_ingress_tstamp.setValid();
        /*
        hdr.int_ingress_tstamp.ingress_tstamp =
        (bit<32>) standard_metadata.enq_timestamp;
        */
        hdr.int_ingress_tstamp.ingress_tstamp =
        (bit<32>) standard_metadata.ingress_global_timestamp;
    }

    //egress_timestamp
    action int_set_header_5() {
        hdr.int_egress_tstamp.setValid();
        /*
        hdr.int_egress_tstamp.egress_tstamp =
        (bit<32>) standard_metadata.enq_timestamp +
        (bit<32>) standard_metadata.deq_timedelta;
        */
        hdr.int_egress_tstamp.egress_tstamp =
        (bit<32>) standard_metadata.egress_global_timestamp;
    }

    // level 2, ingress_port_id & egress_port_id
    action int_set_header_6() {
        hdr.int_level2_port_ids.setValid();
        //TODO: Needs implementation
        hdr.int_level2_port_ids.ingress_port_id = 0xFFFF;
        hdr.int_level2_port_ids.egress_port_id = 0xFFFF;
    }

    //egress_port_tx_utilization
    action int_set_header_7() {
        // TODO: needs implementation
        hdr.int_egress_port_tx_util.setValid();
        hdr.int_egress_port_tx_util.egress_port_tx_util = 0;
    }

    /* action functions for bits 4-7 combinations, 4 is msb, 7 is lsb */
    /* Each bit set indicates that corresponding INT header should be added */
    action int_set_header_0407_i0() {
    }
    action int_set_header_0407_i1() {
        int_set_header_7();
    }
    action int_set_header_0407_i2() {
        int_set_header_6();
    }
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
    }
    action int_set_header_0407_i4() {
        int_set_header_5();
    }
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
    }
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i8() {
        int_set_header_4();
    }
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
    }
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i15() {
        int_set_header_7(); //deq_timedelta
        int_set_header_6(); //enq_timestamp
        int_set_header_5(); //egress_qid & deq_qdepth
        int_set_header_4(); //enq_qdepth
    }

    /* Table to process instruction bits 4-7 */
    table int_inst_0407{
        key = {
            hdr.int_meta.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        default_action = int_set_header_0407_i0();
        const entries = {
            0 : int_set_header_0407_i0();
            1 : int_set_header_0407_i1();
            2 : int_set_header_0407_i2();
            3 : int_set_header_0407_i3();
            4 : int_set_header_0407_i4();
            5 : int_set_header_0407_i5();
            6 : int_set_header_0407_i6();
            7 : int_set_header_0407_i7();
            8 : int_set_header_0407_i8();
            9 : int_set_header_0407_i9();
            10 : int_set_header_0407_i10();
            11 : int_set_header_0407_i11();
            12 : int_set_header_0407_i12();
            13 : int_set_header_0407_i13();
            14 : int_set_header_0407_i14();
            15 : int_set_header_0407_i15();
        }
    }

    apply{
        int_inst_0003.apply();
        int_inst_0407.apply();
        // int_inst_0811.apply();
    }
}

control Int_transit(inout headers_t hdr,
                    inout metadata meta,
                    in    standard_metadata_t standard_metadata)
{

    Int_metadata_insert() int_metadata_insert;

    action int_hop_cnt_exceeded() {
        hdr.int_meta.e = 1;
    }

    action int_transit_params(bit<32> switch_id, bit<16> l3_mtu) {
        meta.int_metadata.switch_id = switch_id;
        // say hml is 2, then 2 << 2 means multiplying 2 by 4 times. (bit shifting)
        // total 8 bytes which makes sense since each hop can insert 4 or 8 bytes
        meta.int_metadata.insert_byte_cnt =
            (bit<16>) hdr.int_meta.hop_metadata_len << 2;

        meta.int_metadata.int_data_len =
            (bit<8>) hdr.int_meta.hop_metadata_len;

        meta.fwd_metadata.l3_mtu = l3_mtu;
    }

    action int_mtu_limit_hit() {
        hdr.int_meta.m = 1;
    }

    action int_hop_cnt_decrement() {
        hdr.int_meta.remaining_hop_cnt =
            hdr.int_meta.remaining_hop_cnt - 1;
    }

    action int_update_outer_encap()
    {
        //INT shim and meta length was already added either in this switch as
        //being source switch before or the first switch in the path added it

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + meta.int_metadata.insert_byte_cnt;
        hdr.udp.length_ = hdr.udp.length_ + meta.int_metadata.insert_byte_cnt;
        //INT shim len = INT shim header length + INt metadata header length +
        //INT stack length (defined by field in metadata header).
        hdr.int_shim.len = hdr.int_shim.len + meta.int_metadata.int_data_len;
    }

    table tb_int_transit {
        // key = {}
        key = {
             hdr.int_meta.ver: exact;
        }
        actions = {
            int_transit_params;
        }
    }

    apply {
        // Add INT metadata, after header validation.
        if (hdr.int_meta.remaining_hop_cnt == 0) {
            // Remaining hop count exceeds. Set e bit and do not add metadata.
            int_hop_cnt_exceeded();
        } else if ((hdr.int_meta.instruction_mask_0811 ++
                    hdr.int_meta.instruction_mask_1215)
                    & 8w0xFE == 0 ) {
            /* v1.0 spec allows two options for handling unsupported
            * INT instructions. This exmple code skips the entire
            * hop if any unsupported bit (bit 8 to 14 in v1.0 spec) is set.
            * EDER: Right so bits 8 to 14, that is why & 8w0xFE.
            * But then what about the 15th bit? Need to check the standard.
            */
            tb_int_transit.apply();

            // check MTU limit
            if (hdr.ipv4.totalLen + meta.int_metadata.insert_byte_cnt
                > meta.fwd_metadata.l3_mtu) {
                // MTU limit will exceed. Set m bit and do not add INT metadata.
                int_mtu_limit_hit();
            } else if(hdr.int_meta.isValid()){
                // Add INT metadata and update INT shim header and outer headers.
                int_hop_cnt_decrement();
                int_metadata_insert.apply(hdr, meta, standard_metadata);
                int_update_outer_encap();
            }
        }
    }
}

control Int_egress(inout headers_t   hdr,
                   inout metadata meta,
                   in    standard_metadata_t standard_metadata)
{



    Int_source_sink() int_source_sink;
    Int_transit() int_transit;
    Int_report() int_report;


    apply{
        /* INT processing is only applied to packets with valid TCP or UDP header,
         * and not coming from or going to CPU_PORT.
            EDER: This needs to change for SDN Traffic Eng. use case
         */
        if (standard_metadata.ingress_port != CPU_PORT &&
            standard_metadata.egress_port != CPU_PORT &&
            (hdr.icmp.isValid() || hdr.udp.isValid() || hdr.tcp.isValid())) {
            // Determine whether this switch acts as a sink or not for a given packet.
            // (Acts as a sink when a packet is being forwarded to a host.)
            // We need to do this in egress since the egress port is defined in ingress?


            // Manipulate a packet, as source or sink
            int_source_sink.apply(hdr, meta, standard_metadata);

            // Manipulate a packet, as transit
            if (hdr.int_meta.isValid()) {
                int_transit.apply(hdr, meta, standard_metadata);
            }

            if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                /* send int report */
                int_report.apply(hdr, meta, standard_metadata);
            }

        }
    }
}
