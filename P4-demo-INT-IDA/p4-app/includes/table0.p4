

control Table0_control(inout headers_t hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets_and_bytes) table0_counter;

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action set_egress_port(macAddr_t dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }


    table table0 {
        key = {
            //If you put a field to be exact and others ternary, you always
            //need to provide the field what is exact in the runtime rules
            //but you can omit the rest of ternary rules.

            standard_metadata.ingress_port : ternary;
            hdr.ethernet.srcAddr           : ternary;
            hdr.ethernet.dstAddr           : ternary;
            hdr.ethernet.etherType         : ternary;
            hdr.ipv4.srcAddr               : ternary;
            hdr.ipv4.dstAddr               : ternary;
            hdr.ipv4.protocol              : ternary;
        }
        actions = {
            set_egress_port();
            send_to_cpu();
            _drop();
        }
        const default_action = _drop();
        counters = table0_counter;
    }

    apply {
        table0.apply();
     }
}
