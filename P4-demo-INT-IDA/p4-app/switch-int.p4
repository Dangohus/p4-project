#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/checksum.p4"
#include "includes/controller_io.p4"
#include "includes/headers.p4"
#include "includes/int.p4"
#include "includes/parsers.p4"
#include "includes/port_counters.p4"
#include "includes/table0.p4"


control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    Port_counters_ingress() port_counters_ingress;
    Packetio_ingress() packetio_ingress;
    Table0_control() table0_control;
    Int_ingress() int_ingress;


    apply{
        // We are using this control block to increment counters
        port_counters_ingress.apply(hdr, standard_metadata);
        // We are using this control block to check the traffic coming from the
        // controller.
        packetio_ingress.apply(hdr, standard_metadata);
        // We use this table to set the egress port, then use it to
        // forward the traffic to port
        table0_control.apply(hdr, meta, standard_metadata);
        // We use this to mark the switch and this the processing stage
        // (using local metadata) to be first hop (important for source INT
        // header setting)
        int_ingress.apply(hdr, meta, standard_metadata);


        if(hdr.int_shim.isValid() &&
            hdr.int_meta.isValid() && meta.int_metadata.last_hop == 1) {
        //if(standard_metadata.egress_spec == 1){
            // clone packet for Telemetry Report
            clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
        }

    }
}

control EgressImpl(inout headers_t hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata)
{
    Port_counters_egress() port_counters_egress;
    Int_egress() int_egress;
    Packetio_egress() packetio_egress;

    apply{
        int_egress.apply(hdr, meta, standard_metadata);
        port_counters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);

    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
