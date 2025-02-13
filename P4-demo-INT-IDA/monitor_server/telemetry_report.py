from scapy.all import rdpcap, Packet
from scapy.all import IntField, ShortField, ByteField, BitField

packets = rdpcap('s2-eth2_in.pcap')

HOPS = 2
ShimSize = 4
TailSize = 4
INTSize = 8
MetadataSize = 16

class TelemetryReport(Packet):
    name = "Telemetry Report Header"

    fields_desc = [
        BitField('ver', 0, 4),
        BitField('len', 0, 4),
        BitField('nprot', 0, 3),
        BitField('repMdBits', 0, 6),
        BitField('rsvd', 0, 6),
        BitField('d', 0, 1),
        BitField('q', 0, 1),
        BitField('f', 0, 1),
        BitField('hw_id', 0, 6),
        IntField('switch_id', 0),
        IntField('seq_no', 0),
        IntField('ingress_tstamp', 0),
    ]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            if(self.f & 0x1)
                return Ether
        return Padding


bind_layers(UDP, TelemetryReport, dport=17171)
bind_layers(TelemetryReport, Ether, f=1) # Tracked Flow association
