from scapy.packet import Packet, bind_layers, Padding
from scapy.fields import BitField, ByteField, ShortField, IntField, Field
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether






class INT_shim(Packet):
    oName = "Telemetry Report Header"

    fields_desc = [
        ByteField('int_type', 0),
        ByteField('rsvd1', 0),
        ByteField('len', 1),
        BitField('dscp', 0, 6),
        BitField('rsvd2', 0, 2)
    ]


class INT_meta(Packet):
    name = "INT Metadata Header"

    fields_desc = [
        BitField('ver', 0, 4),
        BitField('rep', 0, 2),
        BitField('c', 0, 1),
        BitField('e', 0, 1),
        BitField('m', 0, 1),
        BitField('rsvd1', 0, 7),
        BitField('rsvd2', 0, 3),
        BitField('hop_metadata_len', 0, 5),
        ByteField('remaining_hop_cnt', 0),
        BitField('instruction_mask_0003', 0, 4),
        BitField('instruction_mask_0407', 0, 4),
        BitField('instruction_mask_0811', 0, 4),
        BitField('instruction_mask_1215', 0, 4),
        ShortField('rsvd3', 0),
    ]

class INT_metata_stack(Packet):
    name = "INT Metadata Stack"

    def do_dissect(self, s):
        pass


    def extract_padding(self, p):
        return "", p

class INT_Switch_Id(Packet):
    name = "Switch ID"

    fields_desc = [
        IntField('switch_id', 0),
    ]

class INT_level1_port_ids(Packet):
    name = "Level 1 port IDs"

    fields_desc = [
        ShortField('level1_ingress_port_id', 0),
        ShortField('level1_egress_port_id', 0)
    ]

class INT_hop_latency_(Packet):
    name = "Hop Latency"

    fields_desc = [
        IntField('hop_latency', 0),
    ]

class INT_q_occupancy_(Packet):
    name = "Queue Occupancy"

    fields_desc = [
        ByteField('q_id', 0),
        BitField('q_occupancy', 0, 24),
    ]

class INT_ingress_tstamp_t(Packet):
    name = "Ingress Timestamp"

    fields_desc = [
        IntField('ingress_tstamp', 0),
    ]

class INT_egress_tstamp(Packet):
    name = "Egress Timestamp"

    fields_desc = [
        IntField('egress_tstamp', 0),
    ]

class INT_level2_port_ids(Packet):
    name = "Level 2 Port Ids"

    fields_desc = [
        ShortField('level2_ingress_port_id', 0),
        ShortField('level2_egress_port_id', 0)
    ]

class INT_egress_port_tx_util(Packet):
    name = "Egress Port TX util"

    fields_desc = [
        IntField('egress_port_tx_util', 0),
    ]


def _parse_headers_and_body(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      - the first line (e.g., "GET ...")
      - the headers in a dictionary
      - the body '''
    try:
        headers = s[: + len(crlfcrlf)].decode("utf-8")
        body = s[crlfcrlfIndex + len(crlfcrlf):]
    except:
        headers = s
        body = ''
    first_line, headers = headers.split("\r\n", 1)
    return first_line.strip(), _parse_headers(headers), body

def _dissect_headers(obj, s):
    ''' Takes a HTTP packet as the string s, and populates the scapy layer obj
        (either HTTPResponse or HTTPRequest). Returns the first line of the
        HTTP packet, and the body
    '''
    headers, payload = _parse_headers_and_payload(s)
    obj.setfieldval('Headers', '\r\n'.join(list(headers.values())))
    for f in obj.fields_desc:
        canonical_name = _canonicalize_header(f.name)
        try:
            header_line = headers[canonical_name]
        except:
            continue
        key, value = header_line.split(':', 1)
        obj.setfieldval(f.name,  value.strip())
        del headers[canonical_name]
    if headers:
        # Kept for compatibility
        obj.setfieldval(
            'Additional-Headers', '\r\n'.join(list(headers.values())) + '\r\n')
    return first_line, body

class TelemetryReport(Packet):

    name = "INT telemetry report"

    # default value a for telemetry report with INT
    fields_desc = [
        BitField("ver" , 1 , 4),
        BitField("len" , 5 , 4),
        BitField("nProto", 0, 4),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 1, 1),
        BitField("reserved", None, 15),
        BitField("hw_id", None, 6),
        IntField("sw_id", None),
        IntField("seqNumber", None),
        IntField("ingressTimestamp", None)
    ]


    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()

        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f] = fval
        return s


class InBandTelemetry(Packet):
    name = "In band Telemetry"

    def guess_payload_class(self, payload):
        return TelemetryReport


bind_layers(UDP, InBandTelemetry, dport=12345)
bind_layers(TelemetryReport, Ether, nProto = 0)
bind_layers(TelemetryReport, IP, nProto = 1)
#IPv6

#bind_layers(INT_shim, INT_meta)
#bind_layers(INT_meta, INT_metata_stack)
