#!/usr/bin/env python
import sys
import struct
import binascii
import MySQLdb
import socket
import uuid
import json
from datetime import datetime
import calendar

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.layers.inet import IP, ICMP, UDP, TCP, Raw
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
#from int_lib.telemetryreport import TelemetryReport

class INT_switch_id(Packet):
    name = "Switch ID"

    fields_desc = [
        IntField('switch_id', 0),
    ]

class INT_level1_port_ids(Packet):
    name = "Level 1 port IDs"

    fields_desc = [
        ShortField('l1_ingress_port_id', 0),
        ShortField('l1_egress_port_id', 0)
    ]

class INT_hop_latency(Packet):
    name = "Hop Latency"

    fields_desc = [
        IntField('hop_latency', 0),
    ]

class INT_q_occupancy(Packet):
    name = "Queue Occupancy"

    fields_desc = [
        ByteField('q_id', 0),
        BitField('q_occupancy', 0, 24),
    ]

class INT_ingress_tstamp(Packet):
    name = "Ingress Timestamp"

    fields_desc = [
        IntField('ingress_global_timestamp', 0),
    ]

class INT_egress_tstamp(Packet):
    name = "Egress Timestamp"

    fields_desc = [
        IntField('egress_global_timestamp', 0),
    ]

class INT_level2_port_ids(Packet):
    name = "Level 2 Port Ids"

    fields_desc = [
        ShortField('l2_ingress_port_id', 0),
        ShortField('l2_egress_port_id', 0)
    ]

class INT_egress_port_tx_util(Packet):
    name = "Egress Port TX util"

    fields_desc = [
        IntField('egress_port_tx_util', 0),
    ]

class INT_shim(Packet):
    oName = "Telemetry Report Header"

    fields_desc = [
        ByteField('int_type', 0),
        ByteField('rsvd1', 0),
        ByteField('len', 0),
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

class TelemetryReport(Packet):
    name = "INT telemetry report"

    fields_desc = [
        BitField("ver" , 1 , 4),
        BitField("len" , 4 , 4),
        BitField("nProto", 0, 3),
        BitField("repMdBits", 0, 6),
        BitField("rsvd", 0, 6),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 0, 1),
        BitField("hw_id", 0, 6),
        IntField("switch_id", None),
        IntField("seq_no", None),
        IntField("ingress_tstamp", None)
    ]

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def extract_0003_i0():
    return
def extract_0003_i1(b):
    return
def extract_0003_i2(b):
    return
def extract_0003_i3(b):
    return
def extract_0003_i4(b):
    return
def extract_0003_i5(b):
    retur
def extract_0003_i6(b):
    return
def extract_0003_i7(b):
    return
def extract_0003_i8(b):
    return
def extract_0003_i9(b):
    return
def extract_0003_i10(b):
    data = {}
    s_id = INT_switch_id(b[0:4])
    s_id.show()
    hop_l = INT_hop_latency(b[4:8])
    hop_l.show()
    data["switch_id"] = s_id.switch_id
    data["hop_latency"] = hop_l.hop_latency
    return data

def extract_0003_i11(b):
    return
def extract_0003_i12(b):
    return
def extract_0003_i13(b):
    return
def extract_0003_i14(b):
    return
def extract_0003_i15(b):
    return

def extract_ins_00_03(instruction, b):

    if(instruction == 0):
        return extract_0003_i0(b)
    elif(instruction == 1):
        return extract_0003_i1(b)
    elif(instruction == 2):
        return extract_0003_i2(b)
    elif(instruction == 3):
        return extract_0003_i3(b)
    elif(instruction == 4):
        return extract_0003_i4(b)
    elif(instruction == 5):
        return extract_0003_i5(b)
    elif(instruction == 6):
        return extract_0003_i6(b)
    elif(instruction == 7):
        return extract_0003_i7(b)
    elif(instruction == 8):
        return extract_0003_i8(b)
    elif(instruction == 9):
        return extract_0003_i9(b)
    elif(instruction == 10):
        return extract_0003_i10(b)
    elif(instruction == 11):
        return extract_0003_i11(b)
    elif(instruction == 12):
        return extract_0003_i12(b)
    elif(instruction == 13):
        return extract_0003_i13(b)
    elif(instruction == 14):
        return extract_0003_i14(b)
    elif(instruction == 15):
        return extract_0003_i15(b)

def extract_ins_04_07(instruction, b):
    return

def extract_metadata_stack(b, total_data_len, hop_m_len, instruction_mask_0003, instruction_mask_0407, info):

    numHops = total_data_len / hop_m_len

    info["instruction_mask_0003"] = instruction_mask_0003
    info["instruction_mask_0407"] = instruction_mask_0407
    info["data"] = {}

    #print("##[ INT Metadata Stack ]##")

    i=0
    for hop in range(numHops,0,-1):
        offset = i*hop_m_len
        #print("##[ Data from hop "+str(hop)+" ]##")
        info["data"]["hop_"+str(hop)] = {}
        if(instruction_mask_0003 != 0):
            data_0003 = extract_ins_00_03(instruction_mask_0003, b[offset:offset+hop_m_len])
            info["data"]["hop_"+str(hop)] = data_0003

        if(instruction_mask_0407 != 0):
            data_0407 = extract_ins_04_07(instruction_mask_0407, b[offset:offset+hop_m_len])
            info["data"]["hop_"+str(hop)].update(data_0407)

        i+=1

    return info

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "h4-eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find h4-eth0 interface"
        exit(1)
    return iface

def get_flow_uuid(conn, info):

    mon_id = ""

    cursor = conn.cursor()

    get_uuid = ("SELECT mon_id "
                "FROM flows "
                "WHERE ip_src=%s AND ip_dst=%s AND ip_proto=%s AND port_src=%s AND port_dst=%s")

    check_values = (info["ip_src"], info["ip_dst"], info["ip_proto"], int(info["port_src"]), int(info["port_dst"]))

    cursor.execute(get_uuid, check_values)

    row = cursor.fetchone()
    if row is not None:
        mon_id = row[0]
        #print("ID was recognised: "+mon_id)
    else:
        mon_id = str(uuid.uuid4())
        #print("Using a new ID: "+mon_id)
        #print("For these values: %s", check_values)
        insert_new_flow_mon(conn, info, mon_id)

    cursor.close()
    return mon_id

def insert_new_flow_mon(conn, info, mon_id):

    cursor = conn.cursor()

    insert_q = (
          "INSERT INTO flows (mon_id, ip_src, ip_dst, ip_proto, port_src, port_dst, instruction_mask_0003, instruction_mask_0407) "
          "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")

    check_values = (mon_id, info["ip_src"], info["ip_dst"], info["ip_proto"], \
                    info["port_src"], info["port_dst"], info["instruction_mask_0003"], info["instruction_mask_0407"] )

    """print("Inserting new flow info: %s, %s, %s, %s, %s, %s, %s ", \
            (mon_id, info["ip_src"], info["ip_dst"], info["port_src"], \
            info["port_dst"], info["instruction_mask_0003"], info["instruction_mask_0407"]))"""

    cursor.execute(insert_q, check_values)
    conn.commit()

    cursor.close()

def insert_data_to_db(conn, info):

    cursor = conn.cursor()

    for k, v in info["data"].iteritems():
        # Here we iterate over each op and their data
        #k = hop number (switch or node)
        #v = all instructions and their data
        fields = ""
        data = []
        data.extend((info["mon_id"], info["rec_time"]))
        #Here inside each switch we iterate over
        #i = mask data storing
        #j = data itself (swithc_id, latency ...)

        if not fields:
            fields+=", "
        fields+=", ".join([key for key,val in v.items()])
        data.extend([val for key,val in v.items()])

        data_values = tuple(data)

        cols = (", %s"*(len(data)-2))

        insert_q = ("INSERT INTO demo_data (mon_id, inserted_at"+fields+") "
              "VALUES (%s, %s" + cols + ")")

        #print("Query: %s", insert_q)
        #print("Fields to be inserted: %s", fields)
        #print("Data to be inserted: %s", data_values)


        cursor.execute(insert_q, data_values)
        conn.commit()

    cursor.close()

def handle_pkt(packet, conn, flows):

    info = { }
    print("Handling report.")

    info["rec_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    pkt = bytes(packet)
    #print "## PACKET RECEIVED ##"

    ICMP_PROTO = 1
    TCP_PROTO = 6
    UDP_PROTO = 17

    ETHERNET_HEADER_LENGTH = 14
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20

    INT_REPORT_HEADER_LENGTH = 16
    INT_SHIM_LENGTH = 4
    INT_SHIM_WORD_LENGTH = 1
    INT_META_LENGTH = 8
    INT_META_WORD_LENGTH = 2

    OUTER_ETHERNET_OFFSET = 0
    OUTER_IP_HEADER = OUTER_ETHERNET_OFFSET + ETHERNET_HEADER_LENGTH
    OUTER_L4_HEADER_OFFSET = OUTER_IP_HEADER + IP_HEADER_LENGTH


    INNER_ETHERNET_OFFSET = INT_REPORT_HEADER_LENGTH
    INNER_IP_HEADER_OFFSET = INNER_ETHERNET_OFFSET + ETHERNET_HEADER_LENGTH
    INNER_L4_HEADER_OFFSET = INNER_IP_HEADER_OFFSET + IP_HEADER_LENGTH

    INT_SHIM_OFFSET = INT_REPORT_HEADER_LENGTH+\
                      ETHERNET_HEADER_LENGTH+\
                      IP_HEADER_LENGTH


    eth_report = Ether(pkt[0:ETHERNET_HEADER_LENGTH])
    #eth_report.show()

    ip_report = IP(pkt[OUTER_IP_HEADER:OUTER_IP_HEADER+IP_HEADER_LENGTH])
    #ip_report.show()

    udp_report = UDP(pkt[OUTER_L4_HEADER_OFFSET:OUTER_L4_HEADER_OFFSET+UDP_HEADER_LENGTH])
    #udp_report.show()

    raw_payload = bytes(packet[Raw]) # to get payload

    telemetry_report = TelemetryReport(raw_payload[0:INT_REPORT_HEADER_LENGTH])
    #telemetry_report.show()

    inner_eth = Ether(raw_payload[INNER_ETHERNET_OFFSET:INNER_ETHERNET_OFFSET+ETHERNET_HEADER_LENGTH])
    #inner_eth.show()

    inner_ip = IP(raw_payload[INNER_IP_HEADER_OFFSET : INNER_IP_HEADER_OFFSET+IP_HEADER_LENGTH])
    #inner_ip.show()

    info["ip_src"] = (inner_ip.src).strip("'")
    info["ip_dst"] = (inner_ip.dst).strip("'")
    info["ip_proto"] = inner_ip.proto

    info["port_dst"] = 0
    info["port_src"] = 0

    inner_tcp = None
    inner_udp = None

    if inner_ip.proto == ICMP_PROTO:
        INT_SHIM_OFFSET+=ICMP_HEADER_LENGTH
        inner_icmp = ICMP(raw_payload[INNER_L4_HEADER_OFFSET : INNER_L4_HEADER_OFFSET+ICMP_HEADER_LENGTH])
        #inner_icmp.show()
    elif inner_ip.proto == TCP_PROTO:
        INT_SHIM_OFFSET+=TCP_HEADER_LENGTH
        inner_tcp = TCP(raw_payload[INNER_L4_HEADER_OFFSET : INNER_L4_HEADER_OFFSET+TCP_HEADER_LENGTH])
        #inner_tcp.show()
        info["port_src"] = inner_tcp.sport
        info["port_dst"] = inner_tcp.dport
    elif inner_ip.proto == UDP_PROTO:
        INT_SHIM_OFFSET+=UDP_HEADER_LENGTH
        inner_udp = UDP(raw_payload[INNER_L4_HEADER_OFFSET : INNER_L4_HEADER_OFFSET+UDP_HEADER_LENGTH])
        #inner_udp.show()
        info["port_src"] = inner_udp.sport
        info["port_dst"] = inner_udp.dport
    else:
        return

    INT_META_OFFSET = INT_SHIM_OFFSET + INT_SHIM_LENGTH

    #print("SHIM OFFSET: "+str(INT_SHIM_OFFSET))

    int_shim = INT_shim(raw_payload[INT_SHIM_OFFSET : INT_SHIM_OFFSET+INT_SHIM_LENGTH])
    #int_shim.show()
    int_meta = INT_meta(raw_payload[INT_META_OFFSET : INT_META_OFFSET+INT_META_LENGTH])
    int_meta.show()

    INT_METADATA_STACK_OFFSET = INT_META_OFFSET + INT_META_LENGTH
    INT_METADATA_STACK_LENGTH = (int_shim.len - INT_SHIM_WORD_LENGTH - INT_META_WORD_LENGTH) * 4

    stack_payload = raw_payload[INT_METADATA_STACK_OFFSET:INT_METADATA_STACK_OFFSET+INT_METADATA_STACK_LENGTH]

    info = extract_metadata_stack(stack_payload,\
                           INT_METADATA_STACK_LENGTH,
                           int_meta.hop_metadata_len * 4,\
                           int_meta.instruction_mask_0003,\
                           int_meta.instruction_mask_0407,\
                           info)
    #print(info)
    info["mon_id"] = get_flow_uuid(conn, info)

    insert_data_to_db(conn, info)

    sys.stdout.flush()


def main():
    flows = {}
    conn = None
    try:
        pass
        conn = MySQLdb.connect('localhost', 'root', 'root', 'intdata')
    except MySQLdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])

    iface = 'root-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(
        filter="udp and port 12345",
        iface = iface,
        prn = lambda x: handle_pkt(x, conn, flows))

if __name__ == '__main__':
    main()
