from __future__ import print_function
import threading
from bcc import BPF
from influxdb import InfluxDBClient
from ipaddress import IPv4Address
from libc.stdint cimport uintptr_t


# change array len of sw_ids.. to .. tx_utilizes to match with max_int_hop in the collector
cdef enum: __MAX_INT_HOP = 6
_MAX_INT_HOP = __MAX_INT_HOP
cdef struct Event:
    unsigned int   src_ip
    unsigned int   dst_ip
    unsigned short src_port
    unsigned short dst_port
    unsigned short ip_proto
    unsigned char  num_INT_hop
    unsigned int   sw_ids[__MAX_INT_HOP]
    unsigned short in_port_ids[__MAX_INT_HOP]
    unsigned short e_port_ids[__MAX_INT_HOP]
    unsigned int   hop_latencies[__MAX_INT_HOP]
    unsigned short queue_ids[__MAX_INT_HOP]
    unsigned short queue_occups[__MAX_INT_HOP]
    unsigned int   ingr_times[__MAX_INT_HOP]
    unsigned int   egr_times[__MAX_INT_HOP]
    unsigned int   lv2_in_e_port_ids[__MAX_INT_HOP]
    unsigned int   tx_utilizes[__MAX_INT_HOP]
    unsigned int   flow_latency
    unsigned int   flow_sink_time
    unsigned char  is_n_flow
    unsigned char  is_flow
    unsigned char  is_hop_latency
    unsigned char  is_queue_occup
    # unsigned char  is_queue_congest
    unsigned char  is_tx_utilize


class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self, max_int_hop=6, debug_mode=0, int_dst_port=54321, int_time=False,
                    host="localhost", database="INTdatabase",event_mode="THRESHOLD"):
        super(InDBCollector, self).__init__()

        self.MAX_INT_HOP = _MAX_INT_HOP
        self.SERVER_MODE = "INFLUXDB"
        self.INT_DST_PORT = int_dst_port
        self.EVENT_MODE = event_mode
        self.int_time = int_time

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
            cflags=["-w",
                    "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                    "-D_INT_DST_PORT=%s" % self.INT_DST_PORT,
                    "-D_EVENT_MODE=%s" % self.EVENT_MODE,
                    "-D_SERVER_MODE=%s" % self.SERVER_MODE])
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")

        self.flow_paths = {}

        self.lock = threading.Lock()
        self.event_data = []

        self.client = InfluxDBClient(host=host, database=database)

        self.debug_mode = debug_mode


    def attach_iface(self, iface):
        if iface in self.ifaces:
            print("already attached to ", iface)
            return
        self.bpf_collector.attach_xdp(iface, self.fn_collector, 0)
        self.ifaces.add(iface)

    def detach_iface(self, iface):
        if iface not in self.ifaces:
            print("no program attached to ", iface)
            return
        self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces.remove(iface)

    def detach_all_iface(self):
        for iface in self.ifaces:
            self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces = set()

    def int_2_ip4_str(self, ipint):
        cdef unsigned char i
        return '.'.join([str(ipint >> (i << 3) & 0xFF) for i in [3, 2, 1, 0]])

    def poll_events(self):
        self.bpf_collector.kprobe_poll()

    def open_events(self):
        def _process_event(ctx, data, size):

            cdef uintptr_t _event =  <uintptr_t> data
            cdef Event *event = <Event*> _event

            # push data

            event_data = []

            if event.is_n_flow or event.is_flow:
                path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))

                event_data.append(u"flow_stat\\,%s:%d->%s:%d\\,proto\\=%d flow_latency=%d,path=\"%s\"%s" % (
                                    self.int_2_ip4_str(event.src_ip),
                                    event.src_port,
                                    self.int_2_ip4_str(event.dst_ip),
                                    event.dst_port,
                                    event.ip_proto,
                                    event.flow_latency,
                                    path_str,
                                    ' %d' % event.flow_sink_time if self.int_time else ''))

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_hop_latency >> i) & 0x01):
                        event_data.append(u"flow_hop_latency\\,%s:%d->%s:%d\\,proto\\=%d\\,sw_id\\=%d value=%d%s" % (
                                    self.int_2_ip4_str(event.src_ip),
                                    event.src_port,
                                    self.int_2_ip4_str(event.dst_ip),
                                    event.dst_port,
                                    event.ip_proto,
                                    event.sw_ids[i],
                                    event.hop_latencies[i],
                                    ' %d' % event.egr_times[i] if self.int_time else ''))

            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_tx_utilize >> i) & 0x01):
                        event_data.append("port_tx_utilize\\,sw_id\\=%d\\,port_id\\=%d value=%d%s" % (
                                        event.sw_ids[i], event.e_port_ids[i], event.tx_utilizes[i],
                                        ' %d' % event.egr_times[i] if self.int_time else ''))

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_queue_occup >> i) & 0x01):
                        event_data.append("queue_occupancy\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
                                        event.sw_ids[i], event.queue_ids[i], event.queue_occups[i],
                                        ' %d' % event.egr_times[i] if self.int_time else ''))

            # if event.is_queue_congest:
            #     for i in range(0, event.num_INT_hop):
            #         if ((event.is_queue_congest >> i) & 0x01):
            #             event_data.append("queue_congestion\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
            #                         event.sw_ids[i], event.queue_ids[i], event.queue_congests[i],
            #                         ' %d' % event.egr_times[i] if self.int_time else ''))

            self.lock.acquire()
            self.event_data.extend(event_data)
            self.lock.release()

            # Print event data for debug
            if self.debug_mode==1:
                print("*" * 20)
                print("src_ip", event.src_ip)
                print("dst_ip", event.dst_ip)
                print("src_port", event.src_port)
                print("dst_port", event.dst_port)
                print("ip_proto", event.ip_proto)
                print("num_INT_hop", event.num_INT_hop)
                print("sw_ids", event.sw_ids)
                print("in_port_ids", event.in_port_ids)
                print("e_port_ids", event.e_port_ids)
                print("hop_latencies", event.hop_latencies)
                print("queue_ids", event.queue_ids)
                print("queue_occups", event.queue_occups)
                print("ingr_times", event.ingr_times)
                print("egr_times", event.egr_times)
                print("lv2_in_e_port_ids", event.lv2_in_e_port_ids)
                print("tx_utilizes", event.tx_utilizes)
                print("flow_latency", event.flow_latency)
                print("flow_sink_time", event.flow_sink_time)
                print("is_n_flow", event.is_n_flow)
                print("is_flow", event.is_flow)
                print("is_hop_latency", event.is_hop_latency)
                print("is_queue_occup", event.is_queue_occup)
                # print("is_queue_congest", event.is_queue_congest)
                print("is_tx_utilize", event.is_tx_utilize)

        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=512)


    def collect_data(self):

        data = []

        for (flow_id, flow_info) in self.tb_flow.iteritems():
            path_str = ":".join(str(flow_info.sw_ids[i]) for i in reversed(range(0, flow_info.num_INT_hop)))

            flow_id_str = "%s:%d->%s:%d\\,proto\\=%d" % (self.int_2_ip4_str(flow_id.src_ip), \
                                                    flow_id.src_port, \
                                                    self.int_2_ip4_str(flow_id.dst_ip), \
                                                    flow_id.dst_port, \
                                                    flow_id.ip_proto)

            data.append("flow_stat\\,%s flow_latency=%d,path=\"%s\"%s" % (
                    flow_id_str, flow_info.flow_latency, path_str,
                    ' %d' % flow_info.flow_sink_time if self.int_time else ''))

            if flow_info.is_hop_latency:
                for i in range(0, flow_info.num_INT_hop):
                    data.append("flow_hop_latency\\,%s\\,sw_id\\=%d value=%d%s" % (
                            flow_id_str, flow_info.sw_ids[i], flow_info.hop_latencies[i],
                            ' %d' % flow_info.egr_times[i] if self.int_time else ''))

        for (egr_id, egr_info) in self.tb_egr.items():
            data.append("port_tx_utilize\\,sw_id\\=%d\\,port_id\\=%d value=%d%s" % (
                    egr_id.sw_id, egr_id.p_id, egr_info.tx_utilize,
                    ' %d' % egr_info.egr_time if self.int_time else ''))

        for (queue_id, queue_info) in self.tb_queue.items():
            data.append("queue_occupancy\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
                    queue_id.sw_id, queue_id.q_id, queue_info.occup,
                    ' %d' % queue_info.q_time if self.int_time else ''))

            # data.append("queue_congestion\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
            #         queue_id.sw_id, queue_id.q_id, queue_info.congest,
            #         ' %d' % queue_info.q_time if self.int_time else ''))

        return data
