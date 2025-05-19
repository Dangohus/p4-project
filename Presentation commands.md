Begin by setting up veth links to connect the collector.
```
sudo ip link add veth_0 type veth peer name veth_1
sudo ip link set dev veth_0 up 
sudo ip link set dev veth_1 up 
```
Open the collector folder in the project folder
```
cd BPFCollector
```
Start the collector program
```
sudo python3 PTClient.py veth_0 
```
In a new terminal window, open the p4 program folder
```
cd P4-demo-INT-IDA/p4-app/
```
Run the p4 app
```
make run
```
Open terminal for host 1 and host 2 in Mininet
```
xterm h1 h2
```
### Test 1
In host 1 terminal ping host 2.
```
ping 10.0.2.2
```
Let it run and check Grafana dashboard.
### Test 2
In the host 2 terminal open an iperf server
```
iperf -s -p 4444 -i 2
```
In the host 1 terminal run iperf client data transfer
```
iperf -u -c 10.0.2.2 -p 4444 -i 1 -b 1M -l 1000
```
Maybe run a few times and check Grafana.