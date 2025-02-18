# p4-project

### Setup P4 in WSL
run "git clone https://github.com/jafingerhut/p4-guide"
run "./p4-guide/bin/install-p4dev-v8.sh |& tee log.txt"
open ".bashrc" located in "home/*user"
append "source p4setup.bash"
run "echo $PATH"
copy all path variables up to the first one including a c: directory ("/home/eigi/p4-guide/bin:/home/eigi/behavioral-model/tools:/usr/local/bin:/home/eigi/p4dev-python-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib")
go to "tutorials/utils"
open "MAKEFILE"
replace all "PATH" with the copied path variables


### Installing eBPF locally
Sourced from [the lab guide](https://medium.com/btech-engineering/lab-p4-int-in-band-network-telemetry-using-onos-and-ebpf-a84f7649255)
part 5 and forward, but changed siginificantly for modern versions.

To install BCC follow the [source installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source).

Download the BPF Collector 
```
cd ~
git clone https://gitlab.com/tunv_ebpf/BPFCollector.git
cd BPFCollector
git checkout -t origin/spec_1.0
```

Activate BPF & Create new virtual interface
This interface will used for parser, if you reboot VM later, you need add this interfaces again
```
sudo sysctl net/core/bpf_jit_enable=1
pip install cython
sudo ip link add veth_1 type veth peer name veth_2 
sudo ip link set dev veth_1 up 
sudo ip link set dev veth_2 up 
```

### currently here
OPTIONAL. Use influxdb to check if BPF works
```
sudo curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
sudo echo "deb https://repos.influxdata.com/ubuntu bionic stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
sudo apt update
sudo apt install influxdb`
```
check if it works
```
sudo systemctl stop influxdb
sudo systemctl start influxdb
sudo systemctl enable --now influxdb
sudo systemctl is-enabled influxdb
sudo systemctl status influxdb
```