# p4-project

## Setup P4 in WSL
run "git clone https://github.com/jafingerhut/p4-guide"
run "./p4-guide/bin/install-p4dev-v8.sh |& tee log.txt"
open ".bashrc" located in "home/*user"
append "source p4setup.bash"
run "echo $PATH"
copy all path variables up to the first one including a c: directory ("/home/eigi/p4-guide/bin:/home/eigi/behavioral-model/tools:/usr/local/bin:/home/eigi/p4dev-python-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib")
go to "tutorials/utils"
open "MAKEFILE"
replace all "PATH" with the copied path variables


## Installing eBPF locally
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
sudo apt install influxdb
```
check if it works
```
sudo systemctl stop influxdb
sudo systemctl start influxdb
sudo systemctl enable --now influxdb
sudo systemctl is-enabled influxdb
sudo systemctl status influxdb
```
Test connection
```
sudo pip install influxdb

cd ~/BPFCollector
sudo pip install pytest
sudo python3 -m pytest 
```


packages to intall:
```
pip3 install bcc
pip3 install numba
pip3 install pytest
pip3 install bcc
pip3 install bcc
pip3 install bcc
pip3 install bcc
```

### Rebuild kernel to allow headers
This is necessary to run bcc

Install cpio and gedit prior to kernel rebuild
`sudo apt install cpio `
`sudo apt install gedit`

Do the following until and includig step 12.
Skip step 13 and test if it works with step 14 in folder p4-project/test xdp
Kernel rebuild guide https://massoudasadiblog.blogspot.com/2024/07/ebpf-on-wsl2-kernel-version-6x-ubuntu.html?m=1

#### Dissable large recieve offload
Step 16 may fail with "operation not supported". Then use the following
`sudo ethtool -K eth0 lro off`
(source) https://github.com/torvalds/linux/commit/f600b690501550b94e83e07295d9c8b9c4c39f4e

## Installing Prometheus
Continuing [the lab guide](https://medium.com/btech-engineering/lab-p4-int-in-band-network-telemetry-using-onos-and-ebpf-a84f7649255) on part two of the monitoring section
```
cd ~
pip install prometheus-client
wget https://s3-eu-west-1.amazonaws.com/deb.robustperception.io/41EFC99D.gpg | sudo apt-key add -
sudo apt update
sudo apt -y install prometheus
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl status prometheus
```
Influx db might trow errors on `sudo apt update` "E: The repository 'https://repos.influxdata.com/ubuntu bionic InRelease' is not signed." Then use 
```
curl -fsSL https://repos.influxdata.com/influxdata-archive_compat.key | \
   gpg --dearmor | \
   sudo tee  /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
```

## Installing Grafana
Continuing [the lab guide](https://medium.com/btech-engineering/lab-p4-int-in-band-network-telemetry-using-onos-and-ebpf-a84f7649255) on part two of the monitoring section 4.
```
nano grafana.sh
sudo apt-get install gnupg2 curl software-properties-common -y
curl https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
sudo apt-get update -y
sudo apt-get install grafana -y
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server
```

Open Grafana on localhost:3000 and login with admin/admin
Go to Connections -> Data sources and add the Prometheus data source.
In Connection/Prometheus server URL write `http://localhost:9090`.
Use "Save and Test" in the bottom to check it works.