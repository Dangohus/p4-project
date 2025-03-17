# p4-project

This project has been developed on WSL on Linux 24.04.

## Setup P4 in WSL
Using the P4 installation guide from https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md#quick-instructions-for-successful-install-script-run
```
git clone https://github.com/jafingerhut/p4-guide
./p4-guide/bin/install-p4dev-v8.sh |& tee log.txt
```
- open ".bashrc" located in "home/*user"
- append "source p4setup.bash"

## Installing eBPF locally

### Rebuild kernel to allow headers
To run BCC on WSL it is necesarry to have certain settings enabled, that can only be set when rebuilding the kernel.

Install cpio and gedit prior to kernel rebuild
`sudo apt install cpio `
`sudo apt install gedit`

Using the following guide: https://massoudasadiblog.blogspot.com/2024/07/ebpf-on-wsl2-kernel-version-6x-ubuntu.html
Do steps 0 through 12.

Skip step 13 and test if it works with step 14 in folder `p4-project/test xdp`, then continue the last steps of the guide.

#### Troubleshooting dissable large recieve offload
Step 16 may fail with "operation not supported". Then use the following
`sudo ethtool -K eth0 lro off`.
[Source](https://github.com/torvalds/linux/commit/f600b690501550b94e83e07295d9c8b9c4c39f4e)

### Installing BCC

Sourced from [the lab guide](https://medium.com/btech-engineering/lab-p4-int-in-band-network-telemetry-using-onos-and-ebpf-a84f7649255)
part 5 and forward, but changed siginificantly for modern versions.

To install BCC follow the [source installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source). This takes a while.

### Setting up the BPFCollector
A modified version of the BPFColloctor from https://gitlab.com/tunv_ebpf/BPFCollector/ is already found in this repo.

Activate BPF & Create new virtual interface.
This interface will used for parser, if you reboot VM later, you need add these interfaces again.
```
sudo sysctl net/core/bpf_jit_enable=1
pip install cython
sudo ip link add veth_0 type veth peer name veth_1
sudo ip link set dev veth_0 up 
sudo ip link set dev veth_1 up 
```

### [Optional] Use influxdb to check if BPF works
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
sudo pip install pytest
pip3 install bcc
pip3 install numba
pip3 install pytest

cd /BPFCollector
sudo python3 -m pytest 
```
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
Influx db might throw errors on `sudo apt update` "E: The repository 'https://repos.influxdata.com/ubuntu bionic InRelease' is not signed." Then use 
```
curl -fsSL https://repos.influxdata.com/influxdata-archive_compat.key | \
   gpg --dearmor | \
   sudo tee  /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
```

We want to change the port of Prometheus, since P4 uses 9090 for switches.
```
cd /usr/lib/systemd/system
sudo nano prometheus.service 
```
Change exec start to the following
```
ExecStart=/usr/bin/prometheus  \
  --config.file=/etc/prometheus/prometheus.yml \
  --web.listen-address=0.0.0.0:9089
```
Additionally we want to add a job to the Prometheus config yml file, and update it to listen on it's own, changed, port as well.
```
sudo nano /etc/prometheus/prometheus.yml
```
Append the following job the the file (it is important to use tab and not space)
```
  - job_name: p4switch
    static_configs:
    - targets: ['localhost:8000']
```
And edit the static_configs targets from 9090 to 9089. Save and exit the file.

Then rebuild and check the status
```
sudo systemctl daemon-reload
sudo systemctl restart prometheus
sudo systemctl status prometheus
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
In Connection/Prometheus server URL write `http://localhost:9089`.
Use "Save and Test" in the bottom to check it works.

## General troubleshooting
When installing python packages with pip, we have ran into issues where the packages still is not found unless it is installed with `sudo pip install [pkg]`. This is often no allowed and requires breaking system packages with `sudo pip install [pkg] --break-system-packages`.