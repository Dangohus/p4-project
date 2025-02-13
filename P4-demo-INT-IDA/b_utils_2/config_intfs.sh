#Commands to make h4 to root DB connection work

#Config in root namespace (Host PC):
sudo ip tuntap add tap-root mode tap
sudo ip link set tap-root up
sudo ip link add br-root type bridge
sudo ip link set root-eth0 master br-root
sudo ip link set tap-root master br-root
sudo ip link set br-root address 00:00:00:00:22:22
sudo ip addr add 10.0.223.225/24 dev br-root
sudo ip link set br-root up

#Config when mininet is taken down (Host PC):
#sudo ip link set root-eth0 nomaster
#sudo ip link set tap-root nomaster
#sudo ip link set br-root down
#sudo ip link set tap-root down
#sudo ip link delete br-root type bridge
