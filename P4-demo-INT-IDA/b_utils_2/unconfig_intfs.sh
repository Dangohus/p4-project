#Commands to make h4 to root DB connection work

#Config when mininet is taken down (Host PC):
sudo ip link set root-eth0 nomaster
sudo ip link set tap-root nomaster
sudo ip link set br-root down
sudo ip link set tap-root down
sudo ip link delete tap-root
sudo ip link delete br-root type bridge
