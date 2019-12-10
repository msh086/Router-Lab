# create three routers
sudo ip netns add R1
sudo ip netns add R2
sudo ip netns add R3
# create links R1-R2 and R2-R3
sudo ip link add veth1 type veth peer name eth1
sudo ip link add veth3 type veth peer name eth2
sudo ip link set veth1 netns R1
sudo ip link set veth3 netns R3
sudo ip link set eth1 netns R2
sudo ip link set eth2 netns R2
# turn up port and assign IP address
sudo ip netns exec R1 ip link set veth1 up
sudo ip netns exec R3 ip link set veth3 up
sudo ip netns exec R2 ip link set eth1 up
sudo ip netns exec R2 ip link set eth2 up
sudo ip netns exec R1 ip addr add 192.168.3.1/24 dev veth1
sudo ip netns exec R2 ip addr add 192.168.3.2/24 dev eth1
sudo ip netns exec R2 ip addr add 192.168.4.1/24 dev eth2
sudo ip netns exec R3 ip addr add 192.168.4.2/24 dev veth3
