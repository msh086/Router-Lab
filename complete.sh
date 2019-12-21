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
# sudo ip netns exec R2 ip addr add 192.168.3.2/24 dev eth1
# sudo ip netns exec R2 ip addr add 192.168.4.1/24 dev eth2
sudo ip netns exec R3 ip addr add 192.168.4.2/24 dev veth3
# allow R1 and R3 to forward ICMP
sudo ip netns exec R1 bash -c 'echo 1 > /proc/sys/net/ipv4/conf/all/forwarding'
sudo ip netns exec R3 bash -c 'echo 1 > /proc/sys/net/ipv4/conf/all/forwarding'

# create two PCs
sudo ip netns add PC1
sudo ip netns add PC2
# create link PC1-R1, PC2-R3
sudo ip link add from-pc1 type veth peer name to-pc1
sudo ip link add from-pc2 type veth peer name to-pc2
sudo ip link set from-pc1 netns PC1
sudo ip link set from-pc2 netns PC2
sudo ip link set to-pc1 netns R1
sudo ip link set to-pc2 netns R3
# turn up port and assign IP address
sudo ip netns exec PC1 ip link set from-pc1 up
sudo ip netns exec PC2 ip link set from-pc2 up
sudo ip netns exec R1 ip link set to-pc1 up
sudo ip netns exec R3 ip link set to-pc2 up
sudo ip netns exec PC1 ip addr add 192.168.1.2/24 dev from-pc1
sudo ip netns exec R1 ip addr add 192.168.1.1/24 dev to-pc1
sudo ip netns exec R3 ip addr add 192.168.5.2/24 dev to-pc2
sudo ip netns exec PC2 ip addr add 192.168.5.1/24 dev from-pc2
# add static routing entries
sudo ip netns exec PC1 ip route add default via 192.168.1.1 dev from-pc1
sudo ip netns exec PC2 ip route add default via 192.168.5.2

# fix TCP checksum
sudo ip netns exec PC1 ethtool -K from-pc1 tx off
sudo ip netns exec R1 ethtool -K to-pc1 tx off
sudo ip netns exec R1 ethtool -K veth1 tx off
sudo ip netns exec R2 ethtool -K eth1 tx off
sudo ip netns exec R2 ethtool -K eth2 tx off
sudo ip netns exec R3 ethtool -K veth3 tx off
sudo ip netns exec R3 ethtool -K to-pc2 tx off
sudo ip netns exec PC2 ethtool -K from-pc2 tx off
