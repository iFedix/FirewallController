#!/bin/bash
if test `whoami` != root; then 
	echo Permesso negato. Avviare lo script come root!
	exit 1
fi

if test "$1" == 'c'; then
	echo "Pulizia iniziata: "
	mn -c
	echo -n "Eliminazione namespace: "
	ip netns del h1
	exit 2
fi

ip netns add h1
echo -n "Host disponibili: " 
ip netns list
echo "Creazione switch s2.." 
ovs-vsctl add-br s1 
echo "Creazione collegamento tra switch e host.." 
ip link add h1-eth0 type veth peer name s1-eth1
ip link set h1-eth0 netns h1
ovs-vsctl add-port s1 s1-eth1
echo "Aggiunta indirizzo a h1.." 
ip netns exec h1 ifconfig h1-eth0 10.0.0.1
echo "Creazione link tra switch s1 e interfaccia eth0.." 
ifconfig eth0 0.0.0.0
ovs-vsctl add-port s1 eth0
echo "Aggiunta controller remoto.." 
ovs-vsctl set-controller s1 tcp:10.5.5.55:6633
echo "Situazione openvswith:" 
ovs-vsctl show
echo "Configurazione interfacce.."
ifconfig s1-eth1 up
ifconfig s1-eth1 0
ifconfig s1 up
ip addr add 10.1.1.1/24 dev s1
echo "Impostazione route verso il controller.."
ip route add 10.5.5.0/24 dev s1
echo "TUTTO FATTO!"



