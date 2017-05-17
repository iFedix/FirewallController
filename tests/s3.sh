#!/bin/bash
if test `whoami` != root; then 
	echo Permesso negato. Avviare lo script come root!
	exit 1
fi

if test "$1" == 'c'; then
	echo "Pulizia iniziata: "
	mn -c
	echo -n "Eliminazione namespace: "
	ip netns del h2	
	exit 2
fi

ip netns add h2
echo -n "Host disponibili: " 
ip netns list
echo "Creazione switch s3.." 
ovs-vsctl add-br s3 
echo "Creazione collegamento tra switch e host.." 
ip link add h2-eth0 type veth peer name s3-eth2
ip link set h2-eth0 netns h2
ovs-vsctl add-port s3 s3-eth2 
echo "Aggiunta indirizzo a h1.." 
ip netns exec h2 ifconfig h2-eth0 10.0.0.2
echo "Creazione link tra switch s3 e interfaccia eth0.." 
ifconfig eth0 0.0.0.0
ovs-vsctl add-port s3 eth0
echo "Aggiunta controller remoto.." 
ovs-vsctl set-controller s3 tcp:10.5.5.55:6633
echo "Situazione openvswith:" 
ovs-vsctl show
echo "Configurazione interfacce.."
ifconfig s3-eth2 up
ifconfig s3-eth2 0
ifconfig s3 up
ip addr add 10.9.9.1/24 dev s3
echo "Impostazione route verso il controller.."
ip route add 10.5.5.0/24 dev s3
echo "TUTTO FATTO!"



