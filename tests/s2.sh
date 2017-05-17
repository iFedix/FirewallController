#!/bin/bash
if test `whoami` != root; then 
	echo Permesso negato. Avviare lo script come root!
	exit 1
fi

if test "$1" == 'c'; then
	echo "Pulizia iniziata: "
	mn -c
	exit 2
fi

echo "Creazione switch.." 
ovs-vsctl add-br s2 
echo "Creazione link tra switch e interfaccia eth1" 
ifconfig eth1 0.0.0.0
ovs-vsctl add-port s2 eth1
echo "Creazione link tra switch e interfaccia eth2" 
ifconfig eth2 0.0.0.0
ovs-vsctl add-port s2 eth2
echo "Aggiunta controller remoto.." 
ovs-vsctl set-controller s2 tcp:10.5.5.55:6633
echo "Situazione openvswith:" 
ovs-vsctl show
echo "Configurazione switch.."
ip addr add 10.5.5.55/24 dev s2
echo "Impostazione route verso i due switch.."
sleep 1
ip route add 10.1.1.0/24 dev s2
ip route add 10.9.9.0/24 dev s2
echo "TUTTO FATTO!"



