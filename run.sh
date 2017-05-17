#!/bin/sh

export PYTHONPATH=$PYTHONPATH:.

~/ryu/bin/ryu-manager --observe-links ~/ryu/ryu/app/WebGUI/my_fileserver ~/ryu/ryu/app/WebGUI/tap_rest ~/ryu/ryu/app/WebGUI/live_rest ryu.app.rest_topology ryu.app.ofctl_rest.py

#nota: ryu.app.rest_topology serve per vedere la topologia nella pagina add rules e le ofctl_rest (sono quelle generali) servono per vedere le flow negli switch ed utilizzarle nella pagina flows
