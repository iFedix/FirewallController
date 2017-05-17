# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.

import logging

import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication
import tap
import re
import socket
from ryu.ofproto import inet

LOG = logging.getLogger('ryu.app.sdnhub_apps.tap_rest')

# REST API
#
# Configure tap
#
# get all taps
# GET /tap
#
# create tap filter
# POST /v1.0/tap/create
#
# delete tap filter
# DELETE /v1.0/tap/delete
#

# Check se MAC e' valido


def is_mac_valid(x):
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", x.lower()):
        return True
    else:
        return False

# Check se l'IP e' valido


def is_ip_valid(x):
    y = x.split('/')
    if len(y) > 2:
        return False
    try:
        socket.inet_aton(y[0])
        return True
    except socket.error:
    	return False


class TapController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TapController, self).__init__(req, link, data, **config)
        self.tap = data['tap']
        self.tap.dpset = data['dpset']

    # Serie di controlli su cio' che ci si aspetta dai dati ricevuti
    def is_filter_data_valid(self, filter_data):
        if 'sources' not in filter_data:
            LOG.error('missing sources %s', filter_data)
            return False
        else:
            for source in filter_data['sources']:
                if 'dpid' not in source or 'port_no' not in source:
                    LOG.error('Invalid source description %s', source)
                    return False

        if 'sinks' not in filter_data:
            LOG.error('missing sinks %s', filter_data)
            return False
        else:
            for sink in filter_data['sinks']:
                if 'dpid' not in sink or 'port_no' not in sink:
                    LOG.error('Invalid source description %s', sink)
                    return False

        if 'fields' in filter_data:
            for key, val in filter_data['fields'].items():
                if key == 'dl_src' or key == 'dl_dst' or key == 'dl_host':
                    if not is_mac_valid(val):
                        LOG.error('Invalid MAC address in filter field %s=%s', key, val)
                        return False
                if key == 'nw_src' or key == 'nw_dst' or key == 'nw_host':
                    if 'dl_type' not in filter_data['fields']:
                        LOG.error('Ethertype is not set, but IP fields specified')
                        return False
                    if not is_ip_valid(val):
                        LOG.error('Invalid IP address in filter field %s=%s', key, val)
                        return False
                if key == 'tp_src' or key == 'tp_dst' or key == 'tp_port':
                    nw_proto = filter_data['fields']['nw_proto']
                    if nw_proto != inet.IPPROTO_TCP and nw_proto != inet.IPPROTO_UDP:
                        LOG.error('Non TCP/UDP packet specifies TP fields')
                        return False

        return True

    def create_tap(self, req, **_kwargs):
    	# Come delete_tap
        try:
            filter_data = eval(req.body)
            print filter_data
            if not self.is_filter_data_valid(filter_data):
                return Response(status=400)
        except SyntaxError:
            LOG.error('Invalid syntax %s', req.body)
            return Response(status=400)

        if self.tap.create_tap(filter_data):
        	return Response(status=200, content_type='application/json', body=json.dumps({'status': 'success'}))
        else:
            LOG.error('Create tap failed')
            return Response(status=501)

    def delete_tap(self, req, **_kwargs):
        try:
        	# eval e' una funzione che esegue un programma python il cui codice e' nell'argomento della funzione
            filter_data = eval(req.body)
            if not self.is_filter_data_valid(filter_data):
                return Response(status=400)
        except SyntaxError:
            LOG.error('Invalid syntax %s', req.body)

        # Se va tutto bene, si cancella la FlowMod e si restituisce una pagina di risposta che indica status=200 (successo)
        # ha un contenuto di tipo json
        # che sarebbe la stringa della funzione dump
        # serializzata attraverso la stessa funzione
        self.tap.delete_tap(filter_data)
        return Response(status=200, content_type='application/json', body=json.dumps({'status': 'success'}))


class TapRestApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
        'tap': tap.StarterTap
    }

    def __init__(self, *args, **kwargs):
        super(TapRestApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        tap = kwargs['tap']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        self.data['tap'] = tap

        wsgi.registory['TapController'] = self.data
        mapper = wsgi.mapper

        mapper.connect('tap', '/v1.0/tap/create',
                       controller=TapController, action='create_tap',
                       conditions=dict(method=['POST']))

        mapper.connect('tap', '/v1.0/tap/delete',
                       controller=TapController, action='delete_tap',
                       conditions=dict(method=['POST']))
