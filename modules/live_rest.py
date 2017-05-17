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

from webob import Response

from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication
import live

live_instance_name = 'live_app'

# REST API
#
# Configure packet in requests
#
# Accept req
# GET /rest/accept
#
# Deny req
# GET /rest/deny
#
# get all live communications
# GET /rest/communications
#

# Check se MAC e' valido


class LiveController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(LiveController, self).__init__(req, link, data, **config)
        self.live_app = data[live_instance_name]

    def accept(self, req, **_kwargs):
        self.live_app.accept()

    def deny(self, req, **_kwargs):
        self.live_app.deny()

    def list_communications(self, req, **_kwargs):
        body = self.live_app.list_communications()
        return Response(content_type='text/html', body=body)


class LiveRestApi(live.Live):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(LiveRestApi, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(LiveController,
                      {live_instance_name: self})
        mapper = wsgi.mapper

        mapper.connect('live', '/rest/accept',
                       controller=LiveController, action='accept',
                       conditions=dict(method=['GET']))

        mapper.connect('live', '/rest/deny',
                       controller=LiveController, action='deny',
                       conditions=dict(method=['GET']))

        mapper.connect('live', '/rest/communications',
                       controller=LiveController, action='list_communications',
                       conditions=dict(method=['GET']))
