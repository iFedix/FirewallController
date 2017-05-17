# Copyright (C) 2014 SDN Hub
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import random
import ryu.utils

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3

LOG = logging.getLogger('ryu.app.sdnhub_apps.tap')


class StarterTap(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StarterTap, self).__init__(*args, **kwargs)

        # Il parametro broadened_field e' una matrice: associa ad ogni tipo di host i due parametri corrispondenti
        # Ad un host ethernet associa l'indirizzo sorgente e destinazione ethernet
        # Ad un host ip associa l'indirizzo sorgente e destinazione ip
        # Ad un host tcp associa l'indirizzo sorgente e destinazione tcp
        self.broadened_field = {'dl_host': ['dl_src', 'dl_dst'],
                                'nw_host': ['nw_src', 'nw_dst'],
                                'tp_port': ['tp_src', 'tp_dst']}

    # funzione di notifica errori
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg

        # logger che notifica il problema
        # da evidenziare 02x che e' una variabile che prende il valore indicato successivamente
        # e lo formatta in modo da usare almeno due cifre e soprattutto usare il formato esadecimale di scrittura
        # visto che la x e' minuscola, significa che scriveremo in minuscolo anche le cifre esadecimale
        LOG.info('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s', msg.type, msg.code, ryu.utils.hex_array(msg.data))

    # Riscrive tutto il dizionario come prima, solo che la chiave originale viene sostituita con una nuova
    def change_field(self, old_attrs, original, new):
        new_attrs = {}
        for key, val in old_attrs.items():
            if (key == original):
                new_attrs[new] = val
            else:
                new_attrs[key] = val
        return new_attrs

    def create_tap(self, filter_data):
        LOG.debug("Creating tap with filter = %s", str(filter_data))

        # If dl_host, nw_host or tp_port are used, the recursively call the individual filters.
        # This causes the match to expand and more rules to be programmed.
        result = True
        filter_data.setdefault('fields', {})
        filter_fields = filter_data['fields']

        for key, val in self.broadened_field.iteritems():
            if key in filter_fields:
                for new_val in val:
                    filter_data['fields'] = self.change_field(filter_fields, key, new_val)
                    result = result and self.create_tap(filter_data)

                return result

        # Fino a qua, le stesse cose di delete_tap, si ha semplicemente in piu' la variabile result

        # If match fields are exact, then proceed programming switches

        # Iterate over all the sources and sinks, and collect the individual
        # hop information. It is possible that a switch is both a source,
        # a sink and an intermediate hop.
        for source in filter_data['sources']:
            for sink in filter_data['sinks']:

                # Handle error case
                if source == sink:
                    continue

                # Nella versione base, il datapath non puo' essere diverso tra arrivo e sorgente (limitazione, forse da risolvere)
                if source['dpid'] != sink['dpid']:
                    LOG.debug("Mismatching source and sink switch")
                    return False

                datapath = self.dpset.get(source['dpid'])

                # If dpid is invalid, return
                if datapath is None:
                    LOG.debug("Unable to get datapath for id = %s", str(source['dpid']))
                    return False

                ofproto = datapath.ofproto
                ofproto_parser = datapath.ofproto_parser

                in_port = source['port_no']
                out_port = sink['port_no']
                filter_fields = filter_data['fields'].copy()

                # Create action list
                actions = [ofproto_parser.OFPActionOutput(out_port)]

                # Create match
                if in_port != 'all':  # If not sniffing on all in_ports
                    filter_fields['in_port'] = in_port
		#print(filter_fields)
                match = ofctl_v1_3.to_match(datapath, filter_fields)
		#print(match)

                # Genero un cookie, ovvero un identificatore per il FlowMod message
                cookie = random.randint(0, 0xffffffffffffffff)


                inst = [ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

                # install the flow in the switch
                # idle_timeout imposta il tempo idle di attesa prima di scartare il messaggio
                # hard_timeout imposta il tempo massimo di attesa prima di scartare il messaggio
                mod = ofproto_parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, instructions=inst, cookie=cookie)

                datapath.send_msg(mod)

                LOG.debug("Flow inserted to switch %x: cookie=%s, out_port=%d, match=%s", datapath.id, str(cookie), out_port, str(filter_fields))

        LOG.info("Created tap with filter = %s", str(filter_data))
        return True

    def delete_tap(self, filter_data):
        LOG.debug("Deleting tap with filter %s", str(filter_data))

        # If dl_host, nw_host or tp_port are used, the recursively call the individual filters.
        # This causes the match to expand and more rules to be programmed.

        # Aggiungiamo a filter_data (che dovrebbe essere una matrice contenente i dati introdotti nel form) la chiave fields (se non e' gia' presente) assegnandogli come valore {}
        filter_data.setdefault('fields', {})
        # Salviamo in filter_fields i valori associati alla variabile fields (se ce ne sono)
        filter_fields = filter_data['fields']

        # iteritems() e' un metodo efficiente di iterare sulle tuple
        for key, val in self.broadened_field.iteritems():
        	# se dl_host o nw_host o tp_port sono stati specificati nel form, si entra in questo if
            if key in filter_fields:

                for new_val in val:
                	# qui, per ogni valore presente in val per la chiave considerata key, si setta filter_data come prima
                	# tranne per la chiave che stiamo considerando, che non viene riregistrata
                	# al suo posto, una nuova tupla con chiave new_val e stesso valore che spettava a key
                    filter_data['fields'] = self.change_field(filter_fields, key, new_val)

                    # si chiama ricorsivamente questa funzione, l'ultima chiamata che ci sara' produrra'
                    # un argomento filter_data completamente privo di chiavi presenti anche in broadened_field
                    # ma che avra' come chiavi i valori di broadened_field
                    # mentre i valori saranno quelli che si avevano prima
                    
                    # Qual e' lo scopo?
                    # Modificare tutte le chiavi generiche presenti in filter_data con le chiavi specifiche presenti nei valori di broadened_fields
                    # Difatti, le chiavi generiche in filter_data e broadened_fields combaciano
                    # Questo succedera' solo quando l'ultimo valore associato all'ultima chiave di broadened_fields sara' definito come chiave a filter_data
                    
                    self.delete_tap(filter_data)

                # Questo return, se ci si pensa, viene preso solo quando filter_data non ha ancora sostituito tutte le sue chiavi
                # Serve appunto, per ogni volta che viene chiamata ricorsivamente la funzione
                # a non far arrivare ogni chiamata fino all'invio del messaggio (non ce n'e' bisogno, si invia direttamente il filter_data finale)
                return

        # Una volta effettuati tutti i cambi, si prosegue
        # Si prendono tutte le sorgenti presenti in filter_data
        for source in filter_data['sources']:

        	# Per ogni sorgente prendo la porta scritta nel form
            in_port = source['port_no']

            # Esegue una shallow copy della lista filter_data['fields']
            filter_fields = filter_data['fields'].copy()

            if in_port != 'all':  # If not sniffing on all in_ports
                filter_fields['in_port'] = in_port

            # Troviamo il datapath utilizzando il modulo dpset, che gestisce appunto gli switch
            # Basta prendere, con il metodo get, l'id del datapath dalla variabile source
            datapath = self.dpset.get(source['dpid'])

            # If dpid is invalid, return
            if datapath is None:
                continue

            # Passi classici
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser

            # Creo il parametro match basato sul datapath trovato e sui filter_fields
            match = ofctl_v1_3.to_match(datapath, filter_fields)

            # Creo il FlowMod da inviare con azione delete e diretto verso qualsiasi gruppo o porta
            mod = ofproto_parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

            datapath.send_msg(mod)
