# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

# INIZIO CLASSE
class Live(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Live, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	#creo la mac address table (vedere sotto per dettagli). Si tratta di un dizionario che poi diventera' un dizionario di dizionari!
	#Cioe' per esempio la mac table finale sara': mac_to_port = {1: {"00:00:00:02": 2, "00:00:00:01": 1}, 2: {"00:00:00:02": 1, "00:00:00:01":2}}
	
	self.messages = []
	self.communications = "" #sono tutte le cominicazioni registrate dal controller
	self.currentroutes = [] #Lista GLOBALE (non viene mai eliminata) di informazioni sui collegamenti tra host che bisogna fare: 
		   #es [00:00:00:00:00:01 00:00:00:00:00:02 ICMP, 00:00:00:00:00:05 00:00:00:00:00:07 HTTP]
		   #NB: non vengono inserite in questa lista le coppie duali (es 00:00:00:00:00:02 00:00:00:00:00:01 ICMP), perche' la comunicazione deve essere biunivoca
		   #vedere check per questo comportamento
	self.story = [] #Lista di informazioni sui collegamenti tra host che bisogna fare 
			#es [00:00:00:00:00:01 00:00:00:00:00:02 ICMP, 00:00:00:00:00:05 00:00:00:00:00:07 HTTP]
	
	#Differenza tra current routes e story: story e' una lista che serve a tener traccia dei collegamenti che bisogna fare. Una volta che un packet in nuovo entra, viene 		aggiunto a story una nuova entry che sara' poi eliminata quando il pacchetto viene accettato o rifiutato. Current routes e' una lista simile ma che non cancella i 		valori e ha un singolo valore per i pacchetti speculari (cioe' se entra 00:00:00:00:00:02 00:00:00:00:00:01 ICMP e poi 00:00:00:00:00:01 00:00:00:00:00:02 ICMP verra' 		aggiunta solo una entry). Serve a tener traccia delle comunicazioni gia' accettate. Infatti se il primo pacchetto e' stato accettato, currentroutes fa in modo che i 		percorsi intermedi verso il destinatario vengano automaticamente accettati (senza autorizzazione dell'utente). Funziona a mo di intent tramite una tabella globale.
	
	
    # ---------------------METODI UTILI-----------------------------
    def getProtocol(self, pkt):
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
	tp = pkt.get_protocol(tcp.tcp)
	port = 0
	if tp:
		port = tp.dst_port
	ud = pkt.get_protocol(udp.udp)
	if ud:
		port = ud.dst_port
	#print "PORTA: %s" % port
	if pkt_ipv4:
		protocol = pkt_ipv4.proto
		if protocol==1:
			return "ICMP"
		if protocol==6:
			if port==80:
				return "HTTP"
			if port==443:
				return "HTTPS"
			return "TCP"
		if protocol==17:
			if port==53:
				return "DNS"
			if port==67:
				return "DHCP"
			return "UDP"
	return "Unknown. If you confirm, you will add a general traffic rule (= every type of traffic) between src and dst"
    
    def getMatch(self, pkt, parser, in_port, dst):
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
	tp = pkt.get_protocol(tcp.tcp)
	port = 0
	if tp:
		port = tp.dst_port
	ud = pkt.get_protocol(udp.udp)
	if ud:
		port = ud.dst_port
	#print "PORTA: %s" % port
	if pkt_ipv4:
		protocol = pkt_ipv4.proto
		if protocol==1:
			return parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=1)
		if protocol==6:
			if port==80:
				return parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=6, tcp_dst=80)
			if port==443:
				return parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=6, tcp_dst=443)
			return parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=6)
		if protocol==17:
			if port==53:
				parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=17, udp_dst=53)
			if port==67:
				parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=17, udp_dst=67)
			return parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=17)
	return parser.OFPMatch(in_port=in_port, eth_dst=dst)

    #metodo per filtrare mac address in ingresso (=passano dal controller senza conferma dell'utente)
    def filtered_ip(self, dst, eth):
	#escludo i seguenti mac address dal filtraggio (passano normalmente):
	#richieste ARP, Link Layer Discovery Protocol, Multicast (ipv6 e ipv), broadcast address
	return eth.ethertype != 0x0806 and self.lldp_filter(dst) and self.ipv4_multicast_filter(dst) and self.ipv6_multicast_filter(dst) and dst != "ff:ff:ff:ff:ff:ff"

    def lldp_filter(self, addr):
	return addr != "01:80:c2:00:00:0e" and addr != "01:80:c2:00:00:03" and addr != "01:80:c2:00:00:00"

    def ipv6_multicast_filter(self, addr):
	#escludo mac da 33-33-00-00-00-00 a 33-33-FF-FF-FF-FF (vedere http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml)
	return addr[:5]!="33:33"
    
    def ipv4_multicast_filter(self, addr):
	#escludo mac da 01-00-5E-00-00-00 a 01-00-5E-7F-FF-FF (vedere https://technet.microsoft.com/en-us/library/cc957928.aspx)
        #print "valuto %s" % addr
	if addr[:8]!="01:00:5e":
            #print "TRUE"
            return True
        else:
            val = addr[9]=='8' or addr[9]=='9' or addr[9]=='a' or addr[9]=='b' or addr[9]=='c' or addr[9]=='d' or addr[9]=='e' or addr[9]=='f'
            #print "Sono nel secondo ramo: %s" % val
            return val
    
    #metodo che serve semplicemente per dire che 00:00:00:00:00:02 00:00:00:00:00:01 ICMP e' uguale a 00:00:00:00:00:01 00:00:00:00:00:02 ICMP 
    #perche' semplicemente e' il ritorno
    def check(self, to_find): #es: to_find: 00:00:00:00:00:02 00:00:00:00:00:01 ICMP
	add = to_find.split( ) #add e' una lista contenente due elementi (i due mac addr)
	case1 = "%s %s %s" % (add[0], add[1], add[2]) 
	#con queste operazioni costruisco due stringhe: 00:00:00:00:00:02 00:00:00:00:00:01 ICMP e 00:00:00:00:00:01 00:00:00:00:00:02 ICMP
	case2 = "%s %s %s" % (add[1], add[0], add[2])
	return (case1 in self.currentroutes or case2 in self.currentroutes) #esiste gia' una occorrenza ritorno true (sarebbe una route gia' autorizzata!)

	#--------------------------------FUNZIONI PRINCIPALI--------------------------------------
    def list_communications(self):
	#prima rest api eseguita: notifica all'utente di una connessione nuova (nuovo packet in da un certo host ad un altro host)

        actual = self.communications
        self.communications = self.communications[self.communications.find('\n') + 1:] #elimino da communications il valore actual e lo faccio prendendo tutto cio' che c'e' dopo il primo \n 			(= svuoto communications)
	
	#print "in coda: %s" % actual

	# L'algoritmo seguente verifica che la generica coppia src e dst sia comparsa per la prima volta. 
	# ES: se h1 pinga h2 per la prima volta all'utente verra' notificato che e' in atto una conessione da per esempio h1 a h2. 
	# In una topologia con due switch e due host pero' (ma comunque vale anche per topologie piu' generiche) dovranno essere aggiunte 4 regole (4 pezzi di percorso): 
	# farsi disegnino della topologia per maggiore chiarezza!
	# 1) da eth1 di s2 provenienti da h2 e diretti a h1 (tramite eth2)
	# 2) da eth2 di s1 provenienti da h2 e diretti a h1 (tramite eth1)
	# 3) da eth1 di s1 provenienti da h1 e diretti a h2 (tramite eth2)
	# 4) da eth2 di s2 provenienti da h1 e diretti a h2 (tramite eth1)
	# Con questo algoritmo alla prima richiesta (es: h1 ping h2) mi memorizzo la coppia h1-h2 (+relativo type)
	# Gli altri pezzi di route (cioe' le altre regole) vengono percio' automaticamente inserite visto che sono che tutte riguardano la coppia h1-h2(+type)

	if(actual!=''):
	    if self.check(actual[:actual.find('\n')]) == True: #serve per tagliare il \n finale: cioe' prende la sottostringa da 0 alla posizione dello \n esclusa
		#print "ENTRY GIA' VISTA %s" % actual[:actual.find('\n')]
		self.accept() #accetto gia'! e' riferita ad una coppia gia accettata dall'utente!
		return "done"; #notifico lo script di js che non deve chiedere niente altro all'utente perche' essendo questo un packet intermedio 
			       #per una connessione tra src e dst gia' autorizzata in precedenza, automaticamente aggiungo la flow nello switch
	    else:
		#print "ENTRY MAI VISTA %s" % actual[:actual.find('\n')]
		self.currentroutes.append(actual[:actual.find('\n')]) #se e' una coppia nuova chiedo all'utente che vuole fare, se accetta al prossimo passo le 
						   #altre regole intermedie vengono aggiunte automaticamente	
        return actual

    def accept(self):
        datapath = self.messages[0].datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = self.messages[0].match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(self.messages[0].data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst

	protocol = self.getProtocol(pkt)
        key = "%s %s %s" % (src, dst, protocol)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
	
	#a seconda del pacchetto in ingresso e del suo tipo di traffico (ICMP, DNS.. ecc) installo una flow appropriata
	match = self.getMatch(pkt, parser, in_port, dst);
	#print(match)

        actions = [parser.OFPActionOutput(out_port)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
    	#Se esiste un buffer_id (cioe' se i dati del pacchetto vengono memorizzati nello switch) allora occorre dare il riferimento al buffer (buffer_id)
	#altrimenti non serve
	#mod dice di inserire una openflow mod che utilizzi le istruzioni descritte sopra (applicare immediatamente il comportamente), 
	#le azioni (mandare sulla porta di uscita) e il match (installazione della regola appropriata a seconda del tipo di traffico)
        if self.messages[0].buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=self.messages[0].buffer_id,
                                priority=1, match=match,
                                instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
	
        if key in self.story:
            self.story.remove(key)
	#print "%s eliminata (sono in accept)!" % key
        self.messages.pop(0) #rimuove dalla lista l'elemento 0

    def deny(self):
        datapath = self.messages[0].datapath
        parser = datapath.ofproto_parser
        in_port = self.messages[0].match['in_port']
        pkt = packet.Packet(self.messages[0].data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst
	
	protocol = self.getProtocol(pkt)
        key = "%s %s %s" % (src, dst, protocol)

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

	#Se esiste un buffer_id (cioe' se i dati del pacchetto vengono memorizzati nello switch) allora occorre dare il riferimento al buffer (buffer_id)
	#altrimenti non serve
	#mod dice di inserire una openflow mod che droppi il pacchetto: infatti se negli argomenti non si specifica il campo instructions=inst (come nella accept),
	#questo metodo crea una openflow mod che droppa le regole che fanno match (cioe' che entrano da una certa porta e destinate ad un certo mac address). 
	#Le successive richieste identiche verranno bloccate da questa regola qua inserita! L'unico modo per togliere la regola 
	#e' farlo manualmente sovrascrivendola attraverso l'inserimento manuale con il modulo tap.py
       
        if self.messages[0].buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=self.messages[0].buffer_id,
                                priority=1, match=match)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match)

        datapath.send_msg(mod)
        if key in self.story:
            self.story.remove(key)
	#print "%s eliminata (sono in deny)!" % key
        self.messages.pop(0)

    #----------------------------GESTIONE DEGLI SWITCH-------------------------------------------
    #a seguire un decoratore che mi dice come gestire la fase openflow della richesta delle funzioni dello switch.
    #Specificamente, dopo aver ricevuto la reply dallo switch, viene aggiunto una table-miss flow, cioe' il comportamento
    #di default per i pacchetti che arrivano allo switch e non hanno una flow (non sanno dove essere rediretti dallo switch).
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Delete all existing rules on the switch
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

	#di default i pacchetti vengono mandati al controller con un OFPCML_NO_BUFFER. 
	#Il metodo OFPActionOutput serve ad indicare di mandare fuori il pacchetto con le regole OFPP_CONTROLLER (verso il controller) 
	#e OFPCML_NO_BUFFER (che si traduce nell'inviare tutto il pacchetto senza bufferizzare nulla)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	
	#OFPIT_APPLY_ACTIONS si traduce in applicare immediatamente le azioni in actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
	#con priorita' 0, fanno match tutti i pacchetti! Tutto e' inviato al controller
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	# con questo metodo raccolgo i packet in in ingresso! poi l'utente li accettera' o meno! Li metto in messages
       
	# If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
	# sintassi di msg:
	#OFPPacketIn(buffer_id=256,cookie=0,data='\x01\x80\xc2\x00\x00\x0e\x8e\xf5\xa4\xcd\xa4j\x88\xcc\x02\x16\x07
	#dpid:0000000000000001\x04\x05\x02\x00\x00\x00\x02\x06\x02\x00x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
	#match=OFPMatch(oxm_fields={'in_port': 2}),reason=0,table_id=0,total_len=60))
        in_port = msg.match['in_port'] #su quale porta dello switch?
        datapath = msg.datapath 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id #quale switch? torna l'id (es: 1, 2 ecc)
        pkt = packet.Packet(msg.data)	
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	
        src = eth.src #indirizzo eth src (=mac address)
        dst = eth.dst #indirizzo eth dst (=mac address)

        # Sotto aggiungiamo le informazioni sullo switch dpid
        # Ad ogni indirizzo MAC associa la porta dello switch
	#se il dpid dello switch non esiste nella mac address table, lo aggiungo con ovviamente la lista di mac e porte settata a {} (vuota).
	#Se lo switch c'era gia', il metodo non fa nulla!
        self.mac_to_port.setdefault(dpid, {})

	# learn a mac address to avoid FLOOD next time.
	#in poche parole associo l'indirizzo mac source con la porta in ingresso. 
	#Cioe' associo il dispositivo fisico (mac address) in ingresso con la porta dello switch su cui ascolta!
	#E' come se registrassi chi ha fatto la richiesta! Cioe' associo il mac address alla porta su cui ascolta questo dispositivo!
	#Percio' per esempio un pacchetto di ritorno non dovra' fare flood perche' ora si sa a quale porta e' associato il dispositivo (mac addresss) a cui devo inviare!
	#La tabella sara' fatta come segue (come dicevamo sopra):
	#mac_to_port = {1: {"00:00:00:02": 2, "00:00:00:01": 1}, 2: {"00:00:00:02": 1, "00:00:00:01":2}}

        self.mac_to_port[dpid][src] = in_port

	#ora devo trovare il mac address di destinazione nella tabella dei mac address: 
	#Se associato allo switch dpid esiste un campo destinazione, estraggo la porta out a partire dall'indirizzo mac dst
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
	#altrimenti per forza la porta di uscita sara' un flood: pacchetto inviato a tutte le porte di uscita. 
	#In tal modo spero di raggiungere il mac address della destinazione
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

	#RITROVAMENTO PROTOCOLLO
	protocol = self.getProtocol(pkt)
	#print "protocol: %s" % protocol
	#print "STORIA: %s" % story
	
	#print "DEBUG: Packet in src %s dst %s con protocollo %s" % (src, dst, protocol)

	key = "%s %s %s" % (src, dst, protocol)       
        
	if key not in self.story and self.filtered_ip(dst, eth):
            # appendo il messaggio appena arrivato alla lista dei messaggi in attesa
            self.messages.append(ev.msg)

            # scrivo in output la sorgente e la destinazione separati da uno spazio
            self.communications += str(src)
            self.communications += ' '
            self.communications += str(dst)
	    self.communications += ' '
            self.communications += str(protocol)
            self.communications += '\n'

            self.story.append(key)
	    #print "Aggiunto %s alla storia!" % key

        if self.filtered_ip(dst, eth) == False:

            data = None #i dati da inviare allo switch vengono posti a none. 
			#Perche'? Perche' possono essere bufferizzati all'interno dello switch (e identificati da un buffer_id)
            if msg.buffer_id == ofproto.OFP_NO_BUFFER: #se non esiste nessun buffer_id, i dati vengono presi dal packet_in in ingresso
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
	    #il messaggio di packet out si comporta in due modi a seconda che i dati siano bufferizzati o meno all'interno dello switch:
	    #se lo sono, si andranno a beccare tali dati tramite il buffer_id, se non lo sono il campo data non viene riempito dall'if appena sopra e quindi il controller
	    #manda allo switch un flow mod completo anche dei dati
            datapath.send_msg(out)

