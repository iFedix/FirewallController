/*
 * Copyright (C) 2014 SDN Hub
 *
 * Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 * You may not use this file except in compliance with this License.
 * You may obtain a copy of the License at
 *
 *    http://www.gnu.org/licenses/gpl-3.0.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 */

var url = "http://" + location.hostname + ":8080";
var originalMain;

var portMap = {};

function updateSwitchList() {
    var switchSelect = document.getElementById("switch");

    // $ indica l'oggetto jQuery
    // la funzione getJSON prende un URL e ne serializza il contenuto
    // il secondo argomento indica una funzione che viene eseguita se la richiesta ha successo, ed ha come argomento la pagina web serializzata con JSON
    $.getJSON(url.concat("/v1.0/topology/switches"), function(switches){

        // la funzione sottostante cicla per ogni elemento dell'oggetto serializzato con JSON
        $.each(switches, function(index, value){ 

            // crea l'elemento option
            var el = document.createElement("option");

            // a cui assegna come testo il valore dell'id del datapath
            el.textContent = value.dpid;

            // a cui assegna come valore intrinseco il valore dell'id del datapath
            el.value = value.dpid;

            // infine si appende il figlio allo switch select
            switchSelect.appendChild(el);

            // vengono anche assegnate le porte disponibili 
            portMap[value.dpid] = value.ports;
        });
    }).then(updatePorts); // se la funzione precedente (getJSON) ha successo, esegue updatePorts(), altrimenti nulla
}

function updatePorts() {
    var srcPortSelect = document.getElementById("src-ports");
    removeAllChildren(srcPortSelect);

    var allEl = document.createElement("option");
    allEl.textContent = "all";
    allEl.value = "all";
    allEl.setAttribute('selected', 'selected');
    srcPortSelect.appendChild(allEl);

    var sinkPortSelect = document.getElementById("sink-ports");
    removeAllChildren(sinkPortSelect);

    // assegna a dpid il valore dell'elemento selezionato nel DOM con id=switch
    var dpid = $('#switch').val();

    // per ognuna delle chiavi in portMap
    $.each(portMap[dpid], function(key, value) {

        // trovo il numero della porta dal valore corrente considerato
        var portNum = parseInt(value.port_no);

        // stessa cosa della funzione precedente, sia per le porte in ingresso che per le porte in uscita
        var el = document.createElement("option");
        el.textContent = portNum;
        el.value = portNum;
        srcPortSelect.appendChild(el);

        el = document.createElement("option");
        el.textContent = portNum;
        el.value = portNum;
        sinkPortSelect.appendChild(el);
   });
}

/* Format of the POST data is as follows:

{'fields': {'  'dl_src': mac string,
               'dl_dst': mac string,
               'dl_type': int,
               'dl_vlan': int,
               'nw_src': ip string,
               'nw_dst': ip string,
               'nw_proto': int,
               'tp_src': int,
               'tp_dst': int},
'sources': list of {'dpid': int, 'port_no': int},
'sinks': list of {'dpid': int, 'port_no': int}
}

 */

function makePostData() {

    // sintassi per creare un dizionario
    var tapInfo = {};

    // queste sotto si conoscono
    var dpid = $('#switch').val();
    var srcPorts = $('#src-ports').val();
    var sinkPorts = $('#sink-ports').val();

    if (sinkPorts == undefined) {
        alert("Sink ports need to be specified.");
        return undefined;
    } 

    // si creano le key sources, sinks, fields
    // dove a sources e sinks corrispondono array
    // mentre a fields corrispondono dizionari
    tapInfo['sources'] = [];
    tapInfo['sinks'] = [];
    tapInfo['fields'] = {};

    // se all non e' trovato nell'array srcPorts
    if ($.inArray('all', srcPorts) != -1)
        // allora aggiungi in fondo a tapInfo.sources una sorgente
        // che e' chiaramente formata da un parametro chiamato dpid a cui corrisponde il valore dopo i :
        // e da un altro parametro chiamato port_no a cui corrisponde all
        tapInfo.sources.push({'dpid': parseInt(dpid), 'port_no': 'all'});
    else {
        // per ogni elemento in srcPorts
        $.each(srcPorts, function(index, value) {
            // creo la variabile port, con parametri simili a sopra
            port = {'dpid': parseInt(dpid), 'port_no': parseInt(value)};
            // poi lo aggiungo a sources
            tapInfo.sources.push(port);
        });
    }
    // stessa roba di sopra
    $.each(sinkPorts, function(index, value) {
        var port = {'dpid': parseInt(dpid), 'port_no': parseInt(value)};
        tapInfo.sinks.push(port);
    });

    // altre variabili in cui memorizzare i valori selezionati dall'utente
    var macStr = $('#mac-addr').val();
    var ipStr = $('#ip-addr').val();
    var trafficType = $('#traffic-type').val();
    var macClass = $('#mac-class').val();
    var ipClass = $('#ip-class').val();

    // controllo sul campo MAC address
    if (macClass != "--Ignore--") {
        if (macStr == undefined || macStr=="") {
            alert("MAC address needs to be specified.");
            return undefined;
        }
    }

    // assegnamento a fields di macStr se macClass vale Source, Destination o Src or Dest
    if (macClass == 'Source') 
        tapInfo.fields['dl_src'] = macStr;
    else if (macClass == 'Destination') 
        tapInfo.fields['dl_dst'] = macStr;
    else if (macClass == 'Src or Dest') 
        tapInfo.fields['dl_host'] = macStr;

    // controllo su IP
    if (ipClass != "--Ignore--") {
        if (ipStr == undefined || ipStr=="") {
            alert("MAC address needs to be specified.");
            return undefined;
        }

        // definizione dell'ethertype, un campo nell'header del frame ethernet per indicare quale protocollo e' incapsulato nel payload
        tapInfo.fields['dl_type'] = 0x800;
    }

    // stessa roba di sopra pero' con ipStr
    if (ipClass == 'Source') 
        tapInfo.fields['nw_src'] = ipStr;
    else if (ipClass == 'Destination') 
        tapInfo.fields['nw_dst'] = ipStr;
    else if (ipClass == 'Src or Dest') 
        tapInfo.fields['nw_host'] = ipStr;

    if (trafficType == 'ARP') {
        // stessa roba di sopra dell'ethertype
        tapInfo.fields['dl_type'] = 0x806;
    }

    // Set prerequisite of IPv4 for all other types
    else if (trafficType == 'ICMP') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['nw_proto'] = 1;

    } else if (trafficType == 'TCP') {
        tapInfo.fields['dl_type'] = 0x800;
        // nw_proto indica la stessa cosa dell'ethertype, indica il payload di IP
        tapInfo.fields['nw_proto'] = 6;
    }
    else if (trafficType == 'HTTP') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['nw_proto'] = 6;
        tapInfo.fields['tp_port'] = 80;
    }
    else if (trafficType == 'HTTPS') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['tp_port'] = 443;
        tapInfo.fields['nw_proto'] = 6;
    }
    else if (trafficType == 'UDP') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['nw_proto'] = 0x11;
    }
    else if (trafficType == 'DNS') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['tp_port'] = 53;
        tapInfo.fields['nw_proto'] = 0x11;
    } else if (trafficType == 'DHCP') {
        tapInfo.fields['dl_type'] = 0x800;
        tapInfo.fields['tp_port'] = 67;
        tapInfo.fields['nw_proto'] = 0x11;
    } 
    console.log(tapInfo.fields);

    return tapInfo;
}

function restoreMain() {
    $("#main").replaceWith(originalMain);
    $('#post-status').html('');
}

function setTap() {
    var tapInfo = makePostData();
    if (tapInfo == undefined)
        return;

    // invia una richiesta all'url concatenato con il form serializzato con JSON
    // la funzione all'interno e' vuota, c'e' solo per riempire
    // l'ultimo parametro indica che tipo di contenuto ci si aspetta dal server
    // vedi in tap_rest.py: questa post è agganciata ad una rest api che provocherà lo scatenarsi della funzione create_tap. Questa verificherà che tutto sia corretto   
    // e restituirà una risposta con codice 200 (successo) o 400/501 (fallimento). Vedere in tap_rest.py
    $.post(url.concat("/v1.0/tap/create"), JSON.stringify(tapInfo), function() { 
    }, "json")
    .done(function() { // done indica la reale funzione usata in caso di successo (ovvero ricevuta Response con status 200)
        // crea una deep copy del main corrente e la assegna a originalMain
        originalMain = $('#main').clone();
        $('#post-status').html('');
        // scrivo l'html dell'elemento main
        $('#main').html('<h2>Tap created</h2><p>Successfully created tap. Check the <a href="/web/stats.html#flow">flow statistics</a> to verify that the rules have been created.</p><button class="pure-button pure-button-primary" onclick="restoreMain()">Create another tap</button>');
    })
    .fail(function() { // fail la funzione che interviene in caso di fallimento
        $('#post-status').html('<p style="color:red; background:silver;">Error: Tap creation failed. Please verify your input.');
    });
}

// stessa cosa di sopra tranne per il fatto che questa sotto e' fatta per cancellare
function clearTap() {
    var tapInfo = makePostData();
    if (tapInfo == undefined)
        return;

    $.post(url.concat("/v1.0/tap/delete"), JSON.stringify(tapInfo), function() { 
    }, "json")
    .done(function() {
        originalMain = $('#main').clone();
        $('#post-status').html('');
        $('#main').html('<h2>Tap deleted</h2><p>Successfully deleted tap. Check the <a href="/web/stats.html#flow">flow statistics</a> to verify that the rules have been deleted.</p><button class="pure-button pure-button-primary" onclick="restoreMain()">Create another tap</button>');
    })
    .fail(function() {
        $('#post-status').html('<p style="color:red; background:silver;">Error: Tap deletion failed. Please verify your input.');
    });
}

updateSwitchList();

