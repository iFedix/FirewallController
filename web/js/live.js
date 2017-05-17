// Variabili globale

var url = "http://" + location.hostname + ":8080/";
var confirmTextBase = "Traffic entering from ";
var src = "";
var dst = "";
var proto="";


// Funzioni utili

function createConfirmText(src, dst, proto) {
  return confirmTextBase + src + " to " + dst + " (Type: " + proto +").\n" + "Allow?"
}

function allowCommunication() {
  $.get(url.concat("rest/accept"));
}

function denyCommunication() {
  $.get(url.concat("rest/deny"));
}

function chooseFunction() {
  if (confirm(createConfirmText(src, dst,proto)) == true)
  {
    // se confermato, inviare un messaggio FlowMod verso lo switch che ha generato il packet_in per consentire il flusso bidirezionale del traffico
    allowCommunication(src, dst);
  }
  else
  {
    // altrimenti, inviare un messaggio FlowMod verso lo switch che ha generato il packet_in per droppare tutti i messaggi di quella conversazione
    // anche se si riprova la conversazione in futuro, viene bloccata senza di nuovo richiedere
    denyCommunication(src, dst);
  }
}

function getFirstCommunication() {
  $.get(url.concat("rest/communications")) //scateno la rest api (GET)
    .done(function(data) {

      if (data)
      {
	if(data!="done")
	{
		//Data appare cosi': 00:00:00:00:00:01 00:00:00:00:00:02 ICMP
		//Di seguito estraggo i vari pezzi:
        	src = data.split('\n')[0].split(' ')[0];		
        	dst = data.split('\n')[0].split(' ')[1];  
		proto = data.split('\n')[0].split(' ')[2];
		//Se il protocollo comincia con Unknown. significa che devo dare in uscita il messaggio configurato in live.py e cioe': 
		//Unknown. If you confirm, you will add a general traffic rule (= every type of traffic) between src and dst
		if(proto=="Unknown.")
			proto = data.split('\n')[0].substring(36) //Comincio dalla 36 lettera di data e cioe' dalla U di Unknown	
        	chooseFunction();
	}
      }
      else
      {
        console.log("Requested page is empty");
      }
  
    })
    .fail(function(data) { 
      console.log("Failed sending request");
    });
}


// Main

// ogni secondo controllo se ci sono stati nuovi tentativi di comunicazione
setInterval(getFirstCommunication, 500);
