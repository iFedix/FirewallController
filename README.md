# Firewall Controller

Ryu controller application that blocks traffic in real time and waits for user's decisions. Specifically, every new traffic in the network will be blocked and will wait for user decisions (in order to block or accept that kind of traffic). A new rule will be automatically added in the switches involved in the network managed by the controller. Furthermore, the user can also see precisely all the rules installed in the network devices and manually add new configurations at any time.  

##  How it works
Based on Ryu component-based framework, we created five modules (in **modules** folder) to be loaded through run.sh.
### my_fileserver.py
It creates a server that answer user's request to certain URLs: like this, we realized a Web GUI, through which a user can send requests to the controller application.
### tap.py
It realizes the "manual" part of the application. In fact, this module is the core for the management of the manual insertion of the rules in the network devices.   
### tap_rest.py
It maps, through WSGI, each request from the Web GUI to tap.py.
### live.py
It realizes the "real time" part of the application. In fact, this module provides methods to interact in real time with network devices installed in the network. With this module, user can decide whether allow or deny a new kind of traffic found in the network. 
### live_rest.py
It maps, through WSGI, each request from the Web GUI to live_rest.py.

Note: all the interactions between user and ryu application are provided by Javascript/JQuery scripts that you can find in the **/web/js** folder.

## Tests

In the folder **tests**, there are three shell scripts that will let you emulate the network shown in the picture inside the folder. These are needed in order to test how this controller application works. Try communicating between those two computers using different protocols and see how this controller application behaves (for example you can test a simple ping between the computers).

## Docs

Inside folder **docs**, you can find some documents, where all the files in this repository, among many other things, are described in detail, if you are interested.

## License and more

Firewall Controller is published under **GNU General Public License v3.0**. Special thanks to **Srini Seetharaman** from http://sdnhub.org for his Ryu related works.

Copyright (©) [**MrOverfl00w**](https://github.com/MrOverflOOw) & [**iFedix**](https://github.com/iFedix) 2017
