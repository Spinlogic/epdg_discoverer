# ePDG discoverer
Resolves the IP addresses of ePDGs from most mobile operators in the world and checks if each ePDG responds to ICMP and whether it accepts IKEv2 connection.

Variations of this code may also be used by advanced users to perform load test or controlled attacks on specific nodes. If you need more info about this, you can contact me via github or [@Spinlogic](www.spinlogic.net)

## Introduction
3GPP specification TS23.402 defines the network architecture for non-3GPP accesses. The most important of such access technologies is IEEE 802.11 (i.e. WiFi).
There are basically two architectural variants, one for "trusted" WiFi access and one for "untrusted" WiFi access. The "untrusted" access variant is currently the most commonly used by cellular network operators around the world.

In the "untrusted" case, the clients (mobile phones) establish a secure connection to a node called ePDG (evolved Packet Data Gateway).

Untrusted WLAN access is used to provide VoWiFi (Voice over WiFi) service.

## ePDG address resolution
For any mobile network operator, the URI of their ePDG's is defined in 3GPP TS23.003 as follows:

>epdg.epc.mcc<_mcc_>.mnc<_mnc_>.pub.3gppnetwork.org

where <_mcc_> is the three digits mobile country code of the country of the operator and <_mnc_> is the mobile network code of the operator in this country, with three digits length (add zeros on the left of the mnc if it has with less than three digits). 

For example, Spain has mcc = 214 and Movistar (Telefónica) has mnc = 07 in Spain. Therefore the URI for Movistar ePDG's is:

>epdg.epc.mcc214.mnc007.pub.3gppnetwork.org

The script does both, IPv4 and IPv6, resolutions. If the ePDG resolves to multiple addresses, then each IP address is in one line in the output file. 

## Usage
>python3 vowifi_scanner <_operatorsfilename_> <_outputfilename_>

where:

* **operatorfilename** is a file with the list of operators to check. It is a tap separated values file in which the first column is the mcc, the second is the mnc, the third is the operator name and the fourth is the country name.
* **outputfilename** is the output file. It is also a tab separated values file for which the first four columns are the same as for the operatorfilename, the fifth column is the IP address of the ePDG, the sixth column shows whether the ePDG responds to ICMP echo, and the seventh column shows the packet length to IKEv2_SA_INIT request. This file can easily be imported by all major spreadsheets.

Note that the ePDG address of some operators is resolved, but it does not respond to neither ICMP nor IKEv2_SA_INIT messages. This could mean that the ePDG is off, geoblocked, or does not like the received request and drops it (if it is an IKEv2 one, specially). 

## Dependencies
This script depends on the following modules:

* [scapy](https://github.com/secdev/scapy). But you need to apply the patch inside the patches folder to scapy's "ikev2.py" inside its contrib directory. This patch fixes a problem with the key length transform attribute and adds IKEv2 configuration parameters to scapy. 
* [PyCriptodome](https://www.pycryptodome.org/en/latest/). Only needed if you are going to try to go beyond IKE_SA_INIT procedure and send IKE_AUTH request. Read below.

The Diffie-Hellman key exchange is derived from [diffiehellman](https://github.com/chrisvoncsefalvay/diffiehellman) , but it has been modified to include DH Group 2 and 128 bit keys and several other minor issues.

## Advanced use

"ikev2_class.py" contains code for a first IKEv2_AUTH exchange with the ePDG, using AES-CBC encription with the keys generated as described in [RFC7296](https://tools.ietf.org/html/rfc7296). You can use "test_ikev2.py" to play around with this procedure.

I am using this code to test vulnerabilities in ePDG and side effects into other NW nodes (AAA, HSS). 
Feel free to contact via github or [@Spinlogic](www.spinlogic.net) if you want to know more.

