# ePDG discoverer
Resolves the IP addresses of ePDGs from most mobile operators in the world and checks if each ePDG responds to ICMP and whether it accepts IKEv2 connection

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

## Usage
>vowifi_scanner <_operatorsfilename_> <_outputfilename_>

where:

* **operatorfilename** is a file with the list of operators to check. It is a tap separated values file in which the first column is the mcc, the second is the mnc, the third is the operator name and the fourth is the country name.
* **outputfilename** is the output file. It is also a tab separated values file for which the first four columns are the same as for the operatorfilename, the fifth column is the IP address of the ePDG, the sixth column shows whether the ePDG responds to ICMP echo, and the seventh column shows the packet length to IKEv2_SA_INIT request. This file can easily be imported by all major spreadsheets.

## Dependencies
This script uses [scapy](https://github.com/secdev/scapy).