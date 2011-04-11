pran
====

pran is a low-level tool to search .pcap files which contain telecom
signalling packets. It is mainly useful inside an Erlang program.

pran's approach to searching is: First, find all packets which match
the given binary search pattern. Second, decode the packets which were
found. This makes pran very fast in the important case of large .pcap
files and a binary search pattern which only matches a small number of
the packets in the file.


Examples
--------

(An example or two of a search would be nice here, just to show
which function to run and what the output is meant to look like.)

Protocols
---------

GSM MAP
SS7 TCAP
SS7 SCCP
SS7 MTP3
SS7 MTP2

SIP
SDP

TCP
UDP
IP
Ethernet


Building
--------

Install Erlang, then run 'make' in the top level.
