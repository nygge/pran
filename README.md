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

48> {ok,FD}=pran:open_file("mtp2.pcap", "").
{ok,<0.152.0>}
49> pran:read(FD).                          
[#frame{seq_no = 1,
        timestamp = {1234,378,932000},
        incl_payload_len = 5,orig_payload_len = 5,truncated = false,
        payload_bin = <<141,184,0,241,193>>},
 {mtp2,{fisu}}]
50> pran:read(FD).
[#frame{seq_no = 2,
        timestamp = {1234,379,764000},
        incl_payload_len = 36,orig_payload_len = 36,
        truncated = false,
        payload_bin = <<141,185,31,133,2,64,0,0,0,0,1,0,33,0,10,
                        2,2,8,6,1,16,...>>},
 {mtp2,#mtp2_msu{bsn = 13,bib = 1,fsn = 57,fib = 1,
                 sio = undefined,sif = undefined}},
 {mtp3,#mtp3_msu{ni = 2,prio = 0,si = isup,opc = 1,dpc = 2,
                 sls = 0}},
 {isup,<<0,0,1,0,33,0,10,2,2,8,6,1,16,18,82,85,33,10,6,7,
         1,17,19,...>>}]
51> pran:close(FD).                         
ok

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
