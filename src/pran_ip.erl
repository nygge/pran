%%%-------------------------------------------------------------------
%%% File    : pran_ip.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : Decode IP packets.
%%%
%%% Created : 27 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_ip).

%% API
-export([decode/3]).

-include("ip.hrl").

-define(IP_VERSION_4, 4).
-define(IP_VERSION_6, 6).

-define(IP_MIN_HDR_LEN, 5).

-define(IP_ICMP, 16#01).
-define(IP_IGMP, 16#02).
-define(IP_TCP,  16#06).
-define(IP_UDP,  16#11).
-define(IP_OSPF, 16#59).
-define(IP_SCTP, 16#84).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------

%%====================================================================
%% Internal functions
%%====================================================================
%% Non-fragmented IP package
decode(<<?IP_VERSION_4:4, HLen:4, _SrvcType:8, _TotLen:16, 
	 _ID:16, _Res:1, 
	 _DF:1,              % Don't Fragment
	 0:1,                % More Fragments
	 0:13,               % Fragment Offset
	 _TTL:8, Proto:8, _HdrChkSum:16,
	 SrcIP1:8,SrcIP2:8,SrcIP3:8,SrcIP4:8,
	 DestIP1:8,DestIP2:8,DestIP3:8,DestIP4:8,
	 RestDgram/binary>>, Stack, _Opts) when HLen>=5 ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<IPOpts:OptsLen/binary,Data/binary>> = RestDgram,
    Protocol = protocol(Proto),
    {[{ip_v4,#ip4{src={SrcIP1,SrcIP2,SrcIP3,SrcIP4},
		  dst={DestIP1,DestIP2,DestIP3,DestIP4},
		  proto=Protocol,
		  opts=IPOpts}}|Stack],
     Data,Protocol};

%% First fragment
decode(<<?IP_VERSION_4:4, HLen:4, _SrvcType:8, _TotLen:16, 
	 _ID:16, _Res:1, 
	 _DF:1,              % Don't Fragment
	 1:1,                % More Fragments
	 0:13,               % Fragment Offset
	 _TTL:8, Proto:8, _HdrChkSum:16,
	 SrcIP1:8,SrcIP2:8,SrcIP3:8,SrcIP4:8,
	 DestIP1:8,DestIP2:8,DestIP3:8,DestIP4:8,
	 RestDgram/binary>>, Stack, _Opts) when HLen>=5 ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<IPOpts:OptsLen/binary,Data/binary>> = RestDgram,
    Protocol = protocol(Proto),
    {[{ip_v4,#ip4{src={SrcIP1,SrcIP2,SrcIP3,SrcIP4},
		  dst={DestIP1,DestIP2,DestIP3,DestIP4},
		  proto=Protocol,
		  opts=IPOpts}}|Stack],
     Data,Protocol};

%% Intermediate fragment
decode(<<?IP_VERSION_4:4, HLen:4, _SrvcType:8, _TotLen:16, 
	 _ID:16, _Res:1, 
	 _DF:1,              % Dont Fragment
	 1:1,                % More Fragments
	 FragOffset:13,      % Fragment Offset
	 _TTL:8, Proto:8, _HdrChkSum:16,
	 SrcIP1:8,SrcIP2:8,SrcIP3:8,SrcIP4:8,
	 DestIP1:8,DestIP2:8,DestIP3:8,DestIP4:8,
	 RestDgram/binary>>, Stack, _Opts) when HLen>=5 ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<IPOpts:OptsLen/binary,Data/binary>> = RestDgram,
    Protocol = protocol(Proto),
    Hdr = #ip4{src={SrcIP1,SrcIP2,SrcIP3,SrcIP4},
	       dst={DestIP1,DestIP2,DestIP3,DestIP4},
	       proto=Protocol,
	       opts=IPOpts
	      },
    {[{ip_v4,Hdr}|Stack],Data,Protocol};

%% Last fragment
decode(<<?IP_VERSION_4:4, HLen:4, _SrvcType:8, _TotLen:16, 
	 _ID:16, _Res:1, 
	 _DF:1,              % Dont Fragment
	 0:1,                % More Fragments
	 FragOffset:13,      % Fragment Offset
	 _TTL:8, Proto:8, _HdrChkSum:16,
	 SrcIP1:8,SrcIP2:8,SrcIP3:8,SrcIP4:8,
	 DestIP1:8,DestIP2:8,DestIP3:8,DestIP4:8,
	 RestDgram/binary>>, Stack, _Opts) when HLen>=5 ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<IPOpts:OptsLen/binary,Data/binary>> = RestDgram,
    Protocol = protocol(Proto),
    {[{ip_v4,#ip4{src={SrcIP1,SrcIP2,SrcIP3,SrcIP4},
		  dst={DestIP1,DestIP2,DestIP3,DestIP4},
		  proto=Protocol,
		  opts=IPOpts}}|Stack],
     Data,Protocol};

decode(<<?IP_VERSION_6:4, Tr_class:8, Flow_label:20, _Payload_len:16,
	 Next_header:8, Hop_limit:8,
	 Src_address:16/binary-unit:8,
	 Dst_address:16/binary-unit:8,
	 RestDgram/binary>>,
      Stack, _Opts) ->
    Protocol = protocol(Next_header),
    {[{ip_v6, #ip6{src=bin_to_ip6_addr(Src_address),
		   dst=bin_to_ip6_addr(Dst_address),
		   class=Tr_class,
		   flow_label=Flow_label,
		   hop_limit=Hop_limit,
		   proto=Protocol}}|Stack], RestDgram, Protocol}.


bin_to_ip6_addr(Bin) ->
    list_to_tuple([Byte || <<Byte:8>> <= Bin]).

protocol(?IP_ICMP) ->
    icmp;
protocol(?IP_IGMP) ->
    igmp;
protocol(?IP_UDP) ->
    udp;
protocol(?IP_TCP) ->
    tcp;
protocol(?IP_SCTP) ->
    sctp;
protocol(?IP_OSPF) ->
    ospf;
protocol(Unknown) ->
    error_logger:info_report([{module,?MODULE},
			      {error, unknown_protocol},
			      {protocol,Unknown}]),
    {ip_protocol,Unknown}.
