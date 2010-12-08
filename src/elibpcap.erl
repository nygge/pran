%%%-------------------------------------------------------------------
%%% File    : elibpcap.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : Library for reading libpcap files.
%%%
%%% Created : 25 Nov 2010 by Anders Nygren <anders.nygren@gmail.com>
%%%-------------------------------------------------------------------
-module(elibpcap).

-compile(export_all).

%% API
-export([file_header/1,
	 decode_frame/4]).

-include("elibpcap.hrl").

-define(MAGIC, 16#a1b2c3d4).
-define(NET_ETHERNET,1).
-define(NET_MTP_2,140).

-define(PROTOCOLS,[{{udp,5060},sip}, {{tcp,5060},sip},
		   {{udp,5062},sip}, {{tcp,5062},sip},
		   {{udp,5063},sip}, {{tcp,5063},sip}
		  ]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
file(File) ->
    {ok,Bin} = file:read_file(File),
    {#file_hdr{order=Order,major=2,minor=4,network=Net},Rest} = file_header(Bin),
    dec_packets(Order, Net, Rest).

%%====================================================================
%% Internal functions
%%====================================================================
dec_packets(Order, Net, Rest) ->
    dec_frames(Order, Net, Rest, 1, []).

dec_frames(_Order, _Network, <<>>, _N, Acc) ->
    lists:reverse(Acc);
dec_frames(Order, Network, Bin, N, Acc) ->
    {P,Rest} = decode_frame(Order, Network, N, Bin),
    dec_frames(Order, Network, Rest, N+1, [P|Acc]).

file_header(<<?MAGIC:4/little-unsigned-integer-unit:8, 
	      Major:2/little-unsigned-integer-unit:8, 
	      Minor:2/little-unsigned-integer-unit:8,
	      GMT_to_localtime:4/little-unsigned-integer-unit:8, 
	      Sigfigs:4/little-unsigned-integer-unit:8, 
	      Snaplen:4/little-unsigned-integer-unit:8, 
	      Network:4/little-unsigned-integer-unit:8, 
	      Data/binary>>) ->
    {#file_hdr{order = little,
	       major = Major,
	       minor = Minor,
	       gmt_to_localtime = GMT_to_localtime,
	       sigfigs= Sigfigs,
	       snaplen = Snaplen,
	       network = network(Network)},
     Data};
file_header(<<?MAGIC:4/big-unsigned-integer-unit:8, 
	      Major:2/big-unsigned-integer-unit:8, 
	      Minor:2/big-unsigned-integer-unit:8,
	      GMT_to_localtime:4/big-unsigned-integer-unit:8, 
	      Sigfigs:4/big-unsigned-integer-unit:8, 
	      Snaplen:4/big-unsigned-integer-unit:8, 
	      Network:4/big-unsigned-integer-unit:8, 
	      Data/binary>>) ->
    {#file_hdr{order = big,
	       major = Major,
	       minor = Minor,
	       gmt_to_localtime = GMT_to_localtime,
	       sigfigs= Sigfigs,
	       snaplen = Snaplen,
	       network = network(Network)},
     Data}.

network(?NET_ETHERNET) ->
    ethernet;
network(?NET_MTP_2) ->
    mtp_2.

decode_frame(little, Network, Seq,
	      <<Timestamp_s:4/little-unsigned-integer-unit:8, 
		Timestamp_us:4/little-unsigned-integer-unit:8, 
		Incl_payload_len:4/little-unsigned-integer-unit:8, 
		Orig_payload_len:4/little-unsigned-integer-unit:8,
		Payload:Incl_payload_len/binary-unit:8,
		Rest/binary>>) ->
    Truncated= Incl_payload_len<Orig_payload_len, 
    {#frame{seq_no=Seq,
	    timestamp_s = Timestamp_s,
	    timestamp_us = Timestamp_us,
	    incl_payload_len = Incl_payload_len, 
	    orig_payload_len = Orig_payload_len,
	    truncated=Truncated,
	    payload = dec_pk_payload(little, Network, Payload)},
     Rest};
decode_frame(big, Network, Seq,
	      <<Timestamp_s:4/big-unsigned-integer-unit:8, 
		Timestamp_us:4/big-unsigned-integer-unit:8, 
		Incl_payload_len:4/big-unsigned-integer-unit:8, 
		Orig_payload_len:4/big-unsigned-integer-unit:8,
		Payload:Incl_payload_len/binary-unit:8,
		Rest/binary>>) ->
    Truncated= Incl_payload_len<Orig_payload_len, 
    {#frame{seq_no=Seq,
	    timestamp_s = Timestamp_s,
	    timestamp_us = Timestamp_us,
	    incl_payload_len = Incl_payload_len, 
	    orig_payload_len = Orig_payload_len,
	    truncated=Truncated,
	    payload = dec_pk_payload(big, Network, Payload)},
     Rest}.

dec_pk_payload(big, ethernet, Payload) ->
    pran_ethernet:decode(big, Payload);
dec_pk_payload(little, ethernet, Payload) ->
    pran_ethernet:decode(little, Payload).

decode_tcp_udp_payload(Proto, Src, Dst, Payload) ->
    case payload_protocol(Proto, Src,Dst) of
	sip ->
	    case (rfc3261:'SIP-message'())(erlang:binary_to_list(Payload)) of
		{ok, PDU, []} -> {sip,PDU};
		fail -> Payload
	    end;
	unknown -> Payload
    end.

payload_protocol(Proto, FromPort, ToPort) ->
    case {port_to_protocol(Proto, FromPort),
	  port_to_protocol(Proto, ToPort)} of
	{undefined,undefined} -> unknown;
	{AppProto, undefined} -> AppProto;
	{undefined, AppProto} -> AppProto;
	{AppProto, AppProto} -> AppProto;
	_ -> unknown
    end.

port_to_protocol(Proto,Port) ->
    case lists:keysearch({Proto,Port},1,?PROTOCOLS) of
	{value,{_Key, Prot}} ->
	    Prot;
	false ->
	    undefined
    end.
