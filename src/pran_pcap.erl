%%%-------------------------------------------------------------------
%%% File    : pran_pcap.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : Library for reading libpcap files.
%%%
%%% Created : 25 Nov 2010 by Anders Nygren <anders.nygren@gmail.com>
%%%-------------------------------------------------------------------
-module(pran_pcap).

-compile(export_all).

%% API
-export([file_header/1,
	 get_frame/3]).

-include("elibpcap.hrl").

-define(MAGIC, 16#a1b2c3d4).
-define(NET_ETHERNET,1).
-define(NET_MTP_2,140).
-define(NET_MTP_3,141).

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
    file_header(Bin).

%%====================================================================
%% Internal functions
%%====================================================================
%% packets(Order, Net, Rest, Opts) ->
%%     dec_frames(Order, Net, Rest, 1, [], Opts).

%% dec_frames(_Order, _Network, <<>>, _N, Acc, _Opts) ->
%%     lists:reverse(Acc);
%% dec_frames(Order, Network, Bin, N, Acc, Opts) ->
%%     {P,Rest} = decode_frame(Order, Network, N, Bin, Opts),
%%     dec_frames(Order, Network, Rest, N+1, [P|Acc], Opts).

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
    mtp2;
network(?NET_MTP_3) ->
    mtp3;
network(Unknown) ->
    Unknown.

get_frame(little, Seq,
	  <<Timestamp_s:4/little-unsigned-integer-unit:8, 
	    Timestamp_us:4/little-unsigned-integer-unit:8, 
	    Incl_payload_len:4/little-unsigned-integer-unit:8, 
	    Orig_payload_len:4/little-unsigned-integer-unit:8,
	    Payload:Incl_payload_len/binary-unit:8,
	    Rest/binary>>) ->
    mk_frame_rec(little, Seq,
		 Timestamp_s, Timestamp_us, 
		 Incl_payload_len, Orig_payload_len,
		 Payload, Rest);
get_frame(big, Seq,
	  <<Timestamp_s:4/big-unsigned-integer-unit:8, 
	    Timestamp_us:4/big-unsigned-integer-unit:8, 
	    Incl_payload_len:4/big-unsigned-integer-unit:8, 
	    Orig_payload_len:4/big-unsigned-integer-unit:8,
	    Payload:Incl_payload_len/binary-unit:8,
	    Rest/binary>>) ->
    mk_frame_rec(big, Seq,
		 Timestamp_s, Timestamp_us, 
		 Incl_payload_len, Orig_payload_len,
		 Payload, Rest);
get_frame(_Endian, _Seq, _Bin) ->
    need_more_data.

mk_frame_rec(_Endian, Seq,
	     Timestamp_s, Timestamp_us, 
	     Incl_payload_len, Orig_payload_len,
	     Payload, Rest) ->
    Truncated= Incl_payload_len<Orig_payload_len, 
    {#frame{seq_no=Seq,
	    timestamp = {Timestamp_s div 1000000, Timestamp_s rem 1000,
			 Timestamp_us},
	    incl_payload_len = Incl_payload_len, 
	    orig_payload_len = Orig_payload_len,
	    truncated = Truncated,
	    payload_bin = Payload},
	    %% payload = pran_utils:decode_payload(Endian, Network, Payload, Opts)},
     Rest}.
