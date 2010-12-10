%%%-------------------------------------------------------------------
%%% File    : pran_tcp.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : TCP packet decoder.
%%%
%%% Created : 27 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_tcp).

%% API
-export([decode/3]).

-include("tcp.hrl").

-define(TCP_MIN_HDR_LEN,5).
-define(TCP_OPT_EOO,0).
-define(TCP_OPT_NOP,1).
-define(TCP_OPT_MAX_SEG_SIZE,2).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------

decode(<<Src:16, Dst:16, SeqNo:32, AckNo:32, Offset:4, _Reserved:6,
	 URG:1, ACK:1, PSH:1, RST:1, SYN:1, FIN:1,
	 Window:16, Checksum:16, Urgent:16, More/binary>>,Stack, Opts) ->
    OptsLen = 4*(Offset - ?TCP_MIN_HDR_LEN),
    <<OptsBin:OptsLen/binary-unit:8,Payload/binary>> = More,
    TCPopts = opts(OptsBin),
    Protocol = pran_tcp_udp_utils:payload_protocol(tcp,Src,Dst,Opts),
    Hdr = #tcp{src=Src,
	       dst=Dst,
	       seq_no=SeqNo,
	       ack_no=AckNo,
	       offset=Offset,
	       flags=[Flag||{Flag,1} <- lists:zip([urg,ack,psh,rst,syn,fin],
						  [URG,ACK,PSH,RST,SYN,FIN])],
	       window=Window,
	       checksum=Checksum,
	       urgent=Urgent,
	       options=TCPopts},
    {[{tcp,Hdr}|Stack],Payload,Protocol}.

%%====================================================================
%% Internal functions
%%====================================================================
opts(Bin) ->
    opts(Bin,[]).

opts(<<?TCP_OPT_EOO:8,_Pad/binary>>, Acc) ->
    Acc;
opts(<<?TCP_OPT_NOP:8,More/binary>>, Acc) ->
    opts(More, Acc);
opts(<<?TCP_OPT_MAX_SEG_SIZE:8, 4:8, Max:2/integer-unit:8, More/binary>>, Acc) ->
    opts(More, [{max_segment_size,Max}|Acc]);
opts(<<3:8,3:8,ShiftCount:8,More/binary>>, Acc) ->
    opts(More, [{wsopt,ShiftCount}|Acc]);
opts(<<4:8,2:8,More/binary>>, Acc) ->
    opts(More, [sack_permitted|Acc]);
opts(<<5:8,Len:8,Rest/binary>>, Acc) ->
    Slen = (Len-2),
    <<SACK:Slen/binary-unit:8,More/binary>> = Rest,
    Ss = [{L,R} || <<L:32,R:32>> <= SACK],
    opts(More, [{sack, Ss}|Acc]);
opts(<<8:8,10:8,TSval:32,TSecr:32,More/binary>>, Acc) ->
    opts(More, [{tsopt,TSval,TSecr}|Acc]);
opts(<<>>, Acc) ->
    Acc.

