%%%-------------------------------------------------------------------
%%% File    : pran_udp.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : UDP packet decoder.
%%%
%%% Created : 27 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_udp).

%% API
-export([decode/3]).

-include("udp.hrl").

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(<<Src:16,Dst:16,_Len:16,_Chk:16,Payload/binary>>,Stack,Opts) ->
    Hdr = #udp{src=Src,dst=Dst},
    Protocol = pran_tcp_udp_utils:payload_protocol(udp,Src,Dst,Opts),
    {[Hdr|Stack],Payload,Protocol}.

%%====================================================================
%% Internal functions
%%====================================================================
