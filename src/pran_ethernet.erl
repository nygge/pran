%%%-------------------------------------------------------------------
%%% File    : pran_ethernet.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : 
%%%
%%% Created : 27 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_ethernet).

%% API
-export([decode/3]).

-include("ethernet.hrl").

-define(IPv4,16#0800).
-define(IPv6,16#86DD).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(<<S1,S2,S3,S4,S5,S6,
	 D1,D2,D3,D4,D5,D6,
	 Type:16,
	 Payload/binary>>,
       Stack,_Opts) ->
    Protocol = protocol(Type),
    Hdr = #ethernet{src={S1,S2,S3,S4,S5,S6},
		    dst={D1,D2,D3,D4,D5,D6},
		    type=Protocol},
    {[{ethernet,Hdr}|Stack],Payload,Protocol}.

%%====================================================================
%% Internal functions
%%====================================================================
protocol(?IPv4) ->
    ip;
protocol(?IPv6) ->
    ip;
protocol(Type) ->
    Type.
