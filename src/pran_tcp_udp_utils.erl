%%%-------------------------------------------------------------------
%%% File    : pran_tcp_udp_utils.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : 
%%%
%%% Created : 28 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_tcp_udp_utils).

%% API
-export([payload_protocol/4]).

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
payload_protocol(Proto, FromPort, ToPort,_Opts) ->
    case {port_to_protocol(Proto, FromPort),
	  port_to_protocol(Proto, ToPort)} of
	{undefined,undefined} -> unknown;
	{AppProto, undefined} -> AppProto;
	{undefined, AppProto} -> AppProto;
	{AppProto, AppProto} -> AppProto;
	_ -> unknown
    end.

%%====================================================================
%% Internal functions
%%====================================================================
port_to_protocol(Proto,Port) ->
    case lists:keysearch({Proto,Port},1,sip_ports()) of
	{value,{_Key, Prot}} ->
	    Prot;
	false ->
	    undefined
    end.

%% just for testing, should be replaced by Opts
sip_ports() ->
    [{{Prot,Port},sip} || Prot <- [tcp,udp], Port <- [4060,5060,5065,5070,6060,7060,8060]].
