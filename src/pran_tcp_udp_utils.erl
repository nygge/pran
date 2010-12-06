%%%-------------------------------------------------------------------
%%% File    : pran_tcp_udp_utils.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : 
%%%
%%% Created : 28 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_tcp_udp_utils).

%% API
-export([decode_payload/5]).

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

decode_payload(Proto, Src, Dst, Payload, _Opts) ->
    case payload_protocol(Proto, Src, Dst) of
	sip ->
	    try (rfc3261:'SIP-message'())(erlang:binary_to_list(Payload)) of
		{ok, PDU, []} -> 
		    {sip,PDU};
		fail ->
%%		    io:format("failed to decode ~p~n",[Payload]),
		    Partial = partial_sip(erlang:binary_to_list(Payload)),
		    {sip,Partial}
	    catch
		_:_ -> Payload
	    end;
	unknown -> Payload
    end.

%%====================================================================
%% Internal functions
%%====================================================================


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
    case lists:keysearch({Proto,Port},1,sip_ports()) of
	{value,{_Key, Prot}} ->
	    Prot;
	false ->
	    undefined
    end.

sip_ports() ->
    [{{Prot,Port},sip} || Prot <- [tcp,udp], Port <- [4060,5060,5065,5070,6060,7060,8060]].


partial_sip(PDU) ->
    case (rfc3261:'Request-Line'())(PDU) of
	{ok,RL,More} ->
	    {Hs,Rest} = get_headers(More,[]),
	    {'Request',RL,Hs,Rest};
	fail ->
	    case (rfc3261:'Status-Line'())(PDU) of
		{ok,SL,More} ->
		    {Hs,Rest} = get_headers(More,[]),
		    {SL,Hs,Rest};
		fail ->
		    fail
	    end
    end.

get_headers(Bs,Acc) ->
    case (rfc3261:'message-header'())(Bs) of
	{ok,H,More} ->
	    get_headers(More,[H|Acc]);
	fail ->
	    {lists:reverse(Acc),Bs}
    end.
		 
