%%%-------------------------------------------------------------------
%%% File    : pran_sip.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : SDP decoder for PRAN.
%%%
%%% Created :  8 Dec 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_sdp).

%% API
-export([decode/3]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(Payload, Stack, _Opts) ->
    try rfc4566:decode('session-description',Payload) of
	{ok, PDU, <<>>} -> 
	    {[{sdp,PDU}|Stack],<<>>,done};
	{ok, PDU, More} ->  %% This only happens with fragmented packets
	    {[{sdp,PDU}|Stack],More,done};
	fail ->
	    {[{sdp,Payload}|Stack],<<>>,done}
    catch
	_:Reason ->
	    io:format("SDP failed ~p~n",[Reason]),
	    {[{sdp_failed,Payload}|Stack],<<>>,done}
    end.

%%====================================================================
%% Internal functions
%%====================================================================
