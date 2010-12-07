%%%-------------------------------------------------------------------
%%% File    : pran_map.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created :  4 Dec 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_map).

%% API
-export([decode/3]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(invoke,{local,2},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','UpdateLocationArg',Bin);
decode(returnResult,{local,2},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','UpdateLocationRes',Bin);
decode(invoke,{local,46},Bin) ->
    asn1rt:decode('MAP-SM-DataTypes-v6','MO-ForwardSM-Arg',Bin);
decode(returnResult,{local,46},Bin) ->
    asn1rt:decode('MAP-SM-DataTypes-v6','MO-ForwardSM-Res',Bin);
decode(invoke,{local,56},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','SendAuthenticationInfoArg',Bin);
decode(returnResult,{local,56},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','SendAuthenticationInfoRes',Bin);
decode(TCop,Op,Bin) ->
    error_logger:info_report([{module,?MODULE},
			      {do_not_know_how_to_decode, TCop,Op}]),
    Bin.
    
%%====================================================================
%% Internal functions
%%====================================================================
