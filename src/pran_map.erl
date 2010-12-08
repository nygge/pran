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
    'MAP-MS-DataTypes-v6':decode('UpdateLocationArg',Bin);
decode(returnResult,{local,2},Bin) ->
    'MAP-MS-DataTypes-v6':decode('UpdateLocationRes',Bin);
decode(invoke,{local,46},Bin) ->
    'MAP-SM-DataTypes-v6':decode('MO-ForwardSM-Arg',Bin);
decode(returnResult,{local,46},Bin) ->
    'MAP-SM-DataTypes-v6':decode('MO-ForwardSM-Res',Bin);
decode(invoke,{local,56},Bin) ->
    'MAP-MS-DataTypes-v6':decode('SendAuthenticationInfoArg',Bin);
decode(returnResult,{local,56},Bin) ->
    'MAP-MS-DataTypes-v6':decode('SendAuthenticationInfoRes',Bin);
decode(TCop,Op,Bin) ->
    error_logger:info_report([{module,?MODULE},
			      {do_not_know_how_to_decode, TCop,Op}]),
    Bin.
    
%%====================================================================
%% Internal functions
%%====================================================================
