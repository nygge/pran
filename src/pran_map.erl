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
decode(invoke,{local,56},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','SendAuthenticationInfoArg',Bin);
decode(returnResult,{local,56},Bin) ->
    asn1rt:decode('MAP-MS-DataTypes-v6','SendAuthenticationInfoRes',Bin);
decode(_TCop,_Op,Bin) ->
    Bin.
    
%%====================================================================
%% Internal functions
%%====================================================================
