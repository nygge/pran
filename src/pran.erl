%%%-------------------------------------------------------------------
%%% File    : pran.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : Library for reading libpcap files.
%%%
%%% Created : 25 Nov 2010 by Anders Nygren <anders.nygren@gmail.com>
%%%-------------------------------------------------------------------
-module(pran).

-compile(export_all).

%% API
-export([file/1,file/2]).

-include("elibpcap.hrl").

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
file(File) ->
    Opts = pran_utils:load_config(),
    file(File, Opts).

file(File, Opts) ->
    {ok,Bin} = file:read_file(File),
    {#file_hdr{order=Order,
	       major=2,minor=4,
	       network=Net},FBin} = pran_pcap:file_header(Bin),
    pran_pcap:packets(Order, Net, FBin, Opts).

grep_file(File, Pat) when is_list(Pat) ->
    grep_file(File, list_to_binary(Pat));
grep_file(File, Pat) when is_binary(Pat) ->
    CP = pran_utils:mk_pattern(Pat),
    grep_file(File, {filters,[{pcap,{contain,CP}}]});
grep_file(File, Filter) when is_tuple(Filter) ->
    Opts = pran_utils:load_config(),
    {ok,FD}=pran_pcap_file:open(File, [Filter|Opts]),
    read_loop(FD,pran_pcap_file:read(FD)).

read_loop(FD,X) ->
    read_loop(FD,X,[]).

read_loop(_FD,eof,Acc) ->
    lists:reverse(Acc);
read_loop(FD,#frame{payload_bin=Bin}=Fr,Acc) ->
    io:format("~p~n",[Fr]),
    read_loop(FD,pran_pcap_file:read(FD),[]).
%% read_loop(_FD,eof,Acc) ->
%%     lists:reverse(Acc);
%% read_loop(FD,#frame{payload_bin=Bin}=Fr,Acc) ->
%%     %% io:format("~p~n",[Fr]),
%%     Rs=read_loop(FD,pran_pcap_file:read(FD),[Fr|Acc]).
