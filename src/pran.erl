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
-export([open_file/2,
	 read/1,
	 close/1,
	 grep_file/2]).

-include("elibpcap.hrl").

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
open_file(File, Pat) when is_list(Pat) ->
    open_file(File, list_to_binary(Pat));
open_file(File, Pat) when is_binary(Pat) ->
    CP = pran_utils:mk_pattern(Pat),
    open_file(File, {filters,[{pcap,{contain,CP}}]});
open_file(File, Filter) when is_tuple(Filter) ->
    Opts = pran_utils:load_config(),
    {ok,_FD}=pran_pcap_file:open(File, [Filter|Opts]).

read(FD) ->
    pran_pcap_file:read(FD).

close(FD) ->
    pran_pcap_file:close(FD).

grep_file(File, Pat) when is_list(Pat) ->
    grep_file(File, list_to_binary(Pat));
grep_file(File, Pat) when is_binary(Pat) ->
    CP = pran_utils:mk_pattern(Pat),
    grep_file(File, {filters,[{pcap,{contain,CP}}]});
grep_file(File, Filter) when is_tuple(Filter) ->
    Opts = pran_utils:load_config(),
    {ok,FD}=pran_pcap_file:open(File, [Filter|Opts]),
    read_loop(FD,pran_pcap_file:read(FD)).

read_loop(FD,Frame) when is_list(Frame) ->
    io:format("~p~n",[Frame]),
    read_loop(FD,pran_pcap_file:read(FD));
read_loop(_FD,eof) ->
    ok.
