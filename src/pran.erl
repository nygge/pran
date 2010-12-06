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

-define(DEF_OPTS,[{decoders,[{ethernet,pran_ethernet},
			     {ip,pran_ip},
			     {udp,pran_udp},
			     {tcp,pran_tcp},
			     {mtp2,pran_mtp2},
			     {mtp3,pran_mtp3},
			     {sccp,pran_sccp}
			    ]}]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
file(File) ->
    file(File, ?DEF_OPTS).

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
    {ok,FD}=pran_pcap_file:open(File, [Filter|?DEF_OPTS]),
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
