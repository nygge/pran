%%%-------------------------------------------------------------------
%%% File    : pran_utils.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created : 28 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_utils).

%% API
-export([decode_payload/3,
	 decode_payload/4,
	 filter/3,
	 get_conf_par/3,
	 load_config/0,
	 mk_pattern/1]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode_payload(Protocol, Payload, Opts) ->
    do_decode(Protocol, Payload, [], Opts).

decode_payload(Endian, Protocol, Payload, Opts) ->
    do_decode(Endian, Protocol, Payload, [], Opts).

do_decode(_Protocol, <<>>, Stack, _Opts) ->
    lists:reverse(Stack);
do_decode(Protocol, Payload, Stack, Opts) ->
    %% io:format("decode ~p ~p~n",[Protocol,Stack]),
    case get_decoder(Protocol,Opts) of
	unknown -> lists:reverse([{Protocol,Payload}|Stack]);
	Decoder ->
	    {NewStack, Remaining, NextProtocol} = Decoder:decode(Payload, Stack, Opts),
	    do_decode(NextProtocol, Remaining, NewStack, Opts)
    end.

do_decode(_Endian, _Protocol, <<>>, Stack, _Opts) ->
    lists:reverse(Stack);
do_decode(Endian, Protocol, Payload, Stack, Opts) ->
    %% io:format("decode ~p ~p~n",[Protocol,Stack]),
    case get_decoder(Protocol,Opts) of
	unknown -> lists:reverse([{Protocol,Payload}|Stack]);
	Decoder ->
	    {NewStack, Remaining, NextProtocol} = Decoder:decode(Payload, Stack, Opts),
	    do_decode(Endian,NextProtocol, Remaining, NewStack, Opts)
    end.

filter(Bin, Protocol, Filters) when is_atom(Protocol), is_list(Filters) ->
    Fs = proplists:get_value(Protocol, Filters, []),
    apply_filter(Bin, Fs).

get_conf_par(Protocol, Par, Opts) ->
    case lists:keysearch(Protocol,1,Opts) of
	{value,{Protocol,ProtoOpts}} ->
	    case lists:keysearch(Par,1,ProtoOpts) of
		{value,{Par,Value}} ->
		    Value;
		false ->
		    undefined
	    end;
	false -> 
	    undefined
    end.

load_config() ->    
    %% Priv = code:priv_dir(pran),
    Priv = "/home/anders/src/pran/priv",
    WC = filename:join([Priv,"*.conf"]),
    Fs = filelib:wildcard(WC),
    T = [file:consult(F)||F<-Fs],
    [KV||{ok,[KV]} <- T].

%% the binary module was introduced in R14. So we work around
%% that for older versions
mk_pattern(Pat) ->
    try 
	binary:compile_pattern(Pat)
    catch
	_:_ ->
	    Pat
    end.

%%====================================================================
%% Internal functions
%%====================================================================
get_decoder(Proto,Opts) ->
    case lists:keysearch(pran,1,Opts) of
	{value,{pran,POpts}} ->
	    case lists:keysearch(decoders,1,POpts) of
		{value,{decoders,Decoders}} ->
		    case lists:keysearch(Proto,1,Decoders) of
			{value,{Proto,Decoder}} ->
			    Decoder;
			false ->
			    unknown
		    end;
		false -> 
		    unknown
	    end;
	false ->
	    unknown
    end.

apply_filters(Bin, [F|Fs]) ->
    case apply_filter(Bin,F) of
	pass ->
	    apply_filters(Bin, Fs);
	fail ->
	    fail
    end;
apply_filters(_Bin, []) ->
    pass.

apply_filter(Bin, {contain, Pat}) ->
    case f_contain(Bin, Pat) of
	nomatch ->
	    fail;
	_Match ->
	    pass
    end.
	    
f_contain(Bin,Pat) when is_tuple(Pat) ->
    binary:match(Bin,Pat,[]);

f_contain(Bin,Pat) ->
    Len = byte_size(Pat),
    case Bin of
	<<Pat:Len/binary-unit:8,_Rest/binary>> -> found;
	<<_:8,Rest/binary>> -> f_contain(Rest,Pat);
	<<>> ->  not_found
    end.
