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
	 mk_pattern/1]).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode_payload(Protocol, Payload, Opts) ->
    case get_decoder(Protocol,Opts) of
	unknown -> Payload;
	Decoder -> Decoder:decode(Payload, Opts)
end.

decode_payload(Endian, Protocol, Payload, Opts) ->
    case get_decoder(Protocol,Opts) of
	unknown -> Payload;
	Decoder -> Decoder:decode(Payload, Opts)
end.

filter(Bin, Protocol, Filters) when is_atom(Protocol), is_list(Filters) ->
    Fs = proplists:get_value(Protocol, Filters, []),
%%    io:format("filter ~p ~p ~p~n",[Protocol,Filters,Fs]),
    apply_filter(Bin, Fs).

%%====================================================================
%% Internal functions
%%====================================================================
get_decoder(Proto,Opts) ->
    case lists:keysearch(decoders,1,Opts) of
	{value,{decoders,Decoders}} ->
	    case lists:keysearch(Proto,1,Decoders) of
		{value,{Proto,Decoder}} ->
%%		    io:format("get_decoder ~p -> ~p~n",[Proto,Decoder]),
		    Decoder;
		false ->
		    io:format("get_decoder ~p~n",[Proto]),
		    unknown
	    end;
	false -> 
	    io:format("get_decoder ~p~n",[Proto]),
	    unknown
    end.

mk_pattern(Pat) ->
    try 
	binary:compile_pattern(Pat)
    catch
	_:_ ->
	    Pat
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
