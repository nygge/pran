%%%-------------------------------------------------------------------
%%% File    : pran_tcap.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created :  4 Dec 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_tcap).

%% API
-export([decode/2]).

-include_lib("tcap/include/DialoguePDUs.hrl").
-include_lib("tcap/include/TCAPMessagesBasic.hrl").

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(Bin,Opts) ->
    {ok,Rec}=asn1rt:decode('TCAPMessagesBasic','TCMessage',Bin),
    decode1(Rec).

%%====================================================================
%% Internal functions
%%====================================================================
decode1({'begin',#'Begin'{components=asn1_NOVALUE}=B}) ->
    B;
decode1({'begin',#'Begin'{dialoguePortion=DP,
			  components=Cs}=B}) when is_list(Cs) ->
    Dlg = decode_dialoguePortion(DP),
    AC = get_ac(Dlg),
    Decoder = ac_to_decoder(AC,[]),
    Cs1 = [decode_component(C,Decoder) || C<-Cs],
    B#'Begin'{dialoguePortion=Dlg,components=Cs1};

decode1({'continue',#'Continue'{dialoguePortion=DP,
				components=Cs}=C}) when is_list(Cs) ->
    Dlg = decode_dialoguePortion(DP),
    AC = get_ac(Dlg),
    Decoder = ac_to_decoder(AC,[]),
    Cs1 = [decode_component(C,Decoder) || C<-Cs],
    C#'Continue'{dialoguePortion=Dlg,components=Cs1};
decode1({abort,#'Abort'{}=A}) ->
    A;
decode1({'end',#'End'{}=E}) ->
    E.

decode_dialoguePortion({'EXTERNAL',{syntax,?'dialogue-as-id'},_,Bin}) ->
    {ok,{_Alt,Value}} = asn1rt:decode('DialoguePDUs','DialoguePDU',Bin),
    Value;
decode_dialoguePortion(asn1_NOVALUE) ->
    asn1_NOVALUE.

get_ac(#'AARQ-apdu'{'application-context-name'=AC}) ->
    AC;
get_ac(#'AARE-apdu'{'application-context-name'=AC}) ->
    AC;
get_ac(asn1_NOVALUE) ->
    asn1_NOVALUE.

ac_to_decoder(AC,Opts) ->
    proplists:get_value(AC, Opts, pran_map).
	

decode_component({invoke,#'Invoke'{operationCode=OpCode,parameter=Param}=I},
		  Decoder) ->
    Result = case Decoder:decode(invoke,OpCode,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    I#'Invoke'{parameter={map,Result}};
decode_component({returnResultLast,
		  #'ReturnResult'{
		    result=#'ReturnResult_result'{operationCode=OpCode,
						  parameter=Param}=R}=I},
		 Decoder) ->
    Result = case Decoder:decode(returnResult,OpCode,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    I#'ReturnResult'{result=R#'ReturnResult_result'{parameter={map,Result}}};
decode_component({returnResultLast,
		  #'ReturnResult'{result=asn1_NOVALUE}=I},_Decoder) ->
    I.

