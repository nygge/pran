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
    Dlg=decode_dialoguePortion(DP),
    Cs1 = [decode_component(C) || C<-Cs],
    B#'Begin'{dialoguePortion=Dlg,components=Cs1};

decode1({'continue',#'Continue'{dialoguePortion=DP,
				components=Cs}=C}) when is_list(Cs) ->
    Dlg=decode_dialoguePortion(DP),
    Cs1 = [decode_component(C) || C<-Cs],
    C#'Continue'{dialoguePortion=Dlg,components=Cs1};
decode1({abort,#'Abort'{}=A}) ->
    A;
decode1({'end',#'End'{}=E}) ->
    E.

decode_dialoguePortion({'EXTERNAL',{syntax,Syntax},_,Bin}) ->
    {ok,R} = asn1rt:decode('DialoguePDUs','DialoguePDU',Bin),
    R;
decode_dialoguePortion(asn1_NOVALUE) ->
    asn1_NOVALUE.

decode_component({invoke,#'Invoke'{operationCode=OpCode,parameter=Param}=I}) ->
    Result = case pran_map:decode(invoke,OpCode,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    I#'Invoke'{parameter={map,Result}};
decode_component({returnResultLast,
		  #'ReturnResult'{
		    result=#'ReturnResult_result'{operationCode=OpCode,
						  parameter=Param}=R}=I}) ->
    Result = case pran_map:decode(returnResult,OpCode,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    I#'ReturnResult'{result=R#'ReturnResult_result'{parameter={map,Result}}};
decode_component({returnResultLast,
		  #'ReturnResult'{result=asn1_NOVALUE}=I}) ->
    I.
