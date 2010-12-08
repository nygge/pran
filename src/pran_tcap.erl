%%%-------------------------------------------------------------------
%%% File    : pran_tcap.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created :  4 Dec 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_tcap).

%% API
-export([decode/3]).

%% Dummy function used when no decoder is found
-export([nothing/2]).

-include_lib("tcap/include/DialoguePDUs.hrl").
-include_lib("tcap/include/TCAPMessagesBasic.hrl").

-record(operation, {ac, name, op_code, module, function, arg, res}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
decode(Bin,Stack,Opts) ->
    {ok,Rec}='TCAPMessagesBasic':decode('TCMessage',Bin),
    {{dialogue,Dlg},{components,Cs}} = decode1(Rec, Opts),
    {Cs++[{tcap,Dlg}]++Stack,<<>>,undefined}.

%%====================================================================
%% Internal functions
%%====================================================================
decode1({'begin',#'Begin'{components=asn1_NOVALUE}=B}, Opts) ->
    B;
decode1({'begin',#'Begin'{dialoguePortion=DP,
			  components=Cs}=B},
	Opts) when is_list(Cs) ->
    Dlg = decode_dialoguePortion(DP),
    AC = get_ac(Dlg),
    Cs1 = [decode_component(AC,C,Opts) || C<-Cs],
    {{dialogue,B#'Begin'{dialoguePortion=Dlg}},{components,Cs1}};

decode1({'continue',#'Continue'{dialoguePortion=DP,
				components=Cs}=C}, 
	Opts) when is_list(Cs) ->
    Dlg = decode_dialoguePortion(DP),
    AC = get_ac(Dlg),
    Cs1 = [decode_component(AC,C,Opts) || C<-Cs],
    C#'Continue'{dialoguePortion=Dlg,components=Cs1};
decode1({abort,#'Abort'{}=A}, Opts) ->
    A;
decode1({'end',#'End'{}=E}, Opts) ->
    E.

decode_dialoguePortion({'EXTERNAL',{syntax,?'dialogue-as-id'},_,Bin}) ->
    {ok,{_Alt,Value}} = 'DialoguePDUs':decode('DialoguePDU',Bin),
    Value;
decode_dialoguePortion(asn1_NOVALUE) ->
    asn1_NOVALUE.

get_ac(#'AARQ-apdu'{'application-context-name'=AC}) ->
    AC;
get_ac(#'AARE-apdu'{'application-context-name'=AC}) ->
    AC;
get_ac(asn1_NOVALUE) ->
    asn1_NOVALUE.

decode_component(AC,{invoke,#'Invoke'{operationCode=OpCode,parameter=Param}=I},
		 Opts) ->
    #operation{module=Mod,function=Fun,arg=Type} = find_decoder(AC,OpCode,Opts),
    Result = case Mod:Fun(Type,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    %% I#'Invoke'{parameter={map,Result}};
    {map,Result};
decode_component(AC,{returnResultLast,
		  #'ReturnResult'{
		    result=#'ReturnResult_result'{operationCode=OpCode,
						  parameter=Param}=R}=I},
		 Opts) ->
    #operation{module=Mod,function=Fun,arg=Type} = find_decoder(AC,OpCode,Opts),
    Result = case Mod:Fun(Type,Param) of
		 {ok,Arg} -> Arg;
		 Error -> Error
	     end,
    %% I#'ReturnResult'{result=R#'ReturnResult_result'{parameter={map,Result}}};
    {map,Result};
decode_component(AC,{returnResultLast,
		  #'ReturnResult'{result=asn1_NOVALUE}=I},_Opts) ->
    I.

find_decoder(AC,OpCode,Opts) ->
    Ops = pran_utils:get_conf_par(tcap,operations,Opts),
    case [Op || #operation{ac=AC1,op_code=Op1}=Op <- Ops, AC==AC1,Op1==OpCode] of
	[] ->
	    ORec = #operation{ac=AC,op_code=OpCode,
			      module=?MODULE,function=nothing},
	    ORec;
	[#operation{}=ORec] ->
	    ORec
    end.

%% Dummy function used when no decoder is found
nothing(_Type,Bin) ->
    Bin.
