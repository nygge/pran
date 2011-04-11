%%%-------------------------------------------------------------------
%%% @copyright Anders Nygren
%%% File    : pran_mtp2.erl
%%% @author Anders Nygren <anders.nygren@gmail.com>
%%% @doc Decode MTP level 2 msus.
%%% @end
%%% Created :   6 Feb 2007 by Anders Nygren <anders.nygren@gmail.com>
%%% Modified :  by Carlos Mijares <cmijares@txm.com.mx>
%%%-------------------------------------------------------------------
-module(pran_mtp2).
-export([decode/3]).

-include("mtp2.hrl").

decode(Bin, Stack, _Opts) ->
    ESNformat = false,
    {Header, Payload, NextProtocol} = do_decode(ESNformat,Bin),
    {[{mtp2,Header}|Stack], Payload, NextProtocol}.

%% Decode "normal" messages (without an Extended Sequence Number)
do_decode(false=_ESN, <<BIB:1, BSN:7, FIB:1, FSN:7, _Spare:2, LI:6,
			Rest/binary>>) when LI > 2->
    {#mtp2_msu{bsn=BSN, bib=BIB, fsn=FSN, fib=FIB}, Rest, mtp3};

do_decode(false=_ESN, <<_BIB:1, _BSN:7, _FIB:1, _FSN:7, _Spare:2, LI:6,
			_CK/binary>>) when LI == 0 ->
    {{fisu}, <<>>, done};

do_decode(false=_ESN, <<_BIB:1, _BSN:7, _FIB:1, _FSN:7, _Spare:2, LI:6,
			Status:8, Rest/binary>>) when LI==1 ->
    {{lssu, Status}, Rest, done};

do_decode(false=_ESN, <<_BIB:1, _BSN:7, _FIB:1, _FSN:7, _Spare:2, LI:6,
			Status:16, Rest/binary>>) when LI==2 ->
    {{lssu, Status}, Rest, done};

%% Decode messages with a Extended Sequence Number
do_decode(true=_ESN, <<BSN:12,_Res1:3,BIB:1, FSN:12, _Res2:3, FIB:1, LI:9,
		       _Spare:7, Rest/binary>>) when LI > 2 ->
    {#mtp2_msu{bsn=BSN, bib=BIB, fsn=FSN, fib=FIB}, Rest, mtp3};


%% Is this correct?
do_decode(true=_ESN, <<_BSN:12,_Res1:3,_BIB:1, _FSN:12, _Res2:3, _FIB:1,
		       LI:9, _Spare:7, Rest/binary>>) when LI==0 ->
    {{fisu}, Rest, done};

%% Is this correct?
do_decode(true=_ESN, <<_BSN:12,_Res1:3,_BIB:1, _FSN:12, _Res2:3, _FIB:1,
		       LI:9, _Spare:7, Status:8, Rest/binary>>)
  when LI==1; LI==2 ->
    {{lssu, Status}, Rest, done};

%% Is this correct?
do_decode(true=_ESN, <<_BSN:12,_Res1:3,_BIB:1, _FSN:12, _Res2:3, _FIB:1,
		   LI:9, _Spare:7, Status:16, Rest/binary>>) when LI==1; LI==2 ->
    {{lssu, Status}, Rest, done};


do_decode(_ESN, _MSU) ->
    {decode_error}.
