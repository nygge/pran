%%%-------------------------------------------------------------------
%%% @copyright 2007 Telexpertise de Mexico, S.A. de C.V.
%%% File    : mtp3.erl
%%% @author Anders Nygren <anders@txm.com.mx>
%%% @doc
%%% @end
%%% Created : 14 Jan 2007 by Anders Nygren <anders@txm.com.mx>
%%%-------------------------------------------------------------------
-module(pran_mtp3).

-export([decode/3]).

-include("mtp3.hrl").

decode(<<NI:2,PRIO:2,SI:4,
	 DPClo:8,
	 OPClo:2,DPChi:6,
	 OPCmid:8,
	 SLS:4,OPChi:4,
	 Payload/binary>>,
       Stack, _Opts) ->
    <<OPC:16>> = <<0:2,OPChi:4,OPCmid:8,OPClo:2>>,
    <<DPC:16>> = <<0:2,DPChi:6,DPClo:8>>,
    Proto=si(SI),
    {[{mtp3, #mtp3_msu{ni=NI, prio=PRIO, si=Proto, dpc=DPC, opc=OPC, sls=SLS}}|Stack],
     Payload,Proto}.


si(?SNMM) ->  snmm;
si(?SNTMM) -> sntmm;
si(?SCCP) ->  sccp;
si(?TUP) ->   tup;
si(?ISUP) ->  isup;
si(?DUP1) ->  dup1;
si(?DUP2) ->  dup2;
si(?BISDN) -> bisdn;
si(?SISDN) -> sisdn.
