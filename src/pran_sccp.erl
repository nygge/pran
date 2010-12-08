%%%-------------------------------------------------------------------
%%% @copyright 2007 Telexpertise de Mexico, S.A. de C.V.
%%% File    : sccp_pdu.erl
%%% @author Anders Nygren <anders.nygren@txm.com.mx>
%%% @doc Decode SCCP pdus.
%%% @end
%%% Created :  6 Feb 2007 by Anders Nygren <anders.nygren@txm.com.mx>
%%%-------------------------------------------------------------------
-module(pran_sccp).

-export([decode/3]).

-include("sccp_params.hrl").
-include("sccp_pdu.hrl").

-include_lib("eunit/include/eunit.hrl").

%% Unitdata(UDT)
decode(<<?UDT:8, MH:4, PC:4,CalledPAPtr:8,CallingPAPtr:8,DataPtr:8,Vdata/binary>>,Stack,_Opts) ->
    Called=address_dec(get_par(CalledPAPtr-3,Vdata)),
    Calling=address_dec(get_par(CallingPAPtr-2,Vdata)),
    Data=get_par(DataPtr-1,Vdata),
    {[{sccp,#udt{prot_cl=PC, msg_handling=MH, calling=Calling,
		 called=Called}}|Stack],
     Data,tcap};

decode(<<?UDTS:8,RC:8,CalledPAPtr:8,CallingPAPtr:8,DataPtr:8,Vdata/binary>>,
       _Stack,_Opts) ->
    Called=address_dec(get_par(CalledPAPtr-3,Vdata)),
    Calling=address_dec(get_par(CallingPAPtr-2,Vdata)),
    Data=get_par(DataPtr-1,Vdata),
    {{sccp,#udts{ret_cause=RC,calling=Calling,called=Called}},
     Data, next_protocol};

decode(<<?XUDT:8,MH:4, PC:4,HopC:8,CalledPAPtr:8,CallingPAPtr:8,DataPtr:8,OptPtr:8,Vdata/binary>>,_Stack,_Opts) ->
    Called=address_dec(get_par(CalledPAPtr-4,Vdata)),
    Calling=address_dec(get_par(CallingPAPtr-3,Vdata)),
    Data=get_par(DataPtr-2,Vdata),
    Opts = if
    	OptPtr == 0 ->
    		[];
    	true ->
    		get_opts(OptPtr-1,Vdata)
    end,
    {{sccp,#xudt{prot_cl=PC, msg_handling=MH, calling=Calling,
		 called=Called,hop_cnt=HopC,opts=Opts}},Data,next_protocol}.


get_par(0,Data) ->
    get_par(Data);
get_par(Offset,Data) ->
    <<_Skip:Offset/binary,Rest/binary>> = Data,
    get_par(Rest).

get_par(Data) ->
    <<Len:8,Rest/binary>> = Data,
    <<Par:Len/binary,_R/binary>> = Rest,
    Par.

%%===============================================================
%% @spec address_dec(binary()) -> sccp_address()
%% @doc
%% Decode an SCCP address. Used for both Called Party Address and Calling
%% Party Address. See ITU-T Q.713 for details.
%% @end
-spec address_dec(<<_:8,_:_*8>>) -> #sccp_address{}.
address_dec(<<_RNU:1,RI:1,GTI:4,SSNI:1,PCI:1,Addr/binary>>=_P) ->
    {SPC,C1} = get_spc(PCI,Addr),
    {SSN,C2} = get_ssn(SSNI,C1),
    GT = gt_dec(GTI,C2),
    #sccp_address{ri=RI,spc=SPC,ssn=SSN,gt=GT}.


%% Get signalling point code
get_spc(0,Bin) when is_binary(Bin) ->
    {undefined,Bin};
get_spc(1,<<SPC:16,Rest/binary>>) ->
    {spc_dec(<<SPC:16>>), Rest}.

%% Decode Signalling Point Code
spc_dec(<<L:8,0:2,M:6>>) ->
    <<PC:16>> = <<M,L>>,
    PC.

%% get susbsystem number
get_ssn(0,Bin) ->
    {undefined,Bin};
get_ssn(1,<<SSN:8,More/binary>>) ->
    {ssn_dec(SSN),More}.

ssn_dec(0) ->
    not_used;
ssn_dec(1) ->
    sccp_man;
ssn_dec(2) ->
    res_itu;
ssn_dec(3) ->
    isup;
ssn_dec(4) ->
    omap;
ssn_dec(5) ->
    map;
ssn_dec(6) ->
    hlr;
ssn_dec(7) ->
    vlr;
ssn_dec(8) ->
    msc;
ssn_dec(9) ->
    eic;
ssn_dec(10) ->
    auc;
ssn_dec(11) ->
    isdn_ss;
ssn_dec(145) ->
    gmlc;
ssn_dec(146) ->
    camel;
ssn_dec(147) ->
    scf;
ssn_dec(149) ->
    sgsn;
ssn_dec(150) ->
    ggsn;
ssn_dec(N) when N<256 ->
    N.

%% get global title
-spec gt_dec(byte(), binary()) -> undefined | global_title().
gt_dec(0,_Bin) ->
    undefined;
gt_dec(1,<<OE:1,NAI:7,AI/binary>>) ->
    Odd = case OE of
	      0 -> even;
	      1 -> odd
	  end,
    #gt_0001{nature=nai_dec(NAI),digits=number:bcd_bin_to_digitlist(AI, Odd)};
gt_dec(2,<<TT:8,AI/binary>>) ->
    #gt_0010{translation=TT,digits=AI};
gt_dec(3,<<TT:8,NP:4,ES:4,AI/binary>>) ->
    GTAI=decode_gtai(ES,AI),
    #gt_0011{translation=TT,numbering_plan=NP,encoding=ES,digits=GTAI};
gt_dec(4,<<TT:8,NP:4,ES:4,0:1,NAI:7,AI/binary>>) ->
    GTAI=decode_gtai(ES,AI),
    #gt_0100{translation=TT,numbering_plan=NP,encoding=ES,
	     nature=nai_dec(NAI),digits=GTAI}.
%% Decode Nature of Address
nai_dec(0) ->
    unknown;
nai_dec(1) ->
    subscriber;
nai_dec(3) ->
    national;
nai_dec(4) ->
    international;
nai_dec(N) ->
    N.

-spec decode_gtai(integer(),binary()) -> binary()|[char()].
decode_gtai(ES, AI) ->
    case ES of
	1 ->
	    bcd_bin_to_digitlist(AI, odd);
	2 ->
	    bcd_bin_to_digitlist(AI, even);
	_ ->
	    AI
    end.

bcd_bin_to_digitlist(<<_:4, B:4>>, odd) ->
    [B];
bcd_bin_to_digitlist(<<A:4, B:4>>, even) ->
    [B,A];
bcd_bin_to_digitlist(<<A:4,B:4,Rest/binary>>,OE) ->
    [B,A]++bcd_bin_to_digitlist(Rest, OE).

%% Get rid of the offset (from parameter pointer to the real data)
get_opts(0,Data) ->
    get_opts(Data);
get_opts(Offset,Data) ->
    <<_Skip:Offset/binary,Rest/binary>> = Data,
    get_opts(Rest).

%% Get the next paramater (name, length and value)
get_opts(<<0:8>>) ->
    [];
get_opts(<<Name:8,Len:8,Rest/binary>>) when Name =/= ?LONGDATA ->
    <<Par:Len/binary,Cont/binary>> = Rest,
    [get_opt(Name,Par)|get_opts(Cont)].

%% Decode a parameter (name, length and value)
get_opt(?SEGMENTATION,<<First:1,Class:1,_Spare:2,RemSegs:4,SegLocalRef:24>>) ->
    #segmentation{first=First,class=Class,rem_segs=RemSegs,
		  seg_local_ref=SegLocalRef};
get_opt(?IMPORTANCE,<<_Spare:5,Importance:3>>) ->
    #importance{importance=Importance}.

%%========================================================================
%%
%% EUnit tests
%%

triq_test_() ->
    {timeout, 60,
     fun() ->
	     true = triq:module(tq_sccp_addr)
     end}.

ssn_dec_test() ->
    ?assert(ssn_dec(0) == not_used),
    ?assert(ssn_dec(1) == sccp_man),
    ?assert(ssn_dec(2) == res_itu),
    ?assert(ssn_dec(3) == isup),
    ?assert(ssn_dec(4) == omap),
    ?assert(ssn_dec(5) == map),
    ?assert(ssn_dec(6) == hlr),
    ?assert(ssn_dec(7) == vlr),
    ?assert(ssn_dec(8) == msc),
    ?assert(ssn_dec(9) == eic),
    ?assert(ssn_dec(10) == auc),
    ?assert(ssn_dec(11) == isdn_ss),
    ?assert(ssn_dec(146) == camel),
    ?assert(ssn_dec(147) == scf),
    ?assert(ssn_dec(149) == sgsn),
    ?assert(ssn_dec(150) == ggsn),
    ?assert(ssn_dec(25) == 25).

spc_dec_test() ->
    ?assert(spc_dec(<<16#0102:16>>) == 16#201).

gt_dec_test() ->
    ?assert(gt_dec(0,<<>>) ==  undefined),
    Odd0 = 0,
    Odd1 = 1,
    NAI = 45,
    AI = <<2:4,1:4,0:4,3:4>>,
    ?assert(gt_dec(1,<<Odd0:1,NAI:7,AI/binary>>) == #gt_0001{nature= NAI,digits=[1,2,3,0]}),
    ?assert(gt_dec(1,<<Odd1:1,NAI:7,AI/binary>>) == #gt_0001{nature= NAI,digits=[1,2,3]}),
    ?assert(gt_dec(2,<<56:8,AI/binary>>) == #gt_0010{translation=56,digits=AI}),
    ESOdd = 1,
    ESEven = 2,
    ?assert(gt_dec(3,<<56:8,8:4,ESEven:4,AI/binary>>) ==
	    #gt_0011{translation=56,numbering_plan=8,encoding=ESEven,
		     digits=[1,2,3,0]}),
    ?assert(gt_dec(3,<<56:8,8:4,ESOdd:4,AI/binary>>) ==
	    #gt_0011{translation=56,numbering_plan=8,encoding=ESOdd,
		     digits=[1,2,3]}),

    ?assert(gt_dec(4,<<56:8,8:4,ESEven:4,0:1,NAI:7,AI/binary>>) ==
	    #gt_0100{translation=56,numbering_plan=8,encoding=ESEven,
		     nature=NAI,digits=[1,2,3,0]}).
