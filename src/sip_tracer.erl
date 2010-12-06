%%%-------------------------------------------------------------------
%%% File    : sip_tracer.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created : 26 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(sip_tracer).

%% API
-export([dump_file/1,
	 view_file/1]).

-include("elibpcap.hrl").
-include("ethernet.hrl").
-include("ip.hrl").
-include("tcp.hrl").
-include("udp.hrl").

-record(sip, {src_addr,
	      src_port,
	      dst_addr,
	      dst_port,
	      slogan,
	      frame}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
view_file(File) ->
    CPid = start_et(),
    Es = [extract_info(P) || P <- pran:file(File)],
    [report_event(CPid,E) || E <- Es],
    ok.

dump_file(File) ->
    [extract_info(P) || P <- pran:file(File)].

%%====================================================================
%% Internal functions
%%====================================================================
start_et() ->
    {ok,VPid} = et_viewer:start(),
    et_viewer:get_collector_pid(VPid).

report_event(CPid, #sip{src_addr=From,dst_addr=To,
			slogan={request,Method},frame=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, Method,[{request,PDU}]);
report_event(CPid, #sip{src_addr=From,dst_addr=To,
			slogan={status, Code, Phrase},frame=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, Code,[{response,PDU}]);
report_event(CPid, #sip{src_addr=From,dst_addr=To,
			slogan=parse_failed,frame=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, parse_failed,
			      [{parse_failed,PDU}]);
report_event(_CPid,[]) ->
    ok.
    
extract_info(#frame{payload=#ethernet{
		      payload=#ip4{src=SrcIP,
				   dst=DstIP,
				   payload=#udp{src=SrcPort,
						dst=DstPort,
						payload={sip,SIP}}}}}=Frame) ->
    #sip{src_addr=addr_to_actor(SrcIP,SrcPort),
	 src_port=SrcPort,
	 dst_addr=addr_to_actor(DstIP,DstPort),
	 dst_port=DstPort,
	 slogan=extract_sip(SIP),
	 frame=Frame};
extract_info(#frame{payload=#ethernet{
		      payload=#ip4{src=SrcIP,
				   dst=DstIP,
				   payload=#tcp{src=SrcPort,
						dst=DstPort,
						payload={sip,SIP}}}}}=Frame) ->
    #sip{src_addr=addr_to_actor(SrcIP,SrcPort),
	 src_port=SrcPort,
	 dst_addr=addr_to_actor(DstIP,DstPort),
	 dst_port=DstPort,
	 slogan=extract_sip(SIP),
	 frame=Frame};
extract_info(#frame{seq_no=Seq}=_What) ->
%%    io:format("seq=~p what = ~p~n",[Seq,_What]),
    [].

extract_sip({'Request',
	     {'Request-Line',Method,_URI,_Version},
	     _Headers,
	     _Body}) ->
    {request,Method};
extract_sip([[["SIP",47,"2",46,"0"],32,StatusCode,32,ReasonPhrase,"\r\n"]|_]) ->
    {status, StatusCode,ReasonPhrase};
extract_sip(X) ->
    io:format("what = ~p~n",[X]),
    parse_failed.

addr_to_actor({127,0,0,1},5065) ->
    a_party;
addr_to_actor({127,0,0,1},4060) ->
    p_cscf;
addr_to_actor({127,0,0,1},5060) ->
    i_cscf;
addr_to_actor({127,0,0,1},5070) ->
    asyxa;
addr_to_actor({127,0,0,1},6060) ->
    s_cscf;
addr_to_actor({127,0,0,1},5067) ->
    b_party.
