%%%-------------------------------------------------------------------
%%% File    : sip_tracer.erl
%%% Author  : Anders Nygren <>
%%% Description : 
%%%
%%% Created : 26 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(sip_tracer).

%% API
-export([view_file/2]).

-include("elibpcap.hrl").
-include("ethernet.hrl").
-include("ip.hrl").
-include("tcp.hrl").
-include("udp.hrl").

-record(sip, {timestamp,
	      from,
	      to,
	      src_addr,
	      src_port,
	      dst_addr,
	      dst_port,
	      slogan,
	      body}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: 
%% Description:
%%--------------------------------------------------------------------
view_file(File,Filter) ->
    Pid = start_et(),
    {ok,FD} = pran:open_file(File,Filter),
    read_loop(FD,Pid).

%%====================================================================
%% Internal functions
%%====================================================================
start_et() ->
    {ok,VPid} = et_viewer:start(),
    et_viewer:get_collector_pid(VPid).

read_loop(FD, Pid) ->
    case pran:read(FD) of
	Packet when is_list(Packet) ->
	    io:format("packet ~p~n",[Packet]),
	    process_packet(Pid,Packet),
	    read_loop(FD,Pid);
	eof ->
	    eof
    end.

process_packet(CPid,Packet) ->
    case extract_info(Packet) of
	ignore -> ignore;
	Rec -> report_event(CPid, Rec)
    end.

extract_info([#frame{timestamp=TS}|More]) ->
    extract_info(More,[{ts,TS}]).

extract_info([{ethernet,#ethernet{}}|More],Acc) ->
    extract_info(More,Acc);
extract_info([{ip_v4,#ip4{src=SrcIP,dst=DstIP}}|More],Acc) ->
    extract_info(More,[{src_ip,SrcIP},{dst_ip,DstIP}|Acc]);
extract_info([{udp,#udp{src=SrcPort,dst=DstPort}}|More],
	     [{src_ip,SrcIP},{dst_ip,DstIP}|_]=Acc) ->
    From = addr_to_actor(SrcIP,SrcPort),
    To = addr_to_actor(DstIP,DstPort),
    extract_info(More,[{from,From},{to,To},
		       {src_port,SrcPort},
		       {dst_port,DstPort}|Acc]);
extract_info([{tcp,#tcp{src=SrcPort,dst=DstPort}}|More],
	     [{src_ip,SrcIP},{dst_ip,DstIP}|_]=Acc) ->
    From = addr_to_actor(SrcIP,SrcPort),
    To = addr_to_actor(DstIP,DstPort),
    extract_info(More,[{from,From},{to,To},
		       {src_port,SrcPort},
		       {dst_port,DstPort}
		       |Acc]);
extract_info([{sip,SIP}|Body],
	     [{from,From},{to,To},
	      {src_port,SrcPort},{dst_port,DstPort},
	      {src_ip,SrcIP},{dst_ip,DstIP},
	      {ts,TS}]) ->
    #sip{timestamp=TS,
	 from=From,
	 to=To,
	 src_addr=SrcIP,
	 src_port=SrcPort,
	 dst_addr=DstIP,
	 dst_port=DstPort,
	 slogan=extract_sip(SIP),
	 body={SIP,Body}};
extract_info([{unknown,_}|_],_) ->
    ignore.

extract_sip({'Request',
		  {'Request-Line',Method,_URI,_Version},
	     _Headers}) ->
    {request,Method};
extract_sip({'Request',
		  {'Request-Line',Method,_URI,_Version},
	     _Headers,_Rest}) ->
    {request,Method};

extract_sip({'Response',{'Status-Line',{'SIP-Version',"2.0"}
			 ,StatusCode,ReasonPhrase},_Hdrs}) ->
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
    b_party;
addr_to_actor({192,168,49,25},_Port) ->
    a_sub;
addr_to_actor({192,168,49,56},_Port) ->
    b_sub;
addr_to_actor({192,168,32,249},_Port) ->
    cscf;
addr_to_actor({192,168,32,251},_Port) ->
    cscf;
addr_to_actor({192,168,32,44},_Port) ->
    lpi;
addr_to_actor(IP,_Port) ->
    IP.

report_event(CPid, #sip{from=From,to=To,
			slogan={request,Method},body=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, Method,[{request,PDU}]);
report_event(CPid, #sip{from=From,to=To,
			slogan={status, Code, _Phrase},body=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, Code,[{response,PDU}]);
report_event(CPid, #sip{from=From,to=To,
			slogan=parse_failed,body=PDU}) ->
    et_collector:report_event(CPid, 90, From, To, parse_failed,
			      [{parse_failed,PDU}]);
report_event(_CPid,[]) ->
    ok.
    
