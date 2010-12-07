%%%-------------------------------------------------------------------
%%% File    : pran_pcap_file.erl
%%% Author  : Anders Nygren <anders.nygren@gmail.com>
%%% Description : 
%%%
%%% Created : 29 Nov 2010 by Anders Nygren <>
%%%-------------------------------------------------------------------
-module(pran_pcap_file).

-behaviour(gen_server).

%% API
-export([open/2,
	 read/1]).

-export([test_read_file/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).


-include("elibpcap.hrl").

-define(BLOCKSIZE, 64000).
-define(FILE_HDR_LEN,24).
-define(FRAME_HDR_LEN,16).

-record(state, {fd,
		offset=?FILE_HDR_LEN,
		network,
		endian,
		seq=1,
		decoders,
		filters,
		options,
		buffer}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: open() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
open(File, Opts) ->
    gen_server:start_link(?MODULE, [File,Opts], []).

read(Fd) ->
    gen_server:call(Fd,read).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Args) -> {ok, State} |
%%                         {ok, State, Timeout} |
%%                         ignore               |
%%                         {stop, Reason}
%% Description: Initiates the server
%%--------------------------------------------------------------------
init([File,Opts]) ->
    Decoders = proplists:get_value(decoders, Opts),
    Filters =  proplists:get_value(filters, Opts, []),
    io:format("pcap_file opts ~p~n",[Opts]),
    {ok, Fd} = file:open(File, [read, raw, binary]),
    {ok, Bin} = file:pread(Fd, 0, ?BLOCKSIZE),
    case pran_pcap:file_header(Bin) of
	{#file_hdr{order = Endian,
		   major = _Major, minor = _Minor,
		   gmt_to_localtime = _GMT_to_localtime,
		   sigfigs= _Sigfigs, snaplen = _Snaplen,
		   network = Network},
	 Rest} ->
	    {ok, #state{fd=Fd,
			decoders=Decoders,
			filters=Filters,
			options=Opts,
			network=Network,
			endian=Endian,
			buffer=Rest}};
	_Error ->
	    {stop,{unknown_format,_Error}}
    end.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call(read, _From, State) ->
    case get_next(State) of
	{#frame{}=Frame,State1} ->
	    {reply, Frame, State1};
	eof ->
	    {stop, normal, eof, State}
    end.


%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
get_next(#state{seq=Seq,
		endian=Endian,
		network=Network,
		filters=Filters,
		options=Opts,
		offset=Offset,
		buffer=Bin}=State) ->
    case pran_pcap:get_frame(Endian,Seq,Bin) of
	{#frame{incl_payload_len=Len,payload_bin=Payload}=Frame,Rest} ->
	    case pran_utils:filter(Payload,pcap,Filters) of
		pass ->
		    io:format("packet no ~p~n",[Seq]),
		    PL = pran_utils:decode_payload(Endian, Network, Payload, Opts),
		    {Frame#frame{payload=PL},
		     State#state{seq=Seq+1,
				 offset=Offset+Len+?FRAME_HDR_LEN,
				 buffer=Rest}};
		fail ->
		    get_next(State#state{seq=Seq+1,
					 offset=Offset+Len+?FRAME_HDR_LEN,
					 buffer=Rest})
	    end;
	need_more_data ->
	    case read_block(State) of
		{ok,State1} -> get_next(State1);
		eof -> eof
	    end
    end.

read_block(#state{fd=Fd, offset=Offset}=State) ->
    case file:pread(Fd, Offset, ?BLOCKSIZE) of
	{ok, Data} ->
	    {ok,State#state{buffer=Data}};
	eof ->
	    eof
    end.

%%--------------------------------------------------------------------
%%% Test functions
%%--------------------------------------------------------------------
test_read_file(File) ->
    et:trace_me(80, test_read_frames,pcap_file,open,[]),
    {ok,Pid} = open(File,[]),
    F=read(Pid),
    test_read_frames(F,Pid).

test_read_frames(eof,Pid) ->
    ok;
test_read_frames(F,Pid) ->
%%    io:format("~p~n",[F]),
    et:trace_me(80, test_read_frames,pcap_file,read,[]),
    F1=read(Pid),
    test_read_frames(F1,Pid).
