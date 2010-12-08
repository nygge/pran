-record(mtp3_msu,{ni,
		  prio,
		  si,
		  opc,
		  dpc,
		  sls
		 }).

%% Service Indicators
-define(SNMM,	2#0000).  % Signalling network management messages
-define(SNTMM,	2#0001).  % Signalling network testing and maintenance messages
-define(SCCP,	2#0011).  % Signalling Connection Control Part
-define(TUP,	2#0100).  % Telephone User Part
-define(ISUP,	2#0101).  % ISDN User Part
-define(DUP1,	2#0110).  % Data User Part (call and circuit-related messages)
-define(DUP2,	2#0111).  % Data User Part (facility registration and cancellation messages)
-define(BISDN,	2#1001).  % Broadband ISDN User Part
-define(SISDN,	2#1010).  % Satellite ISDN User Part
