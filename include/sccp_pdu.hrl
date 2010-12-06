%% Message Types
-define(CR,     1).  % Connection Request
-define(CC,     2).  % Connection Confirm
-define(CREF,   3).  % Connection Refused
-define(RLSD,   4).  % Released
-define(RLC,    5).  % Release Complete
-define(DT1,    6).  % Data Form 1
-define(DT2,    7).  % Data Form 2
-define(AK,     8).  % Data Acknowledgement
-define(UDT,    9).  % Unitdata
-define(UDTS,  10).  % UnitdataService
-define(ED,    11).  % Expedited Data
-define(EA,    12).  % Expedited Data Acknowledgement
-define(RSR,   13).  % Reset Request
-define(RSC,   14).  % Reset Confirmation
-define(ERR,   15).  % Protocol Data Unit Error
-define(IT,    16).  % Inactivity Test
-define(XUDT,  17).  % Extended Unitdata
-define(XUDTS, 18).  % Extended Unitdata Service
-define(LUDT,  19).  % Long Unitdata
-define(LUDTS, 20).  % Long Unitdata Service

%% Parameter Names
-define(EOOP,            2#00000000).  % End of Optional Parameters
-define(DESTLOCALREF,    2#00000001).  % Destination Local Reference
-define(SOURCELOCALREF,  2#00000010).  % Source Local Reference
-define(CALLEDPARTYADDR, 2#00000011).  % Called Party Address
-define(CALLINGPARTYADDR,2#00000100).  % Calling Party Address
-define(PROTCLASS,       2#00000101).  % Protocol Class
-define(SEGMREASS,       2#00000110).  % Segmentation/Reassembly
-define(RECSEQNO,        2#00000111).  % Receive Sequence Number
-define(SEQSEG,          2#00001000).  % Sequencing/Segmenting
-define(CREDIT,          2#00001001).  % Credit
-define(RELCAUSE,        2#00001010).  % Release Cause
-define(RETCAUSE,        2#00001011).  % Return Cause
-define(RESETCAUSE,      2#00001100).  % Reset Cause
-define(ERRCAUSE,        2#00001101).  % Error Cause
-define(REFUSALCAUSE,    2#00001110).  % Refusal Cause
-define(DATA,            2#00001111).  % Data
-define(SEGMENTATION,    2#00010000).  % Segmentation
-define(HOPCOUNTER,      2#00010001).  % Hop Counter
-define(IMPORTANCE,      2#00010010).  % Importance
-define(LONGDATA,        2#00010011).  % Long Data
-define(MSGTYPEINTW,     2#11111000).  % Message Type Interworking (ANSI)
-define(INS,             2#11111001).  % Intermediate Network Selection (ANSI)
-define(ISNI,            2#11111010).  % Intermediate Signalling Network Identification (ANSI)

%% Protocol Class
-define(CLASS0,0).
-define(CLASS1,1).
-define(CLASS2,2).
-define(CLASS3,3).

