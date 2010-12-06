-type ssn()  :: not_used | sccp_man | res_itu | isup | omap | map
              | hlr | vlr | msc | eic | auc | isdn_ss | camel | sgsn
              | ggsn | scf | byte().


%% Parameters
-record(gt_0001,{nature,
		 digits}).
-record(gt_0010,{translation,
		 digits}).
-record(gt_0011,{translation,
		 numbering_plan,
		 encoding,
		 digits}).
-record(gt_0100,{translation,
		 numbering_plan,
		 encoding,
		 nature,
		 digits}).

-type global_title() :: #gt_0001{}
                      | #gt_0010{}
                      | #gt_0011{}
                      | #gt_0100{}.

%%-type ri() :: 0 | 1.
-record(sccp_address,{ri ,%   :: ri(),
		 spc,%    :: 0..32768,
		 ssn   :: ssn(),
		 gt    ::  undefined | global_title()}).

%% Optional Parameters
-record(importance,{importance}).
-record(segmentation,{first,
		      class,
		      rem_segs,
		      seg_local_ref}).

%% PDU records
-record(udt,{prot_cl,
	     msg_handling,
	     calling   :: #sccp_address{},
	     called    :: #sccp_address{},
	     data}).

-record(udts,{ret_cause,
	      calling   :: #sccp_address{},
	      called    :: #sccp_address{},
	      data}).
-record(xudt,{prot_cl,
	      msg_handling,
	      calling   :: #sccp_address{},
	      called    :: #sccp_address{},
	      hop_cnt,
	      data,
	      opts}).
-record(sccp_data, {calling   	:: #sccp_address{},
		    called    			:: #sccp_address{},
		    data}).

