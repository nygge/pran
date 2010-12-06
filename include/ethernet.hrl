-type mac_address() :: {byte(),byte(),byte(),byte(),byte(),byte()}.

-record(ethernet,
	{src                 :: mac_address(),
	 dst                 :: mac_address(),
	 type,
	 payload             :: binary|tuple()}).

