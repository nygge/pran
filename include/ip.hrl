-record(ip4,
	{src,
	 dst,
	 proto,
	 opts}).

-record(ip6,
	{src,
	 dst,
	 class,
	 flow_label,
	 hop_limit,
	 proto
	}).
