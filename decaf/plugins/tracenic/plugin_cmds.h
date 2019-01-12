
#ifdef CONFIG_TCG_TAINT
//NIC
{
	.name		= "taint_nic",
	.args_type	= "state:i",
	.mhandler.cmd	= do_taint_nic,
	.params		= "state",
	.help		= "set the network input to be tainted or not"
},
{
	.name		= "taint_nic_filter",
	.args_type	= "type:s,value:s",
	.mhandler.cmd	= (void (*)())update_nic_filter,
	.params		= "<clear|proto|sport|dport|src|dst> value",
	.help		= "Update filter for tainting NIC"
},
{
	.name		= "ignore_dns",
	.args_type	= "state:i",
	.mhandler.cmd	= set_ignore_dns,
	.params		= "state",
	.help		= "set flag to ignore received DNS packets"
},
//taint keystroke
{
	.name		= "taint_sendkey",
	.args_type	= "key:s",
	.mhandler.cmd	= do_taint_sendkey,
	.params		= "key taint_origin offset",
	.help		= "send a tainted key to the guest system"
},
{
	.name		= "taint_perc",
	.args_type	= "percentage:i",
	.mhandler.cmd	= do_perc,
	.params		= "inverse of the percentage of network inputs to be tainted e.g. for 20 percent use 5",
	.help		= "set the percentage of the inputs to be tainted"
},

#endif//CONFIG_TCG_TAINT


