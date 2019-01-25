{
	.name		= "nbench_cmd",
	.args_type	= "procname:s,counter:i?,randchance:i?",
	.mhandler.cmd	= nbench_cmd,
	.params		= "[procname counter randchance]",
	.help		= "nbench_cmd nbench.exe 1 0 -> deterministically taint every randnum call. nbench_cmd nbench.exe 0 100 -> randomly taint 1 out of 100"
},
{
	.name		= "taint_sendkey",
	.args_type	= "key:s",
	.mhandler.cmd	= do_taint_sendkey,
	.params		= "key taint_origin offset",
	.help		= "send a tainted key to the guest system"
},
{
	.name		= "nbench_count",
	.args_type	= "counter:s?",
	.mhandler.cmd	= nbench_counter,
	.params		= "",
	.help		= "Printing the number of randnum function calls and the hooks"
},
