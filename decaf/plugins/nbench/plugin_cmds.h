{
	.name		= "nbench_rand",
	.args_type	= "counter:i,randchance:i?",
	.mhandler.cmd	= nbench_cmd,
	.params		= "[interval randchance]",
	.help		= "nbench_rand nbench.exe 1 0 -> deterministically taint every (interval) randnum call. nbench_cmd nbench.exe 0 100 -> randomly taint 1 out of 100"
},
{
	.name		= "nbench",
	.args_type	= "counter:i",
	.mhandler.cmd	= nbench,
	.params		= "[count]",
	.help		= "nbench 10 -> taint 10 bytes of the arrays nbench programs use"
},
{
	.name		= "nbench_debug",
	.args_type	= "mode:i",
	.mhandler.cmd	= nbench_debug,
	.params		= "[mode]",
	.help		= "nbench_debug 1 -> 1 activates debuging and 0 deactivates it "
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
