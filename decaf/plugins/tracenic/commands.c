/* 
 Tracecap is owned and copyright (C) BitBlaze, 2007-2010.
 All rights reserved.
 Do not copy, disclose, or distribute without explicit written
 permission.

 Author: Juan Caballero <jcaballero@cmu.edu>
 Zhenkai Liang <liangzk@comp.nus.edu.sg>
 */
#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef CONFIG_TCG_TAINT
#include "shared/tainting/taintcheck_opt.h" // AWH
#include "shared/tainting/tainting.h"
#endif
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "conf.h"
// AWH #include "libfstools.h"
#include "slirp/slirp.h"


#include "conditions.h"

#include "network.h"


#include "hookapi.h"
#include "function_map.h"
#include "utils/Output.h" // AWH
#include "vmi_c_wrapper.h" // AWH
#include "qemu-timer.h" // AWH

/* Plugin interface */
static plugin_interface_t tracing_interface;
//to keep consistent
static DECAF_Handle nic_rec_cb_handle;
static DECAF_Handle nic_send_cb_handle;
static DECAF_Handle keystroke_cb_handle;

int io_logging_initialized = 0;

char current_mod[32] = "";
char current_proc[32] = "";

/* Origin and offset set by the taint_sendkey monitor command */
#ifdef CONFIG_TCG_TAINT
//static int taint_sendkey_origin = 0;
//static int taint_sendkey_offset = 0;
static int taint_key_enabled=0;
#endif

/* Current thread id */
uint32_t current_tid = 0;

uint32_t should_trace_all_kernel = 0;

// AWH - Changed to use new mon_cmd_t datatype
static mon_cmd_t tracing_info_cmds[] = { { NULL, NULL, }, };

// AWH - Forward declarations of other funcs used below
static int tracing_init(void);
static void tracing_cleanup(void);
/* target-i386/op_helper.c */
extern uint32_t helper_cc_compute_all(int op);

#ifdef CONFIG_TCG_TAINT

//check EIP tainted
static void tracing_send_keystroke(DECAF_Callback_Params *params)
{
	/* If not tracing, return */
	if (tracepid == 0)
	return;
	if(!taint_key_enabled)
	return;

	int keycode=params->ks.keycode;
	uint32_t *taint_mark=params->ks.taint_mark;
	*taint_mark=taint_key_enabled;
	taint_key_enabled=0;
	printf("taint keystroke %d \n ",keycode);
}

// void do_taint_sendkey(const char *key, int taint_origin, int taint_offset)
void do_taint_sendkey(Monitor *mon, const QDict *qdict)
{
	// Set the origin and offset for the callback
	if(qdict_haskey(qdict, "key"))
	{
		//register keystroke callback
		taint_key_enabled=1;
		if (!keystroke_cb_handle)
		keystroke_cb_handle = DECAF_register_callback(DECAF_KEYSTROKE_CB,
				tracing_send_keystroke, &taint_key_enabled);
		// Send the key
		do_send_key(qdict_get_str(qdict, "key"));

	}
	else
	monitor_printf(mon, "taint_sendkey command is malformed\n");
}

#endif //CONFIG_TCG_TAINT

static int tracing_init(void) {
	int err = 0;

	procname_clear();
//	// Parse configuration file
//	err = check_ini(ini_main_default_filename);
//	if (err) {
//		DECAF_printf( "Could not find INI file: %s\n"
//				"Use the command 'load_config <filename> to provide it.\n",
//				ini_main_default_filename);
//	}
	return 0;
}

static void tracing_cleanup(void) {
	DECAF_stop_vm();

if (nic_rec_cb_handle)
		DECAF_unregister_callback(DECAF_NIC_REC_CB, nic_rec_cb_handle);
	if (nic_send_cb_handle)
		DECAF_unregister_callback(DECAF_NIC_SEND_CB, nic_send_cb_handle);
	if (keystroke_cb_handle)
		DECAF_unregister_callback(DECAF_KEYSTROKE_CB, keystroke_cb_handle);
	DECAF_start_vm();
}


static mon_cmd_t tracing_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

int monitored_pid = 0;


extern target_ulong VMI_guest_kernel_base;
plugin_interface_t * init_plugin() {


	tracing_interface.plugin_cleanup = tracing_cleanup;
	tracing_interface.mon_cmds = tracing_term_cmds;
	tracing_interface.info_cmds = tracing_info_cmds;

	//for now, receive block begin callback globally
	DECAF_stop_vm();

#ifdef CONFIG_TCG_TAINT
	//  //register taint nic callback
	nic_rec_cb_handle = DECAF_register_callback(DECAF_NIC_REC_CB,
			tracing_nic_recv, NULL);
	nic_send_cb_handle = DECAF_register_callback(DECAF_NIC_SEND_CB,
			tracing_nic_send, NULL);
	printf("register nic callback \n");

#endif /*CONFIG_TCG_TAINT*/


	DECAF_start_vm();
	tracing_init();
	return &tracing_interface;
}
