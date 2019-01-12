/* 
   Tracecap is owned and copyright (C) BitBlaze, 2007-2010.
   All rights reserved.
   Do not copy, disclose, or distribute without explicit written
   permission. 

   Author: Juan Caballero <jcaballero@cmu.edu>
*/
#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "DECAF_callback.h"
#include "tracecap.h"
#include "conditions.h"
#include "network.h"
#include "conf.h"

/* Default configuration flags */
int conf_trace_only_after_first_taint = 1;
int conf_log_external_calls = 0;
int conf_write_ops_at_insn_end = 0;
int conf_save_state_at_trace_start = 0;
int conf_save_state_at_trace_stop = 0;

/* Environment variables */
int tracing_table_lookup = 1;
static int conf_ignore_dns = 0;
static int conf_tainted_only = 0;
static int conf_single_thread_only = 0;
static int conf_tracing_kernel_all = 0;
static int conf_tracing_kernel_tainted = 0;
static int conf_tracing_kernel_partial = 0;
static int conf_detect_memory_exception = 0;
static int conf_detect_null_pointer = 0;
static int conf_detect_process_exit = 0;
static int conf_detect_tainted_eip = 0;

/* Default hook files */
char hook_dirname[256] = DECAF_HOME "/shared/hooks/hook_plugins";
char hook_plugins_filename[256] = PLUGIN_PATH "/ini/hook_plugin.ini";

/* Default configuration file */
char ini_main_default_filename[256] = PLUGIN_PATH "/ini/main.ini";


//void set_ignore_dns(int state)
void set_ignore_dns(Monitor *mon, const QDict *qdict)
{
  if (/*state*/ qdict_get_int(qdict, "state")) {
    conf_ignore_dns = 1;
    monitor_printf(default_mon, "Ignore DNS flag on.\n");
  }
  else {
    conf_ignore_dns = 0;
    monitor_printf(default_mon, "Ignore DNS flag off.\n");
  }
}

inline int tracing_ignore_dns()
{
    return conf_ignore_dns;
}

//void set_tainted_only(int state)
void set_tainted_only(Monitor *mon, const QDict *qdict)
{
  if (/*state*/ qdict_get_int(qdict, "state")) {
    conf_tainted_only = 1;
    monitor_printf(default_mon, "Taint-only flag on.\n");
  }
  else {
    conf_tainted_only = 0;
    monitor_printf(default_mon, "Taint-only flag off.\n");
  }
}

inline int tracing_tainted_only()
{
    return conf_tainted_only;
}

//void set_single_thread_only(int state)
void set_single_thread_only(Monitor *mon, const QDict *qdict)
{
  if (/*state*/ qdict_get_int(qdict, "state")) {
    conf_single_thread_only = 1;
    monitor_printf(default_mon, "Single-thread-only flag on.\n");
  }
  else {
    conf_single_thread_only = 0;
    monitor_printf(default_mon, "Single-thread-only flag off.\n");
  }
}

inline int tracing_single_thread_only()
{
    return conf_single_thread_only;
}

//void set_kernel_all(int state)
void set_kernel_all(Monitor *mon, const QDict *qdict)
{
  if (/*state*/qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_all = 1;
    monitor_printf(default_mon, "Kernel-all flag on.\n");
  }
  else {
    conf_tracing_kernel_all = 0;
    monitor_printf(default_mon, "Kernel-all flag off.\n");
  }
}

inline int tracing_kernel_all()
{
    return conf_tracing_kernel_all;
}

//void set_kernel_tainted(int state)
void set_kernel_tainted(Monitor *mon, const QDict *qdict)
{
  if (/*state*/qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_tainted = 1;
    monitor_printf(default_mon, "Kernel-tainted flag on.\n");
  }
  else {
    conf_tracing_kernel_tainted = 0;
    monitor_printf(default_mon, "Kernel-tainted flag off.\n");
  }
}

inline int tracing_kernel_tainted()
{
    return conf_tracing_kernel_tainted;
}

//void set_kernel_partial(int state)
void set_kernel_partial(Monitor *mon, const QDict *qdict)
{
  if (/*state*/ qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_partial = 1;
    monitor_printf(default_mon, "Kernel-partial flag on.\n");
  }
  else {
    conf_tracing_kernel_partial = 0;
    monitor_printf(default_mon, "Kernel-partial flag off.\n");
  }
}

inline int tracing_kernel_partial()
{
    return conf_tracing_kernel_partial;
}

inline int tracing_kernel()
{
    return conf_tracing_kernel_all || conf_tracing_kernel_partial ||
        conf_tracing_kernel_tainted;
}

/* Print configuration variables */
void print_conf_vars()
{
  monitor_printf(
	default_mon,
      "TABLE_LOOKUP: %d\nTRACE_AFTER_FIRST_TAINT: %d\nLOG_EXTERNAL_CALLS: %d\nWRITE_OPS_AT_INSN_END: %d\nSAVE_STATE_AT_TRACE_START: %d\nSAVE_STATE_AT_TRACE_STOP: %d\nPROTOS_IGNOREDNS: %d\nTAINTED_ONLY: %d\nSINGLE_THREAD_ONLY: %d\nTRACING_KERNEL_ALL: %d\nTRACING_KERNEL_TAINTED: %d\nTRACING_KERNEL_PARTIAL: %d\nDETECT_MEMORY_EXCEPTION: %d\nDETECT_NULL_POINTER: %d\nDETECT_PROCESS_EXIT: %d\nDETECT_TAINTED_EIP: %d\n",
      tracing_table_lookup,
      conf_trace_only_after_first_taint,
      conf_log_external_calls,
      conf_write_ops_at_insn_end,
      conf_save_state_at_trace_start,
      conf_save_state_at_trace_stop,
      conf_ignore_dns, 
      conf_tainted_only,
      conf_single_thread_only,
      conf_tracing_kernel_all,
      conf_tracing_kernel_tainted,
      conf_tracing_kernel_partial,
      conf_detect_memory_exception,
      conf_detect_null_pointer,
      conf_detect_process_exit,
      conf_detect_tainted_eip
  );
}

/* Parse network filter configuration */
void check_filter_conf(struct cnfnode *cn_root) {
#if TAINT_ENABLED
  struct cnfresult *cnf_res;

  /* Transport */
  cnf_res = cnf_find_entry(cn_root, "network/filter_transport");
  if (cnf_res) {
    update_nic_filter("proto",cnf_res->cnfnode->value);
  }
  /* Source port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_sport");
  if (cnf_res) {
    update_nic_filter("sport",cnf_res->cnfnode->value);
  }
  /* Destination port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_dport");
  if (cnf_res) {
    update_nic_filter("dport",cnf_res->cnfnode->value);
  }
  /* Source addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_saddr");
  if (cnf_res) {
    update_nic_filter("src",cnf_res->cnfnode->value);
  }
  /* Destination addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_daddr");
  if (cnf_res) {
    update_nic_filter("dst",cnf_res->cnfnode->value);
  }
#endif  
  
}


