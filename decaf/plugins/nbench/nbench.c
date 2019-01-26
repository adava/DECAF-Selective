/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Sina Davanian
 * @date July 23 2018
 */

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "shared/vmi_callback.h"
#include "utils/Output.h"

//basic stub for plugins
static plugin_interface_t nbench_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle randHook_handle = DECAF_NULL_HANDLE;
DECAF_Handle keystroke_cb_handle = DECAF_NULL_HANDLE;
static int taint_key_enabled=0;

static uint8_t mode = -1;
static uint8_t debug_mode = 0;
static char *targetname="nbench.exe";
static uint32_t targetpid;
static uint32_t targetcr3 = 0;
time_t current_time;
time_t later_time;
time_t diff_time;
char* c_time_string;
struct timespec start, end;
static uint32_t cond_func_hook_handle = 0;

FILE *fp=NULL; //sina
static uint32_t counter_rand = 0; //sina
static unsigned long counter_start = 0;
static unsigned long counter_btaints = 0;
static unsigned long calls=0;
static uint32_t random_chance=0;
static target_ulong gvaaddr;

void rand_hook_logic(DECAF_Callback_Params *opaque)
{
	target_ulong pc_from = 0x00403037; //sina: randnum
	target_ulong pc_from2 = 0x00402F71; //sina: hook 2 (inlined randnum)
	target_ulong pc_from3 = 0x00402f80;
	uint32_t random_num1 =0;
	uint32_t buf;
	if(targetcr3==cpu_single_env->cr[3] && (opaque->be.cur_pc==pc_from || opaque->be.cur_pc==pc_from2 || opaque->be.cur_pc==pc_from3))
	{
		if (debug_mode){
			DECAF_printf("randnum eax=0x%x\n",cpu_single_env->regs[0]);
		}

		counter_start++;
		if(counter_rand==0){
			if(random_chance!=0){
				random_num1 = rand()%random_chance;
			}
			else{
				DECAF_printf("random_chance is not initialized, issue nbench_cmd again\n");
				hookapi_remove_hook(randHook_handle);
			}
			if(random_num1==1){
				calls++;
				taint_reg(opaque->be.env,R_EAX);
			}
		}
		else if(counter_start%counter_rand==0){
			calls++;
			taint_reg(opaque->be.env,R_EAX);
		}
		//hookapi_remove_hook(randHook_handle);
	}
}

void hook_memAlloc(DECAF_Callback_Params *opaque)
{
	target_ulong page, phys_addr;
	target_ulong pc_from = 0x00409F94; //sina: Allocatemem ret address
	target_ulong pc_to = 0x00407FF9;
	target_ulong buf;
	if(targetcr3==cpu_single_env->cr[3] && (opaque->be.cur_pc==pc_from))
	{
				gvaaddr = cpu_single_env->regs[0];
				if (debug_mode==2){
					page = cpu_single_env->regs[0] & TARGET_PAGE_MASK;
					phys_addr = DECAF_get_phys_addr(cpu_single_env, page);
					phys_addr = phys_addr + (cpu_single_env->regs[0] & ~TARGET_PAGE_MASK);
					DECAF_read_mem(cpu_single_env,cpu_single_env->regs[0],10,&buf);
					DECAF_printf("memAlloc eax (gvaaddr for allocated array)=0x%x, phys_addr=0x%x, value at gvaaddr=0x%x\n",cpu_single_env->regs[0],phys_addr,&buf);
				}

	}
}

void hook_DonNumIter_printarray(DECAF_Callback_Params *opaque) //sina: this function was used to check whether the identified gvaddr indeed will containt the generated random values
{
	target_ulong page, phys_addr;
	target_ulong vaddr = cpu_single_env->regs[3]; //at the beginning of this loop EBX contains the arraybase address
	uint32_t size = 4*cpu_single_env->regs[0];
	uint32_t *buf= (uint32_t *) malloc(size);
	target_ulong pc_from = 0x00403E53; //sina: Allocatemem ret address
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from))
	{
				page = vaddr & TARGET_PAGE_MASK;
				phys_addr = DECAF_get_phys_addr(cpu_single_env, page);
				phys_addr = phys_addr + (vaddr & ~TARGET_PAGE_MASK);
				DECAF_read_mem(cpu_single_env,vaddr,size,buf);
				DECAF_printf("vaddr=0x%x, phys_addr=0x%x, value=0x%x\n",vaddr,phys_addr,&buf);
	}
}

void hook_DonNumIter_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x00403E6E; //sina: the block after the array is fully loaded
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for NumSort\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

void hook_DoStrIter_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x004039E9; //sina: the block where second time DoStringIteration is executed in loop
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for StringSort\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

void hook_DoBFIter_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x00403D41; //sina: the block where second time DoStringIteration is executed in loop
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for BF\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

void hook_DoFPE_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x004026D1; //sina: the block right after the load loop
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for FPE\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

void hook_DoIDEA_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x00408EF1; //sina: the block where plain1 text is loaded with random strings
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for IDEA\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

void hook_DoHUF_taintArray(DECAF_Callback_Params *opaque)
{
	target_ulong phys_addr;
	target_ulong pc_from = 0x004093B4; //sina: the block where plain text is loaded with random strings
	uint8_t taint = 0xff;
	if(targetcr3==cpu_single_env->cr[3] && (cpu_single_env->eip==pc_from) && gvaaddr)
	{
				phys_addr = DECAF_get_phys_addr(cpu_single_env, gvaaddr);
				if (debug_mode){
					DECAF_printf("tainting vaddr=0x%x, phys_addr=0x%x for HUFFMAN\n",gvaaddr,phys_addr);
				}
				taint_mem(phys_addr,counter_btaints,&taint);
				gvaaddr = 0;
	}
}

static void createproc_callback(VMI_Callback_Params* params)
{
	//target_ulong pc = 0x00403EB0; //sina: this is what disassembly and debugging suggests
	//target_ulong pc_tb = 0x0040302B; //sina: turned out, the address in the analyzed version is actually 0x00402fe0. Since we are interested in return, the address is what you see for the last block in randnum
	target_ulong pc_from = 0x00403037; //sina: randnum
	target_ulong pc_from2 = 0x00402F20; //sina: hook 2 (inlined randnum)
	target_ulong pc_from3 = 0x00402f80; //sina: hook 3 (inlined randnum) for stringsorrt
	target_ulong pc_allocmemret = 0x00409F94; //sina: Allocatemem ret address
	target_ulong pc_allocmemret_to = 0x00407FF9;
	target_ulong pc_DoNumIterationLoopbeginToCallRandNum = 0x00403E53;
	target_ulong pc_DoNumIterationLoopLoadAfter = 0x00403E6E;//sina: the block right after the load loop
	target_ulong pc_DoStrIterationLoopLoadAfter = 0x004039E9;//sina: the block right after the load loop
	target_ulong pc_DoBFIterLoopLoadAfter = 0x00403D41;//sina: the block right after the load loop
	target_ulong pc_DoFPEIterationLoopLoadAfter = 0x004026D1;//sina: the block right after the load loop
	target_ulong pc_DoIDEAIterationLoopLoadAfter = 0x00408EF1;//sina: the block right after the load loop
	target_ulong pc_DoHUFIterationLoopLoadAfter = 0x004093B4;//sina: the block right after the load loop
    if(targetcr3 != 0) //if we have found the process, return immediately
    	return;

	if (strcasecmp(targetname, params->cp.name) == 0) {
		targetpid = params->cp.pid;
		targetcr3 = params->cp.cr3;
		DECAF_printf("Process found: pid=%d, cr3=%08x\n", targetpid, targetcr3);
		//clock_gettime(CLOCK_REALTIME, &proc_start_time);
		//DECAF_registerOptimizedBlockBeginCallback(hook_DonNumIter_printarray, NULL, pc_DoNumIterationLoopbeginToCallRandNum, OCB_CONST);
		if (mode){
			DECAF_registerOptimizedBlockEndCallback(hook_memAlloc,NULL,pc_allocmemret,INV_ADDR);
			DECAF_registerOptimizedBlockBeginCallback(hook_DonNumIter_taintArray, NULL, pc_DoNumIterationLoopLoadAfter, OCB_CONST);
			DECAF_registerOptimizedBlockBeginCallback(hook_DoStrIter_taintArray, NULL, pc_DoStrIterationLoopLoadAfter, OCB_CONST);
			DECAF_registerOptimizedBlockBeginCallback(hook_DoBFIter_taintArray, NULL, pc_DoBFIterLoopLoadAfter, OCB_CONST);
			DECAF_registerOptimizedBlockBeginCallback(hook_DoFPE_taintArray, NULL, pc_DoFPEIterationLoopLoadAfter, OCB_CONST);
			DECAF_registerOptimizedBlockBeginCallback(hook_DoIDEA_taintArray, NULL, pc_DoIDEAIterationLoopLoadAfter, OCB_CONST);
			DECAF_registerOptimizedBlockBeginCallback(hook_DoHUF_taintArray, NULL, pc_DoHUFIterationLoopLoadAfter, OCB_CONST);
		}
		else{
			//good for Random testing
			DECAF_registerOptimizedBlockEndCallback(rand_hook_logic,NULL,pc_from,INV_ADDR);
			DECAF_registerOptimizedBlockEndCallback(rand_hook_logic,NULL,pc_from2,INV_ADDR);
			DECAF_registerOptimizedBlockEndCallback(rand_hook_logic,NULL,pc_from3,INV_ADDR);
			//randHook_handle = hookapi_hook_function(0, pc , targetcr3, rand_hook_logic, NULL, 0);
			//DECAF_registerMatchBlockEndCallback(rand_hook_logic,NULL,pc_from,INV_ADDR);
		}
	}
}


static void removeproc_callback(VMI_Callback_Params* params)
{
    unsigned long s;
    double ms;
	if (targetpid == params->cp.pid && targetcr3 == params->cp.cr3) { //Stop the test when the monitored process terminates
//		clock_gettime(CLOCK_REALTIME, &proc_end_time); //sina: measuring the transition overhead
//		s = proc_end_time.tv_sec - proc_start_time.tv_sec;
//		ms =  (proc_end_time.tv_nsec - proc_start_time.tv_nsec)/ 1.0e6;
		//DECAF_printf("addr=0x%x, and leaving = %u, entering = %u in taint_io_read, softmmu_taint_template.h!\n", addr, leaving_1cache, entering_2cache);

//		DECAF_printf("exec_time is s = %lu and ms = %f, overall_overhead= %f  in taint_io_read, softmmu_taint_template.h!\n", s, ms, transition_overhead);
	}
}


static void nbench_cmd(Monitor* mon, const QDict* qdict)
{
	mode = 0;
	if ((qdict != NULL) && (qdict_haskey(qdict, "counter"))) {
		counter_rand = qdict_get_int(qdict, "counter");
	}
	if ((qdict != NULL) && (qdict_haskey(qdict, "randchance"))) {
		random_chance = qdict_get_int(qdict, "randchance");
	}
}


static void nbench(Monitor* mon, const QDict* qdict)
{
	mode = 1;
	if ((qdict != NULL) && (qdict_haskey(qdict, "counter"))) {
		counter_btaints = qdict_get_int(qdict, "counter");
	}
}

static void nbench_debug(Monitor* mon, const QDict* qdict)
{
	if ((qdict != NULL) && (qdict_haskey(qdict, "mode"))) {
		debug_mode = qdict_get_int(qdict, "mode");
	}
}

static void nbench_counter(Monitor* mon, const QDict* qdict)
{
	//DECAF_printf("Random num1=%d\n, Random num2=%d", random_num1,random_num2);
	if (!mode){
		DECAF_printf("Stats: called=%lu, hooked=%lu\n", counter_start,calls);
	}
}

static void tracing_send_keystroke(DECAF_Callback_Params *params)
{
  if(!taint_key_enabled)
	  return;

  int keycode=params->ks.keycode;
  uint32_t *taint_mark=params->ks.taint_mark;
  *taint_mark=taint_key_enabled;
  taint_key_enabled=0;
  printf("taint keystroke %d \n ",keycode);
}

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

    do_send_key(qdict_get_str(qdict, "key"));

  }
  else
    monitor_printf(mon, "taint_sendkey command is malformed\n");
}


static int nbench_init(void)
{
	srand((unsigned)time(&current_time));
	DECAF_printf("nbench init...\n");
	//register for process create and process remove events
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
			&createproc_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB,
			&removeproc_callback, NULL);
	if ((processbegin_handle == DECAF_NULL_HANDLE)
			|| (removeproc_handle == DECAF_NULL_HANDLE)) {
		DECAF_printf(
				"Could not register for the create or remove proc events\n");
	}
	return (0);
}

static void nbench_cleanup(void)
{
	// procmod_Callback_Params params;

	DECAF_printf("Bye world\n");

	if (processbegin_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_CREATEPROC_CB,
				processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}

	if (removeproc_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
		removeproc_handle = DECAF_NULL_HANDLE;
	}
	if (blockbegin_handle != DECAF_NULL_HANDLE) {
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
		blockbegin_handle = DECAF_NULL_HANDLE;
	}

}

static mon_cmd_t performance_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	nbench_interface.mon_cmds = performance_term_cmds;
	nbench_interface.plugin_cleanup = &nbench_cleanup;

	//initialize the plugin
	nbench_init();
	return (&nbench_interface);
}

