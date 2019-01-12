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
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "tracecap.h"
#include "bswap.h"
#include "shared/function_map.h"
#include "vmi_callback.h"
#include "vmi_c_wrapper.h"
#include "conf.h"
#include "conditions.h" // AWH


FILE *tracelog = 0;
FILE *tracenetlog = 0;
FILE *tracehooklog = 0;
FILE *calllog = 0;
FILE *alloclog = 0;
uint32_t tracepid = 0;
target_ulong tracecr3 = 0;
uint32_t dump_pc_start = 0;
int skip_decode_address = 0;
int skip_trace_write = 0;
unsigned int tracing_child = 0;
uint32_t insn_tainted=0;
extern int should_trace_all_kernel;

/* Filename for functions file */
char functionsname[128]= "";

/* Filename for trace file */
char tracename[128]= "";
char *tracename_p = tracename;


/* Start usage */
struct rusage startUsage;



int tracing_start(uint32_t pid, const char *filename)
{
  return 0;
}

void tracing_stop()
{

}

