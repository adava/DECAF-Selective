/* 
   Tracecap is owned and copyright (C) BitBlaze, 2007-2010.
   All rights reserved.
   Do not copy, disclose, or distribute without explicit written
   permission. 

   Author: Juan Caballero <jcaballero@cmu.edu>
*/
#ifndef _TRACE_H_
#define _TRACE_H_

#include <inttypes.h>
/* AWH - Conflict between BFD and QEMU's fpu/softfloat.h */
#ifdef INLINE
#undef INLINE
#endif /* INLINE */
//#include "DECAF_lib.h"
#include "DECAF_main.h" // AWH

/* Starting origin for network connections */
#define TAINT_ORIGIN_START_TCP_NIC_IN 10000
#define TAINT_ORIGIN_START_UDP_NIC_IN 11000
#define TAINT_ORIGIN_MODULE           20000
#define MAX_NUM_TAINTBYTE_RECORDS 3

typedef struct _taint_byte_record {
  uint32_t source;              // Tainted data source (network,keyboard...)
  uint32_t origin;              // Identifies a network flow
  uint32_t offset;              // Offset in tainted data buffer (network)
} TaintByteRecord;

#define TAINT_RECORD_FIXED_SIZE 1

typedef struct _taint_record {
  uint8_t numRecords;          // How many TaintByteRecord currently used
  TaintByteRecord taintBytes[MAX_NUM_TAINTBYTE_RECORDS];
} taint_record_t;


typedef struct _trace_header {
  int magicnumber;
  int version;
  int n_procs;
  uint32_t gdt_base;
  uint32_t idt_base;
} TraceHeader;

/* Structure to hold trace statistics */
struct trace_stats {
  uint64_t insn_counter_decoded; // Number of instructions decoded
  uint64_t insn_counter_traced; // Number of instructions written to trace
  uint64_t insn_counter_traced_tainted; // Number of tainted instructions written to trace
  uint64_t operand_counter;      // Number of operands decoded
};

/* Exported variables */
extern int received_tainted_data;

#endif // _TRACE_H_

