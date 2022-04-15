// Copyright 2021 Daniel Weber, Ahmad Ibrahim, Hamed Nemati, Michael Schwarz, Christian Rossow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//     limitations under the License.


#include "executor.h"

#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <sstream>

#include "code_generator.h"
#include "logger.h"

namespace osiris {

Executor::Executor() {
  // allocate memory for memory accesses during execution
  for (size_t i = 0; i < execution_data_pages_.size(); i++) {
    void* addr = reinterpret_cast<void*>(kMemoryBegin + i * kPagesize);
    // check that page is not mapped
    int ret = msync(addr, kPagesize, 0);
    if (ret != -1 || errno != ENOMEM) {
      LOG_ERROR("Execution page is already mapped. Aborting!");
      std::exit(1);
    }
    char* page = static_cast<char*>(mmap(addr,
                                         kPagesize,
                                         PROT_READ | PROT_WRITE,
                                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                         -1,
                                         0));

    if (page != reinterpret_cast<void*>(kMemoryBegin + i * kPagesize) || page == MAP_FAILED) {
      LOG_ERROR("Couldn't allocate memory for execution (data memory). Aborting!");
      std::exit(1);
    }
    execution_data_pages_[i] = page;
  }

  // allocate memory that holds the actual instructions we execute
  for (size_t i = 0; i < execution_code_pages_.size(); i++) {
    execution_code_pages_[i] = static_cast<char*>(mmap(nullptr,
                                                       kPagesize,
                                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                                       MAP_PRIVATE | MAP_ANONYMOUS,
                                                       -1,
                                                       0));
    if (execution_code_pages_[i] == MAP_FAILED) {
      LOG_ERROR("Couldn't allocate memory for execution (exec memory). Aborting!");
      std::exit(1);
    }
  }

#if DEBUGMODE == 0
  // if we are not in DEBUGMODE this will instead be inlined in Executor::ExecuteCodePage()
  std::array<int, 4> signals_to_handle = {SIGSEGV, SIGILL, SIGFPE, SIGTRAP};
  // register fault handler
  RegisterFaultHandler<signals_to_handle.size()>(signals_to_handle);
#endif
}

Executor::~Executor() {
#if DEBUGMODE == 0
  // if we are not in DEBUGMODE this will instead be inlined in Executor::ExecuteCodePage()
  std::array<int, 4> signals_to_handle = {SIGSEGV, SIGILL, SIGFPE, SIGTRAP};
  UnregisterFaultHandler<signals_to_handle.size()>(signals_to_handle);
#endif
}

int Executor::TestResetSequence(const byte_array& trigger_sequence,
                                const byte_array& measurement_sequence,
                                const byte_array& reset_sequence,
                                int no_testruns,
                                int reset_executions_amount,
                                int64_t* cycles_difference) {
  byte_array nop_sequence = CreateSequenceOfNOPs(reset_sequence.size());
  std::vector<int64_t> clean_runs;
  std::vector<int64_t> noisy_runs;
  clean_runs.reserve(no_testruns);
  noisy_runs.reserve(no_testruns);

  // intuition:
  //  given a valid measure and trigger sequence:
  //  when reset;measure == trigger;reset;measure (or very small diff) -> reset sequence works
  CreateResetTestrunCode(0, nop_sequence, measurement_sequence, reset_sequence,
                         reset_executions_amount);
  CreateResetTestrunCode(1, trigger_sequence, measurement_sequence, reset_sequence,
                         reset_executions_amount);
  for (int i = 0; i < no_testruns; i++) {
    // get timing with reset sequence
    uint64_t cycles_elapsed_reset_measure;
    int error = ExecuteTestrun(0, &cycles_elapsed_reset_measure);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }
    clean_runs.push_back(cycles_elapsed_reset_measure);
  }

  for (int i = 0; i < no_testruns; i++) {
    // get timing without reset sequence
    uint64_t cycles_elapsed_trigger_reset_measure;
    int error = ExecuteTestrun(1, &cycles_elapsed_trigger_reset_measure);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }
    noisy_runs.push_back(cycles_elapsed_trigger_reset_measure);
  }
  *cycles_difference = static_cast<int64_t>(median<int64_t>(clean_runs) -
      median<int64_t>(noisy_runs));
  return 0;
}

int Executor::TestSequenceTriple(const byte_array& trigger_sequence,
                                 const byte_array& measurement_sequence,
                                 const byte_array& reset_sequence,
                                 int no_testruns,
                                 int64_t* cycles_difference) {
  std::vector<int64_t> results;
  CreateTestrunCode(0, trigger_sequence, reset_sequence, measurement_sequence, 1);
  CreateTestrunCode(1, reset_sequence, trigger_sequence, measurement_sequence, 1);
  for (int i = 0; i < no_testruns; i++) {
    // get timing for first experiment
    uint64_t cycles_elapsed_trigger_reset;
    int error = ExecuteTestrun(0, &cycles_elapsed_trigger_reset);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }

    // get timing for second experiment
    uint64_t cycles_elapsed_reset_trigger;
    error = ExecuteTestrun(1, &cycles_elapsed_reset_trigger);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }
    int64_t cycles_difference_per_run = static_cast<int64_t>(cycles_elapsed_trigger_reset) -
        static_cast<int64_t>(cycles_elapsed_reset_trigger);
    results.push_back(cycles_difference_per_run);
  }
  *cycles_difference = static_cast<int64_t>(median<int64_t>(results));
  return 0;
}

int Executor::TestTriggerSequence(const byte_array& trigger_sequence,
                                  const byte_array& measurement_sequence,
                                  const byte_array& reset_sequence,
                                  bool execute_trigger_only_in_speculation,
                                  int no_testruns,
                                  int reset_executions_amount,
                                  int64_t* cycles_difference) {
  // disabled for performance reasons (on 2020-09-03 by Osiris dev)
  // can be enabled again without losing too much performance
  byte_array nop_sequence;// = CreateSequenceOfNOPs(trigger_sequence.size());

  // vectors are preallocated and just get cleared on everyrun for performance
  results_trigger.clear();
  results_notrigger.clear();
  results_trigger.reserve(no_testruns);
  results_notrigger.reserve(no_testruns);


  if (execute_trigger_only_in_speculation) {
    CreateSpeculativeTriggerTestrunCode(0, measurement_sequence,
                                        trigger_sequence,
                                        reset_sequence, reset_executions_amount);
    CreateSpeculativeTriggerTestrunCode(1, measurement_sequence,
                                        nop_sequence,
                                        reset_sequence, reset_executions_amount);
  } else {
    CreateTestrunCode(0, reset_sequence, trigger_sequence, measurement_sequence,
                      reset_executions_amount);
    CreateTestrunCode(1, reset_sequence, nop_sequence, measurement_sequence,
                      reset_executions_amount);
  }

  // get timing with trigger sequence
  for (int i = 0; i < no_testruns; i++) {
    uint64_t cycles_elapsed_trigger;
    int error = ExecuteTestrun(0, &cycles_elapsed_trigger);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }
    if (cycles_elapsed_trigger <= 5000) {
      results_trigger.emplace_back(cycles_elapsed_trigger);
    }
  }

  for (int i = 0; i < no_testruns; i++) {
    // get timing without trigger sequence
    uint64_t cycles_elapsed_notrigger;
    int error = ExecuteTestrun(1, &cycles_elapsed_notrigger);
    if (error) {
      // abort
      *cycles_difference = -1;
      return 1;
    }
    if (cycles_elapsed_notrigger <= 5000) {
      results_notrigger.emplace_back(cycles_elapsed_notrigger);
    }
  }
  double median_trigger = median<int64_t>(results_trigger);
  double median_notrigger = median<int64_t>(results_notrigger);
  *cycles_difference = static_cast<int64_t>(median_notrigger - median_trigger);
  return 0;
}

void Executor::CreateResetTestrunCode(int codepage_no, const byte_array& trigger_sequence,
                                      const byte_array& measurement_sequence,
                                      const byte_array& reset_sequence,
                                      int reset_executions_amount) {
  ClearDataPage();
  InitializeCodePage(codepage_no);

  // prolog
  AddProlog(codepage_no);
  AddInstructionToCodePage(codepage_no, trigger_sequence);

  AddSerializePrologToCodePage(codepage_no);

  // try to reset microarchitectural state again
  assert(reset_executions_amount <= 100);  // else we need to increase guardian stack space
  for (int i = 0; i < reset_executions_amount; i++) {
    AddInstructionToCodePage(codepage_no, reset_sequence);
  }
  AddSerializeEpilogToCodePage(codepage_no);

  // time measurement sequence
  AddTimerStartToCodePage(codepage_no);
  AddInstructionToCodePage(codepage_no, measurement_sequence);
  AddTimerEndToCodePage(codepage_no);

  // return timing result and epilog
  MakeTimerResultReturnValue(codepage_no);
  AddEpilog(codepage_no);

  // make sure that we do not exceed page boundaries
  assert(code_pages_last_written_index_[codepage_no] < kPagesize);
}

void Executor::CreateTestrunCode(int codepage_no, const byte_array& first_sequence,
                                 const byte_array& second_sequence,
                                 const byte_array& measurement_sequence,
                                 int first_sequence_executions_amount) {
  ClearDataPage();
  InitializeCodePage(codepage_no);

  // prolog
  AddProlog(codepage_no);
  AddSerializePrologToCodePage(codepage_no);

  // first sequence
  // if we need more we also have to increase the guardian stack space
  assert(first_sequence_executions_amount <= 100);
  for (int i = 0; i < first_sequence_executions_amount; i++) {
    AddInstructionToCodePage(codepage_no, first_sequence);
  }
  AddSerializeEpilogToCodePage(codepage_no);

  AddSerializePrologToCodePage(codepage_no);

  // second sequence
  AddInstructionToCodePage(codepage_no, second_sequence);
  AddSerializeEpilogToCodePage(codepage_no);

  // time measurement sequence
  AddTimerStartToCodePage(codepage_no);
  AddInstructionToCodePage(codepage_no, measurement_sequence);
  AddTimerEndToCodePage(codepage_no);

  // return timing result and epilog
  MakeTimerResultReturnValue(codepage_no);
  AddEpilog(codepage_no);

  // make sure that we do not exceed page boundaries
  assert(code_pages_last_written_index_[codepage_no] < kPagesize);
}

void Executor::CreateSpeculativeTriggerTestrunCode(int codepage_no,
                                                   const byte_array& measurement_sequence,
                                                   const byte_array& trigger_sequence,
                                                   const byte_array& reset_sequence,
                                                   int reset_executions_amount) {
  // call rel32
  constexpr char INST_RELATIVE_CALL[] = "\xe8\xff\xff\xff\xff";
  // jmp rel32
  constexpr char INST_RELATIVE_JMP[] = "\xe9\xff\xff\xff\xff";
  // lea rax, [rip + offset]
  constexpr char INST_LEA_RAX_DEREF_RIP_PLUS_OFFSET[] = "\x48\x8d\x05\xff\xff\xff\xff";
  // mov [rsp], rax
  constexpr char INST_MOV_DEREF_RSP_RAX[] = "\x48\x89\x04\x24";
  // ret
  constexpr char INST_RET[] = "\xc3";

  ClearDataPage();
  InitializeCodePage(codepage_no);

  // prolog
  AddProlog(codepage_no);
  AddSerializePrologToCodePage(codepage_no);

  // reset microarchitectural state sequence
  // if the number is higher we need to make sure that we have enough "unimportet guardian" stack space
  assert(reset_executions_amount <= 100);
  for (int i = 0; i < reset_executions_amount; i++) {
    AddInstructionToCodePage(codepage_no, reset_sequence);
  }
  AddSerializeEpilogToCodePage(codepage_no);


  //
  // use spectre-RSB to speculatively execute the trigger
  //

  // note that for all following calculations sizeof has the additional '\0', hence the - 1
  // we use this to generate a call which can be misprecided; target is behind the speculated code
  int32_t call_displacement = trigger_sequence.size() + sizeof(INST_RELATIVE_JMP) - 1;
  // we use this to redirect speculation to the same end as the manipulated stack
  int32_t jmp_displacement = sizeof(INST_LEA_RAX_DEREF_RIP_PLUS_OFFSET) - 1 +
      sizeof(INST_MOV_DEREF_RSP_RAX) - 1 + sizeof(INST_RET) - 1;
  // we use this to generate the actual address where we return and replace
  // the saved rip on the stack before calling RET
  int32_t lea_rip_displacement = sizeof(INST_MOV_DEREF_RSP_RAX) - 1 +
      sizeof(INST_RET) - 1;

  byte_array jmp_displacement_encoded = NumberToBytesLE(jmp_displacement, 4);
  byte_array call_displacement_encoded = NumberToBytesLE(call_displacement, 4);
  byte_array lea_rip_displacement_encoded = NumberToBytesLE(lea_rip_displacement, 4);

  // only place opcode and add offset manually
  AddInstructionToCodePage(codepage_no, INST_RELATIVE_CALL, 1);
  AddInstructionToCodePage(codepage_no, call_displacement_encoded);


  // speculation starts here as return address is mispredicted
  AddInstructionToCodePage(codepage_no, trigger_sequence);
  // this is still only accessible during speculation to redirect speculation to the correct jumpout
  // only place opcode and add offset manually
  AddInstructionToCodePage(codepage_no, INST_RELATIVE_JMP, 1);
  AddInstructionToCodePage(codepage_no, jmp_displacement_encoded);
  //
  // speculation ends here
  //


  // Target of CALL_DISPLACEMENT
  // change the return address on the stack to trigger the missspeculation of the RET
  // only place opcode and add offset manually
  AddInstructionToCodePage(codepage_no, INST_LEA_RAX_DEREF_RIP_PLUS_OFFSET,
                                      3);
  AddInstructionToCodePage(codepage_no, lea_rip_displacement_encoded);
  // wanted return address is now in RAX hence we can manipulate the stack now
  AddInstructionToCodePage(codepage_no, INST_MOV_DEREF_RSP_RAX,
                                      4);
  // return address was manipulated hence RET will return to the correct code but
  // will be mispredicted
  AddInstructionToCodePage(codepage_no, INST_RET, 1);

  // target of LEA_RIP_DISPLACEMENT (manipulated RET) and JMP_DISPLACEMENT
  // serialize after trigger
  //page_idx = AddSerializeInstructionToCodePage(page_idx, codepage_no);

  // time measurement sequence
  AddTimerStartToCodePage(codepage_no);
  AddInstructionToCodePage(codepage_no, measurement_sequence);
  AddTimerEndToCodePage(codepage_no);

  // return timing result and epilog
  MakeTimerResultReturnValue(codepage_no);
  AddEpilog(codepage_no);

  // make sure that we do not exceed page boundaries
  assert(code_pages_last_written_index_[codepage_no] < kPagesize);
}

int Executor::ExecuteTestrun(int codepage_no, uint64_t* cycles_elapsed) {
  return ExecuteCodePage(execution_code_pages_[codepage_no], cycles_elapsed);
}

void Executor::ClearDataPage() {
  for (const auto& datapage : execution_data_pages_) {
    memset(datapage, '\0', kPagesize);
  }
}

void Executor::InitializeCodePage(int codepage_no) {
  constexpr char INST_RET[] = "\xc0\x03\x5f\xd6";
  constexpr char INST_NOP[] = "\x1f\x20\x03\xd5";
  assert(codepage_no < static_cast<int>(execution_code_pages_.size()));
  // memset(execution_code_pages_[codepage_no], INST_NOP, kPagesize);
  code_pages_last_written_index_[codepage_no] = 0;
  for (size_t i = 0; i < kPagesize-4; i+=4)
  {
    AddInstructionToCodePage(codepage_no, INST_NOP, 4);
  }

  // add RET as last instruction (even though AddEpilog adds a RET it could happen that a
  // jump skips it)
  // execution_code_pages_[codepage_no][kPagesize - 1] = INST_RET;
  AddInstructionToCodePage(codepage_no, INST_RET, 4);
  // reset index to write
  code_pages_last_written_index_[codepage_no] = 0;
}

void Executor::AddProlog(int codepage_no) {
  // NOTE: everything in this function must be mirrored by AddEpilog
  constexpr char INST_PUSH_XRIGISTER[] = "\xe0\x07\xbf\xa9\xe2\x0f\xbf\xa9\xe4\x17\xbf\xa9\xe6\x1f\xbf\xa9\xe8\x27\xbf\xa9\xea\x2f\xbf\xa9\xec\x37\xbf\xa9\xee\x3f\xbf\xa9\xf0\x47\xbf\xa9\xf2\x4f\xbf\xa9\xf4\x57\xbf\xa9\xf6\x5f\xbf\xa9\xf8\x67\xbf\xa9\xfa\x6f\xbf\xa9\xfc\x77\xbf\xa9\xfe\x0f\x1f\xf8";
  constexpr char INST_PUSH_QRIGISTER[] = "\xe0\x07\xbf\xad\xe2\x0f\xbf\xad\xe4\x17\xbf\xad\xe6\x1f\xbf\xad\xe8\x27\xbf\xad\xea\x2f\xbf\xad\xec\x37\xbf\xad\xee\x3f\xbf\xad\xf0\x47\xbf\xad\xf2\x4f\xbf\xad\xf4\x57\xbf\xad\xf6\x5f\xbf\xad\xf8\x67\xbf\xad\xfa\x6f\xbf\xad\xfc\x77\xbf\xad\xfe\x7f\xbf\xad";
  constexpr char INST_PUSH_FPRIGISTER[] = "\x00\x44\x3b\xd5\x21\x44\x3b\xd5\xe0\x0f\x1f\xf8\xe1\x0f\x1f\xf8";
  constexpr char INST_MOV_FP_SP[] = "\xfd\x03\x00\x91";
  constexpr char INST_SUB_SP_0x1000[] = "\xff\x07\x40\xd1";


  // safe all callee-saved registers (according to System V amd64 ABI)
  AddInstructionToCodePage(codepage_no, INST_PUSH_XRIGISTER, sizeof(INST_PUSH_XRIGISTER));
  AddInstructionToCodePage(codepage_no, INST_PUSH_QRIGISTER, sizeof(INST_PUSH_QRIGISTER));
  AddInstructionToCodePage(codepage_no, INST_PUSH_QRIGISTER, sizeof(INST_PUSH_FPRIGISTER));

  // save stackpointer in RBP (in case some instruction changes the RSP value)
  AddInstructionToCodePage(codepage_no, INST_MOV_FP_SP, 3);

  // create room on stack that is big enough in case some instructions trashes stack values
  // (e.g. PUSH/POP)
  AddInstructionToCodePage(codepage_no, INST_SUB_SP_0x1000, sizeof(INST_SUB_SP_0x1000));

  // initialize registers R8, RAX, RDI, RSI, RDX and XMM0 to point to memory locations
  // NOTE: this must match the memory registers in the code generation
  // last 4 bytes encode the immediate in little endian
  
  constexpr char INST_MOV_X8_0xffffffff[] = "\xe8\x66\xa2\xd2";
  constexpr char INST_MOV_X0_0xffffffff[] = "\xe0\x66\xa2\xd2";
  constexpr char INST_MOV_X1_0xffffffff[] = "\xe1\x66\xa2\xd2";
  constexpr char INST_MOV_X2_0xffffffff[] = "\xe2\x66\xa2\xd2";
  constexpr char INST_MOV_X3_0xffffffff[] = "\xe3\x66\xa2\xd2";

  constexpr char INST_FMOV_X8_X0[] = "\x00\x01\x67\x9e";

  // add only the first 3 instruction bytes and add the encoded address manually
  AddInstructionToCodePage(codepage_no, INST_MOV_X8_0xffffffff, sizeof(INST_MOV_X8_0xffffffff));

  AddInstructionToCodePage(codepage_no, INST_MOV_X0_0xffffffff, sizeof(INST_MOV_X0_0xffffffff));

  AddInstructionToCodePage(codepage_no, INST_MOV_X1_0xffffffff, sizeof(INST_MOV_X1_0xffffffff));

  AddInstructionToCodePage(codepage_no, INST_MOV_X2_0xffffffff, sizeof(INST_MOV_X2_0xffffffff));

  AddInstructionToCodePage(codepage_no, INST_MOV_X3_0xffffffff, sizeof(INST_MOV_X3_0xffffffff));

  AddInstructionToCodePage(codepage_no, INST_FMOV_X8_X0, sizeof(INST_FMOV_X8_X0));
}

void Executor::AddEpilog(int codepage_no) {
  // NOTE: everything in this function must be mirrored by AddProlog
  constexpr char INST_CLD[] = "\xfc";
  constexpr char INST_POP_R15_R14_R13_R12[] = "\x41\x5f\x41\x5e\x41\x5d\x41\x5c";
  constexpr char INST_POP_RBP_RSP_RBX[] = "\x5d\x5c\x5b";
  constexpr char INST_MOV_RSP_RBP[] = "\x48\x89\xec";
  constexpr char INST_RET[] = "\xc3";
  constexpr char INST_ADD_RSP_0x8[] = "\x48\x83\xc4\x08";
  constexpr char INST_LDMXCSR_RSP[] = "\x0f\xae\x14\x24";
  constexpr char INST_FLDCW_RSP[] = "\xd9\x2c\x24";

  // System-V abi specifies that DF is always zero upon function return
  AddInstructionToCodePage(codepage_no, INST_CLD, 1);
  // restore stack
  AddInstructionToCodePage(codepage_no, INST_MOV_RSP_RBP, 3);

  // restore x87 FPU control word
  AddInstructionToCodePage(codepage_no, INST_FLDCW_RSP, 3);
  AddInstructionToCodePage(codepage_no, INST_ADD_RSP_0x8, 4);

  // restore MXCSR register
  AddInstructionToCodePage(codepage_no, INST_LDMXCSR_RSP, 4);
  AddInstructionToCodePage(codepage_no, INST_ADD_RSP_0x8, 4);

  // restore registers
  AddInstructionToCodePage(codepage_no, INST_POP_R15_R14_R13_R12, 8);
  AddInstructionToCodePage(codepage_no, INST_POP_RBP_RSP_RBX, 3);

  // insert return
  AddInstructionToCodePage(codepage_no, INST_RET, 1);
}

void Executor::AddSerializePrologToCodePage(int codepage_no) {
  // insert CPUID to serialize instruction stream
  constexpr char INST_DSB_ISH[] = "\x9f\x3b\x03\xd5";
  constexpr char INST_ISB[] = "\xdf\x3f\x03\xd5";
  AddInstructionToCodePage(codepage_no, INST_DSB_ISH, sizeof(INST_DSB_ISH));
  AddInstructionToCodePage(codepage_no, INST_ISB, sizeof(INST_ISB));
}

void Executor::AddSerializeEpilogToCodePage(int codepage_no) {
  // insert CPUID to serialize instruction stream
  constexpr char INST_DSB_ISH[] = "\x9f\x3b\x03\xd5";
  constexpr char INST_ISB[] = "\xdf\x3f\x03\xd5";
  AddInstructionToCodePage(codepage_no, INST_ISB, sizeof(INST_ISB));
  AddInstructionToCodePage(codepage_no, INST_DSB_ISH, sizeof(INST_DSB_ISH));
}

void Executor::AddTimerStartToCodePage(int codepage_no) {
  AddSerializePrologToCodePage(codepage_no);
  constexpr char INST_MRS_X10_PMCCNTR_EL0[] = "\x0a\x9d\x3b\xd5";
  // move result to R10 s.t. we can use it later in AddTimerEndToCodePage
  AddInstructionToCodePage(codepage_no, INST_MRS_X10_PMCCNTR_EL0, sizeof(INST_MRS_X10_PMCCNTR_EL0));
}

void Executor::AddTimerEndToCodePage(int codepage_no) {
  constexpr char INST_MRS_X11_PMCCNTR_EL0[] = "\x0b\x9d\x3b\xd5";
  constexpr char INST_SUB_X11_X11_X10[] = "\x6b\x01\x0a\xcb";

  AddInstructionToCodePage(codepage_no, INST_MRS_X11_PMCCNTR_EL0, sizeof(INST_MRS_X11_PMCCNTR_EL0));
  AddSerializeEpilogToCodePage(codepage_no);
  AddInstructionToCodePage(codepage_no, INST_SUB_X11_X11_X10, sizeof(INST_SUB_X11_X11_X10));
}

void Executor::AddInstructionToCodePage(int codepage_no,
                                          const char* instruction_bytes,
                                          size_t instruction_length) {
  size_t page_idx = code_pages_last_written_index_[codepage_no];
  // page_idx == kPageSize means code page is full
  if (page_idx + instruction_length > kPagesize) {
    std::stringstream sstream;
    sstream << "Problematic code page is at address 0x"
            << std::hex << reinterpret_cast<int64_t>(execution_code_pages_[codepage_no]);
    LOG_DEBUG(sstream.str());
    LOG_ERROR("Generated code exceeds page boundary");
    std::abort();
  }

  assert(codepage_no < static_cast<int>(execution_code_pages_.size()));
  memcpy(execution_code_pages_[codepage_no] + page_idx, instruction_bytes, instruction_length);
  code_pages_last_written_index_[codepage_no] = page_idx + instruction_length;
}

void Executor::AddInstructionToCodePage(int codepage_no,
                                          const byte_array& instruction_bytes) {
  size_t page_idx = code_pages_last_written_index_[codepage_no];
  if (page_idx + instruction_bytes.size() >= kPagesize) {
    std::stringstream sstream;
    sstream << "Problematic code page is at address 0x"
      << std::hex << reinterpret_cast<int64_t>(execution_code_pages_[codepage_no]);
    LOG_DEBUG(sstream.str());
    LOG_ERROR("Generated code exceeds page boundary (" +
      std::to_string(page_idx + instruction_bytes.size()) + "/" + std::to_string(kPagesize) + ")");
    std::abort();
  }

  size_t new_page_idx = page_idx;
  assert(codepage_no < static_cast<int>(execution_code_pages_.size()));
  for (std::byte b : instruction_bytes) {
    execution_code_pages_[codepage_no][new_page_idx] = std::to_integer<int>(b);
    new_page_idx++;
  }
  code_pages_last_written_index_[codepage_no] = new_page_idx;
}

void Executor::MakeTimerResultReturnValue(int codepage_no) {
  constexpr char MOV_X0_X11[] = "\xe0\x03\x0b\xaa";

  AddInstructionToCodePage(codepage_no, MOV_X0_X11, sizeof(MOV_X0_X11));
}

byte_array Executor::CreateSequenceOfNOPs(size_t length) {
  constexpr auto INST_NOP_AS_DECIMAL = static_cast<unsigned char>(0x90);
  byte_array nops;
  std::byte nop_byte{INST_NOP_AS_DECIMAL};
  for (size_t i = 0; i < length; i++) {
    nops.push_back(nop_byte);
  }
  return nops;
}

//
// fault handling logic
//
static jmp_buf fault_handler_jump_buf;

// Fault counters
static int sigsegv_no = 0;
static int sigfpe_no = 0;
static int sigill_no = 0;
static int sigtrap_no = 0;

void Executor::PrintFaultCount() {
  std::cout << "=== Faultcounters of Executor ===" << std::endl
            << "\tSIGSEGV: " << sigsegv_no << std::endl
            << "\tSIGFPE: " << sigfpe_no << std::endl
            << "\tSIGILL: " << sigill_no << std::endl
            << "\tSIGTRAP: " << sigtrap_no << std::endl
            << "=================================" << std::endl;
}

void Executor::FaultHandler(int sig) {
  // NOTE: this function and Executor::ExecuteCodePage must both be static functions
  //       for the signal handling + jmp logic to work
  switch (sig) {
    case SIGSEGV:sigsegv_no++;
      break;
    case SIGFPE:sigfpe_no++;
      break;
    case SIGILL:sigill_no++;
      break;
    case SIGTRAP:sigtrap_no++;
      break;
    default:std::abort();
  }

  // jump back to the previously stored fallback point
  longjmp(fault_handler_jump_buf, 1);
}

template<size_t size>
void Executor::RegisterFaultHandler(std::array<int, size> signals_to_handle) {
  for (int sig : signals_to_handle) {
    signal(sig, Executor::FaultHandler);
  }
}

template<size_t size>
void Executor::UnregisterFaultHandler(std::array<int, size> signals_to_handle) {
  for (int sig : signals_to_handle) {
    signal(sig, SIG_DFL);
  }
}

__attribute__((no_sanitize("address")))
int Executor::ExecuteCodePage(void* codepage, uint64_t* cycles_elapsed) {
  /// NOTE: this function and Executor::FaultHandler must both be static functions
  ///       for the signal handling + jmp logic to work


#if DEBUGMODE == 1
  // list of signals that we catch and throw as errors
  // (without DEBUGMODE the array is defined in the error case)
  std::array<int, 4> signals_to_handle = {SIGSEGV, SIGILL, SIGFPE, SIGTRAP};
  // register fault handler (if not in debugmode we do this in constructor/destructor as
  //    this has a huge impact on the runtime)
  RegisterFaultHandler<signals_to_handle.size()>(signals_to_handle);
#endif

  if (!setjmp(fault_handler_jump_buf)) {
    // jump to codepage
    uint64_t cycle_diff = ((uint64_t(*)()) codepage)();
    // set return argument
    *cycles_elapsed = cycle_diff;

#if DEBUGMODE == 1
    // unregister signal handler (if not in debugmode we do this in constructor/destructor as
    // this has a huge impact on the runtime)
    UnregisterFaultHandler<signals_to_handle.size()>(signals_to_handle);
#endif

    return 0;
  } else {
    // if we reach this; the code has caused a fault

    // unmask the signal again as we reached this point directly from the signal handler
#if DEBUGMODE == 0
    // only allocate the array in case of an error to safe execution time
    // list of signals that we catch and throw as errors
    std::array<int, 4> signals_to_handle = {SIGSEGV, SIGILL, SIGFPE, SIGTRAP};
#endif
    sigset_t signal_set;
    sigemptyset(&signal_set);
    for (int sig : signals_to_handle) {
      sigaddset(&signal_set, sig);
    }
    sigprocmask(SIG_UNBLOCK, &signal_set, nullptr);

#if DEBUGMODE == 1
    // unregister signal handler (if not in debugmode we do this in constructor/destructor as
    // this has a huge impact on the runtime)
    UnregisterFaultHandler<signals_to_handle.size()>(signals_to_handle);
#endif

    // report that we crashed
    *cycles_elapsed = -1;
    return 1;
  }
}

}  // namespace osiris
