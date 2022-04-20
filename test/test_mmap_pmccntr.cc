#include<sys/mman.h>
#include<cstring>
#include<iostream>
#include<sstream>
#include<array>
#include<assert.h>

using namespace std;

constexpr int kPagesize = 1024;

array<char*,2> execution_code_pages_;
int code_pages_last_written_index_[2];
void reset() {
  code_pages_last_written_index_[0] = 0;
  code_pages_last_written_index_[1] = 0;
}
void AddInstructionToCodePage(int codepage_no, const char* instruction_bytes, size_t instruction_length) {
  instruction_length--;
  size_t page_idx = code_pages_last_written_index_[codepage_no];
  // page_idx == kPageSize means code page is full
  if (page_idx + instruction_length > kPagesize) {
    std::stringstream sstream;
    sstream << "Problematic code page is at address 0x"
            << std::hex << reinterpret_cast<int64_t>(execution_code_pages_[codepage_no]);
    cout << (sstream.str()) << endl;
    cout << ("Generated code exceeds page boundary\n");
    std::abort();
  }

  assert(codepage_no < static_cast<int>(execution_code_pages_.size()));
  memcpy(execution_code_pages_[codepage_no] + page_idx, instruction_bytes, instruction_length);
  code_pages_last_written_index_[codepage_no] = page_idx + instruction_length;
}

void AddSerializePrologToCodePage(int codepage_no) {
  // insert CPUID to serialize instruction stream
  constexpr char INST_DSB_ISH[] = "\x9f\x3b\x03\xd5";
  constexpr char INST_ISB[] = "\xdf\x3f\x03\xd5";
  AddInstructionToCodePage(codepage_no, INST_DSB_ISH, sizeof(INST_DSB_ISH));
  AddInstructionToCodePage(codepage_no, INST_ISB, sizeof(INST_ISB));
}

void AddSerializeEpilogToCodePage(int codepage_no) {
  // insert CPUID to serialize instruction stream
  constexpr char INST_DSB_ISH[] = "\x9f\x3b\x03\xd5";
  constexpr char INST_ISB[] = "\xdf\x3f\x03\xd5";
  AddInstructionToCodePage(codepage_no, INST_ISB, sizeof(INST_ISB));
  AddInstructionToCodePage(codepage_no, INST_DSB_ISH, sizeof(INST_DSB_ISH));
}

void AddTimerStartToCodePage(int codepage_no) {
  constexpr char INST_MRS_X10_PMCCNTR_EL0[] = "\x0a\x9d\x3b\xd5";
  AddSerializePrologToCodePage(codepage_no);
  // move result to R10 s.t. we can use it later in AddTimerEndToCodePage
  AddInstructionToCodePage(codepage_no, INST_MRS_X10_PMCCNTR_EL0, sizeof(INST_MRS_X10_PMCCNTR_EL0));
}

void AddLoop(int codepage_no) {
  constexpr char INST_SUB_X0_X0_1[] = "\x00\x04\x00\xd1";
  constexpr char INST_CBZ_X0_4[] = "\xe0\xff\xff\xb5";

  AddInstructionToCodePage(codepage_no, INST_SUB_X0_X0_1, sizeof(INST_SUB_X0_X0_1));
  AddInstructionToCodePage(codepage_no, INST_CBZ_X0_4, sizeof(INST_CBZ_X0_4));
}

void AddTimerEndToCodePage(int codepage_no) {
  constexpr char INST_MRS_X11_PMCCNTR_EL0[] = "\x0b\x9d\x3b\xd5";

  constexpr char INST_MOV_X0_X10[] = "\xe0\x03\x0a\xaa";
  constexpr char INST_MOV_X1_X11[] = "\xe1\x03\x0b\xaa";
  constexpr char INST_SUB_X2_X1_X0[] = "\x22\x00\x00\xcb";

  constexpr char INST_RESULT[] = "\x00\x05\x00\xa9\x02\x09\x00\xf9";
  constexpr char INST_RET[] = "\xc0\x03\x5f\xd6";
  
  
  AddSerializeEpilogToCodePage(codepage_no);

  AddInstructionToCodePage(codepage_no, INST_MRS_X11_PMCCNTR_EL0, sizeof(INST_MRS_X11_PMCCNTR_EL0));

  AddInstructionToCodePage(codepage_no, INST_MOV_X0_X10, sizeof(INST_MOV_X0_X10));
  AddInstructionToCodePage(codepage_no, INST_MOV_X1_X11, sizeof(INST_MOV_X1_X11));
  AddInstructionToCodePage(codepage_no, INST_SUB_X2_X1_X0, sizeof(INST_SUB_X2_X1_X0));
  // AddSerializeEpilogToCodePage(codepage_no);
  AddInstructionToCodePage(codepage_no, INST_RESULT, sizeof(INST_RESULT));
  AddInstructionToCodePage(codepage_no, INST_RET, sizeof(INST_RET));
}
 

struct Time{
  long long st;
  long long ed;
  long long du;
};
int main() {
  
  execution_code_pages_[0] = static_cast<char*>(mmap(nullptr,
                                                      kPagesize,
                                                      PROT_READ | PROT_WRITE | PROT_EXEC,
                                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                                      -1,
                                                      0));
  if (execution_code_pages_[0] == MAP_FAILED) {
    cout << ("Couldn't allocate memory for execution (exec memory). Aborting!\n");
    std::exit(1);
  }
  
  long long last_du = 0;
  for(long long i = 1; i < 100000000000; i*=2) {  
      reset();
      AddTimerStartToCodePage(0);
      AddLoop(0);
      AddTimerEndToCodePage(0);
      __builtin___clear_cache(execution_code_pages_[0], execution_code_pages_[0]+kPagesize);

      auto f = (Time(*)(long long))execution_code_pages_[0];
      Time time = f(i);
      cout << i << ' ' << time.st << ' ' << time.ed << ' ' << time.du << ' ' << (last_du + i) - time.du << '\n'; 
      last_du = time.du;
  }
}