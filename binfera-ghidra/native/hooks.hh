#pragma once
#include <string>
#include <cstdint>
namespace ghidra { class Funcdata; class LoadImage; class PcodeOp; }
std::string binfera_sla();
void binfera_check();
bool binfera_jump_target_valid(ghidra::LoadImage *image, uint64_t function, uint64_t target);
bool binfera_forwarded_return(ghidra::Funcdata &function, const ghidra::PcodeOp &ret, int slot);
