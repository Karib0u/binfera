#pragma once
#include <string>
#include <cstdint>
namespace ghidra { class LoadImage; }
std::string binfera_sla();
void binfera_check();
bool binfera_jump_target_valid(ghidra::LoadImage *image, uint64_t function, uint64_t target);
