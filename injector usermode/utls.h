#pragma once
#include "crypter.h"

#include "lazy_importer.h"

unsigned long long GetModuleBaseAddress(unsigned long procId, const wchar_t* modName);
unsigned long long get_var_offset(void* var);
unsigned long long get_updated_var(void* var);
