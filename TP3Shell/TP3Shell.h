#pragma once
#include <Windows.h>
#include <map>
#include <stdint.h>
#include <vector>

#include "TP3ShellInfo.h"

#include "compress/compress.h"

#include "PEImage.h"

namespace tp3shell {
typedef struct _TP3_IMPORT_SYMBOL_INFO {
  uint32_t ModuleNameOffset;
  uint32_t Field_04;
  uint64_t SymbolHash;
} TP3_IMPORT_SYMBOL_INFO;

typedef struct _TP3_ORIGINAL_SECTION_INFO {
  IMAGE_SECTION_HEADER section;
  uint32_t Field_2C;
  uint32_t OriginalVirtualAddress;
  uint32_t OriginalSizeOfRawData;
  uint32_t LastOffset;
} TP3_ORIGINAL_SECTION_INFO;

typedef struct _TP3_8EF4127CF77ECA3DDB612FCF233DC3A8 {
  uint32_t SymbolInfoOffset;
  uint32_t Address;
} TP3_8EF4127CF77ECA3DDB612FCF233DC3A8;

class Unpacker {
public:
  Unpacker();
  ~Unpacker();

  int doit(const char *file);

private:
  bool BuildDLLSymbolHashTable(const char *moduleName);
  std::pair<uint16_t, std::string> GetSymbolByHash(const char *moduleName,
                                                   uint64_t hash);

  int PrebuildDLLSymbolHashTable(std::vector<std::string> &importModuleList);

  int LoadShellInfo(PEImage &pe);
  int DepackSection(BYTE *base);
  int SearchDetailInfoOffset(PEImage &pe, uint32_t &off1, uint32_t &off2);
  int DecryptOriginalSectionInfo(PEImage &pe, uint32_t off);
  int DepackRemainSection(PEImage &pe);
  int HandleIAT(PEImage &pe, uint32_t off,
                std::vector<IMPORT_ADDRESS_INFO> &vecImportAddressInfo);

private:
  TP3SHELLINFO ShellInfo;
  tp3shell::compress::CompressType Compress;
  std::map<uint64_t, std::map<uint64_t, std::pair<uint16_t, std::string>>>
      DllSymbolHashMap;
};
} // namespace tp3shell
