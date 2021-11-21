#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

#include "CEncodeBuffer.h"
#include "PEImage.h"
#include "TP3Shell.h"
#include "TP3ShellInfo.h"
#include "compress/aplib.h"
#include "crypto.h"
#include <fstream>
#include <map>

#include "compress/compress.h"
#include "compress/lz4.h"

namespace tp3shell {
namespace utils {
std::string GetRootPath() {
  char oldpath[MAX_PATH];
  std::string result;

  GetModuleFileNameA(NULL, oldpath, MAX_PATH);
  char *pFilePart1 = strrchr(oldpath, '\\');
  if (pFilePart1 != NULL) {
    *pFilePart1 = 0;
  }
  result = oldpath;

  return result;
}

void bar(const char *file, std::string &path, std::string &filename) {
  char szFullPath[MAX_PATH] = {};
  char *pFilePart = NULL;

  path = "";
  filename = "";

  GetFullPathNameA(file, MAX_PATH, szFullPath, &pFilePart);
  if (pFilePart != NULL) {
    filename = std::string(pFilePart);
    *pFilePart = 0;
  }

  if (filename.empty()) {
    filename = "TP3Shell";
  }
  path = szFullPath;
}
} // namespace utils
} // namespace tp3shell

namespace tp3shell {
using namespace tp3shell::compress;

Unpacker::Unpacker() : Compress(CompressType::None) {}

Unpacker::~Unpacker() {}

bool Unpacker::BuildDLLSymbolHashTable(const char *moduleName) {
  uint64_t hashModuleName = tp3shell::crypto::hash(moduleName);

  auto iter = DllSymbolHashMap.find(hashModuleName);
  if (iter != DllSymbolHashMap.end()) {
    return true;
  }
  std::map<uint64_t, std::pair<uint16_t, std::string>> hashtable;

  HMODULE hModule = LoadLibraryExA(moduleName, NULL, 0);
  if (hModule == NULL) {
    return false;
  }
  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;

#define RVA2Ptr(x) ((void *)((uint8_t *)pImageDosHeader + (x)))
  PIMAGE_DATA_DIRECTORY pIdd = NULL;
  PIMAGE_NT_HEADERS32 pImageNtHeader32 =
      (IMAGE_NT_HEADERS32 *)((uint8_t *)pImageDosHeader +
                             pImageDosHeader->e_lfanew);
  if (pImageNtHeader32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    return false;
  }

  pIdd = &pImageNtHeader32->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (pIdd->VirtualAddress != NULL && pIdd->Size != 0) {
    IMAGE_EXPORT_DIRECTORY *pImageExportDirectory =
        (IMAGE_EXPORT_DIRECTORY *)RVA2Ptr(pIdd->VirtualAddress);
    uint32_t *pNames =
        (uint32_t *)RVA2Ptr(pImageExportDirectory->AddressOfNames);
    uint16_t *pOrds =
        (uint16_t *)RVA2Ptr(pImageExportDirectory->AddressOfNameOrdinals);
    uint32_t *pFuncs =
        (uint32_t *)RVA2Ptr(pImageExportDirectory->AddressOfFunctions);

    for (size_t i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
      uint64_t hashFuncName = 0;
      const char *pszFuncName = NULL;
      pszFuncName = (const char *)RVA2Ptr(pNames[i]);

      hashFuncName = tp3shell::crypto::hash(pszFuncName);
      if (hashtable.find(hashFuncName) != hashtable.end()) {
        printf("[WARRING] %s\n", pszFuncName);
      }
      // pFuncs[pOrds[i]];
      hashtable[hashFuncName] = {i, pszFuncName};
      ;
    }

    for (size_t i = 0; i < pImageExportDirectory->NumberOfFunctions; i++) {
      uint64_t hashFuncName = 0;
      char pszOrdinal[0x10] = {};

      if (pFuncs[i] == 0) {
        continue;
      }
      uint16_t ordinal = (uint16_t)(pImageExportDirectory->Base + i);
      sprintf(pszOrdinal, "#%d", ordinal);

      hashFuncName = tp3shell::crypto::hash(pszOrdinal);
      auto it = hashtable.find(hashFuncName);
      if (it != hashtable.end()) {
        printf("[WARRING] %s\n", pszOrdinal);
      }
      hashtable[hashFuncName] = {ordinal, pszOrdinal};
    }
  }
#undef RVA2Ptr
  DllSymbolHashMap[hashModuleName] = hashtable;
  return true;
}

std::pair<uint16_t, std::string>
Unpacker::GetSymbolByHash(const char *moduleName, uint64_t hash) {
  uint64_t hashModuleName = tp3shell::crypto::hash(moduleName);

  auto iter = DllSymbolHashMap.find(hashModuleName);
  if (iter == DllSymbolHashMap.end()) {
    return {};
  }

  auto iter2 = iter->second.find(hash);
  if (iter2 == iter->second.end()) {
    return {};
  }

  return iter2->second;
}

int Unpacker::PrebuildDLLSymbolHashTable(
    std::vector<std::string> &importModuleList) {
  for (auto &s : importModuleList) {
    if (!BuildDLLSymbolHashTable(s.c_str())) {
      printf("\n\n[ERROR]  BuildDLLSymbolHashTable BOOM  %s\n\n", s.c_str());
    }
  }
  return 0;
}

int Unpacker::LoadShellInfo(PEImage &pe) {
  std::vector<uint8_t> shell_info;

  auto section = pe.GetSection(".tls");
  if (section == NULL) {
    return -1;
  }

  uint8_t *p = (uint8_t *)pe.RVA2Ptr(section->VirtualAddress);
  int magic = *(int32_t *)&p[4];

  Compress = magic2compresstype(magic);

  if (Compress == CompressType::LZ4) {
    shell_info = tp3uncompress(p, section->SizeOfRawData);
  } else {
    return -4;
  }

  if (!ShellInfo.Unmarshal(shell_info)) {
    return -3;
  }

  return 0;
}

int Unpacker::DepackSection(BYTE *base) {
  for (auto &t : ShellInfo.PackedSectionInfo.items) {
    BYTE *p = base + t.vaoff;
    uint32_t off = 0;
    uint32_t off_b = 0;
    std::vector<uint8_t> data(t.vasize);

    if (t.sizes.size() == 0) {
      return -1;
    }
    for (auto size : t.sizes) {
      std::vector<uint8_t> v;
      if (Compress == CompressType::LZ4) {
        int32_t uncompsize = *(int32_t *)&p[off];
        int32_t compsize = *(int32_t *)&p[off + 4];
        v = lz4::uncompress(p + off + 8, compsize, uncompsize);
      } else if (Compress == CompressType::AP32) {
        v = ap32::uncompress(p + off, size);
      }

      if (v.empty()) {
        return -1;
      }
      memcpy(&data[off_b], v.data(), v.size());
      off += size;
      off_b += v.size();
    }
    memcpy(p, data.data(), data.size());
  }
  return 0;
}

int Unpacker::SearchDetailInfoOffset(PEImage &pe, uint32_t &off1,
                                     uint32_t &off2) {
  off1 = off2 = 0;

  PIMAGE_SECTION_HEADER pSection = pe.GetLastSection();
  if (pSection == NULL) {
    return -1;
  }
  BYTE *beg = (BYTE *)pe.RVA2Ptr(pSection->VirtualAddress);
  BYTE *end = NULL;
  size_t koff = 0;

  do {
    size_t maxsize = 0;
    for (size_t i = koff; i < pSection->SizeOfRawData; i++) {
      if (Compress == CompressType::LZ4) {
        if (*(DWORD *)&beg[i] == lz4::magic) {
          maxsize = i - 4;
          koff = i + 4;
          break;
        }
      } else if (Compress == CompressType::AP32) {
        if (*(DWORD *)&beg[i] == ap32::magic) {
          maxsize = i - 4;
          koff = i + 4;
          break;
        }
      }
    }

    if (maxsize == 0) {
      return -1;
    }

    end = beg + maxsize;
    for (int i = 4; i < 0x100; i++) {
      uint32_t esize = (i ^ 0x44AA874D) + 0x7E76C424;
      if (*(DWORD *)&end[-i - 4] == esize) {
        off1 = pSection->VirtualAddress + maxsize - i - 4;
        off2 = pSection->VirtualAddress + maxsize;
        break;
      }
    }

    if (off1 != 0 || off2 != 0) {
      break;
    }
  } while (koff < pSection->SizeOfRawData);

  if (off1 != 0 || off2 != 0) {
    return 0;
  }

  return -1;
}

int Unpacker::DecryptOriginalSectionInfo(PEImage &pe, uint32_t off) {
  if (off == 0) {
    return -1;
  }

  while (off != 0) {
    CEncodeBuffer ebuf;

    TP3_ORIGINAL_SECTION_INFO info;

    if (!ebuf.decode((uint8_t *)pe.RVA2Ptr(off), info, off)) {
      return -2;
    }

    off = info.LastOffset;
  }
  return 0;
}

int Unpacker::DepackRemainSection(PEImage &pe) {
  size_t count = pe.GetCountOfSection();
  for (size_t i = 0; i < count; i++) {
    PIMAGE_SECTION_HEADER pImageSectionHeader = pe.GetSectionByIndex(i);
    if (pImageSectionHeader == NULL) {
      continue;
    }
    BYTE *p = (BYTE *)pe.RVA2Ptr(pImageSectionHeader->VirtualAddress);
    int magic = *(uint32_t *)&p[4];
    if (magic == lz4::magic || magic == ap32::magic) {
      auto r = tp3uncompress(p, pImageSectionHeader->SizeOfRawData);
      if (r.empty()) {
        return -1;
      }
      memcpy(p, r.data(), r.size());
    }
  }

  return 0;
}

int Unpacker::HandleIAT(
    PEImage &pe, uint32_t off,
    std::vector<IMPORT_ADDRESS_INFO> &vecImportAddressInfo) {
  if (off == 0) {
    return -1;
  }

  int offs[3] = {};

  for (size_t i = 0; i < 3; i++) {
    int32_t size = (*(int32_t *)pe.RVA2Ptr(off) + 0x749388AC) ^ 0x265E3862;
    if (size <= 0) {
      return -2;
    }
    offs[i] = off;
    off += 4 + size;
  }

  std::vector<uint8_t> moduleNamePool, importSymbolInfoPool, cryptedIndexesPool;

  moduleNamePool = tp3uncompress((uint8_t *)pe.RVA2Ptr(offs[0])); // MODULE_NAME
  importSymbolInfoPool = tp3uncompress((uint8_t *)pe.RVA2Ptr(
      offs[1])); // MODULE_NAME_OFFSET uint32_t FUNC_NAME_HASH
  cryptedIndexesPool = tp3uncompress((uint8_t *)pe.RVA2Ptr(offs[2]));

  int count = (*(int32_t *)&cryptedIndexesPool[0] - 0x7C68325A) ^ 0xAE92A541;
  uint32_t foff = 4;

  IMPORT_ADDRESS_INFO t;

  for (int i = 0; i < count; i++) {
    TP3_8EF4127CF77ECA3DDB612FCF233DC3A8 sa;

    CEncodeBuffer ebuf;
    if (!ebuf.decode(&cryptedIndexesPool[foff], sa, foff)) {
      return -3;
    }

    printf("[INFO] %08X %08X", sa.SymbolInfoOffset, sa.Address);

    TP3_IMPORT_SYMBOL_INFO *symbolInfo =
        (TP3_IMPORT_SYMBOL_INFO *)&importSymbolInfoPool[sa.SymbolInfoOffset];

    const char *pszModule =
        (const char *)&moduleNamePool[symbolInfo->ModuleNameOffset];

    if (!BuildDLLSymbolHashTable(pszModule)) {
      printf("\n\n[ERROR]  BuildDLLHashTable BOOM  %s.%016llX\n\n", pszModule,
             symbolInfo->SymbolHash);
      return -5;
    }
    auto funcName = GetSymbolByHash(pszModule, symbolInfo->SymbolHash);

    if (funcName.second.empty()) {
      printf("\n\n[WARRING] FUNC NOT FOUND\n\n");
    }
    printf("  %s.%016llX.%s\n", pszModule, symbolInfo->SymbolHash,
           funcName.second.c_str());

    if (t.ModuleName != pszModule || (t.items.back().Rva + 4) != sa.Address) {
      if (!t.ModuleName.empty()) {
        vecImportAddressInfo.push_back(t);
      }
      t = {};
      t.ModuleName = pszModule;
    }

    t.items.push_back(
        {sa.Address, funcName.first, funcName.first, funcName.second});

    foff += ebuf.getChunkSize() + 4;
  }
  return 0;
}

int Unpacker::doit(const char *file) {
  std::string oldpath;
  std::string path;
  std::string filename;

  PEImage peImageMaster(file); //.tp3:004E436A orig_entry_point:

  if (!peImageMaster.IsValid()) {
    printf("[ERROR] INVALID PE FILE\n");
    return -1;
  }

  oldpath = tp3shell::utils::GetRootPath();
  SetCurrentDirectoryA(oldpath.c_str());
  tp3shell::utils::bar(file, path, filename);

  auto vecImportDLL = peImageMaster.GetImportDllList();
  if (vecImportDLL.size() != 1) {
    printf("[ERROR] NOT TP3SHELL PACKED PE FILE\n");
    return -1;
  }

  PEImage peImageBase(path + vecImportDLL.front());
  if (!peImageBase.IsValid()) {
    printf("[ERROR] LOAD BASE\n");
    return -1;
  }

  int hResult = 0;

  hResult = LoadShellInfo(peImageBase);
  printf("LoadShellInfo: %d\n", hResult);
  if (hResult < 0) {
    return -1;
  }

  hResult = DepackSection((BYTE *)peImageMaster.GetImageDosHeader());
  printf("DepackSection: %d\n", hResult);
  if (hResult < 0) {
    return -1;
  }

  hResult = DepackRemainSection(peImageMaster);
  printf("tou: %d\n", hResult);
  if (hResult < 0) {
    return -1;
  }

  uint32_t off1 = 0;
  uint32_t off2 = 0;

  hResult = SearchDetailInfoOffset(peImageMaster, off1, off2);
  printf("SearchDetailInfoOffset: %d %08X %08X\n", hResult, off1, off2);
  if (hResult < 0) {
    return -1;
  }

  if (off1 != 0) {
    hResult = DecryptOriginalSectionInfo(peImageMaster, off1);
    printf("DecryptOriginalSectionInfo: %d\n", hResult);
    if (hResult < 0) {
      return -1;
    }
  }

  SetCurrentDirectoryA(path.c_str());

  PrebuildDLLSymbolHashTable(ShellInfo.ImportModuleList.items);

  if (off2 != 0) {
    std::vector<IMPORT_ADDRESS_INFO> vecImportAddressInfo;
    hResult = HandleIAT(peImageMaster, off2, vecImportAddressInfo);
    printf("HandleIAT: %d\n", hResult);
    if (hResult < 0) {
      return -1;
    }
    hResult = peImageMaster.RebuildIAT(vecImportAddressInfo);
    printf("RebuildIAT: %d\n", hResult);
  }

  peImageMaster.FixPEHeader();

  SetCurrentDirectoryA(oldpath.c_str());

  peImageMaster.Dump("./" + filename + ".testdump");

  return 0;
}

} // namespace tp3shell

int main(int argc, char *argv[]) {
  int result = 0;
  const char *path = NULL;

  if (argc >= 2) {
    path = argv[1];
  } else {
    if (IsDebuggerPresent()) {
      path = "E:\\ÌÚÑ¶ÓÎÏ·\\Ó¢ÐÛÁªÃË\\Game\\League of Legends.exe";
    } else {
      printf("usage: TP3Shell EXE_FULLPATH");
      return 0;
    }
  }

  tp3shell::Unpacker unpacker;

  result = unpacker.doit(path);

  if (result != 0) {
    system("pause");
  }
  return 0;
}
