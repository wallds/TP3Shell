#pragma once
#include <Windows.h>
#include <string>
#include <vector>

// x_base.dll.tls section:
// key
// packed(shell_info)

// shell_info:
// CONST
// COUNT
// (ITEM_ID, ITEM_SIZE)[COUNT]
// DATA

// 0x00:bin tessafe
// 0x02:bin vsandbox
// 0x04:bin tesmonitor
// 0x08:LUA BYTECODE Lua5.2
// 0x0A:section info
// 0x0B:import module list
// 0x13:tp3pywrapper

typedef struct _SHELLINFO_PACKED_SECTION_ITEM {
  uint32_t chunksize;
  uint32_t vaoff;
  uint32_t vasize;
  std::vector<uint32_t> sizes;
} SHELLINFO_PACKED_SECTION_ITEM, *PSHELLINFO_PACKED_SECTION_ITEM;

typedef struct _SHELLINFO_PACKED_SECTION {
  std::vector<SHELLINFO_PACKED_SECTION_ITEM> items;

  bool Unmarshal(uint8_t *data, uint32_t size);
} SHELLINFO_PACKED_SECTION, *PSHELLINFO_PACKED_SECTION;

typedef struct _SHELLINFO_FILE_INDEX {
  uint32_t Size;
  uint32_t Field_04;
  uint32_t Field_08;
  uint32_t Field_0C;
  uint32_t Field_10;
  uint32_t Offset;
  wchar_t Path[MAX_PATH];
} SHELLINFO_FILE_INDEX, *PSHELLINFO_FILE_INDEX;

typedef struct _SHELLINFO_RESOURCE_ITEM {
  SHELLINFO_FILE_INDEX FileIndex;
  std::vector<uint8_t> FileData;
} SHELLINFO_RESOURCE_ITEM, *PSHELLINFO_RESOURCE_ITEM;

typedef struct _SHELLINFO_RESOURCE {
  int32_t Size = 0;
  int32_t Count = 0;
  std::vector<SHELLINFO_RESOURCE_ITEM> items;

  virtual bool Unmarshal(uint8_t *data, uint32_t size);
} SHELLINFO_RESOURCE, *PSHELLINFO_RESOURCE;

typedef struct _SHELLINFO_RESOURCE_V2 : public SHELLINFO_RESOURCE {
  uint32_t Field_00 = 0;
  uint32_t Field_04 = 0;

  virtual bool Unmarshal(uint8_t *data, uint32_t size);
} SHELLINFO_RESOURCE_V2, *PSHELLINFO_RESOURCE_V2;

typedef struct _SHELLINFO_IMPORT_MODULE_LIST {
  std::vector<std::string> items;

  bool Unmarshal(uint8_t *data, uint32_t size);
} SHELLINFO_IMPORT_MODULE_LIST, *PSHELLINFO_IMPORT_MODULE_LIST;

typedef struct _TP3SHELLINFO {
  SHELLINFO_RESOURCE BinTessafe;                 // 0x00
  SHELLINFO_RESOURCE_V2 BinVSandbox;             // 0x02
  SHELLINFO_RESOURCE BinTesmonitor;              // 0x04
  std::vector<uint8_t> LuacBytecode;             // 0x08
  SHELLINFO_PACKED_SECTION PackedSectionInfo;    // 0x0A
  SHELLINFO_IMPORT_MODULE_LIST ImportModuleList; // 0x0B

  bool Unmarshal(std::vector<uint8_t> &data);
} TP3SHELLINFO, *PTP3SHELLINFO;
