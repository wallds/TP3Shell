#include "TP3ShellInfo.h"

int DumpShellInfo(uint8_t *data, size_t size, size_t id) {
  char s[50] = {};
  sprintf(s, "./shellinfo_%d.bin", id);
  FILE *fp = fopen(s, "wb");
  if (fp == NULL) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fflush(fp);
  fclose(fp);
  fp = NULL;
  return 0;
}

bool SHELLINFO_PACKED_SECTION::Unmarshal(uint8_t *data, uint32_t size) {
  uint32_t off = 0;

  if (size < 4) {
    return false;
  }
  int32_t count = *(int32_t *)&data[0];
  off += 4;

  if (count <= 0) {
    return false;
  }

  this->items.resize(count);
  for (size_t i = 0; i < count; i++) {
    this->items[i].chunksize = *(uint32_t *)&data[off];
    off += 4;
    this->items[i].vaoff = *(uint32_t *)&data[off];
    off += 4;
    this->items[i].vasize = *(uint32_t *)&data[off];
    off += 4;
    this->items[i].sizes.resize(*(uint32_t *)&data[off]);
    off += 4;
    for (size_t j = 0; j < this->items[i].sizes.size(); j++) {
      this->items[i].sizes[j] = (*(uint32_t *)&data[off]);
      off += 4;
    }
  }

  return true;
}

bool SHELLINFO_RESOURCE::Unmarshal(uint8_t *data, uint32_t size) {
  uint32_t off = 0;

  if (size < 8) {
    return false;
  }
  int32_t size2 = *(int32_t *)&data[0];
  off += 4;

  if (size2 <= 0 || (size2 + 4) > size) {
    return false;
  }

  int32_t count = *(int32_t *)&data[4];
  off += 4;

  if (count <= 0) {
    return false;
  }
  Size = size2;
  Count = count;
  this->items.resize(count);
  for (size_t i = 0; i < count; i++) {
    this->items[i].FileIndex = *(SHELLINFO_FILE_INDEX *)&data[off];
    off += sizeof(SHELLINFO_FILE_INDEX);

    auto &fileIndex = this->items[i].FileIndex;
    auto &fileData = this->items[i].FileData;

    fileData.resize(fileIndex.Size);
    memcpy(fileData.data(), &data[4 + fileIndex.Offset], fileIndex.Size);
  }

  return true;
}

bool SHELLINFO_RESOURCE_V2::Unmarshal(uint8_t *data, uint32_t size) {
  if (size < 8) {
    return false;
  }

  Field_00 = *(uint32_t *)&data[0];
  Field_04 = *(uint32_t *)&data[4];

  return SHELLINFO_RESOURCE::Unmarshal(data + 8, size - 8);
}

bool SHELLINFO_IMPORT_MODULE_LIST::Unmarshal(uint8_t *data, uint32_t size) {
  uint32_t off = 0;
  const char *p = (const char *)&data[0];
  do {
    std::string s;
    s = std::string(p);
    if (s.size() == 0) {
      break;
    }
    items.push_back(s);
    off += s.size() + 1;
    p = (const char *)&data[off];
  } while (off < size);

  return false;
}

bool TP3SHELLINFO::Unmarshal(std::vector<uint8_t> &data) {
  if (data.size() == 0) {
    return false;
  }

  int32_t count = *(int32_t *)&data[4];
  if (count <= 0) {
    return false;
  }
  uint32_t off = 8 + count * 8;

  for (size_t i = 0; i < count; i++) {
    uint32_t itemID = *(uint32_t *)&data[8 + 8 * i];
    int32_t itemSize = *(int32_t *)&data[8 + 8 * i + 4];
    if (itemSize == 0) {
      continue;
    }
    if (itemSize < 0) {
      return false;
    }

    switch (itemID) {
    case 0x00:
      BinTessafe.Unmarshal(&data[off], itemSize);
      break;
    case 0x02:
      BinVSandbox.Unmarshal(&data[off], itemSize);
      break;
    case 0x04:
      BinTesmonitor.Unmarshal(&data[off], itemSize);
      break;
    case 0x08: {
      auto itemData = std::vector<uint8_t>(itemSize);
      memcpy(itemData.data(), &data[off], itemSize);

      LuacBytecode = itemData;
    } break;
    case 0x0A:
      PackedSectionInfo.Unmarshal(&data[off], itemSize);
      break;
    case 0x0B:
      ImportModuleList.Unmarshal(&data[off], itemSize);
      break;
    // case 0x13: // 19 tp3pywrapper
    //  break;
    default:
      printf("[WARNING] UNHANDLE SHELLINFO ID: %08X SIZE: %08X\n", itemID,
             itemSize);
      DumpShellInfo(&data[off], itemSize, itemID);
      break;
    }
    off += itemSize;
  }

  return true;
}
