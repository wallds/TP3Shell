#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <vector>

typedef struct _IMPORT_ADDRESS_INFO_ITEM {
  uint32_t Rva;
  uint32_t Hint;
  uint16_t Ord;
  std::string Func;
} IMPORT_ADDRESS_INFO_ITEM;

typedef struct _IMPORT_ADDRESS_INFO {
  std::string ModuleName;
  std::vector<IMPORT_ADDRESS_INFO_ITEM> items;
} IMPORT_ADDRESS_INFO;

class PEImage {
public:
  PEImage();
  PEImage(uint8_t *p, size_t size);
  PEImage(std::string strFileName);
  ~PEImage();

  inline bool IsValid() { return m_bValid; }
  inline bool IsAMD64() { return m_bIsAMD64; }

  size_t GetFileImageSize() { return m_nFileImageSize; }
  size_t GetMemImageSize() { return m_nMemImageSize; }
  DWORD GetTimeDateStamp() { return m_nTimeDateStamp; }

  IMAGE_SECTION_HEADER *GetSection(std::string s) {
    IMAGE_SECTION_HEADER *sec = NULL;
    IMAGE_SECTION_HEADER *pSection = GetFirstSection();

    for (size_t i = 0; i < GetCountOfSection(); i++) {
      size_t len = s.size();

      if (!strncmp((char *)pSection[i].Name, s.c_str(), min(len, 8))) {
        sec = &pSection[i];
        break;
      }
    }
    return sec;
  }

  PIMAGE_SECTION_HEADER GetFirstSection() {
    if (IsAMD64()) {
      IMAGE_NT_HEADERS64 *pImageNtHeader64 = GetImageNtHeaders64();
      if (pImageNtHeader64 != NULL) {
        return IMAGE_FIRST_SECTION(pImageNtHeader64);
      }
    } else {
      IMAGE_NT_HEADERS32 *pImageNtHeader32 = GetImageNtHeaders32();
      if (pImageNtHeader32 != NULL) {
        return IMAGE_FIRST_SECTION(pImageNtHeader32);
      }
    }
    return NULL;
  }

  PIMAGE_SECTION_HEADER GetLastSection() {
    size_t count = GetCountOfSection();
    if (count == 0) {
      return NULL;
    }
    return GetSectionByIndex(count - 1);
  }

  PIMAGE_SECTION_HEADER GetSectionByIndex(size_t index) {
    IMAGE_SECTION_HEADER *pSection = GetFirstSection();
    if (pSection == NULL) {
      return NULL;
    }
    size_t count = GetCountOfSection();
    if (count == 0) {
      return NULL;
    }
    if (index >= count) {
      return NULL;
    }
    return pSection + index;
  }

  PIMAGE_SECTION_HEADER AddNewSection(const char *name, uint32_t size) {
    IMAGE_NT_HEADERS32 *pImageNtHeader32 = GetImageNtHeaders32();
    if (pImageNtHeader32 == NULL) {
      return NULL;
    }

    PIMAGE_SECTION_HEADER pSection =
        (GetSectionByIndex(0) + pImageNtHeader32->FileHeader.NumberOfSections);
    pImageNtHeader32->FileHeader.NumberOfSections += 1;

    strncpy((char *)pSection->Name, name, 8);
    pSection->Misc.VirtualSize = size;
    pSection->SizeOfRawData = size;
    pSection->VirtualAddress = pSection->PointerToRawData = m_nMemImageSize;
    pSection->PointerToRelocations = 0;
    pSection->PointerToLinenumbers = 0;
    pSection->NumberOfRelocations = 0;
    pSection->NumberOfLinenumbers = 0;
    pSection->Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    m_nMemImageSize += size;
    pImageNtHeader32->OptionalHeader.SizeOfImage = m_nMemImageSize;

    pImageNtHeader32 = NULL;
    pSection = NULL;

    m_vecMemImage.resize(m_nMemImageSize);
    m_pImageDosHeader = (PIMAGE_DOS_HEADER)m_vecMemImage.data();
    m_pImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((BYTE *)m_pImageDosHeader +
                                                m_pImageDosHeader->e_lfanew);

    return GetLastSection();
  }

  size_t GetCountOfSection() {
    if (IsAMD64()) {
      IMAGE_NT_HEADERS64 *pImageNtHeader64 = GetImageNtHeaders64();
      if (pImageNtHeader64 == NULL) {
        return 0;
      }
      return pImageNtHeader64->FileHeader.NumberOfSections;
    }
    IMAGE_NT_HEADERS32 *pImageNtHeader32 = GetImageNtHeaders32();
    if (pImageNtHeader32 == NULL) {
      return 0;
    }
    return pImageNtHeader32->FileHeader.NumberOfSections;
  }

  PIMAGE_DOS_HEADER GetImageDosHeader() { return m_pImageDosHeader; }

  PIMAGE_NT_HEADERS32 GetImageNtHeaders32() { return m_pImageNtHeaders32; }
  PIMAGE_NT_HEADERS64 GetImageNtHeaders64() { return m_pImageNtHeaders64; }

  void *RVA2Ptr(uint32_t rva) {
    if (rva > m_nMemImageSize) {
      return NULL;
    }
    return (BYTE *)m_pImageDosHeader + rva;
  }

  std::string GetTimeDateStampUnix();
  bool RebuildIAT(std::vector<IMPORT_ADDRESS_INFO> &info);
  bool Dump(std::string file);
  bool FixPEHeader();

  std::vector<std::string> GetImportDllList() { return m_vecImportDllList; }

private:
  bool ParseFileImageI386(IMAGE_DOS_HEADER *pImageDosHeader, size_t size);
  bool ParseMemImageI386(IMAGE_DOS_HEADER *pImageDosHeader, size_t size);

  bool ParseFileImageAMD64(IMAGE_DOS_HEADER *pImageDosHeader, size_t size);
  bool ParseMemImageAMD64(IMAGE_DOS_HEADER *pImageDosHeader, size_t size);

private:
  bool m_bValid;
  size_t m_nFileImageSize;
  size_t m_nMemImageSize;
  DWORD m_nTimeDateStamp;
  PIMAGE_DOS_HEADER m_pImageDosHeader;
  PIMAGE_NT_HEADERS32 m_pImageNtHeaders32;
  PIMAGE_NT_HEADERS64 m_pImageNtHeaders64;

  std::vector<uint8_t> m_vecFileImage; //ÎÄ¼þ¾µÏñ
  std::vector<uint8_t> m_vecMemImage;  //ÄÚ´æ¾µÏñ
  std::vector<uint8_t> m_AttachData;
  std::vector<std::string> m_vecImportDllList;

  bool m_bIsAMD64;
};
