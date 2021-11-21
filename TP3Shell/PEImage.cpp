#include "PEImage.h"
#include <fstream>
#include <map>
#include <time.h>

PEImage::PEImage() {
  m_bIsAMD64 = false;
  m_bValid = false;
  m_nFileImageSize = 0;
  m_nMemImageSize = 0;
  m_nTimeDateStamp = 0;
  m_pImageDosHeader = NULL;
  m_pImageNtHeaders32 = NULL;
}

PEImage::PEImage(uint8_t *p, size_t size) : PEImage() {
  if (p == NULL || size == 0) {
    return;
  }
  IMAGE_DOS_HEADER *pImageDosHeader = (IMAGE_DOS_HEADER *)p;
  if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return;
  }
  if ((size_t)pImageDosHeader->e_lfanew >= size) {
    return;
  }
  IMAGE_NT_HEADERS *pImageNtHeader =
      (IMAGE_NT_HEADERS *)((uint8_t *)pImageDosHeader +
                           pImageDosHeader->e_lfanew);
  if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
    return;
  }
  switch (pImageNtHeader->FileHeader.Machine) {
  case IMAGE_FILE_MACHINE_I386:
    m_bValid = ParseFileImageI386(pImageDosHeader, size);
    break;
  case IMAGE_FILE_MACHINE_AMD64:
    m_bValid = ParseFileImageAMD64(pImageDosHeader, size);
    m_bIsAMD64 = true;
    break;
  default:
    break;
  }
}

PEImage::PEImage(std::string strFileName) : PEImage() {
  std::ifstream ifs(strFileName.c_str(), std::ios::binary, SH_DENYNO);

  if (!ifs.is_open()) {
    return;
  }
  size_t fileSize = 0;
  ifs.seekg(0, std::ios::end);
  fileSize = (size_t)ifs.tellg();
  ifs.seekg(0, std::ios::beg);
  std::vector<uint8_t> image(fileSize);
  ifs.read((char *)image.data(), fileSize);
  ifs.close();

  m_vecFileImage = image;
  new (this) PEImage(m_vecFileImage.data(), m_vecFileImage.size());
}

PEImage::~PEImage() {}

std::string PEImage::GetTimeDateStampUnix() {
  char strTimeStamp[100] = {};
  tm timeinfo;
  time_t curtime = GetTimeDateStamp();
  if (localtime_s(&timeinfo, &curtime) == 0) {
    strftime(strTimeStamp, sizeof(strTimeStamp), "%Y-%m-%d %I:%M:%S",
             &timeinfo);
  }
  return std::string(strTimeStamp);
}

bool PEImage::RebuildIAT(std::vector<IMPORT_ADDRESS_INFO> &info) {
  std::map<std::string, uint32_t> mapStringPoolOff;
  std::map<std::string, uint32_t> mapImportByNameOff;
  PIMAGE_SECTION_HEADER pSection = AddNewSection(".FixIAT", 0x10000);
  uint32_t off = pSection->VirtualAddress;

  // build module name string pool
  for (auto &v : info) {
    mapStringPoolOff[v.ModuleName] = off;
    memcpy(RVA2Ptr(off), v.ModuleName.data(), v.ModuleName.size());
    off += v.ModuleName.size() + 1;
  }

  // build import by name pool
  for (auto &v : info) {
    for (auto &n : v.items) {
      if (n.Func.front() != '#') {
        PIMAGE_IMPORT_BY_NAME ImportByName =
            (PIMAGE_IMPORT_BY_NAME)RVA2Ptr(off);

        mapImportByNameOff[v.ModuleName + "." + n.Func] = off;

        ImportByName->Hint = n.Hint;
        memcpy(ImportByName->Name, n.Func.data(), n.Func.size());
        off += 2 + n.Func.size() + 1;
      }
    }
  }
  uint32_t iat = 0;
  // build image import descriptor
  PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)RVA2Ptr(off);

  for (auto &v : info) {
    piid->OriginalFirstThunk = 0;
    piid->TimeDateStamp = 0;
    piid->ForwarderChain = -1;
    piid->Name = mapStringPoolOff[v.ModuleName];
    piid->FirstThunk = piid->OriginalFirstThunk = v.items.front().Rva;

    for (auto &n : v.items) {
      PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)RVA2Ptr(n.Rva);
      if (n.Func.front() == '#') {
        pThunkData->u1.Ordinal = IMAGE_ORDINAL_FLAG | n.Ord;
      } else {
        pThunkData->u1.AddressOfData =
            mapImportByNameOff[v.ModuleName + "." + n.Func];
      }
      if (iat == 0) {
        iat = n.Rva;
      }
    }
    piid++;
  }
  PIMAGE_DATA_DIRECTORY pIdd = NULL;

  PIMAGE_NT_HEADERS32 pImageNtHeader32 = GetImageNtHeaders32();
  pIdd = &pImageNtHeader32->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  pIdd->VirtualAddress = off;
  pIdd->Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * info.size();

  if (iat != 0) {
    for (size_t i = 0; i < GetCountOfSection(); i++) {
      PIMAGE_SECTION_HEADER p = GetSectionByIndex(i);

      if (iat >= p->VirtualAddress &&
          iat < p->VirtualAddress + p->Misc.VirtualSize) {
        p->Characteristics |= IMAGE_SCN_MEM_WRITE;
      }
    }
  }
  return false;
}

bool PEImage::Dump(std::string file) {
  std::ofstream ofs(file.c_str(), std::ios::binary, SH_DENYNO);

  if (!ofs.is_open()) {
    return false;
  }
  ofs.write((char *)m_vecMemImage.data(), m_vecMemImage.size());
  ofs.write((char *)m_AttachData.data(), m_AttachData.size());
  ofs.close();

  return true;
}

bool PEImage::FixPEHeader() {
  IMAGE_NT_HEADERS32 *pImageNtHeader32 = GetImageNtHeaders32();

#define ALIGN(x, mask) (((x) + ((mask)-1)) & ~((mask)-1))
  // Fix SizeOfHeaders
  DWORD sectionAlignment = pImageNtHeader32->OptionalHeader.SectionAlignment;
  pImageNtHeader32->OptionalHeader.SizeOfHeaders =
      ALIGN(pImageNtHeader32->OptionalHeader.SizeOfHeaders, sectionAlignment);

  // Fix Section
  IMAGE_SECTION_HEADER *pSection = IMAGE_FIRST_SECTION(pImageNtHeader32);
  for (size_t i = 0; i < pImageNtHeader32->FileHeader.NumberOfSections; i++) {

    DWORD nSize = ALIGN(pSection[i].Misc.VirtualSize, sectionAlignment);

    pSection[i].Misc.VirtualSize = nSize;
    pSection[i].SizeOfRawData = nSize;
    pSection[i].PointerToRawData = pSection[i].VirtualAddress;
  }
#undef ALIGN
  return false;
}

bool PEImage::ParseFileImageI386(IMAGE_DOS_HEADER *pImageDosHeader,
                                 size_t size) {
  std::vector<uint8_t> vecMemImage;

  IMAGE_NT_HEADERS32 *pImageNtHeader32 =
      (IMAGE_NT_HEADERS32 *)((uint8_t *)pImageDosHeader +
                             pImageDosHeader->e_lfanew);
  if (pImageNtHeader32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    return false;
  }
  vecMemImage =
      std::vector<uint8_t>(pImageNtHeader32->OptionalHeader.SizeOfImage);

  memcpy(vecMemImage.data(), pImageDosHeader,
         pImageNtHeader32->OptionalHeader.SizeOfHeaders);
  // section:
  IMAGE_SECTION_HEADER *pSection = IMAGE_FIRST_SECTION(pImageNtHeader32);
  for (size_t i = 0; i < pImageNtHeader32->FileHeader.NumberOfSections; i++) {
    pSection[i].Name; // 8char without '\0'
    pSection[i].Misc.VirtualSize;
    if (pSection[i].PointerToRawData + pSection[i].SizeOfRawData > size ||
        pSection[i].VirtualAddress + pSection[i].SizeOfRawData >
            vecMemImage.size()) {
      return false;
    }
    memcpy(vecMemImage.data() + pSection[i].VirtualAddress,
           (uint8_t *)pImageDosHeader + pSection[i].PointerToRawData,
           pSection[i].SizeOfRawData);

    m_nFileImageSize = max(m_nFileImageSize, pSection[i].PointerToRawData +
                                                 pSection[i].SizeOfRawData);
    m_nMemImageSize = max(m_nMemImageSize, pSection[i].VirtualAddress +
                                               pSection[i].Misc.VirtualSize);
  }

  m_AttachData.resize(size - m_nFileImageSize);

  memcpy(m_AttachData.data(), (uint8_t *)pImageDosHeader + m_nFileImageSize,
         m_AttachData.size());

  m_vecMemImage = vecMemImage;
  return ParseMemImageI386((IMAGE_DOS_HEADER *)m_vecMemImage.data(),
                           m_vecMemImage.size());
}

bool PEImage::ParseMemImageI386(IMAGE_DOS_HEADER *pImageDosHeader,
                                size_t size) {
  // Export Directory
  IMAGE_DATA_DIRECTORY *pIdd = NULL;
  IMAGE_NT_HEADERS32 *pImageNtHeader32 =
      (IMAGE_NT_HEADERS32 *)((uint8_t *)pImageDosHeader +
                             pImageDosHeader->e_lfanew);
  if (pImageNtHeader32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    return false;
  }

  m_pImageDosHeader = pImageDosHeader;
  m_pImageNtHeaders32 = pImageNtHeader32;

  m_nTimeDateStamp = pImageNtHeader32->FileHeader.TimeDateStamp;
  pIdd = &pImageNtHeader32->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (pIdd->VirtualAddress != NULL && pIdd->Size != 0) {
    IMAGE_EXPORT_DIRECTORY *pImageExportDirectory =
        (IMAGE_EXPORT_DIRECTORY *)((uint8_t *)pImageDosHeader +
                                   pIdd->VirtualAddress);
    pImageExportDirectory->NumberOfFunctions;
  }

  // Import Directory
  pIdd = &pImageNtHeader32->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  // if (pIdd->VirtualAddress != NULL && pIdd->Size != 0) {
  //	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor =
  //(IMAGE_IMPORT_DESCRIPTOR *)((uint8_t *)pImageDosHeader +
  // pIdd->VirtualAddress); 	for (size_t i = 0; i < pIdd->Size /
  // sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
  //
  //		printf("%s\n", ((uint8_t *)pImageDosHeader +
  // pImageImportDescriptor->Name));

  //	}
  //}
  m_vecImportDllList.clear();
  if (pIdd->VirtualAddress != NULL) {
    IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor =
        (IMAGE_IMPORT_DESCRIPTOR *)((uint8_t *)pImageDosHeader +
                                    pIdd->VirtualAddress);
    do {
      m_vecImportDllList.push_back(
          std::string((char *)RVA2Ptr(pImageImportDescriptor->Name)));
      pImageImportDescriptor++;
    } while (pImageImportDescriptor->Characteristics != 0);
  }
  // Reloc Table

  return true;
}

bool PEImage::ParseFileImageAMD64(IMAGE_DOS_HEADER *pImageDosHeader,
                                  size_t size) {
  std::vector<uint8_t> vecMemImage;

  IMAGE_NT_HEADERS64 *pImageNtHeader64 =
      (IMAGE_NT_HEADERS64 *)((uint8_t *)pImageDosHeader +
                             pImageDosHeader->e_lfanew);
  if (pImageNtHeader64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }
  vecMemImage =
      std::vector<uint8_t>(pImageNtHeader64->OptionalHeader.SizeOfImage);

  memcpy(vecMemImage.data(), pImageDosHeader,
         pImageNtHeader64->OptionalHeader.SizeOfHeaders);
  // section:
  IMAGE_SECTION_HEADER *pSection = IMAGE_FIRST_SECTION(pImageNtHeader64);
  for (size_t i = 0; i < pImageNtHeader64->FileHeader.NumberOfSections; i++) {
    pSection[i].Name; // 8char without '\0'
    pSection[i].Misc.VirtualSize;
    if (pSection[i].PointerToRawData + pSection[i].SizeOfRawData > size ||
        pSection[i].VirtualAddress + pSection[i].SizeOfRawData >
            vecMemImage.size()) {
      return false;
    }
    memcpy(vecMemImage.data() + pSection[i].VirtualAddress,
           (uint8_t *)pImageDosHeader + pSection[i].PointerToRawData,
           pSection[i].SizeOfRawData);

    m_nFileImageSize = max(m_nFileImageSize, pSection[i].PointerToRawData +
                                                 pSection[i].SizeOfRawData);
    m_nMemImageSize = max(m_nMemImageSize, pSection[i].VirtualAddress +
                                               pSection[i].Misc.VirtualSize);
  }

  m_AttachData.resize(size - m_nFileImageSize);

  memcpy(m_AttachData.data(), (uint8_t *)pImageDosHeader + m_nFileImageSize,
         m_AttachData.size());

  m_vecMemImage = vecMemImage;
  return ParseMemImageAMD64((IMAGE_DOS_HEADER *)m_vecMemImage.data(),
                           m_vecMemImage.size());
}

bool PEImage::ParseMemImageAMD64(IMAGE_DOS_HEADER *pImageDosHeader,
                                 size_t size) {
  // Export Directory
  IMAGE_DATA_DIRECTORY *pIdd = NULL;
  IMAGE_NT_HEADERS64 *pImageNtHeader64 =
      (IMAGE_NT_HEADERS64 *)((uint8_t *)pImageDosHeader +
                             pImageDosHeader->e_lfanew);
  if (pImageNtHeader64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }

  m_pImageDosHeader = pImageDosHeader;
  m_pImageNtHeaders64 = pImageNtHeader64;

  m_nTimeDateStamp = pImageNtHeader64->FileHeader.TimeDateStamp;
  pIdd = &pImageNtHeader64->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (pIdd->VirtualAddress != NULL && pIdd->Size != 0) {
    IMAGE_EXPORT_DIRECTORY *pImageExportDirectory =
        (IMAGE_EXPORT_DIRECTORY *)((uint8_t *)pImageDosHeader +
                                   pIdd->VirtualAddress);
    pImageExportDirectory->NumberOfFunctions;
  }

  // Import Directory
  pIdd = &pImageNtHeader64->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  // if (pIdd->VirtualAddress != NULL && pIdd->Size != 0) {
  //	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor =
  //(IMAGE_IMPORT_DESCRIPTOR *)((uint8_t *)pImageDosHeader +
  // pIdd->VirtualAddress); 	for (size_t i = 0; i < pIdd->Size /
  // sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
  //
  //		printf("%s\n", ((uint8_t *)pImageDosHeader +
  // pImageImportDescriptor->Name));

  //	}
  //}
  m_vecImportDllList.clear();
  if (pIdd->VirtualAddress != NULL) {
    IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor =
        (IMAGE_IMPORT_DESCRIPTOR *)((uint8_t *)pImageDosHeader +
                                    pIdd->VirtualAddress);
    do {
      m_vecImportDllList.push_back(
          std::string((char *)RVA2Ptr(pImageImportDescriptor->Name)));
      pImageImportDescriptor++;
    } while (pImageImportDescriptor->Characteristics != 0);
  }
  // Reloc Table

  return true;
}
