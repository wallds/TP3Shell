#include "CEncodeBuffer.h"

CEncodeBuffer::CEncodeBuffer() {
  setBuffer(NULL);
  setField_40(0);
  setChunkSize(0);
  setOffset(0);

  // void *p = malloc(0x2800);

  // if (getBuffer() != NULL) {
  //	free(getBuffer());
  //	setBuffer(NULL);
  //}
  // setBuffer(p);
  // setField_40(0x2800);
  // setChunkSize(getChunkSize() + 0);
}

CEncodeBuffer::~CEncodeBuffer() {
  if (getBuffer() != NULL) {
    free(getBuffer());
    setBuffer(NULL);
  }
}

bool CEncodeBuffer::decode4(uint8_t *src, uint32_t size, uint8_t *dst) {
  unsigned int *p; // edi
  unsigned int *q;
  int count;       // eax
  int v7;          // ecx
  unsigned int v8; // ebx
  unsigned int v9; // eax

  p = (unsigned int *)dst;
  q = (unsigned int *)src;
  if (!src || !dst || size <= 0) {
    return false;
  }

  count = size / 4;
  if (count > 0) {
    do {
      v7 = *q;
      v8 = getOffset() % 10 + 10;

      switch (getOffset() % v8) {
      case 1u:
        v9 = (v7 + 1955825836) ^ 0x265E3862;
        break;
      case 2u:
        v9 = (v7 - 1324569152) ^ 0xEC9436C6;
        break;
      case 3u:
        v9 = (v7 - 1335855794) ^ 0x461E9017;
        break;
      case 4u:
        v9 = (v7 + 322533538) ^ 0x187FB540;
        break;
      case 5u:
        v9 = (v7 + 1598176956) ^ 0xEC6B0A98;
        break;
      case 6u:
        v9 = (v7 - 1308278048) ^ 0x4DF8CB4;
        break;
      case 7u:
        v9 = (v7 - 1818113864) ^ 0xBC9A5F81;
        break;
      case 8u:
        v9 = (v7 - 2121712676) ^ 0x44AA874D;
        break;
      case 9u:
        v9 = (v7 + 330508136) ^ 0x748C671;
        break;
      case 0xAu:
        v9 = (v7 + 1840262975) ^ 0xFD52D86C;
        break;
      case 0xBu:
        v9 = (v7 + 1741265080) ^ 0xD49FF28F;
        break;
      case 0xCu:
        v9 = (v7 - 675134342) ^ 0x7116FEAF;
        break;
      case 0xDu:
        v9 = (v7 - 971950728) ^ 0x9A718786;
        break;
      case 0xEu:
        v9 = (v7 + 1658855595) ^ 0xFEDB51A;
        break;
      case 0xFu:
        v9 = (v7 - 1304468108) ^ 0x88DBACDE;
        break;
      case 0x10u:
        v9 = (v7 + 730298460) ^ 0xB87C1A0B;
        break;
      case 0x11u:
        v9 = (v7 + 526388224) ^ 0x4A5BBD37;
        break;
      case 0x12u:
        v9 = (v7 + 184612818) ^ 0x9D774544;
        break;
      case 0x13u:
        v9 = (v7 - 1020367079) ^ 0x864D1615;
        break;
      default:
        v9 = (v7 - 0x7C68325A) ^ 0xAE92A541;
        break;
      }
      *p = v9;
      p++;
      q++;
      count--;
    } while (count);
  }

  return true;
}
