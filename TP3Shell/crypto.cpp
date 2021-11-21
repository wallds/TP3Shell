#include "crypto.h"
#include "compress/aplib.h"
#include "compress/lz4.h"

namespace tp3shell {
namespace crypto {

uint32_t hash1(const char *p) {
  uint32_t h = 0;

  while (*p) {
    h *= 0x83;
    h += *p;
    p++;
  }
  return h;
}

// FNV-1 hash algorithm
uint32_t FNV1_32_HASH(const char *p) {
  if (*p == 0) {
    return 0;
  }
  uint32_t h = 0x811c9dc5;
  while (*p) {
    h *= 0x1000193;
    h ^= *p;
    p++;
  }
  return h;
}

uint64_t hash(const char *s) {
  uint64_t h = 0;

  h = FNV1_32_HASH(s);
  h <<= 32;
  h |= hash1(s);

  return h;
}

bool Decrypt(unsigned int *src, unsigned int *dst, int len, unsigned int off) {
  unsigned int *p; // edi
  unsigned int *q;
  int count;       // eax
  int v7;          // ecx
  unsigned int v8; // ebx
  unsigned int v9; // eax

  p = dst;
  q = src;
  if (!src || !dst || len <= 0) {
    return false;
  }

  count = len / 4;
  if (count > 0) {
    do {
      v7 = *q;
      v8 = off % 10 + 10;

      switch (off % v8) {
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

std::vector<uint8_t> Decrypt2(uint8_t *src, int len, int off) {
  unsigned int *q;
  int v7;               // ecx
  unsigned int v8 = 0;  // ebx
  unsigned int v21 = 0; // eax
  int size = 0;
  unsigned int npadding = 0;
  unsigned int k = 0;
  std::vector<uint8_t> result;

  if (!src || len <= 0) {
    return result;
  }

  q = (uint32_t *)src;
  do {
    v7 = *q;
    v8 = off % 10 + 10;
    size = (q[1] - 0x4EF35240) ^ 0xEC9436C6;
    if (size < 0) {
      return result;
    }
    k = (v7 + 0x749388AC) ^ 0x265E3862;
    switch (k % v8) {
    case 1:
      v21 = (~k) - 8;
      break;
    case 2:
      v21 = (~k) + 6;
      break;
    case 3:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3864) - 8;
      break;
    case 4:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C798) + 5;
      break;
    case 5:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C79C) - 4;
      break;
    case 6:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C799) + 4;
      break;
    case 7:
      v21 = (v7 + 0x749388AC) ^ 0x265E3865;
      break;
    case 8:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3866) - 2;
      break;
    case 9:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3867) + 7;
      break;
    case 0xA:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3863) - 6;
      break;
    case 0xB:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3860) - 1;
      break;
    case 0xC:
      v21 = (v7 + 0x749388AC) ^ 0xD9A1C79A;
      break;
    case 0xD:
      v21 = ((v7 + 0x749388AC) ^ 0x265E3866) - 1;
      break;
    case 0xE:
      v21 = k - 2;
      break;
    case 0xF:
      v21 = k - 6;
      break;
    case 0x10:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C79F) + 6;
      break;
    case 0x11:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C798) + 4;
      break;
    case 0x12:
      v21 = (v7 + 0x749388AC) ^ 0x265E3863;
      break;
    case 0x13:
      v21 = ((v7 + 0x749388AC) ^ 0xD9A1C798) - 4;
      break;
    default:
      v21 = k + 3;
      break;
    }
    npadding = v21 & 0x0F;
    if (k == off) {
      break;
    }

    q = (uint32_t *)((uint8_t *)q + 8 + npadding + size);
  } while ((uint8_t *)q < ((uint8_t *)src + len));

  if (((uint8_t *)q + 8 + npadding + size) > ((uint8_t *)src + len)) {
    return result;
  }

  result.resize(size);

  if (!Decrypt((uint32_t *)((uint8_t *)q + 8 + npadding),
               (uint32_t *)result.data(), size, off)) {
    result.resize(0);
  }

  return result;
}

} // namespace crypto
} // namespace tp3shell
