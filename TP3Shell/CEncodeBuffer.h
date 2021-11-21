#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

class CEncodeBuffer {
public:
  CEncodeBuffer();
  virtual ~CEncodeBuffer();

  __forceinline void setBuffer(void *v) {
    Buffer = (((uint32_t)v) ^ 0x265E3862) - 0x749388AC;
  }
  __forceinline void setField_40(uint32_t v) {
    Field_40 = (v ^ 0xEC9436C6) + 0x4EF35240;
  }
  __forceinline void setChunkSize(uint32_t v) {
    ChunkSize = (v ^ 0x461E9017) + 0x4F9F8AB2;
  }
  __forceinline void setOffset(uint32_t v) {
    Offset = (v ^ 0x187FB540) - 0x133978A2;
  }
  __forceinline void *getBuffer() {
    return (void *)((Buffer + 0x749388AC) ^ 0x265E3862);
  }
  __forceinline uint32_t getField_40() {
    return (Field_40 - 0x4EF35240) ^ 0xEC9436C6;
  }
  __forceinline uint32_t getChunkSize() {
    return (ChunkSize - 0x4F9F8AB2) ^ 0x461E9017;
  }
  __forceinline uint32_t getOffset() {
    return (Offset + 0x133978A2) ^ 0x187FB540;
  }

  template <class T> bool decode(uint8_t *buf, T &value, uint32_t off) {
    int32_t ksize = (*(int32_t *)&buf[0] - 0x7E76C424) ^ 0x44AA874D;

    if (ksize <= 0) {
      return false;
    }

    void *p = malloc(ksize);

    if (getBuffer() != NULL) {
      free(getBuffer());
      setBuffer(NULL);
    }
    setBuffer(p);
    setField_40(ksize);
    setChunkSize(getChunkSize() + 0);
    setOffset(off);
    if (getBuffer() == NULL) {
      return false;
    }
    memcpy(getBuffer(), &buf[4], ksize);

    value = {};

    setChunkSize(ksize);
    unsigned int *q;
    int v7;               // ecx
    unsigned int v8 = 0;  // ebx
    unsigned int v21 = 0; // eax
    int size = 0;
    unsigned int npadding = 0;
    unsigned int k = 0;

    q = (uint32_t *)getBuffer();
    do {
      v7 = *q;
      v8 = getOffset() % 10 + 10;
      size = (q[1] - 0x4EF35240) ^ 0xEC9436C6;
      if (size < 0) {
        return false;
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
      if (k == getOffset()) {
        break;
      }

      q = (uint32_t *)((uint8_t *)q + 8 + npadding + size);
    } while ((uint8_t *)q < ((uint8_t *)getBuffer() + getChunkSize()));

    if (((uint8_t *)q + 8 + npadding + size) >
        ((uint8_t *)getBuffer() + getChunkSize())) {
      return false;
    }

    if (size > sizeof(value)) {
      return false;
    }
    return decode4(((uint8_t *)q + 8 + npadding), size, (uint8_t *)&value);
  }
  bool decode4(uint8_t *src, uint32_t size, uint8_t *dst);

private:
  uint8_t Field_04[20];
  uint32_t Buffer;      // void *Buffer
  uint8_t Field_1C[36]; // rbox1
  uint32_t Field_40;    // Size
  uint8_t Field_44[52]; // rbox2
  uint32_t ChunkSize;   // KSize
  uint8_t Field_7C[68]; // rbox3
  uint32_t Offset;      // Off
};