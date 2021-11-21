#include "compress.h"
#include "aplib.h"
#include "lz4.h"

namespace tp3shell {
namespace compress {

std::vector<uint8_t> ap32::uncompress(uint8_t *p, int size) {
  std::vector<uint8_t> result;
  int origsize = aPsafe_get_orig_size(p);
  if (origsize <= 0) {
    return result;
  }
  result.resize(origsize);
  if (aPsafe_depack(p, size, result.data(), result.size()) <= 0) {
    result = {};
  }
  return result;
}

std::vector<uint8_t> lz4::uncompress(uint8_t *p, int size, int cap) {
  std::vector<uint8_t> result;
  if (size <= 0) {
    return result;
  }

  std::vector<uint8_t> outbuf;
  outbuf.resize(cap);

  int k = LZ4_decompress_safe((const char *)&p[0], (char *)outbuf.data(),
                              size, outbuf.size());
  if (k > 0) {
    result = outbuf;
  }
  return result;
}

CompressType magic2compresstype (int magic) {
  if (magic == lz4::magic) {
    return CompressType::LZ4;
  } else if (magic == ap32::magic) {
    return CompressType::AP32;
  }
  return CompressType::None;
}


std::vector<uint8_t> tp3uncompress(uint8_t *p, int chunksize) {
  std::vector<uint8_t> result; 
  int32_t size = (*(int32_t *)&p[0] + 0x749388AC) ^ 0x265E3862;
  int magic = *(int32_t *)&p[4];

  if (size <= 0) {
    return result;
  }
  if (chunksize != -1) {
    if (size > chunksize) {
      return result;
    }
  }
  CompressType Compress = magic2compresstype(magic);
  if (Compress == CompressType::LZ4) {
    int cap = *(int32_t *)&p[8];
    result = lz4::uncompress(p + 12, size - 8, cap);
  } else if (Compress == CompressType::AP32) {
    result = ap32::uncompress(p + 4, size);
  }
  return result;
}

} // namespace compress
} // namespace tp3shell