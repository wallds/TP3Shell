#pragma once
#include <vector>

namespace tp3shell {
namespace compress {

enum class CompressType {
  None = 0,
  LZ4 = 1,
  AP32 = 2,
  LZMA = 3,
};


class ap32 {
public:
  static const int magic = '23PA';
  static std::vector<uint8_t> uncompress(uint8_t *p, int size);

private:
};

class lz4 {
public:
  static const int magic = '4ZL';
  static std::vector<uint8_t> uncompress(uint8_t *p, int size, int cap);

private:
};

CompressType magic2compresstype(int magic);
std::vector<uint8_t> tp3uncompress(uint8_t *p, int chunksize = -1);
} // namespace compress
} // namespace tp3shell