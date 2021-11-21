#pragma once
#include <stdint.h>
#include <string>
#include <vector>

namespace tp3shell {
namespace crypto {
uint64_t hash(const char *s);
std::vector<uint8_t> Decrypt2(uint8_t *src, int len, int off);

} // namespace crypto
} // namespace tp3shell