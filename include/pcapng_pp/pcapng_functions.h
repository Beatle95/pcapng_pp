#ifndef __PCAPNG_FUNCTIONS_H__
#define __PCAPNG_FUNCTIONS_H__
#include <cstdlib>

namespace pcapng_pp::functions {
    size_t get_4_byte_aligned_len(size_t len);
}
#endif // __PCAPNG_FUNCTIONS_H__
