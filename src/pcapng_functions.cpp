#include <pcapng_pp/pcapng_functions.h>
#include <cstdint>

namespace pcapng_pp::functions {

size_t get_4_byte_aligned_len(size_t len) {
    constexpr auto alignment {sizeof(uint32_t)};
    return len % sizeof(uint32_t) == 0 ? len : (len / alignment + 1) * alignment;
}

} // namespace pcapng_pp::functions
