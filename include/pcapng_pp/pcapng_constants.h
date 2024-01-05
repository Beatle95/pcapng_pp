#ifndef __PCAPNG_CONSTANTS_H__
#define __PCAPNG_CONSTANTS_H__
#include <cstdint>

namespace pcapng_pp::constants {
    constexpr uint32_t interface_block {1};
    constexpr uint32_t simple_packet_block {3};
    constexpr uint32_t enchanced_packet_block {6};
    constexpr uint32_t section_header_block {0x0A0D0D0A};
    constexpr uint32_t custom_data_block {0xB16B00B5};
    constexpr uint32_t unknown_data_block {0xDEADBEEF};

    constexpr uint16_t option_endofopt	{0};
    constexpr uint16_t option_comment {1};
    constexpr uint16_t option_shb_hardware {2};
    constexpr uint16_t option_shb_os {3};
    constexpr uint16_t option_shb_userappl {4};
}
#endif // __PCAPNG_CONSTANTS_H__
