#ifndef __INTERANTYPES_H__
#define __INTERANTYPES_H__
#include <array>
#include <cstdint>
#include <vector>
#include <string>

constexpr size_t max_supported_interface_blocks {32};

namespace pcapng_pp {
    struct PcapngOption {
        std::vector<char> data;
        uint16_t custom_option_code;
    };

    struct PcapngFileInfo {
        std::array<double, max_supported_interface_blocks> timestamp_resolution;
        std::array<uint16_t, max_supported_interface_blocks> link_types;
        std::string file_comment;
        std::string hardware_desc;
        std::string os_desc;
        std::string user_app_desc;
        size_t interface_block_count {};
        uint16_t major_version {};
        uint16_t minor_version {};
    };
}
#endif // __INTERANTYPES_H__
