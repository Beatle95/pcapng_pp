#ifndef __INTERANTYPES_H__
#define __INTERANTYPES_H__
#include <array>
#include <cstdint>
#include <vector>
#include <string>

constexpr size_t max_supported_interface_blocks {32};

namespace pcapng_pp {    
    struct PcapngBlock {
        uint32_t block_type;
	    uint32_t block_total_length;
        std::vector<char> block_body;
    };

    struct PcapngSectionHeader {
        uint32_t byteorder_magic;
        uint16_t major_version;
        uint16_t minor_version;
        uint64_t section_length;
    };

    struct PcapngOption {
        uint16_t custom_option_code;
        std::vector<char> data;
    };

    struct PcapngFileInfo {
        uint16_t major_version;
        uint16_t minor_version;
        std::string file_comment;
        std::string hardware_desc;
        std::string os_desc;
        std::string user_app_desc;
        size_t interface_block_count;
        std::array<uint16_t, max_supported_interface_blocks> link_types;
        std::array<double, max_supported_interface_blocks> timestamp_resolution;
    };
}
#endif // __INTERANTYPES_H__
