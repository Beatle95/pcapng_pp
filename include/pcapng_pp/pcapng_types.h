#ifndef __INTERANTYPES_H__
#define __INTERANTYPES_H__
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace pcapng_pp {
    struct BlockHeader {
        uint32_t type;
        uint32_t length;
    };

    struct PcapngOption {
        std::vector<char> data;
        uint16_t custom_option_code;
    };

    struct PcapngFileInfo {
        std::string file_comment;
        std::string hardware_desc;
        std::string os_desc;
        std::string user_app_desc;
        uint16_t major_version {};
        uint16_t minor_version {};
    };
}
#endif // __INTERANTYPES_H__
