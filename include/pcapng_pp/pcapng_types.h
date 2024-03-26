#ifndef __INTERANTYPES_H__
#define __INTERANTYPES_H__
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace pcapng_pp {
    // we are targeting compilers with no c++20 support, so use non-standard span implementation
    template<typename T> using Span = tcb::span<T>;
    using byte_t = unsigned char;
    
    struct Version {
        uint16_t major;
        uint16_t minor;
    };

    struct BlockHeader {
        uint32_t type;
        uint32_t length;
    };

    struct BlockOption {
        std::vector<byte_t> data;
        uint16_t custom_option_code;
    };

    struct FileInfo {
        std::string file_comment;
        std::string hardware_desc;
        std::string os_desc;
        std::string user_app_desc;
        uint16_t major_version {};
        uint16_t minor_version {};
    };
}
#endif // __INTERANTYPES_H__
