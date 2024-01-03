#ifndef __PCAPNGBLOCKBODY_H__
#define __PCAPNGBLOCKBODY_H__
#include <vector>

namespace pcapng_pp {
    struct PcapngBlockBody {
        virtual ~PcapngBlockBody() = default;
    };

    struct PcapngSectionHeader final : public PcapngBlockBody {
        uint64_t section_length;
        uint32_t byteorder_magic;
        uint16_t major_version;
        uint16_t minor_version;
    };

    struct PcapngInterfaceDescription final : public PcapngBlockBody {
        uint32_t snapshot_length;
        uint16_t link_type;
        uint16_t reserved;
    };

    struct PcapngSimplePacket : PcapngBlockBody {
        std::vector<char> packet_data;
    };

    struct PcapngEnchancedPacket final : public PcapngSimplePacket {
        uint32_t interface_id;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
        uint32_t original_capture_length;
    };

    struct PcapngCustomNonstandardBlockBody final : public PcapngSimplePacket {
        uint32_t reserved0;
        uint32_t reserved1;
    };
}

#endif // __PCAPNGBLOCKBODY_H__
