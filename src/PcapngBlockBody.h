#ifndef __PCAPNGBLOCKBODY_H__
#define __PCAPNGBLOCKBODY_H__

namespace pcapng_pp {
    struct PcapngBlockBody {
        virtual ~PcapngBlockBody() = default;
    };

    struct PcapngSectionHeader final : PcapngBlockBody {
        uint64_t section_length;
        uint32_t byteorder_magic;
        uint16_t major_version;
        uint16_t minor_version;
    };
}

#endif // __PCAPNGBLOCKBODY_H__
