#ifndef __PACKET_H__
#define __PACKET_H__
#include <memory>
#include "pcapng_block.h"

namespace pcapng_pp {
    class Packet {
        public:
            Packet() = delete;
            Packet(PcapngSimplePacket *packet_block);
            Packet(std::unique_ptr<PcapngSimplePacket>&& packet_block);
            Span<const char> get_packet_data() const;

        private:
            std::unique_ptr<PcapngSimplePacket> packet_block_;
    };
}
#endif // __PACKET_H__
