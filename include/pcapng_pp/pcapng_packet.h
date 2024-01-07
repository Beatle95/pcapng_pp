#ifndef __PACKET_H__
#define __PACKET_H__
#include <memory>
#include "pcapng_block.h"
#include "pcapng_interface.h"

namespace pcapng_pp {
    class Packet {
        public:
            Packet() = delete;
            Packet(SimplePacketBlock *packet_block);
            Packet(std::unique_ptr<SimplePacketBlock>&& packet_block);

            Span<const char> get_packet_data() const;
            Interface get_interface() const;

        private:
            std::unique_ptr<SimplePacketBlock> packet_block_;
    };
}
#endif // __PACKET_H__
