#ifndef __PACKET_H__
#define __PACKET_H__
#include <memory>
#include "pcapng_packet_block.h"
#include "pcapng_interface.h"

namespace pcapng_pp {
    class Packet {
        public:
            Packet() = delete;
            Packet(std::unique_ptr<PacketBlock> packet_block);
            Span<const byte_t> get_packet_data() const;
            Interface get_interface() const;
            size_t get_captured_length() const;
            size_t get_original_length() const;
            uint64_t get_timestamp() const;

        private:
            std::unique_ptr<PacketBlock> packet_block_;
    };
}
#endif // __PACKET_H__
