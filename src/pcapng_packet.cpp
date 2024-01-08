#include "pcapng_pp/pcapng_packet.h"
#include <assert.h>

using namespace pcapng_pp;
    
Packet::Packet(SimplePacketBlock *packet_block)
    : packet_block_ {packet_block}
{
    assert(bool(packet_block_));
}

Packet::Packet(std::unique_ptr<SimplePacketBlock>&& packet_block)
    : packet_block_ {std::move(packet_block)}
{
    assert(bool(packet_block_));
}
    
Span<const uint8_t> Packet::get_packet_data() const {
    return packet_block_->get_packet_data();
}

Interface Packet::get_interface() const {
    return Interface {packet_block_->get_interface()};
}

size_t Packet::get_captured_length() const {
    return packet_block_->get_captured_length();
}

size_t Packet::get_original_length() const {
    return packet_block_->get_original_length();
}

uint64_t Packet::get_timestamp() const {
    return packet_block_->get_timestamp();
}
