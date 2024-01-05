#include "pcapng_pp/packet.h"
#include <assert.h>

using namespace pcapng_pp;
    
Packet::Packet(PcapngSimplePacket *packet_block)
    : packet_block_ {packet_block}
{
    assert(bool(packet_block_));
}

Packet::Packet(std::unique_ptr<PcapngSimplePacket>&& packet_block)
    : packet_block_ {std::move(packet_block)}
{
    assert(bool(packet_block_));
}
    
Span<const char> Packet::get_packet_data() const {
    return packet_block_->get_packet_data();
}
