#include "pcapng_pp/pcapng_packet_block.h"

using namespace pcapng_pp;

// PacketBlock

PacketBlock::PacketBlock()
    : BasePcapngBlock {PcapngBlockType::simple_packet}
{    
}

InterfaceBlockPtr PacketBlock::get_interface() const {
    return interface_;
}

Span<const byte_t> PacketBlock::get_packet_data() const {
    return packet_data_;
}

size_t PacketBlock::get_captured_length() const {
    return packet_data_.size();
}

size_t PacketBlock::get_original_length() const {
    return 0;
}

uint64_t PacketBlock::get_timestamp() const {
    return 0;
}

void PacketBlock::set_data(const std::vector<byte_t>& data) {
    packet_data_ = data;
}

void PacketBlock::set_data(std::vector<byte_t>&& data) {
    packet_data_ = std::move(data);
}

void PacketBlock::set_interface(const InterfaceBlockPtr& iface) {
    interface_ = iface;
}

PacketBlock::PacketBlock(PcapngBlockType t) 
    : BasePcapngBlock {t}
{    
}

// EnchancedPacketBlock

EnchancedPacketBlock::EnchancedPacketBlock(uint32_t t_high, uint32_t t_low, uint32_t original_len) 
    : PacketBlock {PcapngBlockType::enchanced_packet},
    timestamp_ {(static_cast<uint64_t>(t_high) << 32) | t_low},
    original_capture_length_ {original_len}
{
}

size_t EnchancedPacketBlock::get_original_length() const {
    return original_capture_length_;
}

uint64_t EnchancedPacketBlock::get_timestamp() const {
    return timestamp_;
}

// CustomPacketBlock

CustomPacketBlock::CustomPacketBlock(uint32_t res0, uint32_t res1)
    : PacketBlock {PcapngBlockType::custom_block},
    reserved0_ {res0},
    reserved1_ {res1}
{
}
