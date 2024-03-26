#include "pcapng_pp/pcapng_block.h"
#include <assert.h>
#include <algorithm>
#include "pcapng_pp/pcapng_constants.h"
#include "pcapng_pp/pcapng_error.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

// AbstractPcapngBlock
    
PcapngBlockType AbstractPcapngBlock::get_type() const {
    return type_;
}

bool AbstractPcapngBlock::is_option_exists(uint16_t option_code) const {
    const auto it {std::find_if(options_.begin(), options_.end(), [option_code](auto&& elem) { return elem.custom_option_code == option_code; })};
    return it != options_.end();
}

Span<const byte_t> AbstractPcapngBlock::get_option_data(uint16_t option_code) const {
    const auto it {std::find_if(options_.begin(), options_.end(), [option_code](auto&& elem) { return elem.custom_option_code == option_code; })};
    if (it == options_.end()) {
        return {};
    }
    return it->data;
}

void AbstractPcapngBlock::add_option(const BlockOption& opt) {
    options_.emplace_back(opt);
}

void AbstractPcapngBlock::add_option(BlockOption&& opt) {
    options_.emplace_back(std::move(opt));
}

AbstractPcapngBlock::AbstractPcapngBlock(PcapngBlockType t) 
    : type_ {t}
{    
}

// SectionHeaderBlock

SectionHeaderBlock::SectionHeaderBlock(uint32_t magic, uint16_t ver_major, uint16_t ver_minor, uint64_t len)
    : AbstractPcapngBlock {PcapngBlockType::section_header},
    section_length_ {len},
    byteorder_magic_ {magic},
    version_ {ver_major, ver_minor}
{    
}

Version SectionHeaderBlock::get_version() const {
    return version_;
}

// InterfaceDescriptionBlock

InterfaceDescriptionBlock::InterfaceDescriptionBlock(uint16_t link, uint16_t reserved, uint32_t snap_len) 
    : AbstractPcapngBlock {PcapngBlockType::interface_description},
    snapshot_length_ {snap_len},
    link_type_ {link},
    reserved_ {reserved}
{    
}
    
uint32_t InterfaceDescriptionBlock::get_snapshot_length() const {
    return snapshot_length_;
}

uint16_t InterfaceDescriptionBlock::get_link_type() const {
    return link_type_;
}

// SimplePacketBlock

SimplePacketBlock::SimplePacketBlock()
    : AbstractPcapngBlock {PcapngBlockType::simple_packet}
{    
}

InterfaceBlockPtr SimplePacketBlock::get_interface() const {
    return interface_;
}

Span<const byte_t> SimplePacketBlock::get_packet_data() const {
    return packet_data_;
}

size_t SimplePacketBlock::get_captured_length() const {
    return packet_data_.size();
}

size_t SimplePacketBlock::get_original_length() const {
    return 0;
}

uint64_t SimplePacketBlock::get_timestamp() const {
    return 0;
}

void SimplePacketBlock::set_data(const std::vector<byte_t>& data) {
    packet_data_ = data;
}

void SimplePacketBlock::set_data(std::vector<byte_t>&& data) {
    packet_data_ = std::move(data);
}

void SimplePacketBlock::set_interface(const InterfaceBlockPtr& iface) {
    interface_ = iface;
}

SimplePacketBlock::SimplePacketBlock(PcapngBlockType t) 
    : AbstractPcapngBlock {t}
{    
}

// EnchancedPacketBlock

EnchancedPacketBlock::EnchancedPacketBlock(uint32_t t_high, uint32_t t_low, uint32_t original_len) 
    : SimplePacketBlock {PcapngBlockType::enchanced_packet},
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

// CustomNonstandardBlock

CustomNonstandardBlock::CustomNonstandardBlock(uint32_t res0, uint32_t res1)
    : SimplePacketBlock {PcapngBlockType::custom_block},
    reserved0_ {res0},
    reserved1_ {res1}
{
}
