#include "pcapng_pp/pcapng_block.h"
#include <cassert>
#include <algorithm>
#include "pcapng_pp/pcapng_constants.h"
#include "pcapng_pp/pcapng_error.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

// BasePcapngBlock
    
PcapngBlockType BasePcapngBlock::get_type() const {
    return type_;
}

bool BasePcapngBlock::is_option_exists(uint16_t option_code) const {
    const auto it {std::find_if(options_.begin(), options_.end(), [option_code](auto&& elem) { return elem.custom_option_code == option_code; })};
    return it != options_.end();
}

Span<const byte_t> BasePcapngBlock::get_option_data(uint16_t option_code) const {
    const auto it {std::find_if(options_.begin(), options_.end(), [option_code](auto&& elem) { return elem.custom_option_code == option_code; })};
    if (it == options_.end()) {
        return {};
    }
    return it->data;
}

std::string BasePcapngBlock::get_option_string(uint16_t option_code) const {
    auto data {get_option_data(option_code)};
    std::string result {data.begin(), data.end()};
    // remove everything after first null-terminator
    result.erase(std::find(result.begin(), result.end(), '\0'), result.end());
    return result;    
}

void BasePcapngBlock::add_option(const BlockOption& opt) {
    options_.emplace_back(opt);
}

void BasePcapngBlock::add_option(BlockOption&& opt) {
    options_.emplace_back(std::move(opt));
}

BasePcapngBlock::BasePcapngBlock(PcapngBlockType t) 
    : type_ {t}
{    
}

// SectionHeaderBlock

SectionHeaderBlock::SectionHeaderBlock(uint32_t magic, uint16_t ver_major, uint16_t ver_minor, uint64_t len)
    : BasePcapngBlock {PcapngBlockType::section_header},
    section_length_ {len},
    byteorder_magic_ {magic},
    version_ {ver_major, ver_minor}
{    
}

Version SectionHeaderBlock::get_version() const {
    return version_;
}

uint32_t SectionHeaderBlock::get_magic() const {
    return byteorder_magic_;
}

// InterfaceDescriptionBlock

InterfaceDescriptionBlock::InterfaceDescriptionBlock(uint16_t link, uint16_t reserved, uint32_t snap_len) 
    : BasePcapngBlock {PcapngBlockType::interface_description},
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
