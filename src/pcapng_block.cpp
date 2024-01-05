#include "pcapng_pp/pcapng_block.h"
#include <assert.h>
#include "pcapng_pp/pcapng_constants.h"
#include "pcapng_pp/pcapng_error.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

constexpr size_t pcapng_section_header_len {16};
constexpr size_t pcapng_interface_block_len {8};
constexpr size_t pcapng_enchanced_packet_len {5 * sizeof(uint32_t)};
constexpr size_t pcapng_custom_nonstandard_block_len {3 * sizeof(uint32_t)};

namespace {
    size_t get_4_byte_aligned_len(size_t len) {
        constexpr auto alignment {sizeof(uint32_t)};
        return len % sizeof(uint32_t) == 0 ? len : (len / alignment + 1) * alignment;
    }
} // namespace

// AbstractPcapngBlock
    
PcapngBlockType AbstractPcapngBlock::get_type() const {
    return type_;
}

const std::list<BlockOption>& AbstractPcapngBlock::get_options() const {
    return options_;
}

AbstractPcapngBlock::AbstractPcapngBlock(PcapngBlockType t) 
    : type_ {t}
{    
}
    
void AbstractPcapngBlock::parse_options(Span<const char> data) {
    // Options structure.
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Option Code              |         Option Length         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // /                       Option Value                            /
    // /              variable length, padded to 32 bits               /
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // /                                                               /
    // /                 . . . other options . . .                     /
    // /                                                               /
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Option Code == opt_endofopt |   Option Length == 0          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
    assert(data.size() != 0);
    for (size_t offset {0}; offset < data.size();) {
        if (offset + 2 * sizeof(uint16_t) > data.size()) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }

        BlockOption new_opt {};
        new_opt.custom_option_code = *reinterpret_cast<const uint16_t*>(&data[offset]);
        offset += sizeof(uint16_t);
        const auto len {*reinterpret_cast<const uint16_t*>(&data[offset])};
        offset += sizeof(uint16_t);

        if (new_opt.custom_option_code == option_endofopt) {
            break;
        }

        const auto actual_len {get_4_byte_aligned_len(len)};
        if (offset + actual_len >= data.size()) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        new_opt.data.insert(new_opt.data.end(), &data[offset], &data[offset + len]);
        offset += actual_len;

        options_.emplace_back(std::move(new_opt));
    }
}

// SectionHeaderBlock

SectionHeaderBlock::SectionHeaderBlock(Span<const char> data)
    : AbstractPcapngBlock {PcapngBlockType::section_header}
{
    // Section header block:
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                   Block Type = 0x0A0D0D0A                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |                      Byte-Order Magic                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 12 |          Major Version        |         Minor Version         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 16 |                                                               |
    //    |                          Section Length                       |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 24 /                                                               /
    //    /                      Options (variable)                       /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if (data.size() < pcapng_section_header_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto ptr {data.data()};
    byteorder_magic_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    version_.major = *reinterpret_cast<const uint16_t*>(std::exchange(ptr, ptr + sizeof(uint16_t)));
    version_.minor = *reinterpret_cast<const uint16_t*>(std::exchange(ptr, ptr + sizeof(uint16_t)));
    section_length_ = *reinterpret_cast<const uint64_t*>(std::exchange(ptr, ptr + sizeof(uint64_t)));
    if (data.size() > pcapng_section_header_len) {
        parse_options(Span<const char> {ptr, data.size() - pcapng_section_header_len});
    }
}
    
SectionHeaderBlock::Version SectionHeaderBlock::get_version() const {
    return version_;
}

// InterfaceDescriptionBlock

InterfaceDescriptionBlock::InterfaceDescriptionBlock(Span<const char> data)
    : AbstractPcapngBlock {PcapngBlockType::interface_description}
{
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                    Block Type = 0x00000001                    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |           LinkType            |           Reserved            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 12 |                            SnapLen                            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 16 /                                                               /
    //    /                      Options (variable)                       /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if (data.size() < pcapng_interface_block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto ptr {data.data()};
    link_type_ = *reinterpret_cast<const uint16_t*>(std::exchange(ptr, ptr + sizeof(uint16_t)));
    reserved_ = *reinterpret_cast<const uint16_t*>(std::exchange(ptr, ptr + sizeof(uint16_t)));
    snapshot_length_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    if (data.size() > pcapng_interface_block_len) {
        parse_options(Span<const char> {ptr, data.size() - pcapng_interface_block_len});
    }
}

// SimplePacketBlock

SimplePacketBlock::SimplePacketBlock(std::vector<char>&& data)
    : AbstractPcapngBlock {PcapngBlockType::simple_packet},
    block_data_ {std::move(data)},
    packet_data_span_ {block_data_}
{
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                    Block Type = 0x00000003                    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |                    Original Packet Length                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 12 /                                                               /
    //    /                          Packet Data                          /
    //    /              variable length, padded to 32 bits               /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if (data.size() < sizeof(uint32_t)) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto size {*reinterpret_cast<const uint32_t*>(data.data())};
    if (size > (data.size() - sizeof(size))) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    packet_data_span_.subspan(sizeof(uint32_t), size);
    // this block doesn't have options
}

Span<const char> SimplePacketBlock::get_packet_data() const {
    return packet_data_span_;
}

size_t SimplePacketBlock::get_captured_length() const {
    return packet_data_span_.size();
}

size_t SimplePacketBlock::get_original_length() const {
    return 0;
}

InterfaceDescConstPtr SimplePacketBlock::get_interface() const {
    return {};
}

uint64_t SimplePacketBlock::get_timestamp() const {
    return 0;
}

SimplePacketBlock::SimplePacketBlock(PcapngBlockType t) 
    : AbstractPcapngBlock {t}
{    
}

// EnchancedPacketBlock

EnchancedPacketBlock::EnchancedPacketBlock(std::vector<char>&& data, Span<InterfaceDescPtr> interfaces) 
    : SimplePacketBlock {PcapngBlockType::enchanced_packet}
{
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                    Block Type = 0x00000006                    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |                         Interface ID                          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 12 |                        Timestamp (High)                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 16 |                        Timestamp (Low)                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 20 |                    Captured Packet Length                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 24 |                    Original Packet Length                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 28 /                                                               /
    //    /                          Packet Data                          /
    //    /              variable length, padded to 32 bits               /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    /                                                               /
    //    /                      Options (variable)                       /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if (data.size() < pcapng_enchanced_packet_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto ptr {data.data()};
    const auto iface_id {*reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)))};
    timestamp_high_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    timestamp_low_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    const auto captured_len {*reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)))};
    original_capture_length_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    if (iface_id >= interfaces.size() || captured_len > data.size() - pcapng_enchanced_packet_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }

    interface_ = interfaces[iface_id];
    block_data_ = std::move(data);
    packet_data_span_ = Span<const char> {ptr, captured_len};
    ptr += get_4_byte_aligned_len(captured_len);

    const auto end_ptr {data.data() + data.size()};
    if (ptr < end_ptr) {
        parse_options(Span<const char> {ptr, end_ptr});
    }
}

size_t EnchancedPacketBlock::get_original_length() const {
    return original_capture_length_;
}

InterfaceDescConstPtr EnchancedPacketBlock::get_interface() const {
    return interface_;
}

uint64_t EnchancedPacketBlock::get_timestamp() const {
    return (static_cast<uint64_t>(timestamp_high_) << 32) | timestamp_low_;
}

// CustomNonstandardBlock

CustomNonstandardBlock::CustomNonstandardBlock(std::vector<char> &&data) 
    : SimplePacketBlock {PcapngBlockType::custom_block}
{
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |             Block Type = 0x00000BAD or 0x40000BAD             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |                Private Enterprise Number (PEN)                |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 12 /                                                               /
    //    /                          Custom Data                          /
    //    /              variable length, padded to 32 bits               /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    /                                                               /
    //    /                      Options (variable)                       /
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    if (data.size() < pcapng_custom_nonstandard_block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto ptr {data.data()};
    const auto len {*reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)))};
    reserved0_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    reserved1_ = *reinterpret_cast<const uint32_t*>(std::exchange(ptr, ptr + sizeof(uint32_t)));
    if (len > data.size() - pcapng_custom_nonstandard_block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }

    block_data_ = std::move(data);
    packet_data_span_ = Span<const char> {ptr, len};
    ptr += get_4_byte_aligned_len(len);

    const auto end_ptr {data.data() + data.size()};
    if (ptr < end_ptr) {
        parse_options(Span<const char> {ptr, end_ptr});
    }
}