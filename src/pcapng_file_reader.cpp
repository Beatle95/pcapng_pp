#include "pcapng_file_reader.h"
#include <array>
#include <assert.h>
#include <optional>
#include "pcapng_error.h"
#include "pcapng_constants.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

constexpr size_t block_base_len {sizeof(uint32_t) * 3};
constexpr size_t blocks_alignment {4};

namespace {
    template<typename T>
    T read_value_from_stream(std::fstream& stream) {
        T result;
        stream.read(reinterpret_cast<char*>(&result), sizeof(result));
        if (stream.gcount() != sizeof(result))
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        return result;
    }
}

PcapngFileReader::PcapngFileReader(const std::filesystem::path& p)
    : file_path_ {std::filesystem::weakly_canonical(p)}
{    
}
    
std::filesystem::path PcapngFileReader::get_path() const {
    return file_path_;
}

const PcapngFileInfo& PcapngFileReader::get_file_info() const {
    assert(is_opened() && "Caling get_file_info() on closed file is not allowed");
    return file_info_;
}

bool PcapngFileReader::is_opened() const {
    return is_opened_;
}

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
void PcapngFileReader::open() {
    if (is_opened_) {
        return;
    }

    file_stream_.open(file_path_, std::ios::binary | std::ios::in);
    if (!file_stream_.good()) {
        throw PcapngError {ErrorCode::unable_to_open};
    }
    // TODO: take to a consideration magic number and endianness
    // TODO: add support for compressed files

    // read section header block
    auto&& block_ptr {read_next_block()};
    assert(block_ptr);
    if (block_ptr->get_type() != PcapngBlockType::section_header) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    fill_file_info(block_ptr.get());
    // TODO: we may want to implement fast interfaces loading here
    is_opened_ = true;
}

Packet PcapngFileReader::read_next_packet() {
    // TODO:
    return Packet {};
}

std::vector<char> PcapngFileReader::read_from_stream(size_t len) {
    std::vector<char> result(len);
    file_stream_.read(result.data(), len);
    if (file_stream_.gcount() != len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    return result;
}

std::unique_ptr<PcapngBlock> PcapngFileReader::read_next_block() {
    //                         1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                          Block Type                           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 /                          Block Body                           /
    //    /              variable length, padded to 32 bits               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Block Total Length                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const auto type {read_value_from_stream<uint32_t>(file_stream_)};
    if (!type) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto len {read_value_from_stream<uint32_t>(file_stream_)};
    // len of block must be on a 32 bit boundary
    if ((len % blocks_alignment) != 0 || len < block_base_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto block_ptr {parse_block(type, read_from_stream(len - block_base_len))};
    // read footer
    const auto footer_len {read_value_from_stream<uint32_t>(file_stream_)};
    if (footer_len != len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    return block_ptr;
}

std::unique_ptr<PcapngBlock> PcapngFileReader::parse_block(uint32_t block_type, std::vector<char>&& block_data) {
    switch (block_type) {
        case section_header_block:
            return std::make_unique<PcapngSectionHeader>(block_data);

        case interface_block:
            return std::make_unique<PcapngInterfaceDescription>(block_data);

        case simple_packet_block:
            return std::make_unique<PcapngSimplePacket>(std::move(block_data));

        case enchanced_packet_block:
            return std::make_unique<PcapngEnchancedPacket>(std::move(block_data));

        case custom_data_block:
            return std::make_unique<PcapngCustomNonstandardBlock>(std::move(block_data));
        
        default:
            throw PcapngError {ErrorCode::unknown_block_type};
    }
}

void PcapngFileReader::fill_file_info(PcapngBlock *block_ptr) {
    assert(block_ptr != nullptr);
    auto section_header {dynamic_cast<PcapngSectionHeader*>(block_ptr)};
    if (section_header == nullptr) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto ver {section_header->get_version()};
    file_info_.major_version = ver.major;
    file_info_.minor_version = ver.minor;
    
    const auto update_string {[](std::string&& new_val, std::string& val_to_upd) {
        val_to_upd = std::move(new_val);
        // remove everything after first null-terminator
        val_to_upd.erase(std::find(val_to_upd.begin(), val_to_upd.end(), '\0'), val_to_upd.end());
    }};

    for (auto&& opt : section_header->get_options()) {
        switch (opt.custom_option_code) {
            case option_comment:
                update_string(std::string {opt.data.begin(), opt.data.end()}, file_info_.file_comment);
                break;

            case option_shb_hardware:
                update_string(std::string {opt.data.begin(), opt.data.end()}, file_info_.hardware_desc);
                break;

            case option_shb_os:
                update_string(std::string {opt.data.begin(), opt.data.end()}, file_info_.os_desc);
                break;

            case option_shb_userappl:
                update_string(std::string {opt.data.begin(), opt.data.end()}, file_info_.user_app_desc);
                break;
        }
    }
}
