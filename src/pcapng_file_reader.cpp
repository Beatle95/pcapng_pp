#include "pcapng_file_reader.h"
#include <array>
#include <assert.h>
#include <optional>
#include "pcapng_error.h"

using namespace pcapng_pp;

constexpr size_t block_required_len {sizeof(uint32_t) * 3};
constexpr size_t blocks_alignment {4};
constexpr size_t pcapng_section_header_len {16};

constexpr uint32_t section_header_block {0x0A0D0D0A};

constexpr uint16_t option_endofopt	{0};
constexpr uint16_t option_comment {1};
constexpr uint16_t option_shb_hardware {2};
constexpr uint16_t option_shb_os {3};
constexpr uint16_t option_shb_userappl {4};

namespace {
    template<typename T>
    T read_value_from_stream(std::fstream& stream) {
        T result;
        stream.read(reinterpret_cast<char*>(&result), sizeof(result));
        if (stream.gcount() != sizeof(result))
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        return result;
    }
    
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
    std::list<PcapngOption> parse_options(const char *data, size_t size) {
        assert(size != 0);
        std::list<PcapngOption> result;
        for (size_t offset {0}; offset < size;) {
            if (offset + 2 * sizeof(uint16_t) > size) {
                throw PcapngError {ErrorCode::wrong_format_or_damaged};
            }

            PcapngOption new_opt {};
            new_opt.custom_option_code = *reinterpret_cast<const uint16_t*>(&data[offset]);
            offset += sizeof(uint16_t);
            const auto len {*reinterpret_cast<const uint16_t*>(&data[offset])};
            offset += sizeof(uint16_t);

            if (new_opt.custom_option_code == option_endofopt) {
                break;
            }

            const auto alignment {sizeof(uint32_t)};
            const auto actual_len {len % alignment == 0 ? len : (len / alignment + 1) * alignment};
            if (offset + actual_len >= size) {
                throw PcapngError {ErrorCode::wrong_format_or_damaged};
            }
            new_opt.data.insert(new_opt.data.end(), &data[offset], &data[offset + len]);
            offset += actual_len;

            result.emplace_back(std::move(new_opt));
        }
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
    file_stream_.open(file_path_, std::ios::binary | std::ios::in);
    if (!file_stream_.good()) {
        throw PcapngError {ErrorCode::unable_to_open};
    }
    // TODO: take to a consideration magic number and endianness
    // TODO: add support for compressed files

    // read section header block
    auto&& block_ptr {read_next_record()};
    assert(block_ptr);
    if (block_ptr->block_type != section_header_block) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    fill_file_info(block_ptr.get());
    // TODO: we may want to implement fast interface loading here
    is_opened_ = true;
}

std::unique_ptr<PcapngBlock> PcapngFileReader::read_next_record() {
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
    if ((len % blocks_alignment) != 0 || len < block_required_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    std::vector<char> data(len - block_required_len);
    file_stream_.read(data.data(), data.size());
    if (file_stream_.gcount() != data.size()) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    // read footer
    const auto footer_len {read_value_from_stream<uint32_t>(file_stream_)};
    if (footer_len != len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto block_ptr {std::make_unique<PcapngBlock>()};
    block_ptr->block_type = type;
    block_ptr->block_total_length = len;
    parse_block(block_ptr.get(), data);
    return block_ptr;
}

void PcapngFileReader::parse_block(PcapngBlock *block, const std::vector<char>& data) {
    switch (block->block_type) {
        case section_header_block:
            parse_section_header_block(block, data);
            break;

        // TODO: other block types
        
        default:
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
}

void PcapngFileReader::parse_section_header_block(PcapngBlock *block, const std::vector<char>& data) {
    //                             1                   2                   3
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
    auto header {std::make_unique<PcapngSectionHeader>()};
    int offset {0};
    header->byteorder_magic = *reinterpret_cast<const uint32_t*>(data.data() + std::exchange(offset, offset + sizeof(uint32_t)));
    header->major_version = *reinterpret_cast<const uint16_t*>(data.data() + std::exchange(offset, offset + sizeof(uint16_t)));
    header->minor_version = *reinterpret_cast<const uint16_t*>(data.data() + std::exchange(offset, offset + sizeof(uint16_t)));
    header->section_length = *reinterpret_cast<const uint64_t*>(data.data() + offset);
    block->block_body = std::move(header);

    if (data.size() > pcapng_section_header_len) {
        block->options = parse_options(data.data() + pcapng_section_header_len, data.size() - pcapng_section_header_len);
    }
}

void PcapngFileReader::fill_file_info(PcapngBlock *block_ptr) {
    assert(block_ptr != nullptr);
    auto section_header {dynamic_cast<PcapngSectionHeader*>(block_ptr->block_body.get())};
    file_info_.major_version = section_header->major_version;
    file_info_.minor_version = section_header->minor_version;
    
    const auto update_string {[](std::string&& new_val, std::string& val_to_upd) {
        val_to_upd = std::move(new_val);
        // remove everything after first null-terminator
        val_to_upd.erase(std::find(val_to_upd.begin(), val_to_upd.end(), '\0'), val_to_upd.end());
    }};
    for (auto&& opt : block_ptr->options) {
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
