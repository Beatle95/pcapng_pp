#include "pcapng_pp/pcapng_file_reader.h"
#include <array>
#include <cassert>
#include "pcapng_pp/pcapng_error.h"
#include "pcapng_pp/pcapng_constants.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

constexpr size_t block_base_len {3 * sizeof(uint32_t)};
constexpr size_t blocks_alignment {sizeof(uint32_t)};
constexpr size_t pcapng_section_header_len {4 * sizeof(uint32_t)};
constexpr size_t pcapng_interface_block_len {2 * sizeof(uint32_t)};
constexpr size_t pcapng_enchanced_packet_len {5 * sizeof(uint32_t)};
constexpr size_t pcapng_custom_nonstandard_block_len {3 * sizeof(uint32_t)};
constexpr size_t min_option_len {2 * sizeof(uint16_t)};

namespace {
    class FileStreamCursorSaver {
        public:
            FileStreamCursorSaver(std::ifstream &s) : stream_ {s}, pos_ {stream_.tellg()} {}
            ~FileStreamCursorSaver() { stream_.seekg(pos_, std::ios::beg); }

        private:
            std::ifstream& stream_;
            std::streampos pos_;
    };

    // utility function, reads specified amount of data, if data is not enough throws PcapngError
    std::vector<byte_t> read_from_stream(size_t len, std::ifstream& stream) {
        std::vector<byte_t> result(len);
        stream.read(reinterpret_cast<char*>(result.data()), len);
        if (stream.gcount() != len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        return result;
    }

    bool is_packet_block_type(uint32_t t) {
        return t == simple_packet_block || t == enchanced_packet_block;
    }

    size_t get_4_byte_aligned_len(size_t len) {
        constexpr auto alignment {sizeof(uint32_t)};
        return len % sizeof(uint32_t) == 0 ? len : (len / alignment + 1) * alignment;
    }

    template<typename T>
    T byteswap(T value) {
        static_assert(std::is_integral_v<T>);
        union {
            T val;
            byte_t arr[sizeof(T)];
        } result;
        result.val = 0;

        auto value_ptr {reinterpret_cast<const byte_t*>(&value)};
        for (size_t i {0}; i < sizeof(T); ++i) {
            result.arr[sizeof(T) - 1 - i] = *(value_ptr++);
        }
        return result.val;
    }
} // namespace

FileReader::FileReader(const std::filesystem::path& p)
    : file_path_ {std::filesystem::weakly_canonical(p)}
{
    file_stream_.open(file_path_, std::ios::binary | std::ios::in);
    if (!file_stream_.good()) {
        throw PcapngError {ErrorCode::unable_to_open};
    }

    // read section header block
    auto&& block_ptr {read_block(read_block_header(file_stream_))};
    assert(block_ptr);
    if (block_ptr->get_type() != PcapngBlockType::section_header) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }

    const auto& section {dynamic_cast<const SectionHeaderBlock&>(*block_ptr)};
    fill_file_info(section);
    // take to a consideration magic number and endianness
    if (section.get_magic() == constants::byte_order_magic) {
        swap_byte_order_ = false;
    } else if (section.get_magic() == byteswap(constants::byte_order_magic)) {
        swap_byte_order_ = true;
    } else {
        throw PcapngError {ErrorCode::wrong_magic_number};
    }
    // TODO: we may want to implement fast interfaces loading here
    // TODO: add support for compressed files
}

std::filesystem::path FileReader::get_path() const {
    return file_path_;
}

const FileInfo& FileReader::get_file_info() const {
    return file_info_;
}

size_t FileReader::get_total_packets_count() {
    size_t result {0};
    FileStreamCursorSaver position_saver {file_stream_};
    file_stream_.seekg(0, std::ios::beg);
    while (file_stream_.peek() != EOF) {
        auto block_header {read_block_header(file_stream_)};
        if (is_packet_block_type(block_header.type)) {
            ++result;
        }
        file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
    }
    return result;
}

uint64_t FileReader::get_packet_pos() const {
    return packet_pos_;
}

uint64_t FileReader::seek_packet(int64_t offset) {
    uint64_t result {0};
    while (offset != 0) {
        if (offset > 0) {
            if (file_stream_.peek() == EOF) {
                return result;
            }
            auto block_header {read_block_header(file_stream_)};
            if (is_packet_block_type(block_header.type)) {
                --packet_pos_;
                --offset;
                ++result;
            } else if (block_header.type == interface_block) {
                // deal with interface blocks only if we are moving forward
                read_next_interface_block(block_header);
            }
            file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        } else if (offset < 0) {
            if (file_stream_.tellg() == 0) {
                return result;
            }
            auto block_header {read_block_header_backwards(file_stream_)};
            if (is_packet_block_type(block_header.type)) {
                ++packet_pos_;
                ++offset;
                ++result;
            }
            file_stream_.seekg(-static_cast<int>(sizeof(BlockHeader)), std::ios::cur);
        }
    }
    return result;
}

std::optional<Packet> FileReader::read_packet() {
    while (file_stream_.peek() != EOF) {
        const auto block_header {read_block_header(file_stream_)};
        if (is_packet_block_type(block_header.type)) {
            ++packet_pos_;
            return std::unique_ptr<PacketBlock> {
                dynamic_cast<PacketBlock*>(read_block(block_header).release())
            };
        } else if (block_header.type == interface_block) {
            // deal with interface blocks only if we are moving forward
            read_next_interface_block(block_header);
        } else {
            // this is some unknown block, for now just skip it
            file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        }
    }
    return {};
}

BlockHeader FileReader::read_block_header(std::ifstream& stream) {
    BlockHeader result;
    result.type = get_value_from_stream<decltype(result.type)>(stream);
    result.length = get_value_from_stream<decltype(result.length)>(stream);
    // length of block must be on a 32 bit boundary
    if ((result.length % blocks_alignment) != 0 || result.length < block_base_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    return result;
}

BlockHeader FileReader::read_block_header_backwards(std::ifstream& stream) {
    assert(stream.tellg() != 0 && stream.is_open());
    if (stream.peek() == EOF) {
        stream.clear();
    }
    stream.seekg(-static_cast<int64_t>(sizeof(uint32_t)), std::ios::cur);
    uint32_t block_len;
    stream.read(reinterpret_cast<char*>(&block_len), sizeof(block_len));
    if ((block_len % sizeof(uint32_t)) != 0 || stream.tellg() < block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    stream.seekg(-static_cast<int64_t>(block_len), std::ios::cur);
    return read_block_header(stream);
}

std::unique_ptr<BasePcapngBlock> FileReader::read_block(const BlockHeader& block_header) {
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
    assert((block_header.length % blocks_alignment) == 0 && block_header.length >= block_base_len);
    std::unique_ptr<BasePcapngBlock> result;
    const auto inner_len {block_header.length - block_base_len};
    switch (block_header.type) {
        case section_header_block:
            result = read_section_block(inner_len);
            break;
        case interface_block:
            result = read_interface_block(inner_len);
            break;
        case simple_packet_block:
            result = read_simple_packet_block(inner_len);
            break;
        case enchanced_packet_block:
            result = read_enchanced_packet_block(inner_len);
            break;
        case custom_data_block:
            result = read_custom_packet_block(inner_len);
            break;
        default:
            throw PcapngError{ErrorCode::unknown_block_type};
    }

    // read footer
    const auto footer_len {get_value_from_stream<uint32_t>(file_stream_)};
    if (footer_len != block_header.length) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    return result;
}

std::unique_ptr<SectionHeaderBlock> FileReader::read_section_block(size_t size) {
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
    if (size < pcapng_section_header_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto block {std::make_unique<SectionHeaderBlock>(
        get_value_from_stream<uint32_t>(file_stream_),
        get_value_from_stream<uint16_t>(file_stream_),
        get_value_from_stream<uint16_t>(file_stream_),
        get_value_from_stream<uint64_t>(file_stream_)
    )};
    size -= pcapng_section_header_len;
    if (size >= min_option_len) {
        read_block_options(size, *block.get());
    } else if (size != 0) {
        file_stream_.seekg(size, std::ios::cur);
    }
    return block;
}

std::unique_ptr<InterfaceDescriptionBlock> FileReader::read_interface_block(size_t size) {
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
    if (size < pcapng_interface_block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto block {std::make_unique<InterfaceDescriptionBlock>(
        get_value_from_stream<uint16_t>(file_stream_),
        get_value_from_stream<uint16_t>(file_stream_),
        get_value_from_stream<uint32_t>(file_stream_)
    )};
    size -= pcapng_interface_block_len;
    if (size >= min_option_len) {
        read_block_options(size, *block.get());
    } else if (size != 0) {
        file_stream_.seekg(size, std::ios::cur);
    }
    return block;
}

std::unique_ptr<PacketBlock> FileReader::read_simple_packet_block(size_t size) {
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
    if (size < sizeof(uint32_t)) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto data_size {get_value_from_stream<uint32_t>(file_stream_)};
    size -= sizeof(uint32_t);
    if (data_size > size) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    auto block {std::make_unique<PacketBlock>()};
    block->set_data(read_from_stream(data_size, file_stream_));
    size -= data_size;
    // this block doesn't have options
    if (size != 0) {
        file_stream_.seekg(size, std::ios::cur);
    }

    // by default each simple packet block is connected to interface with ID == 0
    if (interfaces_.empty()) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    block->set_interface(interfaces_.front());
    return block;
}

std::unique_ptr<EnchancedPacketBlock> FileReader::read_enchanced_packet_block(size_t size) {
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
    if (size < pcapng_enchanced_packet_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto iface_id {get_value_from_stream<uint32_t>(file_stream_)};
    const auto timestamp_high {get_value_from_stream<uint32_t>(file_stream_)};
    const auto timestamp_low {get_value_from_stream<uint32_t>(file_stream_)};
    const auto captured_len {get_value_from_stream<uint32_t>(file_stream_)};
    const auto original_capture_length {get_value_from_stream<uint32_t>(file_stream_)};
    size -= pcapng_enchanced_packet_len;
    if (iface_id >= interfaces_.size() || captured_len > size) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }

    auto block{std::make_unique<EnchancedPacketBlock>(timestamp_high, timestamp_low, original_capture_length)};
    block->set_interface(interfaces_[iface_id]);
    block->set_data(read_from_stream(captured_len, file_stream_));
    size -= captured_len;
    if (size >= min_option_len) {
        read_block_options(size, *block.get());
    } else if (size != 0) {
        file_stream_.seekg(size, std::ios::cur);
    }
    return block;
}

std::unique_ptr<CustomPacketBlock> FileReader::read_custom_packet_block(size_t size) {
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
    if (size < pcapng_custom_nonstandard_block_len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    const auto len {get_value_from_stream<uint32_t>(file_stream_)};
    auto block {std::make_unique<CustomPacketBlock>(
        get_value_from_stream<uint32_t>(file_stream_),
        get_value_from_stream<uint32_t>(file_stream_)
    )};
    size -= pcapng_custom_nonstandard_block_len;
    if (size < len) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }

    block->set_data(read_from_stream(len, file_stream_));
    if (size >= min_option_len) {
        read_block_options(size, *block.get());
    } else if (size != 0) {
        file_stream_.seekg(size, std::ios::cur);
    }
    return block;
}

void FileReader::read_block_options(size_t bytes_to_block_end, BasePcapngBlock& block) {
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
    assert(bytes_to_block_end >= min_option_len);
    while (bytes_to_block_end > 0) {
        if (bytes_to_block_end < min_option_len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }

        BlockOption new_opt {};
        new_opt.custom_option_code = get_value_from_stream<uint16_t>(file_stream_);
        const auto len {get_value_from_stream<uint16_t>(file_stream_)};
        if (new_opt.custom_option_code == option_endofopt) {
            break;
        }

        bytes_to_block_end -= min_option_len;
        const auto actual_len {get_4_byte_aligned_len(len)};
        assert(actual_len >= len);
        if (bytes_to_block_end < actual_len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        new_opt.data = read_from_stream(len ,file_stream_);
        block.add_option(std::move(new_opt));

        bytes_to_block_end -= actual_len;
        const auto diff {actual_len - len};
        if (diff > 0) {
            file_stream_.seekg(diff, std::ios::cur);
        }
    }
}

void FileReader::read_next_interface_block(const BlockHeader& block_header) {
    if (last_interface_offset_ >= file_stream_.tellg() - static_cast<std::streampos>(sizeof(BlockHeader))) {
        file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        return;
    }
    auto&& new_elem {interfaces_.emplace_back(dynamic_cast<InterfaceDescriptionBlock*>(read_block(block_header).release()))};
    assert(bool(new_elem));
    last_interface_offset_ = file_stream_.tellg() - static_cast<std::streampos>(block_header.length);
    assert(last_interface_offset_ >= 0 && last_interface_offset_ % 4 == 0);
}

void FileReader::fill_file_info(const SectionHeaderBlock& section_header) {
    const auto ver {section_header.get_version()};
    file_info_.major_version = ver.major;
    file_info_.minor_version = ver.minor;
    file_info_.file_comment = section_header.get_option_string(option_comment);
    file_info_.hardware_desc = section_header.get_option_string(option_shb_hardware);
    file_info_.os_desc = section_header.get_option_string(option_shb_os);
    file_info_.user_app_desc = section_header.get_option_string(option_shb_userappl);
}

template<typename T>
T FileReader::get_value_from_stream(std::ifstream& stream) {
    static_assert(std::is_integral_v<T>);
    T result;
    stream.read(reinterpret_cast<char*>(&result), sizeof(result));
    if (stream.gcount() != sizeof(result)) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    return swap_byte_order_ ? byteswap(result) : result;
}
