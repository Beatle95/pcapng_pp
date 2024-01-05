#include "pcapng_file_reader.h"
#include <array>
#include <assert.h>
#include <optional>
#include "pcapng_error.h"
#include "pcapng_constants.h"

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

constexpr size_t interfaces_preallocation_size {32};
constexpr size_t block_base_len {sizeof(uint32_t) * 3};
constexpr size_t blocks_alignment {4};

class FileStreamCursorSaver {
    public:
        FileStreamCursorSaver(std::ifstream& s) 
            : file_stream_ {s},
            saved_position_ {file_stream_.tellg()}
        {
        }

        ~FileStreamCursorSaver() {
            file_stream_.seekg(saved_position_, std::ios::beg);
        }

    private:
        std::ifstream& file_stream_;
        std::streampos saved_position_;
};

namespace {
    template<typename T>
    T read_value_from_stream(std::ifstream& stream) {
        T result;
        stream.read(reinterpret_cast<char*>(&result), sizeof(result));
        if (stream.gcount() != sizeof(result))
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        return result;
    }

    // utility function, reads specified amount of data, if data is not enough throws PcapngError
    std::vector<char> read_from_stream(size_t len, std::ifstream& stream) {
        std::vector<char> result(len);
        stream.read(result.data(), len);
        if (stream.gcount() != len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        return result;
    }

    BlockHeader read_block_header(std::ifstream& stream) {
        static_assert(sizeof(BlockHeader) == 2 * sizeof(uint32_t));
        BlockHeader result;
        result.type = read_value_from_stream<uint32_t>(stream);
        result.length = read_value_from_stream<uint32_t>(stream);
        // length of block must be on a 32 bit boundary
        if ((result.length % blocks_alignment) != 0 || result.length < block_base_len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        return result;
    }

    BlockHeader read_block_header_backwards(std::ifstream& stream) {
        assert(stream.tellg() != 0);
        stream.seekg(-static_cast<int64_t>(sizeof(uint32_t)), std::ios::cur);
        uint32_t block_len;
        stream.read(reinterpret_cast<char*>(&block_len), sizeof(block_len));
        if ((block_len % sizeof(uint32_t)) != 0 || stream.tellg() < block_len) {
            throw PcapngError {ErrorCode::wrong_format_or_damaged};
        }
        stream.seekg(-static_cast<int64_t>(block_len), std::ios::cur);
        return read_block_header(stream);
    }

    bool is_packet_block_type(uint32_t t) {
        return t == simple_packet_block || t == enchanced_packet_block;
    }
}

PcapngFileReader::PcapngFileReader(const std::filesystem::path& p)
    : file_path_ {std::filesystem::weakly_canonical(p)}
{
    interfaces_.reserve(interfaces_preallocation_size);
}
    
std::filesystem::path PcapngFileReader::get_path() const {
    return file_path_;
}

const PcapngFileInfo& PcapngFileReader::get_file_info() const {
    assert(is_opened() && "Caling get_file_info() on closed file is not allowed");
    return file_info_;
}

bool PcapngFileReader::is_opened() const {
    return file_stream_.is_open();
}

void PcapngFileReader::open() {
    if (is_opened()) {
        return;
    }

    file_stream_.open(file_path_, std::ios::binary | std::ios::in);
    if (!file_stream_.good()) {
        throw PcapngError {ErrorCode::unable_to_open};
    }

    // TODO: take to a consideration magic number and endianness
    // TODO: add support for compressed files

    // read section header block
    auto&& block_ptr {read_next_block(read_block_header(file_stream_))};
    assert(block_ptr);
    if (block_ptr->get_type() != PcapngBlockType::section_header) {
        throw PcapngError {ErrorCode::wrong_format_or_damaged};
    }
    fill_file_info(block_ptr.get());
    // TODO: we may want to implement fast interfaces loading here
}

void PcapngFileReader::close() {
    if (!is_opened()) {
        return;
    }
    file_stream_.close();
    file_info_ = PcapngFileInfo {};
}

size_t PcapngFileReader::get_total_packet_count() {
    if (!is_opened()) {
        throw PcapngError {ErrorCode::file_not_opened};
    }
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

uint64_t PcapngFileReader::seek_packet(int64_t offset) {
    if (!is_opened()) {
        throw PcapngError {ErrorCode::file_not_opened};
    }
    uint64_t result {0};
    while (offset != 0) {
        assert((file_stream_.tellg() % sizeof(uint32_t)) == 0);
        if (offset > 0) {
            if (file_stream_.peek() == EOF) {
                return result;
            }
            auto block_header {read_block_header(file_stream_)};
            if (is_packet_block_type(block_header.type)) {
                --offset;
                ++result;
            } else if (block_header.type == interface_block) {
                // deal with interface blocks only if we are moving forward
                process_next_interface_block(block_header);
            }
            file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        } else if (offset < 0) {
            if (file_stream_.tellg() == 0) {
                return result;
            }
            auto block_header {read_block_header(file_stream_)};
            if (is_packet_block_type(block_header.type)) {
                ++offset;
                ++result;
            }
        }
    }
    return result;
}

std::optional<Packet> PcapngFileReader::read_packet() {
    if (!is_opened()) {
        throw PcapngError {ErrorCode::file_not_opened};
    }
    while (file_stream_.peek() != EOF) {
        const auto block_header {read_block_header(file_stream_)};
        if (is_packet_block_type(block_header.type)) {
            return dynamic_cast<PcapngSimplePacket*>(read_next_block(block_header).release());
        } else if (block_header.type == interface_block) {
            // deal with interface blocks only if we are moving forward
            process_next_interface_block(block_header);            
        } else {
            // this is some unknown block, for now just skip it
            file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        }
    }
    return {};
}

std::unique_ptr<PcapngBlock> PcapngFileReader::read_next_block(const BlockHeader& block_header) {
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
    auto block_ptr {parse_block(block_header.type, read_from_stream(block_header.length - block_base_len, file_stream_))};
    // read footer
    const auto footer_len {read_value_from_stream<uint32_t>(file_stream_)};
    if (footer_len != block_header.length) {
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
            return std::make_unique<PcapngEnchancedPacket>(std::move(block_data), interfaces_);

        case custom_data_block:
            return std::make_unique<PcapngCustomNonstandardBlock>(std::move(block_data));
        
        default:
            throw PcapngError {ErrorCode::unknown_block_type};
    }
}

void PcapngFileReader::process_next_interface_block(const BlockHeader& block_header) {
    if (last_interface_offset_ >= file_stream_.tellg() - static_cast<std::streampos>(sizeof(BlockHeader))) {
        file_stream_.seekg(block_header.length - sizeof(BlockHeader), std::ios::cur);
        return;
    }
    auto&& new_elem {interfaces_.emplace_back(dynamic_cast<PcapngInterfaceDescription*>(read_next_block(block_header).release()))};
    assert(bool(new_elem));
    last_interface_offset_ = file_stream_.tellg() - static_cast<std::streampos>(block_header.length);
    assert(last_interface_offset_ >= 0 && last_interface_offset_ % 4 == 0);
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
