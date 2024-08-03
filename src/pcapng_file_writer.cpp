#include <pcapng_pp/pcapng_file_writer.h>
#include <filesystem>
#include <pcapng_pp/pcapng_constants.h>
#include <pcapng_pp/pcapng_error.h>
#include <pcapng_pp/pcapng_functions.h>

using namespace pcapng_pp;
using namespace pcapng_pp::constants;

constexpr uint64_t section_header_len {0xFFFFFFFFFFFFFFFF};
constexpr uint32_t simple_packet_block_base_len {4 * 4};
constexpr uint32_t section_block_len {7 * 4};
constexpr uint32_t interface_block_len {5 * 4};
constexpr uint32_t interface_block_snap_len {0};
constexpr uint16_t version_major {1};
constexpr uint16_t version_minor {0};
constexpr uint16_t interfacee_block_reserved_field {0};

FileWriter::FileWriter(const std::filesystem::path& file_path) {
    if (std::filesystem::exists(file_path)) {
        throw PcapngError {ErrorCode::file_exists};
    }
    stream_.exceptions(std::ios::badbit | std::ios::failbit);

    stream_.open(file_path, std::ios::binary);
    if (!stream_) {
        throw PcapngError {ErrorCode::unable_to_open};
    }

    try {
        write_preamble();
    } catch (const std::exception& err) {
        throw PcapngDescriptiveError {ErrorCode::write_error, err.what()};
    }
}

void FileWriter::write_packet(Span<const byte_t> packet_data) {
    try {
        const uint32_t original_len = packet_data.size();
        const uint32_t padding = functions::get_4_byte_aligned_len(original_len) - original_len;
        const uint32_t total_len {simple_packet_block_base_len + original_len + padding};
        stream_.write(reinterpret_cast<const char*>(&simple_packet_block), sizeof(simple_packet_block));
        stream_.write(reinterpret_cast<const char*>(&total_len), sizeof(total_len));
        stream_.write(reinterpret_cast<const char*>(&original_len), sizeof(original_len));
        stream_.write(reinterpret_cast<const char*>(packet_data.data()), packet_data.size());
        if (padding != 0) {
            stream_.seekp(padding, std::ios::cur);
        }
        stream_.write(reinterpret_cast<const char*>(&total_len), sizeof(total_len));
    } catch (const std::exception& err) {
        throw PcapngDescriptiveError {ErrorCode::write_error, err.what()};
    }
}

void FileWriter::write_preamble() {
    // first write section header block
    stream_.write(reinterpret_cast<const char*>(&section_header_block), sizeof(section_header_block));
    stream_.write(reinterpret_cast<const char*>(&section_block_len), sizeof(section_block_len));
    stream_.write(reinterpret_cast<const char*>(&byte_order_magic), sizeof(byte_order_magic));
    stream_.write(reinterpret_cast<const char*>(&version_major), sizeof(version_major));
    stream_.write(reinterpret_cast<const char*>(&version_minor), sizeof(version_minor));
    stream_.write(reinterpret_cast<const char*>(&section_header_len), sizeof(section_header_len));
    stream_.write(reinterpret_cast<const char*>(&section_block_len), sizeof(section_block_len));

    // second, write interface description block
    stream_.write(reinterpret_cast<const char*>(&interface_block), sizeof(interface_block));
    stream_.write(reinterpret_cast<const char*>(&interface_block_len), sizeof(interface_block_len));
    stream_.write(reinterpret_cast<const char*>(&ethernet_link_type), sizeof(ethernet_link_type));
    stream_.write(reinterpret_cast<const char*>(&interfacee_block_reserved_field), sizeof(interfacee_block_reserved_field));
    stream_.write(reinterpret_cast<const char*>(&interface_block_snap_len), sizeof(interface_block_snap_len));
    stream_.write(reinterpret_cast<const char*>(&interface_block_len), sizeof(interface_block_len));
}
