#ifndef __PCAPNGFILE_H__
#define __PCAPNGFILE_H__
#include <filesystem>
#include <fstream>
#include <vector>
#include <optional>
#include "pcapng_block.h"
#include "pcapng_packet.h"

namespace pcapng_pp {
    /*
        Class for reading .pcapng files. In case of an errors public functions throws PcapngError.
    */
    class FileReader {
        public:
            FileReader() = delete;
            // this ctor will open specified file, in case of an error it will throw PcapngError
            explicit FileReader(const std::filesystem::path& p);
            // returns filesystem path to opened file
            std::filesystem::path get_path() const;
            // returns pcapng file info about opened file
            const FileInfo& get_file_info() const;

            // returns the amount of packets inside file (this function will have to go through all file and may be slow on large files)
            // this function does not parses all packets, options, interfaces, etc; so it is possible that file is damaged, but we still
            // may count total amount of packets
            size_t get_total_packets_count();
            // returns current packets position (i.e. the amount of packets that was already read)
            uint64_t get_packet_pos() const;
            // moves internal file position indicator (forward [if offset is positive])/(backward [if offset if negative])
            // on the specified by offset amount of readable packets, returns actual number of packets that was skipped
            uint64_t seek_packet(int64_t offset);
            // reads next packet, if returned object is empty, then EOF was reached
            // in case of any error throws PcapngError
            std::optional<Packet> read_packet();

        private:
            BlockHeader read_block_header(std::ifstream& stream);
            BlockHeader read_block_header_backwards(std::ifstream& stream);
            std::unique_ptr<BasePcapngBlock> read_block(const BlockHeader& block_header);

            std::unique_ptr<SectionHeaderBlock> read_section_block(size_t size);
            std::unique_ptr<InterfaceDescriptionBlock> read_interface_block(size_t size);

            std::unique_ptr<PacketBlock> read_simple_packet_block(size_t size);
            std::unique_ptr<EnchancedPacketBlock> read_enchanced_packet_block(size_t size);
            std::unique_ptr<CustomPacketBlock> read_custom_packet_block(size_t size);

            void read_block_options(size_t bytes_to_block_end, BasePcapngBlock& block);
            // this function reads next interface block and possibly places it inside interfaces_ storage
            void read_next_interface_block(const BlockHeader& block_header);
            void fill_file_info(const SectionHeaderBlock& block_ptr);

            template<typename T>
            T get_value_from_stream(std::ifstream& stream);

        private:
            const std::filesystem::path file_path_;
            // TODO: interfaces must be in section header block
            std::vector<std::shared_ptr<InterfaceDescriptionBlock>> interfaces_;
            std::ifstream file_stream_;
            std::streampos last_interface_offset_ {0};
            FileInfo file_info_ {};
            uint64_t packet_pos_ {};
            bool swap_byte_order_ {false};
    };
}
#endif // __PCAPNGFILE_H__
