#ifndef __PCAPNGFILE_H__
#define __PCAPNGFILE_H__
#include <filesystem>
#include <fstream>
#include <utility>
#include <list>
#include <vector>
#include <optional>
#include "pcapng_block.h"
#include "packet.h"

namespace pcapng_pp {
    /*
        Class for reading .pcapng files. In case of an errors throws PcapngError.
    */
    class PcapngFileReader {
        public:
            PcapngFileReader() = delete;
            explicit PcapngFileReader(const std::filesystem::path& p);

            std::filesystem::path get_path() const;
            const PcapngFileInfo& get_file_info() const;
            bool is_opened() const;

            void open();
            void close();
            // returns the amount of packets inside file (this function will have to go through all file and may be slow on large files)
            // this function does not parses all packets, options, interfaces, etc; so it is possible that file is damaged, but we still
            // may count total amount of packets
            size_t get_total_packet_count();
            // moves internal file position indicator (forward [if offset is positive])/(backward [if offset if negative])
            // on the specified by offset amount of readable packets, returns actual number of packets that was skipped
            uint64_t seek_packet(int64_t offset);
            // reads next packet, if returned object is empty, then EOF was reached
            // in case of any error throws PcapngError
            std::optional<Packet> read_packet();

        private:
            std::unique_ptr<PcapngBlock> read_next_block(const BlockHeader& block_header);
            std::unique_ptr<PcapngBlock> parse_block(uint32_t block_type, std::vector<char>&& block_data);
            // this function reads next interface block and possibly places it inside interfaces_ storage
            void process_next_interface_block(const BlockHeader& block_header);
            void fill_file_info(PcapngBlock *block_ptr);

        private:
            const std::filesystem::path file_path_;
            std::vector<std::shared_ptr<PcapngInterfaceDescription>> interfaces_;
            std::ifstream file_stream_;
            std::streampos last_interface_offset_ {0};
            PcapngFileInfo file_info_ {};
    };
}
#endif // __PCAPNGFILE_H__
