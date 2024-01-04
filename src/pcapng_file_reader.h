#ifndef __PCAPNGFILE_H__
#define __PCAPNGFILE_H__
#include <filesystem>
#include <fstream>
#include <utility>
#include <list>
#include <vector>
#include "pcapng_block.h"
#include "packet.h"

namespace pcapng_pp {
    /*
        Class for reading .pcapng files. In case of an errors throws exceptions
    */
    class PcapngFileReader {
        public:
            PcapngFileReader() = delete;
            explicit PcapngFileReader(const std::filesystem::path& p);

            std::filesystem::path get_path() const;
            // must not have beed called on closed object
            const PcapngFileInfo& get_file_info() const;

            bool is_opened() const;
            void open();
            Packet read_next_packet();

        private:
            // utility function, reads specified amount of data, if data is not enough throws PcapngError
            std::vector<char> read_from_stream(size_t len);
            std::unique_ptr<PcapngBlock> read_next_block();
            std::unique_ptr<PcapngBlock> parse_block(uint32_t block_type, std::vector<char>&& block_data);
            void fill_file_info(PcapngBlock *block_ptr);

        private:
            const std::filesystem::path file_path_;
            std::fstream file_stream_;
            PcapngFileInfo file_info_ {};
            bool is_opened_ {false};
    };
}
#endif // __PCAPNGFILE_H__
