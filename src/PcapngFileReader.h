#ifndef __PCAPNGFILE_H__
#define __PCAPNGFILE_H__
#include <filesystem>
#include <fstream>
#include <utility>
#include "Types.h"

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

        private:
            std::unique_ptr<PcapngBlock> read_next_record();
            std::list<PcapngOption> read_options(std::vector<char>::iterator begin, std::vector<char>::iterator end);

        private:
            const std::filesystem::path file_path_;
            std::fstream file_stream_;
            PcapngFileInfo file_info_ {};
            bool is_opened_ {false};
    };
}
#endif // __PCAPNGFILE_H__
