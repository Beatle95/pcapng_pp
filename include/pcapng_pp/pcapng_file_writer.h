#ifndef __PCAPNG_FILE_WRITER_H__
#define __PCAPNG_FILE_WRITER_H__
#include <fstream>
#include <filesystem>
#include "pcapng_types.h"

namespace pcapng_pp {
    class FileWriter {
        public:
            FileWriter(const std::filesystem::path& file_path);
            void write_packet(Span<const byte_t> packet_data);

        private:
            void write_preamble();

        private:
            std::ofstream stream_;
    };
}
#endif // __PCAPNG_FILE_WRITER_H__
