#ifndef __PCAPNG_FILE_WRITER_H__
#define __PCAPNG_FILE_WRITER_H__
#include <fstream>
#include <filesystem>
#include "pcapng_types.h"

namespace pcapng_pp {
    enum class OpenMode { trunc, append, require_new };

    class FileWriter {
        public:
            FileWriter(const std::filesystem::path& file_path, OpenMode mode);
            void write_interface(uint16_t link_type, uint32_t snap_len = 0xffff);
            void write_packet(Span<const byte_t> packet_data);

        private:
            std::ofstream stream_;
    };
}
#endif // __PCAPNG_FILE_WRITER_H__
