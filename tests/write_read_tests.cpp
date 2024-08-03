#include <gtest/gtest.h>
#include <filesystem>
#include <pcapng_pp/pcapng_file_writer.h>
#include <pcapng_pp/pcapng_file_reader.h>

using namespace pcapng_pp;

const std::filesystem::path test_path {"test.pcapng"};

TEST(WriteRead, WriteRead) {
    std::filesystem::remove(test_path);
    {
        FileWriter writer {test_path};
        for (uint32_t i = 0; i < 1000; ++i) {
            std::vector<unsigned char> data(i);
            for (uint32_t j = 0; j < i; ++j) {
                data[j] = j % 256;
            }
            writer.write_packet(data);
        }
    }
    try {
        FileReader reader {test_path};
        for (uint32_t i = 0; i < 1000; ++i) {
            auto packet {reader.read_packet()};
            ASSERT_TRUE(packet);
            ASSERT_EQ(packet.value().get_captured_length(), i);

            const auto data {packet.value().get_packet_data()};
            for (uint32_t j = 0; j < i; ++j) {
                ASSERT_EQ(data[j], j % 256);
            }
        }
    } catch (...) {
        ASSERT_TRUE(false);
    }
    std::filesystem::remove(test_path);
}