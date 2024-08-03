#include <gtest/gtest.h>
#include <filesystem>
#include "path.h"
#include "pcapng_pp/pcapng_file_reader.h"

using namespace pcapng_pp;

TEST(FileReader, Opening) {
    try {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "simple_correct.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        FileReader reader {file_path};
    } catch (...) {
        ASSERT_TRUE(false) << "Mustn't throw";
    }
    
    try {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "correct_with_options.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";        
        FileReader reader {file_path};
        ASSERT_EQ(reader.get_file_info().file_comment, "Hello world");
    } catch (...) {
        ASSERT_TRUE(false) << "Mustn't throw";
    }
}

TEST(FileReader, Reading) {
    try {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "simple_correct.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        FileReader reader {file_path};
        ASSERT_EQ(reader.get_total_packets_count(), 4);

        auto packet_opt = reader.read_packet();
        ASSERT_TRUE(packet_opt.has_value());
        auto packet_data {packet_opt.value().get_packet_data()};
        ASSERT_EQ(packet_data.size(), 314);
        ASSERT_TRUE(packet_data[0] == 0xFF);
        ASSERT_TRUE(packet_data[48] == 0x3D);
        ASSERT_TRUE(packet_data[0x131] == 0x2A);

        ASSERT_EQ(reader.get_total_packets_count(), 4);

        packet_opt = reader.read_packet();
        packet_data = packet_opt.value().get_packet_data();
        ASSERT_TRUE(packet_opt.has_value());
        ASSERT_EQ(packet_data.size(), 342);
        ASSERT_EQ(packet_data[1], 0x0B);
        ASSERT_EQ(packet_data[0x120], 0xFF);

        packet_opt = reader.read_packet();
        packet_data = packet_opt.value().get_packet_data();
        ASSERT_TRUE(packet_opt.has_value());
        ASSERT_EQ(packet_data.size(), 314);
        ASSERT_EQ(packet_data[0x138], 0xFF);
        ASSERT_EQ(packet_data[0x139], 0x00);

        packet_opt = reader.read_packet();
        packet_data = packet_opt.value().get_packet_data();
        ASSERT_TRUE(packet_opt.has_value());
        ASSERT_EQ(packet_data.size(), 342);
        ASSERT_EQ(packet_data[0x21], 0x0A);
        ASSERT_EQ(packet_data[0x22], 0x00);

        packet_opt = reader.read_packet();
        ASSERT_FALSE(packet_opt.has_value());

        ASSERT_EQ(reader.seek_packet(-3), 3);

        packet_opt = reader.read_packet();
        packet_data = packet_opt.value().get_packet_data();
        ASSERT_TRUE(packet_opt.has_value());
        ASSERT_EQ(packet_data.size(), 342);
        ASSERT_EQ(packet_data[1], 0x0B);
        ASSERT_EQ(packet_data[0x120], 0xFF);
    } catch (...) {
        ASSERT_TRUE(false) << "Mustn't throw";
    }
    
    try {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "correct_with_options.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        FileReader reader {file_path};
        ASSERT_EQ(reader.get_total_packets_count(), 0);

        auto packet_opt = reader.read_packet();
        ASSERT_FALSE(packet_opt.has_value());
    } catch (...) {
        ASSERT_TRUE(false) << "Mustn't throw";
    }
}
