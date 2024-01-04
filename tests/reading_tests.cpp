#include <gtest/gtest.h>
#include <filesystem>
#include "path.h"
#include "pcapng_file_reader.h"

using namespace pcapng_pp;

void try_open(std::string_view name) {
}

TEST(FileReader, Opening) {
    {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "simple_correct.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        PcapngFileReader reader {file_path};
        EXPECT_NO_THROW(reader.open());
    }
    
    {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "correct_with_options.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        PcapngFileReader reader {file_path};
        EXPECT_NO_THROW(reader.open());
        EXPECT_EQ(reader.get_file_info().file_comment, "Hello world");
    }
}

TEST(FileReader, Navigating) {
    {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "simple_correct.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        PcapngFileReader reader {file_path};
        EXPECT_NO_THROW(reader.open());
        EXPECT_EQ(reader.get_total_packet_count(), 4);
    }
    
    {
        const auto file_path {std::filesystem::u8path(test_resources_path) / "correct_with_options.pcapng"};
        ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
        PcapngFileReader reader {file_path};
        EXPECT_NO_THROW(reader.open());
        EXPECT_EQ(reader.get_total_packet_count(), 0);
    }    
}
