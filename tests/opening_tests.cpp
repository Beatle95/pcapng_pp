#include <gtest/gtest.h>
#include <filesystem>
#include "PcapngFileReader.h"

TEST(FileReader, Opening) {
    const auto simple_correct_path {std::filesystem::u8path("./test_resources/simple_correct.pcapng")};
    ASSERT_TRUE(std::filesystem::exists(simple_correct_path)) << "Test file not found";
    pcapng_pp::PcapngFileReader reader {simple_correct_path};
    EXPECT_NO_THROW(reader.open());
}
