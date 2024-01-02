#include <gtest/gtest.h>
#include <filesystem>
#include "path.h"
#include "PcapngFileReader.h"

void try_open(std::string_view name) {
    const auto file_path {std::filesystem::u8path(test_resources_path) / name};
    ASSERT_TRUE(std::filesystem::exists(file_path)) << "Test file not found";
    pcapng_pp::PcapngFileReader reader {file_path};
    EXPECT_NO_THROW(reader.open());
}

TEST(FileReader, Opening) {
    try_open("simple_correct.pcapng");
    try_open("correct_with_options.pcapng");
}
