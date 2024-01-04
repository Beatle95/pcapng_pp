#ifndef __PcapngBlock_H__
#define __PcapngBlock_H__
#include <vector>
#include <list>
#include "tcb/span.hpp"
#include "pcapng_types.h"

/*
    All classes inside this file represents some block types from PcapNg standard.
    They are pretty small and similar, so for now the will be stored in one file.
    
    Class hierarchy:
                 _________________PcapngBlock_________________
                /                      |                      \
    PcapngSectionHeader    PcapngInterfaceDescription    PcapngSimplePacket
                                                            /          \
                                          PcapngEnchancedPacket    PcapngCustomNonstandardBlock
*/
namespace pcapng_pp {
    // we are targeting compilers with no c++20 support, so use non-standard span implementation
    template<typename T> using Span = tcb::span<T>;

    enum class PcapngBlockType {
        section_header,
        interface_description,
        simple_packet,
        enchanced_packet,
        custom_block
    };

    class PcapngBlock {
        public:
            PcapngBlock() = delete;
            virtual ~PcapngBlock() noexcept = default;

            PcapngBlockType get_type() const;
            const std::list<PcapngOption>& get_options() const;

        protected:
            explicit PcapngBlock(PcapngBlockType t);
            void parse_options(Span<const char> data);

        private:
            std::list<PcapngOption> options_;
            const PcapngBlockType type_;
    };


    class PcapngSectionHeader final : public PcapngBlock {
        public:
            struct Version {
                uint16_t major;
                uint16_t minor;
            };

        public:
            explicit PcapngSectionHeader(Span<const char> data);
            Version get_version() const;

        private:
            uint64_t section_length_;
            uint32_t byteorder_magic_;
            Version version_;
    };


    class PcapngInterfaceDescription final : public PcapngBlock {
        public:
            explicit PcapngInterfaceDescription(Span<const char> data);

        private:
            uint32_t snapshot_length_;
            uint16_t link_type_;
            uint16_t reserved_;
    };


    class PcapngSimplePacket : public PcapngBlock {
        public:
            explicit PcapngSimplePacket(std::vector<char>&& data);
            Span<const char> get_packet_data() const;

        protected:
            PcapngSimplePacket(PcapngBlockType t);

        protected:
            // in most of the situation we don't want to reallocate memory for exact packet data
            // (without options and other data which may be presented in packet), so we are storing
            // total data in block_data_ and moving the packet_data_span_ to packet itself
            std::vector<char> block_data_;
            Span<const char> packet_data_span_;
    };


    class PcapngEnchancedPacket final : public PcapngSimplePacket {
        public:
            explicit PcapngEnchancedPacket(std::vector<char>&& data);

        private:
            uint32_t interface_id_;
            uint32_t timestamp_high_;
            uint32_t timestamp_low_;
            uint32_t original_capture_length_;
    };


    class PcapngCustomNonstandardBlock final : public PcapngSimplePacket {
        public:
            explicit PcapngCustomNonstandardBlock(std::vector<char>&& data);

        private:
            uint32_t reserved0_;
            uint32_t reserved1_;
    };
}

#endif // __PcapngBlock_H__
