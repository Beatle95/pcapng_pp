#ifndef __PcapngBlock_H__
#define __PcapngBlock_H__
#include <vector>
#include <list>
#include <memory>
#include "tcb/span.hpp"
#include "pcapng_types.h"

/*
    All classes inside this file represents some block types from PcapNg standard.
    They are pretty small and similar, so for now the will be stored in one file.
    
    Class hierarchy:
                 _________________PcapngBlock_________________
                /                      |                      \
    SectionHeaderBlock    InterfaceDescriptionBlock    SimplePacketBlock
                                                            /          \
                                          EnchancedPacketBlock    CustomNonstandardBlock
*/
namespace pcapng_pp {
    class InterfaceDescriptionBlock;
    // we are targeting compilers with no c++20 support, so use non-standard span implementation
    template<typename T> using Span = tcb::span<T>;
    using InterfaceDescPtr = std::shared_ptr<InterfaceDescriptionBlock>;
    using InterfaceDescConstPtr = std::shared_ptr<const InterfaceDescriptionBlock>;

    enum class PcapngBlockType {
        section_header,
        interface_description,
        simple_packet,
        enchanced_packet,
        custom_block
    };

    class AbstractPcapngBlock {
        public:
            AbstractPcapngBlock() = delete;
            virtual ~AbstractPcapngBlock() noexcept = default;

            PcapngBlockType get_type() const;
            const std::list<BlockOption>& get_options() const;

        protected:
            explicit AbstractPcapngBlock(PcapngBlockType t);
            void parse_options(Span<const char> data);

        private:
            std::list<BlockOption> options_;
            const PcapngBlockType type_;
    };


    class SectionHeaderBlock final : public AbstractPcapngBlock {
        public:
            struct Version {
                uint16_t major;
                uint16_t minor;
            };

        public:
            explicit SectionHeaderBlock(Span<const char> data);
            Version get_version() const;

        private:
            uint64_t section_length_;
            uint32_t byteorder_magic_;
            Version version_;
    };


    class InterfaceDescriptionBlock final : public AbstractPcapngBlock {
        public:
            explicit InterfaceDescriptionBlock(Span<const char> data);

        private:
            uint32_t snapshot_length_;
            uint16_t link_type_;
            uint16_t reserved_;
    };


    class SimplePacketBlock : public AbstractPcapngBlock {
        public:
            explicit SimplePacketBlock(std::vector<char>&& data);
            Span<const char> get_packet_data() const;
            size_t get_captured_length() const;
            virtual size_t get_original_length() const;
            virtual InterfaceDescConstPtr get_interface() const;
            virtual uint64_t get_timestamp() const;

        protected:
            SimplePacketBlock(PcapngBlockType t);

        protected:
            // in most of the situation we don't want to reallocate memory for exact packet data
            // (without options and other data which may be presented in packet), so we are storing
            // total data in block_data_ and moving the packet_data_span_ to packet itself
            std::vector<char> block_data_;
            Span<const char> packet_data_span_;
    };


    class EnchancedPacketBlock final : public SimplePacketBlock {
        public:
            explicit EnchancedPacketBlock(std::vector<char>&& data, Span<InterfaceDescPtr> interfaces);
            size_t get_original_length() const final;
            InterfaceDescConstPtr get_interface() const final;
            uint64_t get_timestamp() const final;

        private:
            InterfaceDescConstPtr interface_;
            uint32_t timestamp_high_;
            uint32_t timestamp_low_;
            uint32_t original_capture_length_;
    };


    class CustomNonstandardBlock final : public SimplePacketBlock {
        public:
            explicit CustomNonstandardBlock(std::vector<char>&& data);

        private:
            uint32_t reserved0_;
            uint32_t reserved1_;
    };
}

#endif // __PcapngBlock_H__
