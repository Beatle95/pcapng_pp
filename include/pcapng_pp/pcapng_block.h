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
                 _____________AbstractPcapngBlock_____________
                /                      |                      \
    SectionHeaderBlock    InterfaceDescriptionBlock    SimplePacketBlock
                                                            /          \
                                          EnchancedPacketBlock    CustomNonstandardBlock
*/
namespace pcapng_pp {
    class InterfaceDescriptionBlock;
    using InterfaceBlockPtr = std::shared_ptr<const InterfaceDescriptionBlock>;

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
            bool is_option_exists(uint16_t option_code) const;
            Span<const char> get_option_data(uint16_t option_code) const;

            void add_option(const BlockOption& opt);
            void add_option(BlockOption&& opt);

        protected:
            explicit AbstractPcapngBlock(PcapngBlockType t);

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
            SectionHeaderBlock(uint32_t magic, uint16_t ver_major, uint16_t ver_minor, uint64_t len);
            Version get_version() const;

        private:
            uint64_t section_length_;
            uint32_t byteorder_magic_;
            Version version_;
    };


    class InterfaceDescriptionBlock final : public AbstractPcapngBlock {
        public:
            InterfaceDescriptionBlock(uint16_t link, uint16_t reserved, uint32_t snap_len);

        private:
            uint32_t snapshot_length_;
            uint16_t link_type_;
            uint16_t reserved_;
    };


    class SimplePacketBlock : public AbstractPcapngBlock {
        public:
            SimplePacketBlock();
            
            InterfaceBlockPtr get_interface() const;
            Span<const char> get_packet_data() const;
            size_t get_captured_length() const;

            virtual size_t get_original_length() const;
            virtual uint64_t get_timestamp() const;

            void set_data(const std::vector<char>& data);
            void set_data(std::vector<char>&& data);
            void set_interface(const InterfaceBlockPtr& iface);

        protected:
            SimplePacketBlock(PcapngBlockType t);

        protected:
            // in most of the situation we don't want to reallocate memory for exact packet data
            // (without options and other data which may be presented in packet), so we are storing
            // total data in block_data_ and moving the packet_data_span_ to packet itself
            std::vector<char> packet_data_;
            InterfaceBlockPtr interface_;
    };


    class EnchancedPacketBlock final : public SimplePacketBlock {
        public:
            EnchancedPacketBlock(uint32_t t_high, uint32_t t_low, uint32_t original_len);
            size_t get_original_length() const final;
            uint64_t get_timestamp() const final;

        private:
            uint64_t timestamp_;
            uint32_t original_capture_length_;
    };


    class CustomNonstandardBlock final : public SimplePacketBlock {
        public:
            CustomNonstandardBlock(uint32_t res0, uint32_t res1);

        private:
            uint32_t reserved0_;
            uint32_t reserved1_;
    };
}

#endif // __PcapngBlock_H__
