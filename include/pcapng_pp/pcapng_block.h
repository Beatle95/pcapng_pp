#ifndef __PcapngBlock_H__
#define __PcapngBlock_H__
#include <vector>
#include <memory>
#include "tcb/span.hpp"
#include "pcapng_types.h"

/*
    All classes inside this file represents some block types from PcapNg standard.
    They are pretty small and similar, so for now the will be stored in one file.
    
    Class hierarchy:
                 _______________BasePcapngBlock_______________
                /                      |                      \
    SectionHeaderBlock    InterfaceDescriptionBlock    PacketBlock
                                                          /          \
                                          EnchancedPacketBlock    CustomPacketBlock
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

    class BasePcapngBlock {
        public:
            BasePcapngBlock() = delete;
            virtual ~BasePcapngBlock() noexcept = default;

            PcapngBlockType get_type() const;
            bool is_option_exists(uint16_t option_code) const;
            Span<const byte_t> get_option_data(uint16_t option_code) const;
            std::string get_option_string(uint16_t option_code) const;

            void add_option(const BlockOption& opt);
            void add_option(BlockOption&& opt);

        protected:
            explicit BasePcapngBlock(PcapngBlockType t);

        private:
            std::vector<BlockOption> options_;
            const PcapngBlockType type_;
    };


    class SectionHeaderBlock final : public BasePcapngBlock {
        public:
            SectionHeaderBlock(uint32_t magic, uint16_t ver_major, uint16_t ver_minor, uint64_t len);
            Version get_version() const;
            uint32_t get_magic() const;

        private:
            uint64_t section_length_;
            uint32_t byteorder_magic_;
            Version version_;
    };


    class InterfaceDescriptionBlock final : public BasePcapngBlock {
        public:
            InterfaceDescriptionBlock(uint16_t link, uint16_t reserved, uint32_t snap_len);
            uint32_t get_snapshot_length() const;
            uint16_t get_link_type() const;

        private:
            uint32_t snapshot_length_;
            uint16_t link_type_;
            uint16_t reserved_;
    };
}

#endif // __PcapngBlock_H__
