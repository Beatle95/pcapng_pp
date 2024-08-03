#ifndef __PCAPNG_PACKET_BLOCK_H__
#define __PCAPNG_PACKET_BLOCK_H__
#include "pcapng_block.h"

namespace pcapng_pp {
    class PacketBlock : public BasePcapngBlock {
        public:
            PacketBlock();
            
            InterfaceBlockPtr get_interface() const;
            Span<const byte_t> get_packet_data() const;
            size_t get_captured_length() const;

            virtual size_t get_original_length() const;
            virtual uint64_t get_timestamp() const;

            void set_data(const std::vector<byte_t>& data);
            void set_data(std::vector<byte_t>&& data);
            void set_interface(const InterfaceBlockPtr& iface);

        protected:
            PacketBlock(PcapngBlockType t);

        protected:
            // in most of the situation we don't want to reallocate memory for exact packet data
            // (without options and other data which may be presented in packet), so we are storing
            // total data in block_data_ and moving the packet_data_span_ to packet itself
            std::vector<byte_t> packet_data_;
            InterfaceBlockPtr interface_;
    };


    class EnchancedPacketBlock final : public PacketBlock {
        public:
            EnchancedPacketBlock(uint32_t t_high, uint32_t t_low, uint32_t original_len);
            size_t get_original_length() const final;
            uint64_t get_timestamp() const final;

        private:
            uint64_t timestamp_;
            uint32_t original_capture_length_;
    };


    class CustomPacketBlock final : public PacketBlock {
        public:
            CustomPacketBlock(uint32_t res0, uint32_t res1);

        private:
            uint32_t reserved0_;
            uint32_t reserved1_;
    };
}
#endif // __PCAPNG_PACKET_BLOCK_H__
