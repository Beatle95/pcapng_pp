#ifndef __PCAPNG_INTERFACE_H__
#define __PCAPNG_INTERFACE_H__
#include "pcapng_block.h"

namespace pcapng_pp {
    class Interface {
        public:
            explicit Interface(const InterfaceBlockPtr& iface);
            uint32_t get_snapshot_length() const;
            uint16_t get_link_type() const;

        private:
            InterfaceBlockPtr interface_block_;
    };
}
#endif // __PCAPNG_INTERFACE_H__
