#ifndef __PCAPNG_INTERFACE_H__
#define __PCAPNG_INTERFACE_H__
#include "pcapng_block.h"

namespace pcapng_pp {
    class Interface {
        public:
            explicit Interface(const InterfaceBlockPtr& iface);

        private:
            InterfaceBlockPtr interface_block_;
    };
}
#endif // __PCAPNG_INTERFACE_H__
