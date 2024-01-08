#include "pcapng_pp/pcapng_interface.h"

using namespace pcapng_pp;

Interface::Interface(const InterfaceBlockPtr& iface)
    : interface_block_ {iface}
{    
}
    
uint32_t Interface::get_snapshot_length() const {
    return interface_block_->get_snapshot_length();
}

uint16_t Interface::get_link_type() const {
    return interface_block_->get_link_type();
}
