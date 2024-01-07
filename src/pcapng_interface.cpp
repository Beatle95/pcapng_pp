#include "pcapng_pp/pcapng_interface.h"

using namespace pcapng_pp;

Interface::Interface(const InterfaceBlockPtr& iface)
    : interface_block_ {iface}
{    
}
