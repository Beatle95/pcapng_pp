#include "PcapngError.h"

using namespace pcapng_pp;

PcapngError::PcapngError(ErrorCode code)
    : code_ {code}
{    
}

const char* PcapngError::what() const {
    switch (code_) {
        case ErrorCode::undefined:
            return "Unknown error";
        // TODO:
        default:
            return "Some error...";
    }
}
