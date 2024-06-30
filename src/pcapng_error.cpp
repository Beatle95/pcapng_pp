#include "pcapng_pp/pcapng_error.h"

using namespace pcapng_pp;

PcapngError::PcapngError(ErrorCode code)
    : code_ {code}
{    
}
    
ErrorCode PcapngError::code() const {
    return code_;
}

const char* PcapngError::what() const noexcept {
    switch (code_) {
        case ErrorCode::undefined:
            return "Unknown error";
        // TODO:
        default:
            return "Some error...";
    }
}

PcapngDescriptiveError::PcapngDescriptiveError(ErrorCode code, std::string_view description)
    : PcapngError {code}, description_ {description}
{
}

const char* PcapngDescriptiveError::what() const noexcept {
    return description_.c_str();
}
