#ifndef __ERROR_H__
#define __ERROR_H__
#include <stdexcept>

namespace pcapng_pp {    
    enum class ErrorCode {
        undefined,
        unable_to_open,
        wrong_format_or_damaged,
        size_mismatch,
        not_enough_memory
    };

    class PcapngError : public std::exception {
        public:
            PcapngError(ErrorCode code);
            const char *what() const final;

        private:
            const ErrorCode code_;
    };
}
#endif // __ERROR_H__
