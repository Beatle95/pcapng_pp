#ifndef __ERROR_H__
#define __ERROR_H__
#include <string_view>
#include <stdexcept>

namespace pcapng_pp {    
    enum class ErrorCode {
        undefined,
        unable_to_open,
        wrong_format_or_damaged,
        size_mismatch,
        unknown_block_type,
        file_not_opened,
        file_exists,
        write_error
    };

    class PcapngError : public std::exception {
        public:
            PcapngError(ErrorCode code);
            ErrorCode code() const;
            const char *what() const noexcept override;

        private:
            const ErrorCode code_;
    };

    class PcapngDescriptiveError : public PcapngError {
        public:
            PcapngDescriptiveError(ErrorCode code, std::string_view description);
            const char *what() const noexcept override;

        private:
            std::string description_;
    };
}
#endif // __ERROR_H__
