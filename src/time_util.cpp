#include "time_util.hpp"

#include <errno.h>
#include <unistd.h>

#include <cstring>
#include <ctime>

#include "config.hpp"
#include "logging.hpp"

// This is a wrapper to nanosleep
// It is written this way so the sleep resumes where it left off after a signal
void sleep_ms(int ms)
{
#ifdef LOG_SLEEPS
    LOG << "Sleeping for " << ms << " ms" << std::endl;
#endif
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    struct timespec rem;
    for (;;) {
        const int res = nanosleep(&req, &rem);
        if (res < 0 && errno == EINTR) {
            std::memcpy(&req, &rem, sizeof(req));
        } else {
            return;
        }
    }
}

void RateCounter::operator--()
{
    --current_value;
    if (current_value <= 0) {
        current_value = max_amt;
        sleep_ms(sleep_amt);
    }
}
