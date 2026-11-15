#include "socket.hpp"

#include <sys/socket.h>
#include <unistd.h>

namespace portscan {

Socket Socket::create_tcp() noexcept {
    return Socket(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
}

void Socket::reset(int fd) noexcept {
    if (fd_ >= 0 && fd_ != fd) ::close(fd_);
    fd_ = fd;
}

}  // namespace portscan
