#include "resolver.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>

namespace portscan {

ResolvedTarget resolve_ipv4(const std::string& host) {
    const bool has_space = std::any_of(host.begin(), host.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    if (host.empty() || host.size() > 253 || has_space) {
        throw ResolveError("alvo inválido: '" + host + "'");
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;  // apenas IPv4
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* raw = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &raw);
    if (rc != 0) {
        throw ResolveError("falha ao resolver '" + host + "': " + ::gai_strerror(rc));
    }
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> guard(raw, ::freeaddrinfo);

    if (raw == nullptr || raw->ai_addr == nullptr || raw->ai_family != AF_INET ||
        raw->ai_addrlen < sizeof(sockaddr_in)) {
        throw ResolveError("nenhum endereço IPv4 encontrado para '" + host + "'");
    }

    ResolvedTarget target;
    std::memcpy(&target.addr, raw->ai_addr, sizeof(sockaddr_in));

    char buffer[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, &target.addr.sin_addr, buffer, sizeof buffer) == nullptr) {
        throw ResolveError("não foi possível formatar o endereço de '" + host + "'");
    }
    target.ip = buffer;
    return target;
}

}  // namespace portscan
