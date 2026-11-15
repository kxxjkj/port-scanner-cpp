#pragma once

#include <netinet/in.h>

#include <stdexcept>
#include <string>

namespace portscan {

/// Falha ao resolver o alvo (DNS ou formato inválido).
class ResolveError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Alvo resolvido para IPv4.
struct ResolvedTarget {
    sockaddr_in addr{};  ///< Endereço pronto para connect() (porta ainda não definida).
    std::string ip;      ///< Representação textual, ex.: "45.33.32.156".
};

/// Resolve um IP ou nome de domínio para um endereço IPv4 via getaddrinfo().
/// @throws ResolveError se o alvo for inválido ou o DNS falhar.
ResolvedTarget resolve_ipv4(const std::string& host);

}  // namespace portscan
