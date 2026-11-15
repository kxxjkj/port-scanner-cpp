#pragma once

#include <cstdint>
#include <string>

namespace portscan {

/// Nome do serviço padrão associado a uma porta TCP (ex.: 22 -> "ssh").
/// Consulta uma tabela interna e, se necessário, /etc/services.
/// Atenção: usa getservbyport(), que não é thread-safe; chame de uma única thread.
std::string service_name(std::uint16_t port);

/// Indica se a porta costuma servir HTTP (usada para enviar um probe de banner).
bool is_http_port(std::uint16_t port) noexcept;

}  // namespace portscan
