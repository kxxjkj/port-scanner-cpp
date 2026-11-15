#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace portscan {

/// Erro de uso da linha de comando (argumento inválido ou ausente).
class UsageError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Opções já validadas, prontas para uso pelo scanner.
struct Options {
    std::string target;
    std::vector<std::uint16_t> ports;
    int timeout_ms = 1000;
    unsigned threads = 100;
    bool grab_banner = true;
    bool show_progress = true;
    bool show_help = false;
};

constexpr int kMinTimeoutMs = 50;
constexpr int kMaxTimeoutMs = 60000;
constexpr unsigned kMaxThreads = 500;

/// Interpreta "80", "1-1024" ou combinações como "22,80,8000-8100".
/// Retorna as portas ordenadas e sem duplicatas.
/// @throws UsageError se o formato ou os valores forem inválidos.
std::vector<std::uint16_t> parse_port_spec(const std::string& spec);

/// Interpreta e valida os argumentos de linha de comando.
/// @throws UsageError em qualquer problema de uso.
Options parse_args(int argc, char* argv[]);

/// Imprime a ajuda de uso na saída padrão.
void print_usage(const char* program);

}  // namespace portscan
