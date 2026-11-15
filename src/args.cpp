#include "args.hpp"

#include <algorithm>
#include <charconv>
#include <iostream>
#include <optional>
#include <string_view>

namespace portscan {
namespace {

std::optional<unsigned long> to_uint(std::string_view text) {
    if (text.empty()) return std::nullopt;
    unsigned long value = 0;
    const char* end = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(text.data(), end, value);
    if (ec != std::errc{} || ptr != end) return std::nullopt;
    return value;
}

std::uint16_t parse_port(std::string_view text) {
    auto value = to_uint(text);
    if (!value || *value < 1 || *value > 65535) {
        throw UsageError("porta inválida: '" + std::string(text) + "' (use valores de 1 a 65535)");
    }
    return static_cast<std::uint16_t>(*value);
}

}  // namespace

std::vector<std::uint16_t> parse_port_spec(const std::string& spec) {
    if (spec.empty()) throw UsageError("intervalo de portas vazio");

    std::vector<std::uint16_t> ports;
    std::string_view rest(spec);

    while (true) {
        const auto comma = rest.find(',');
        const std::string_view token = rest.substr(0, comma);
        if (token.empty()) throw UsageError("intervalo de portas inválido: '" + spec + "'");

        const auto dash = token.find('-');
        if (dash == std::string_view::npos) {
            ports.push_back(parse_port(token));
        } else {
            const unsigned first = parse_port(token.substr(0, dash));
            const unsigned last = parse_port(token.substr(dash + 1));
            if (first > last) {
                throw UsageError("intervalo invertido: '" + std::string(token) +
                                 "' (o início deve ser menor ou igual ao fim)");
            }
            for (unsigned p = first; p <= last; ++p) ports.push_back(static_cast<std::uint16_t>(p));
        }

        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

Options parse_args(int argc, char* argv[]) {
    Options opts;
    std::string port_spec = "1-1024";
    bool has_target = false;

    auto next_value = [&](int& i, const std::string& flag) -> std::string {
        if (i + 1 >= argc) throw UsageError("a opção " + flag + " exige um valor");
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.show_help = true;
            return opts;
        } else if (arg == "-p" || arg == "--ports") {
            port_spec = next_value(i, arg);
        } else if (arg == "-t" || arg == "--timeout") {
            const std::string text = next_value(i, arg);
            auto value = to_uint(text);
            if (!value || *value < static_cast<unsigned long>(kMinTimeoutMs) ||
                *value > static_cast<unsigned long>(kMaxTimeoutMs)) {
                throw UsageError("timeout inválido: '" + text + "' (use de " +
                                 std::to_string(kMinTimeoutMs) + " a " +
                                 std::to_string(kMaxTimeoutMs) + " ms)");
            }
            opts.timeout_ms = static_cast<int>(*value);
        } else if (arg == "-T" || arg == "--threads") {
            const std::string text = next_value(i, arg);
            auto value = to_uint(text);
            if (!value || *value < 1 || *value > kMaxThreads) {
                throw UsageError("número de threads inválido: '" + text + "' (use de 1 a " +
                                 std::to_string(kMaxThreads) + ")");
            }
            opts.threads = static_cast<unsigned>(*value);
        } else if (arg == "--no-banner") {
            opts.grab_banner = false;
        } else if (arg == "--no-progress") {
            opts.show_progress = false;
        } else if (!arg.empty() && arg[0] == '-') {
            throw UsageError("opção desconhecida: " + arg);
        } else {
            if (has_target) throw UsageError("mais de um alvo informado: '" + arg + "'");
            opts.target = arg;
            has_target = true;
        }
    }

    if (!has_target) throw UsageError("nenhum alvo informado");
    opts.ports = parse_port_spec(port_spec);
    return opts;
}

void print_usage(const char* program) {
    std::cout
        << "Uso: " << program << " <alvo> [opções]\n\n"
        << "  <alvo>                 Endereço IPv4 ou nome de domínio\n\n"
        << "Opções:\n"
        << "  -p, --ports <spec>     Portas: 80 | 1-1024 | 22,80,8000-8100 (padrão: 1-1024)\n"
        << "  -t, --timeout <ms>     Timeout por porta em ms, " << kMinTimeoutMs << "-"
        << kMaxTimeoutMs << " (padrão: 1000)\n"
        << "  -T, --threads <n>      Threads simultâneas, 1-" << kMaxThreads << " (padrão: 100)\n"
        << "      --no-banner        Não tenta capturar banners\n"
        << "      --no-progress      Não exibe a barra de progresso\n"
        << "  -h, --help             Mostra esta ajuda\n\n"
        << "Exemplos:\n"
        << "  " << program << " 127.0.0.1 -p 1-1024\n"
        << "  " << program << " scanme.nmap.org -p 20-100 -t 500 -T 200\n\n"
        << "Use apenas em sistemas que você possui ou tem autorização para testar.\n";
}

}  // namespace portscan
