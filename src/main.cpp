#include <unistd.h>

#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>

#include "args.hpp"
#include "resolver.hpp"
#include "scanner.hpp"

namespace {

extern "C" void handle_sigint(int) { portscan::Scanner::request_stop(); }

struct Style {
    const char* green = "";
    const char* yellow = "";
    const char* bold = "";
    const char* dim = "";
    const char* reset = "";

    static Style detect() {
        Style s;
        if (::isatty(STDOUT_FILENO)) {
            s.green = "\033[32m";
            s.yellow = "\033[33m";
            s.bold = "\033[1m";
            s.dim = "\033[2m";
            s.reset = "\033[0m";
        }
        return s;
    }
};

}  // namespace

int main(int argc, char* argv[]) {
    using namespace portscan;

    Options opts;
    try {
        opts = parse_args(argc, argv);
    } catch (const UsageError& e) {
        std::cerr << "Erro: " << e.what() << "\nUse --help para ver as opções.\n";
        return 2;
    }
    if (opts.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    ResolvedTarget target;
    try {
        target = resolve_ipv4(opts.target);
    } catch (const ResolveError& e) {
        std::cerr << "Erro: " << e.what() << '\n';
        return 1;
    }

    const Style style = Style::detect();
    std::cout << style.bold << "Port Scanner TCP" << style.reset << " — alvo: " << opts.target << " ("
              << target.ip << ")\n"
              << "Portas: " << opts.ports.size() << " | Threads: " << opts.threads
              << " | Timeout: " << opts.timeout_ms << " ms\n\n";

    std::signal(SIGINT, handle_sigint);

    ScanConfig config;
    config.timeout_ms = opts.timeout_ms;
    config.threads = opts.threads;
    config.grab_banner = opts.grab_banner;
    config.show_progress = opts.show_progress && ::isatty(STDERR_FILENO);

    std::vector<PortResult> results;
    Scanner scanner(target.addr, opts.ports, config);

    const auto started = std::chrono::steady_clock::now();
    try {
        results = scanner.run();
    } catch (const std::exception& e) {
        std::cerr << "Erro durante a varredura: " << e.what() << '\n';
        return 1;
    }
    const double elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    if (Scanner::stop_requested()) {
        std::cout << style.yellow << "Varredura interrompida pelo usuário (resultados parciais)."
                  << style.reset << "\n\n";
    }

    if (results.empty()) {
        std::cout << "Nenhuma porta aberta encontrada.\n";
    } else {
        std::cout << style.bold << std::left << std::setw(10) << "PORTA"
                  << "SERVIÇO         "  // padding manual: "ç" ocupa 2 bytes e quebraria o setw
                  << "BANNER" << style.reset << '\n';
        for (const auto& r : results) {
            std::cout << style.green << std::left << std::setw(10) << (std::to_string(r.port) + "/tcp")
                      << style.reset << std::setw(16) << r.service << style.dim << r.banner << style.reset
                      << '\n';
        }
    }

    std::cout << '\n'
              << results.size() << " porta(s) aberta(s) | " << scanner.scanned() << "/" << opts.ports.size()
              << " verificadas | " << std::fixed << std::setprecision(2) << elapsed << " s\n";
    return Scanner::stop_requested() ? 130 : 0;  // 130 = convenção para SIGINT
}
