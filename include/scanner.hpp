#pragma once

#include <netinet/in.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace portscan {

/// Configuração da varredura.
struct ScanConfig {
    int timeout_ms = 1000;
    unsigned threads = 100;
    bool grab_banner = true;
    bool show_progress = true;
};

/// Resultado de uma porta aberta.
struct PortResult {
    std::uint16_t port = 0;
    std::string service;
    std::string banner;
};

/// Scanner TCP Connect multi-thread.
///
/// As threads consomem índices de um contador atômico (sem trabalho duplicado)
/// e gravam os resultados em um vetor protegido por std::mutex.
class Scanner {
public:
    Scanner(sockaddr_in target, std::vector<std::uint16_t> ports, ScanConfig config);

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    /// Executa a varredura e devolve as portas abertas, ordenadas.
    /// A thread chamadora desenha a barra de progresso enquanto espera.
    std::vector<PortResult> run();

    /// Número de portas já verificadas.
    std::size_t scanned() const noexcept { return done_.load(); }

    /// Pede o encerramento antecipado (seguro para uso em signal handlers).
    static void request_stop() noexcept;
    static bool stop_requested() noexcept;

private:
    void worker();
    void probe(std::uint16_t port);
    void render_progress() const;

    sockaddr_in target_;
    std::vector<std::uint16_t> ports_;
    ScanConfig config_;

    std::atomic<std::size_t> next_{0};
    std::atomic<std::size_t> done_{0};
    std::atomic<unsigned> active_workers_{0};

    std::mutex results_mutex_;
    std::vector<PortResult> results_;
};

}  // namespace portscan
