#include "scanner.hpp"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#include "services.hpp"
#include "socket.hpp"

namespace portscan {
namespace {

using Clock = std::chrono::steady_clock;

std::atomic<bool> g_stop{false};
static_assert(std::atomic<bool>::is_always_lock_free, "g_stop precisa ser lock-free para uso em signal handlers");

constexpr std::size_t kMaxBannerLen = 80;
constexpr int kMaxBannerWaitMs = 1500;

/// Aguarda eventos em `fd` por até `timeout_ms`, tratando EINTR.
/// Retorna true se o poll() sinalizou algo (eventos ou erro), false em timeout/falha.
bool wait_fd(int fd, short events, int timeout_ms) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (remaining < 0) remaining = 0;

        pollfd pfd{fd, events, 0};
        const int rc = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (rc > 0) return true;
        if (rc == 0) return false;
        if (errno != EINTR) return false;
    }
}

/// Tenta um connect() não-bloqueante com timeout. Devolve o socket conectado ou nullopt.
std::optional<Socket> connect_with_timeout(const sockaddr_in& base, std::uint16_t port, int timeout_ms) {
    Socket sock = Socket::create_tcp();
    if (!sock.valid()) return std::nullopt;

    sockaddr_in addr = base;
    addr.sin_port = htons(port);

    if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof addr) == 0) {
        return std::optional<Socket>{std::move(sock)};
    }
    if (errno != EINPROGRESS) return std::nullopt;

    if (!wait_fd(sock.get(), POLLOUT, timeout_ms)) return std::nullopt;  // filtrada / timeout

    int error = 0;
    socklen_t len = sizeof error;
    if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        return std::nullopt;  // conexão recusada (porta fechada) ou erro de rota
    }
    return std::optional<Socket>{std::move(sock)};
}

/// Limpa o banner: primeira linha, apenas caracteres imprimíveis, tamanho limitado.
/// Para respostas HTTP, anexa também o cabeçalho "Server:" quando existir.
std::string sanitize_banner(const std::string& raw) {
    std::vector<std::string> lines;
    std::string current;
    for (char c : raw) {
        if (c == '\n') {
            lines.push_back(current);
            current.clear();
        } else if (c != '\r') {
            current.push_back(c);
        }
    }
    if (!current.empty()) lines.push_back(current);
    if (lines.empty()) return {};

    std::string text = lines.front();
    if (text.rfind("HTTP/", 0) == 0) {
        for (std::size_t i = 1; i < lines.size(); ++i) {
            if (lines[i].rfind("Server:", 0) == 0) {
                text += " | " + lines[i];
                break;
            }
        }
    }

    for (char& c : text) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc > 0x7e) c = '.';
    }
    if (text.size() > kMaxBannerLen) text = text.substr(0, kMaxBannerLen) + "...";
    return text;
}

std::string read_some(Socket& sock, int timeout_ms) {
    if (!wait_fd(sock.get(), POLLIN, timeout_ms)) return {};
    char buffer[512];
    const ssize_t n = ::recv(sock.get(), buffer, sizeof buffer, MSG_DONTWAIT);
    if (n <= 0) return {};
    return sanitize_banner(std::string(buffer, static_cast<std::size_t>(n)));
}

/// Banner grabbing: primeiro espera o servidor falar (FTP, SSH, SMTP...);
/// se nada vier e a porta for HTTP, envia um HEAD simples.
std::string grab_banner(Socket& sock, std::uint16_t port, int timeout_ms) {
    const int wait_ms = std::min(timeout_ms, kMaxBannerWaitMs);
    std::string banner = read_some(sock, wait_ms);

    if (banner.empty() && is_http_port(port)) {
        static constexpr char kProbe[] = "HEAD / HTTP/1.0\r\n\r\n";
        if (::send(sock.get(), kProbe, sizeof kProbe - 1, MSG_NOSIGNAL) > 0) {
            banner = read_some(sock, wait_ms);
        }
    }
    return banner;
}

}  // namespace

Scanner::Scanner(sockaddr_in target, std::vector<std::uint16_t> ports, ScanConfig config)
    : target_(target), ports_(std::move(ports)), config_(config) {}

void Scanner::request_stop() noexcept { g_stop.store(true); }
bool Scanner::stop_requested() noexcept { return g_stop.load(); }

void Scanner::probe(std::uint16_t port) {
    auto sock = connect_with_timeout(target_, port, config_.timeout_ms);
    if (!sock) return;

    PortResult result;
    result.port = port;
    if (config_.grab_banner) result.banner = grab_banner(*sock, port, config_.timeout_ms);

    std::lock_guard<std::mutex> lock(results_mutex_);
    results_.push_back(std::move(result));
}  // `sock` é fechado automaticamente aqui (RAII)

void Scanner::worker() {
    try {
        while (!g_stop.load()) {
            const std::size_t index = next_.fetch_add(1);
            if (index >= ports_.size()) break;
            probe(ports_[index]);
            done_.fetch_add(1);
        }
    } catch (...) {
        // Uma falha inesperada em uma thread não deve derrubar o processo inteiro.
    }
    active_workers_.fetch_sub(1);
}

void Scanner::render_progress() const {
    constexpr int kWidth = 30;
    const std::size_t total = ports_.size();
    const std::size_t done = std::min(done_.load(), total);
    const int percent = total == 0 ? 100 : static_cast<int>(done * 100 / total);
    const int filled = percent * kWidth / 100;

    std::string bar(static_cast<std::size_t>(filled), '#');
    bar.append(static_cast<std::size_t>(kWidth - filled), '.');
    std::fprintf(stderr, "\r[%s] %3d%% (%zu/%zu)", bar.c_str(), percent, done, total);
    std::fflush(stderr);
}

std::vector<PortResult> Scanner::run() {
    const std::size_t thread_count =
        std::min<std::size_t>(std::max(1u, config_.threads), std::max<std::size_t>(1, ports_.size()));

    std::vector<std::thread> workers;
    workers.reserve(thread_count);
    for (std::size_t i = 0; i < thread_count; ++i) {
        active_workers_.fetch_add(1);
        try {
            workers.emplace_back(&Scanner::worker, this);
        } catch (const std::system_error&) {
            active_workers_.fetch_sub(1);
            break;  // limite de threads do sistema: segue com as que conseguiu criar
        }
    }
    if (workers.empty()) throw std::runtime_error("não foi possível criar threads de varredura");

    while (active_workers_.load() > 0) {
        if (config_.show_progress) render_progress();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    for (auto& t : workers) t.join();

    if (config_.show_progress) {
        render_progress();
        std::fprintf(stderr, "\r\033[K");  // limpa a linha da barra
        std::fflush(stderr);
    }

    std::vector<PortResult> results;
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results = std::move(results_);
    }
    std::sort(results.begin(), results.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });

    // getservbyport() não é thread-safe: resolvemos os nomes aqui, já sem threads.
    for (auto& r : results) r.service = service_name(r.port);
    return results;
}

}  // namespace portscan
