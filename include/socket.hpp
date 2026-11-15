#pragma once

namespace portscan {

/// Wrapper RAII para um descritor de socket POSIX.
/// Garante que o descritor seja fechado ao sair do escopo (sem vazamentos).
class Socket {
public:
    Socket() noexcept = default;
    explicit Socket(int fd) noexcept : fd_(fd) {}
    ~Socket() { reset(); }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd_(other.release()) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }

    /// Cria um socket TCP/IPv4 não-bloqueante e com close-on-exec.
    /// Em caso de falha, o objeto retornado é inválido (valid() == false).
    static Socket create_tcp() noexcept;

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

    /// Entrega a posse do descritor ao chamador sem fechá-lo.
    int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    /// Fecha o descritor atual (se houver) e passa a gerenciar `fd`.
    void reset(int fd = -1) noexcept;

private:
    int fd_ = -1;
};

}  // namespace portscan
