#include "services.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <unordered_map>

namespace portscan {
namespace {

const std::unordered_map<std::uint16_t, const char*>& known_services() {
    static const std::unordered_map<std::uint16_t, const char*> table = {
        {21, "ftp"},         {22, "ssh"},          {23, "telnet"},     {25, "smtp"},
        {53, "dns"},         {80, "http"},         {110, "pop3"},      {111, "rpcbind"},
        {135, "msrpc"},      {139, "netbios-ssn"}, {143, "imap"},      {443, "https"},
        {445, "smb"},        {465, "smtps"},       {587, "submission"}, {993, "imaps"},
        {995, "pop3s"},      {1433, "mssql"},      {1521, "oracle"},   {3306, "mysql"},
        {3389, "rdp"},       {5432, "postgresql"}, {5900, "vnc"},      {6379, "redis"},
        {8000, "http-alt"},  {8080, "http-proxy"}, {8443, "https-alt"}, {27017, "mongodb"},
    };
    return table;
}

}  // namespace

std::string service_name(std::uint16_t port) {
    const auto& table = known_services();
    if (auto it = table.find(port); it != table.end()) return it->second;

    if (const servent* entry = ::getservbyport(htons(port), "tcp")) return entry->s_name;
    return "desconhecido";
}

bool is_http_port(std::uint16_t port) noexcept {
    return port == 80 || port == 8000 || port == 8008 || port == 8080 || port == 8888;
}

}  // namespace portscan
