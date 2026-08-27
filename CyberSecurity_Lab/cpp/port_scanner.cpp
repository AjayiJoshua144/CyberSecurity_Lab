/*
 * =============================================================
 * CyberShield Lab — C++ TCP Port Scanner
 * =============================================================
 * File    : port_scanner.cpp
 * Author  : Ajayi Joshua Abayomi
 * School  : Babcock University, 300L IT
 * Purpose : Scan a target IP for open TCP ports using socket
 *           programming. C++ is used here because it gives us
 *           direct access to low-level network sockets and runs
 *           much faster than Python for this kind of I/O task.
 *
 * Concept : TCP Port Scanning works by attempting a connection
 *           to each port. If the target accepts the connection,
 *           the port is OPEN. If it refuses, it is CLOSED.
 *           This is exactly what attackers do during recon —
 *           and what defenders do to audit their own systems.
 *
 * Usage   : ./port_scanner <target_ip> <start_port> <end_port>
 * Example : ./port_scanner 127.0.0.1 1 1024
 *
 * ETHICAL NOTICE: Only scan systems you own or have permission
 *                 to test. Unauthorized scanning is illegal.
 * =============================================================
 */

#include <iostream>      // cout, cerr
#include <string>        // string
#include <vector>        // vector
#include <thread>        // thread (for concurrent scanning)
#include <mutex>         // mutex (thread-safe output)
#include <chrono>        // timing
#include <fstream>       // file output for reports
#include <sstream>       // string stream

// Linux/macOS network headers
#include <sys/socket.h>  // socket(), connect()
#include <netinet/in.h>  // sockaddr_in
#include <arpa/inet.h>   // inet_pton()
#include <unistd.h>      // close()
#include <fcntl.h>       // fcntl() for non-blocking sockets
#include <cerrno>        // errno
#include <cstring>       // strerror

// -----------------------------------------------
// CONSTANTS — easy to change for learning
// -----------------------------------------------
const int TIMEOUT_MS     = 500;   // How long to wait per port (ms)
const int MAX_THREADS    = 50;    // How many ports to scan at once

// -----------------------------------------------
// Known service names for common ports
// (A real scanner uses /etc/services for this)
// -----------------------------------------------
std::string getServiceName(int port) {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 27017:return "MongoDB";
        default:   return "Unknown";
    }
}

// -----------------------------------------------
// Risk assessment for open ports
// Some open ports are higher risk than others
// -----------------------------------------------
std::string getRiskLevel(int port) {
    // High-risk ports — commonly exploited
    std::vector<int> highRisk = {21, 23, 445, 3389, 6379, 27017};
    // Medium-risk — should be audited
    std::vector<int> medRisk  = {22, 25, 3306, 5432};

    for (int p : highRisk) if (p == port) return "HIGH";
    for (int p : medRisk)  if (p == port) return "MEDIUM";
    return "LOW";
}

// -----------------------------------------------
// CORE FUNCTION: Attempt TCP connection to one port
// Returns: true if port is OPEN, false if CLOSED
// -----------------------------------------------
bool scanPort(const std::string& ip, int port) {
    // Step 1: Create a socket (like opening a phone line)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Step 2: Set socket to non-blocking mode
    // This lets us enforce a timeout (we won't wait forever)
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Step 3: Set up the destination address structure
    struct sockaddr_in target;
    target.sin_family = AF_INET;          // IPv4
    target.sin_port   = htons(port);      // Port (htons converts byte order)
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr); // Convert IP string

    // Step 4: Attempt to connect (this is the actual "knock")
    connect(sock, (struct sockaddr*)&target, sizeof(target));

    // Step 5: Use select() to wait up to TIMEOUT_MS for a response
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = TIMEOUT_MS * 1000;  // Convert ms to microseconds

    bool isOpen = false;
    if (select(sock + 1, nullptr, &fdset, nullptr, &tv) == 1) {
        // Check if connection succeeded (no error on socket)
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        isOpen = (so_error == 0); // No error = connection succeeded = OPEN
    }

    // Step 6: Always close the socket when done
    close(sock);
    return isOpen;
}

// -----------------------------------------------
// SHARED DATA — protected with a mutex so multiple
// threads can safely write results
// -----------------------------------------------
std::mutex outputMutex;
std::vector<std::pair<int, std::string>> openPorts; // <port, service>

// -----------------------------------------------
// THREAD WORKER: Scans a range of ports
// Each thread handles a slice of the port range
// -----------------------------------------------
void scanRange(const std::string& ip, int startPort, int endPort) {
    for (int port = startPort; port <= endPort; ++port) {
        if (scanPort(ip, port)) {
            std::string service = getServiceName(port);
            std::string risk    = getRiskLevel(port);

            // Lock the mutex before printing/storing
            std::lock_guard<std::mutex> lock(outputMutex);
            openPorts.push_back({port, service});
            std::cout << "  [OPEN]  Port " << port
                      << "\t Service: " << service
                      << "\t Risk: " << risk << "\n";
        }
    }
}

// -----------------------------------------------
// REPORT WRITER: Saves results to a text file
// -----------------------------------------------
void saveReport(const std::string& ip, int start, int end,
                long long durationMs) {
    // Build filename with timestamp
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timebuf[32];
    std::strftime(timebuf, sizeof(timebuf), "%Y%m%d_%H%M%S", std::localtime(&t));

    std::string filename = "../reports/port_scan_" + std::string(timebuf) + ".txt";
    std::ofstream report(filename);

    if (!report.is_open()) {
        // Try current directory if reports/ doesn't exist
        filename = "port_scan_" + std::string(timebuf) + ".txt";
        report.open(filename);
    }

    report << "=========================================\n";
    report << " CyberShield Lab — Port Scan Report\n";
    report << " Author: Ajayi Joshua Abayomi\n";
    report << " Babcock University, 300L IT\n";
    report << "=========================================\n\n";
    report << "Target IP   : " << ip << "\n";
    report << "Port Range  : " << start << " – " << end << "\n";
    report << "Scan Time   : " << durationMs << " ms\n";
    report << "Open Ports  : " << openPorts.size() << "\n\n";
    report << "-----------------------------------------\n";
    report << " PORT\t\t SERVICE\t\t RISK\n";
    report << "-----------------------------------------\n";

    for (auto& [port, service] : openPorts) {
        report << " " << port << "\t\t " << service
               << "\t\t " << getRiskLevel(port) << "\n";
    }

    report << "\n=========================================\n";
    report << " Scan complete. Open ports: " << openPorts.size() << "\n";
    report << "=========================================\n";
    report.close();

    std::cout << "\n[+] Report saved to: " << filename << "\n";
}

// -----------------------------------------------
// MAIN FUNCTION — Entry point
// -----------------------------------------------
int main(int argc, char* argv[]) {
    // ---- Banner ----
    std::cout << "\n";
    std::cout << "  ================================================\n";
    std::cout << "   CyberShield Lab — C++ TCP Port Scanner\n";
    std::cout << "   Author: Ajayi Joshua | Babcock University\n";
    std::cout << "  ================================================\n\n";

    // ---- Argument validation ----
    if (argc != 4) {
        std::cerr << "  Usage: ./port_scanner <ip> <start_port> <end_port>\n";
        std::cerr << "  Example: ./port_scanner 127.0.0.1 1 1024\n\n";
        return 1;
    }

    std::string targetIP  = argv[1];
    int startPort = std::stoi(argv[2]);
    int endPort   = std::stoi(argv[3]);

    // ---- Input validation ----
    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
        std::cerr << "  [ERROR] Port range must be between 1 and 65535.\n";
        return 1;
    }

    // ---- Start scan ----
    std::cout << "  Target    : " << targetIP << "\n";
    std::cout << "  Ports     : " << startPort << " – " << endPort << "\n";
    std::cout << "  Threads   : " << MAX_THREADS << "\n";
    std::cout << "  Timeout   : " << TIMEOUT_MS << "ms per port\n\n";
    std::cout << "  [*] Scanning... (open ports shown below)\n";
    std::cout << "  -----------------------------------------\n";

    auto startTime = std::chrono::high_resolution_clock::now();

    // ---- Thread-based scanning ----
    // Divide the port range into chunks, one per thread
    int totalPorts  = endPort - startPort + 1;
    int chunkSize   = std::max(1, totalPorts / MAX_THREADS);
    std::vector<std::thread> threads;

    for (int i = 0; i < MAX_THREADS; ++i) {
        int chunkStart = startPort + (i * chunkSize);
        int chunkEnd   = std::min(chunkStart + chunkSize - 1, endPort);
        if (chunkStart > endPort) break;

        // Launch a thread to scan this chunk
        threads.emplace_back(scanRange, std::ref(targetIP), chunkStart, chunkEnd);
    }

    // Wait for all threads to finish
    for (auto& t : threads) t.join();

    auto endTime  = std::chrono::high_resolution_clock::now();
    long long ms  = std::chrono::duration_cast<std::chrono::milliseconds>
                    (endTime - startTime).count();

    // ---- Results summary ----
    std::cout << "  -----------------------------------------\n";
    std::cout << "\n  [+] Scan complete in " << ms << " ms\n";
    std::cout << "  [+] Open ports found: " << openPorts.size() << "\n";

    if (openPorts.empty()) {
        std::cout << "  [*] No open ports found in range.\n";
    }

    // ---- Save report ----
    saveReport(targetIP, startPort, endPort, ms);

    std::cout << "\n";
    return 0;
}
