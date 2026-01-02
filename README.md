# 🌐 Smart Proxy Server (Phase 1)

**Developer:** Amir Khedri  
[cite_start]**Course:** Computer Networks [cite: 2]  
[cite_start]**University:** University of Isfahan [cite: 1]  
[cite_start]**Semester:** Fall 1404-1405 (2025-2026) [cite: 3, 16]

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![GUI](https://img.shields.io/badge/Interface-Tkinter-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

## 📖 Project Overview
[cite_start]This project implements a multi-threaded **Application Layer Proxy Server** designed to handle HTTP and HTTPS traffic[cite: 17, 25]. [cite_start]Developed as part of the "Computer Networks" course, the application acts as an intermediary between the client (User) and the Internet, forwarding requests and returning responses while providing advanced monitoring capabilities[cite: 20, 21, 22].

Unlike standard command-line proxies, this "Ultimate Edition" features a robust **Graphical User Interface (GUI)** for real-time traffic analysis, cache inspection, and access control.

## ✨ Key Features

### Core Proxy Capabilities
* [cite_start]**HTTP Proxying:** Parses incoming HTTP requests, extracts the destination host, and forwards the data to the target server[cite: 38, 50].
* [cite_start]**HTTPS Tunneling:** Implements the `CONNECT` method to establish a TCP tunnel, allowing secure SSL/TLS traffic to pass through transparently[cite: 55].
* [cite_start]**Concurrency:** Utilizes `threading` and `select` to handle multiple client connections simultaneously without blocking, ensuring high performance[cite: 39, 43].

### Advanced Management
* **🚀 Caching Mechanism:** Reduces network latency by storing HTTP GET responses in memory. [cite_start]Includes a size-limited eviction policy (`CACHE_SIZE = 50`)[cite: 31, 57].
* [cite_start]**🛡️ Filtering (Blacklist):** specific domains (e.g., `badsite.org`) are blocked based on a configurable blacklist, returning a custom `403 Access Denied` error[cite: 33, 58].
* [cite_start]**📝 Comprehensive Logging:** Records every request with timestamps, client IP, URL, methods, and status codes to both a log file (`proxy_log.txt`) and the GUI terminal[cite: 34, 59].

### GUI & Extras (Bonus)
* **Live Traffic Graph:** Visualizes data transfer speeds (KB/s) in real-time.
* [cite_start]**Rate Limiting:** Protects the server from abuse by limiting the number of requests per IP address within a specific time window[cite: 72].
* **Cache Inspector:** A visual tool to view and clear cached URLs manually.

## 🛠️ Installation & Usage

### Prerequisites
* Python 3.x
* No external `pip` packages required (uses standard `tkinter`, `socket`, `threading`).

### Running the Server
1.  Clone the repository:
    ```bash
    git clone [https://github.com/amirkhedri/Proxy-Server.git](https://github.com/amirkhedri/Proxy-Server.git)
    cd Proxy-Server
    ```
2.  Run the application:
    ```bash
    python ProxyServer.py
    ```
3.  The GUI will launch. [cite_start]Click **"START SERVER"** to begin listening on `127.0.0.1:8080`[cite: 76].

### Browser Configuration
[cite_start]To route your traffic through this proxy[cite: 76]:
1.  Open your web browser settings (Chrome/Firefox/Edge).
2.  Search for **Proxy Settings**.
3.  Set the **HTTP** and **HTTPS** proxy to:
    * **Host:** `127.0.0.1`
    * **Port:** `8080`
4.  Browse the web. You will see requests appearing in the "TERMINAL" tab of the application.

## 🏗️ Architecture
The project follows a modular structure integrated into a single executable script:

* **`UltimateProxyGUI`:** Manages the Tkinter main loop, updates real-time graphs, and handles user interactions.
* **`ClientHandler`:** A threaded class responsible for parsing protocols. [cite_start]It distinguishes between standard HTTP requests and HTTPS `CONNECT` tunnels[cite: 44, 49].
* [cite_start]**`StatsEngine`:** A thread-safe singleton that tracks active connections, bytes sent, and cache hits[cite: 71].
* [cite_start]**`handle_https`:** Uses non-blocking I/O to bridge data between the client and the secure target server[cite: 55].

## 📜 License
This project is open-source and available under the MIT License.

---
*Developed by Amir Khedri*