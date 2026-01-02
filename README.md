# 🌐 Smart Proxy Server (Phase 1)

**Developer:** Amir Khedri  
**Course:** Computer Networks  
**University:** University of Isfahan  
**Semester:** Fall 1404-1405 (2025-2026)

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![GUI](https://img.shields.io/badge/Interface-Tkinter-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

## 📖 Project Overview
This project implements a multi-threaded **Application Layer Proxy Server** designed to handle HTTP and HTTPS traffic. Developed as part of the "Computer Networks" course, the application acts as an intermediary between the client (User) and the Internet, forwarding requests and returning responses while providing advanced monitoring capabilities.

Unlike standard command-line proxies, this "Ultimate Edition" features a robust **Graphical User Interface (GUI)** for real-time traffic analysis, cache inspection, and access control.

## ✨ Key Features

### Core Proxy Capabilities
* **HTTP Proxying:** Parses incoming HTTP requests, extracts the destination host, and forwards the data to the target server.
* **HTTPS Tunneling:** Implements the `CONNECT` method to establish a TCP tunnel, allowing secure SSL/TLS traffic to pass through transparently.
* **Concurrency:** Utilizes `threading` and `select` to handle multiple client connections simultaneously without blocking, ensuring high performance.

### Advanced Management
* **🚀 Caching Mechanism:** Reduces network latency by storing HTTP GET responses in memory. Includes a size-limited eviction policy (`CACHE_SIZE = 50`).
* **🛡️ Filtering (Blacklist):** Specific domains (e.g., `badsite.org`) are blocked based on a configurable blacklist, returning a custom `403 Access Denied` error.
* **📝 Comprehensive Logging:** Records every request with timestamps, client IP, URL, methods, and status codes to both a log file (`proxy_log.txt`) and the GUI terminal.

### GUI & Extras (Bonus)
* **Live Traffic Graph:** Visualizes data transfer speeds (KB/s) in real-time.
* **Rate Limiting:** Protects the server from abuse by limiting the number of requests per IP address within a specific time window.
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
3.  The GUI will launch. Click **"START SERVER"** to begin listening on `127.0.0.1:8080`.

### Browser Configuration
To route your traffic through this proxy:
1.  Open your web browser settings (Chrome/Firefox/Edge).
2.  Search for **Proxy Settings**.
3.  Set the **HTTP** and **HTTPS** proxy to:
    * **Host:** `127.0.0.1`
    * **Port:** `8080`
4.  Browse the web. You will see requests appearing in the "TERMINAL" tab of the application.

## 🏗️ Architecture

```mermaid
graph TD
    %% --- Styles ---
    classDef client fill:#38BDF8,stroke:#0f172a,stroke-width:2px,color:black;
    classDef server fill:#10B981,stroke:#047857,stroke-width:2px,color:white;
    classDef internet fill:#6366f1,stroke:#4338ca,stroke-width:2px,color:white;
    classDef block fill:#EF4444,stroke:#b91c1c,stroke-width:2px,color:white;
    classDef decision fill:#F59E0B,stroke:#b45309,stroke-width:2px,color:white;

    %% --- Nodes ---
    User(("👤 User/Client")):::client -->|HTTP Request| Proxy["🛡️ Proxy GUI"]:::server
    
    subgraph Internal ["⚡ Proxy Internal Logic"]
        direction TB
        Proxy --> Parser{"Request Type?"}:::decision
        Parser -->|HTTPS CONNECT| Tunnel["🔒 TCP Tunnel"]:::server
        Parser -->|HTTP GET| CacheCheck{"In Cache?"}:::decision
        
        CacheCheck -- Yes --> ReturnCache["📦 Return Cache"]:::server
        CacheCheck -- No --> Fetch["🌍 Fetch Data"]:::server
        
        Fetch --> Filter{"Blacklisted?"}:::decision
        Filter -- Yes --> Block["🚫 403 Blocked"]:::block
        Filter -- No --> Web["☁️ Web Server"]:::internet
    end
    
    Web -->|Response| Proxy
    Tunnel <-->|Encrypted Stream| Web
    ReturnCache -->|Response| User
    Block -->|Error Page| User