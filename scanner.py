import socket
import threading
from queue import Queue
import argparse
import logging
import time
import csv
import asyncio
from threading import Lock

# ---------------- LOGGING ----------------
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- GLOBALS ----------------
queue = Queue()
TIMEOUT = 1
file_lock = Lock()

# ---------------- SERVICE DETECTION ----------------
def get_service(port):
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 139: "netbios",
        143: "imap", 443: "https", 445: "smb",
        3306: "mysql", 3389: "rdp"
    }
    return services.get(port, "unknown")

# ---------------- CLEAN BANNER ----------------
def grab_banner(sock, port):
    try:
        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        else:
            sock.send(b"\r\n")

        data = sock.recv(1024).decode(errors="ignore")

        # Clean output
        lines = data.split("\n")
        first_line = lines[0].strip()

        server = ""
        for line in lines:
            if "Server:" in line:
                server = line.split("Server:")[1].strip()
                break

        if server:
            return f"{first_line} | {server}"
        return first_line

    except:
        return "No banner"

# ---------------- PORT SCAN ----------------
def scan_port(host, port, output_file=None, csv_file=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        result = s.connect_ex((host, port))

        if result == 0:
            service = get_service(port)

            banner = grab_banner(s, port)

            output = f"[OPEN] {host}:{port} ({service}) - {banner}"
            print(output)

            logging.info(output)

            if output_file:
                with file_lock:
                    with open(output_file, "a") as f:
                        f.write(output + "\n")

            if csv_file:
                with file_lock:
                    with open(csv_file, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([host, port, service, "OPEN", banner])

        s.close()

    except socket.timeout:
        print(f"[TIMEOUT] {host}:{port}")

    except Exception as e:
        print(f"[ERROR] {host}:{port} - {e}")

# ---------------- THREAD WORKER ----------------
def worker(host, output_file, csv_file):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port, output_file, csv_file)
        queue.task_done()

# ---------------- THREAD SCANNER ----------------
def start_scan(host, start_port, end_port, threads, output_file, csv_file):
    print(f"\n[THREAD] Scanning {host} ({start_port}-{end_port})")

    start_time = time.time()

    for port in range(start_port, end_port + 1):
        queue.put(port)

    for _ in range(threads):
        t = threading.Thread(target=worker, args=(host, output_file, csv_file))
        t.daemon = True
        t.start()

    queue.join()

    print(f"Scan completed in {time.time() - start_time:.2f}s")

# ---------------- ASYNC SCANNER ----------------
async def async_scan_port(host, port):
    try:
        reader, writer = await asyncio.open_connection(host, port)

        service = get_service(port)

        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await writer.drain()
            data = (await reader.read(1024)).decode(errors="ignore")
            banner = data.split("\n")[0].strip()
        except:
            banner = "No banner"

        print(f"[OPEN] {host}:{port} ({service}) - {banner}")

        writer.close()
        await writer.wait_closed()

    except:
        pass

async def async_scan(host, start_port, end_port):
    print(f"\n[ASYNC] Scanning {host}")

    tasks = []
    for port in range(start_port, end_port + 1):
        tasks.append(async_scan_port(host, port))

    await asyncio.gather(*tasks)

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")

    parser.add_argument("host", help="Target (single or comma-separated)")
    parser.add_argument("-p", "--ports", required=True)
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("-o", "--output")
    parser.add_argument("--csv")
    parser.add_argument("--async", dest="async_mode", action="store_true")

    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    hosts = args.host.split(",")

    for host in hosts:
        host = host.strip()

        if args.async_mode:
            asyncio.run(async_scan(host, start_port, end_port))
        else:
            start_scan(host, start_port, end_port, args.threads, args.output, args.csv)

# ---------------- RUN ----------------
if __name__ == "__main__":
    main()