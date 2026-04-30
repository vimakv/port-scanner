import socket
import threading
from queue import Queue, Empty
import argparse
import logging
import time
from colorama import Fore, init

# ---------------- INIT ----------------
init(autoreset=True)

# ---------------- LOGGING ----------------
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- GLOBALS ----------------
queue = Queue()


# ---------------- PORT SCAN FUNCTION ----------------
def scan_port(host, port, timeout, show_closed):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        result = s.connect_ex((host, port))

        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "unknown"

            print(Fore.GREEN + f"[OPEN] Port {port} ({service})")
            logging.info(f"{host}:{port} -> OPEN ({service})")

        else:
            if show_closed:
                print(Fore.RED + f"[CLOSED] Port {port}")
                logging.info(f"{host}:{port} -> CLOSED")

        s.close()

    except socket.timeout:
        print(Fore.YELLOW + f"[TIMEOUT] Port {port}")
        logging.info(f"{host}:{port} -> TIMEOUT")

    except Exception as e:
        print(Fore.MAGENTA + f"[ERROR] Port {port}: {e}")
        logging.error(f"{host}:{port} -> ERROR: {e}")


# ---------------- WORKER THREAD ----------------
def worker(host, timeout, show_closed):
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            break

        scan_port(host, port, timeout, show_closed)
        queue.task_done()


# ---------------- MAIN SCAN FUNCTION ----------------
def start_scan(host, start_port, end_port, threads, timeout, show_closed):
    print(Fore.CYAN + f"\nScanning {host} from {start_port} to {end_port}")

    for port in range(start_port, end_port + 1):
        queue.put(port)

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(host, timeout, show_closed))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print(Fore.CYAN + "\nScan completed!")


# ---------------- ARGUMENT PARSER ----------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner")

    parser.add_argument("host", help="Target IP or domain")
    parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 20-100)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=1, help="Timeout per port")
    parser.add_argument("--show-closed", action="store_true", help="Show closed ports")

    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))

    start_time = time.time()

    start_scan(
        args.host,
        start_port,
        end_port,
        args.threads,
        args.timeout,
        args.show_closed
    )

    end_time = time.time()

    print(Fore.CYAN + f"\nScan finished in {end_time - start_time:.2f} seconds")


# ---------------- RUN ----------------
if __name__ == "__main__":
    main()