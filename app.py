import socket
import threading
from queue import Queue
import argparse
import logging

# ---------------- LOGGING SETUP ----------------
logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- GLOBALS ----------------
queue = Queue()
TIMEOUT = 1


# ---------------- PORT SCAN FUNCTION ----------------
def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        result = s.connect_ex((host, port))

        if result == 0:
            print(f"[OPEN] Port {port}")
            logging.info(f"{host}:{port} -> OPEN")
        else:
            print(f"[CLOSED] Port {port}")
            logging.info(f"{host}:{port} -> CLOSED")

        s.close()   # ✅ SAME LEVEL as if/else

    except socket.timeout:
        print(f"[TIMEOUT] Port {port}")
        logging.info(f"{host}:{port} -> TIMEOUT")

    except Exception as e:
        print(f"[ERROR] Port {port}: {e}")
        logging.error(f"{host}:{port} -> ERROR: {e}")


# ---------------- WORKER THREAD ----------------
def worker(host):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port)
        queue.task_done()


# ---------------- MAIN SCAN FUNCTION ----------------
def start_scan(host, start_port, end_port, threads):
    print(f"\nScanning {host} from {start_port} to {end_port}")

    # STEP 1: add ports to queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # STEP 2: start threads
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(host,))
        t.daemon = True
        t.start()

    # wait until all tasks are done
    queue.join()

    print("\nScan completed!")


# ---------------- ARGUMENT PARSER ----------------
def main():
    parser = argparse.ArgumentParser(description="Simple Python Port Scanner")
    parser.add_argument("host", help="Target IP or domain")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 20-100)", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=50)

    args = parser.parse_args()

    host = args.host
    port_range = args.ports.split("-")

    start_port = int(port_range[0])
    end_port = int(port_range[1])

    start_scan(host, start_port, end_port, args.threads)


# ---------------- RUN ----------------
if __name__ == "__main__":
    main()