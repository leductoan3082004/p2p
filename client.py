import bencodepy
import hashlib
import os
import logging
import colorlog
import argparse
import socket
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests

PIECE_LENGTH_FOR_HASH = 512 * 1024

handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s "
        "(in %(filename)s:%(lineno)d)",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)

logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def compute_info_hash(torrent):
    info = torrent["info"]
    info_encoded = bencodepy.encode(info)
    info_hash = hashlib.sha1(info_encoded).hexdigest()
    logger.info(f"InfoHash: {info_hash}")
    return info_hash


def generate_magnet_link(info_hash, tracker_url, file_name):
    return f"magnet:?xt=urn:btih:{info_hash}&dn={file_name}&tr={tracker_url}"


def send_magnet_link_to_tracker(
    info_hash, peer_id, peer_port, tracker_host, tracker_port, file_name, file_size, piece_length
):
    message = f"info_hash={info_hash}&peer_id={peer_id}&peer_port={peer_port}&file_name={file_name}&file_size={file_size}&piece_length={piece_length}"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_host, tracker_port))
            s.sendall(message.encode("utf-8"))
            logger.info("Successfully sent data to tracker.")
    except socket.error as e:
        logger.error(f"Error sending data to tracker: {e}")


def process_torrent_file(file_path, tracker_url, piece_length=PIECE_LENGTH_FOR_HASH, port=8000):
    TORRENT_DIR = f"torrents_{port}"
    FILES_DIR = f"files_{port}"

    if not os.path.exists(TORRENT_DIR):
        os.makedirs(TORRENT_DIR)
    with open(file_path, "rb") as f:
        file_data = f.read()

    pieces = [
        hashlib.sha1(file_data[i: i + piece_length]).digest()
        for i in range(0, len(file_data), piece_length)
    ]

    info = {
        "name": os.path.basename(file_path),
        "length": len(file_data),
        "piece length": piece_length,
        "pieces": b"".join(pieces),
    }

    torrent = {"announce": tracker_url, "info": info}

    info_hash = compute_info_hash(torrent)

    magnet_link = generate_magnet_link(info_hash, tracker_url, info["name"])
    logger.info(f"Magnet Link: {magnet_link}")

    tracker_host, tracker_port = tracker_url.split(":")[1][2:], int(
        tracker_url.split(":")[2].split("/")[0]
    )

    peer_id = socket.gethostname()
    peer_port = port  # Use specified port

    send_magnet_link_to_tracker(
        info_hash,
        peer_id,
        peer_port,
        tracker_host,
        tracker_port,
        info["name"],
        info["length"],
        piece_length,  # Pass piece_length to the tracker
    )

    # Ensure the FILES_DIR exists
    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR)

    # Copy the file to the FILES_DIR and rename it to the info_hash with the original extension
    file_extension = os.path.splitext(file_path)[1]
    new_file_path = os.path.join(FILES_DIR, f"{info_hash}{file_extension}")
    if not os.path.exists(new_file_path):
        with open(new_file_path, "wb") as new_file:
            new_file.write(file_data)
        logger.info(f"Copied and renamed file to: {new_file_path}")
    else:
        logger.error(f"File already exists: {new_file_path}")
        return

    torrent_file_name = os.path.join(TORRENT_DIR, f"{info_hash}.torrent")

    if os.path.exists(torrent_file_name):
        logger.error(f"File already exists: {torrent_file_name}")
        return

    with open(torrent_file_name, "wb") as torrent_file:
        torrent_file.write(bencodepy.encode(torrent))

    logger.info(f".torrent file created: {torrent_file_name}")
    return torrent


def request_file_list(tracker_host, tracker_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_host, tracker_port))
            s.sendall("LIST_FILES".encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            logger.info("Received file list from tracker:")
            print(data)
    except socket.error as e:
        logger.error(f"Error requesting file list from tracker: {e}")


class FileRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/get_file":
            # Read headers
            info_hash = self.headers.get('Info-Hash')
            start = int(self.headers.get('Segment-Start', 0))
            end = int(self.headers.get('Segment-End', 0))

            file_path = next(
                (
                    os.path.join(self.server.files_dir, f)
                    for f in os.listdir(self.server.files_dir)
                    if f.startswith(info_hash)
                ),
                None,
            )

            if file_path and os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                # Ensure end does not exceed file size
                end = min(end, file_size)

                with open(file_path, "rb") as file:
                    file.seek(start)
                    file_data = file.read(end - start)

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(file_data)))
                self.end_headers()
                self.wfile.write(file_data)
                logger.info(
                    f"Served file segment {start}-{end} of {file_path} to {self.client_address}"
                )
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"ERROR: File not found.")
                logger.error(f"Requested file with hash {info_hash} not found.")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"ERROR: Invalid request.")
            logger.error(f"Invalid request path: {self.path}")


def serve_file_requests(host="0.0.0.0", port=8000):
    """Serve file requests from other peers using HTTP."""
    FILES_DIR = f"files_{port}"

    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR)

    server_address = (host, port)
    handler = FileRequestHandler
    httpd = HTTPServer(server_address, handler)
    httpd.files_dir = FILES_DIR  # Pass the files directory to the handler
    logger.info(f"HTTP server is running on {host}:{port}, serving from {FILES_DIR}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logger.info("HTTP server stopped.")


def request_file_metadata(info_hash, tracker_host, tracker_port):
    """Request file metadata from the tracker for a specific info_hash."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_host, tracker_port))
            s.sendall(f"LIST_PEERS_FOR_HASH_INFO:{info_hash}".encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            logger.info(f"Received metadata for {info_hash}: {data}")
            print(data)

            metadata = {}
            for item in data.split(";"):
                key_value = item.split(":", 1)
                if len(key_value) == 2:
                    key, value = key_value
                    metadata[key] = value

            peers = metadata.get("peers", "").split(",")
            file_name = metadata.get("name", "")
            file_size = int(metadata.get("size", 0))
            piece_length = int(metadata.get("piece_length", 0))  # Get piece_length

            return peers, file_name, file_size, piece_length
    except socket.error as e:
        logger.error(f"Error requesting metadata from tracker: {e}")
        return [], "", 0, 0


def download_file_from_peers(
    info_hash,
    file_name,
    file_size,
    peers,
    piece_length=512 * 1024,  # Default piece length
    max_retries=3,
    port=8000,
):
    """Download a file from peers by requesting segments concurrently using HTTP."""
    DOWNLOAD_DIR = f"downloads_{port}"

    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

    segments = [
        (i, min(i + piece_length, file_size)) for i in range(0, file_size, piece_length)
    ]
    file_data = bytearray(file_size)

    # Assign segments to peers evenly
    segment_peer_map = {}
    for idx, segment in enumerate(segments):
        peer = peers[idx % len(peers)]
        segment_peer_map[segment] = peer

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_segment = {}
        for segment in segments:
            start, end = segment
            assigned_peer = segment_peer_map[segment]
            future = executor.submit(
                download_segment_with_retry,
                info_hash,
                start,
                end,
                peers,
                max_retries,
                assigned_peer=assigned_peer,
            )
            future_to_segment[future] = (start, end)

        for future in concurrent.futures.as_completed(future_to_segment):
            start, end = future_to_segment[future]
            try:
                segment_data = future.result()
                if segment_data:
                    file_data[start:end] = segment_data
                    logger.info(f"Downloaded segment {start}-{end}")
                else:
                    logger.error(
                        f"Failed to download segment {start}-{end} after retries"
                    )
            except Exception as e:
                logger.error(f"Error downloading segment {start}-{end}: {e}")

    download_path = os.path.join(DOWNLOAD_DIR, file_name)
    with open(download_path, "wb") as f:
        f.write(file_data)
    logger.info(f"File downloaded and saved to {download_path}")

    # Validate the downloaded file using the info_hash
    is_valid = validate_downloaded_file(download_path, info_hash, PIECE_LENGTH_FOR_HASH)
    if is_valid:
        logger.info("Downloaded file is valid.")
    else:
        logger.error("Downloaded file is invalid. Info hash does not match.")


def validate_downloaded_file(file_path, expected_info_hash, piece_length):
    """Validate the downloaded file by computing its info hash and comparing to expected."""
    with open(file_path, "rb") as f:
        file_data = f.read()

    pieces = [
        hashlib.sha1(file_data[i: i + piece_length]).digest()
        for i in range(0, len(file_data), piece_length)
    ]

    info = {
        "name": os.path.basename(file_path),
        "length": len(file_data),
        "piece length": piece_length,
        "pieces": b"".join(pieces),
    }

    info_encoded = bencodepy.encode(info)
    computed_info_hash = hashlib.sha1(info_encoded).hexdigest()

    logger.info(f"Expected InfoHash: {expected_info_hash}")
    logger.info(f"Computed InfoHash: {computed_info_hash}")

    return expected_info_hash == computed_info_hash


def download_segment_with_retry(info_hash, start, end, peers, max_retries, assigned_peer=None):
    """Attempt to download a segment from peers with retries, starting with assigned_peer."""
    # Start with assigned peer, then try others if necessary
    peers_to_try = [assigned_peer] + [peer for peer in peers if peer != assigned_peer]
    for peer in peers_to_try:
        for attempt in range(max_retries):
            try:
                segment_data = download_segment(peer, info_hash, start, end)
                if segment_data:
                    logger.info(
                        f"Successfully downloaded segment {start}-{end} from {peer} on attempt {attempt + 1}"
                    )
                    return segment_data
                else:
                    logger.warning(
                        f"No data received for segment {start}-{end} from {peer} on attempt {attempt + 1}"
                    )
            except Exception as e:
                logger.error(
                    f"Error on attempt {attempt + 1} for segment {start}-{end} from {peer}: {e}"
                )
        logger.warning(
            f"Failed to download segment {start}-{end} from {peer} after {max_retries} attempts"
        )
    return None


def download_segment(peer, info_hash, start, end):
    """Download a segment of a file from a peer using HTTP headers."""
    try:
        peer_host, peer_port = peer.split(":")
        url = f"http://{peer_host}:{peer_port}/get_file"  # No query parameters
        headers = {
            'Info-Hash': info_hash,
            'Segment-Start': str(start),
            'Segment-End': str(end)
        }
        response = requests.get(url, headers=headers, stream=True, timeout=10)

        if response.status_code == 200:
            data = response.content
            if len(data) == (end - start):
                return data
            else:
                logger.error(
                    f"Received incomplete data for segment {start}-{end} from {peer}"
                )
                return None
        else:
            logger.error(
                f"Received status code {response.status_code} for segment {start}-{end} from {peer}"
            )
            return None
    except requests.RequestException as e:
        logger.error(f"Error downloading segment from {peer}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Create a torrent file, generate a magnet link, request file list, or download a file from peers."
    )
    parser.add_argument("--file_path", help="Path to the file to be torrented.")
    parser.add_argument("--tracker", required=True, help="Tracker URL for the torrent.")
    parser.add_argument(
        "--list_files", action="store_true", help="List files on the tracker."
    )
    parser.add_argument("--serve", action="store_true", help="Start the file server.")
    parser.add_argument(
        "--download", action="store_true", help="Download a file from peers."
    )
    parser.add_argument("--info_hash", help="Info hash of the file to download.")
    parser.add_argument("--port", type=int, help="Port to serve the file on.")

    args = parser.parse_args()

    tracker_host, tracker_port = args.tracker.split(":")[1][2:], int(
        args.tracker.split(":")[2].split("/")[0]
    )

    port = int(args.port) if args.port else 8000

    if args.list_files:
        request_file_list(tracker_host, tracker_port)
    elif args.file_path:
        process_torrent_file(args.file_path, args.tracker, port=port)
    elif args.serve:
        # Run the HTTP server in a separate thread to prevent blocking
        server_thread = threading.Thread(target=serve_file_requests, args=("0.0.0.0", port,))
        server_thread.daemon = True
        server_thread.start()
        try:
            while True:
                pass  # Keep the main thread alive
        except KeyboardInterrupt:
            logger.info("Shutting down the server.")
    elif args.download:
        if not args.info_hash:
            logger.error("--info_hash is required for downloading.")
            return
        peers, file_name, file_size, piece_length = request_file_metadata(
            args.info_hash, tracker_host, tracker_port
        )

        print(peers, file_name, file_size)
        if not file_name or file_size == 0:
            logger.error("Could not determine file metadata.")
            return

        if not peers:
            logger.error("No peers available for download.")
            return

        piece_length = max(piece_length, 512 * 102)
        download_file_from_peers(
            args.info_hash,
            file_name,
            file_size,
            peers,
            piece_length=piece_length,  # Use the same piece_length
            port=port
        )


if __name__ == "__main__":
    main()
