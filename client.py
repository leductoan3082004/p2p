import bencodepy
import hashlib
import os
import logging
import colorlog
import argparse
import socket
import concurrent.futures

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

TORRENT_DIR = "torrents"
FILES_DIR = "files"
DOWNLOAD_DIR = "downloads"
PIECE_LENGHT = 512 * 1024

def hash_segment(segment_data):
    """Calculate the SHA-1 hash of the given segment data."""
    sha1 = hashlib.sha1()
    sha1.update(segment_data)
    return sha1.hexdigest()


def compute_info_hash(torrent):
    info = torrent["info"]
    info_encoded = bencodepy.encode(info)
    info_hash = hashlib.sha1(info_encoded).hexdigest()
    logger.info(f"InfoHash: {info_hash}")
    return info_hash


def generate_magnet_link(info_hash, tracker_url, file_name):
    return f"magnet:?xt=urn:btih:{info_hash}&dn={file_name}&tr={tracker_url}"


def send_magnet_link_to_tracker(
    info_hash, peer_id, peer_port, tracker_host, tracker_port, file_name, file_size
):
    message = f"info_hash={info_hash}&peer_id={peer_id}&peer_port={peer_port}&file_name={file_name}&file_size={file_size}"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_host, tracker_port))
            s.sendall(message.encode("utf-8"))
            logger.info("Successfully sent data to tracker.")
    except socket.error as e:
        logger.error(f"Error sending data to tracker: {e}")


def process_torrent_file(file_path, tracker_url, piece_length=PIECE_LENGHT, peer_port= 6881):
    if not os.path.exists(TORRENT_DIR):
        os.makedirs(TORRENT_DIR)
    with open(file_path, "rb") as f:
        file_data = f.read()

    pieces = [
        hashlib.sha1(file_data[i : i + piece_length]).digest()
        for i in range(0, len(file_data), piece_length)
    ]

    info = {
        "name": file_path.split("/")[-1],
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

    send_magnet_link_to_tracker(
        info_hash,
        peer_id,
        peer_port,
        tracker_host,
        tracker_port,
        info["name"],
        info["length"],
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

    torrent_file_name = f"{TORRENT_DIR}/{info_hash}.torrent"

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


def serve_file_requests(host="0.0.0.0", port=6881):
    """Serve file requests from other peers."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        logger.info(f"Peer server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                logger.info(f"Connected by {addr}")
                try:
                    data = conn.recv(1024).decode("utf-8").strip()
                    if not data:
                        logger.warning(f"cannot receive data from {addr}")

                    if data.startswith("GET_FILE:"):
                        _, info_hash, start, end = data.split(":")
                        start, end = int(start), int(end)
                        file_path = next(
                            (
                                os.path.join(FILES_DIR, f)
                                for f in os.listdir(FILES_DIR)
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

                                # Send data in chunks
                                chunk_size = 4096
                                for i in range(0, len(file_data), chunk_size):
                                    try:
                                        conn.sendall(file_data[i:i + chunk_size])
                                    except (ConnectionResetError, BrokenPipeError):
                                        logger.error(f"Connection to {addr} was reset during file transfer.")
                                        break

                            logger.info(f"Served file segment {start}-{end} of {file_path} to {addr}")
                        else:
                            logger.error(f"Requested file with hash {info_hash} not found.")
                            conn.sendall(b"ERROR: File not found.")
                except ValueError as e:
                    logger.error(f"Invalid request format: {data}")
                    conn.sendall(b"ERROR: Invalid request format.")
                except (ConnectionResetError, BrokenPipeError):
                    logger.error(f"Connection to {addr} was reset during file transfer.")


def request_file_metadata(info_hash, tracker_host, tracker_port):
    """Request file metadata from the tracker for a specific info_hash"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_host, tracker_port))
            s.sendall(f"LIST_PEERS_FOR_HASH_INFO:{info_hash}".encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            logger.info(f"Received metadata for {info_hash}: {data}")

            metadata = {}
            for item in data.split(";"):
                key_value = item.split(":", 1)
                if len(key_value) == 2:
                    key, value = key_value
                    metadata[key] = value

            peers = metadata.get("peers", "").split(",")
            file_name = metadata.get("name", "")
            file_size = int(metadata.get("size", 0))
            pieces = metadata.get("pieces", "").split(",")

            return peers, file_name, file_size, pieces
    except socket.error as e:
        logger.error(f"Error requesting metadata from tracker: {e}")
        return [], "", 0


def download_file_from_peers(
    info_hash,
    file_name,
    file_size,
    peers,
    pieces,
    piece_length=PIECE_LENGHT,
    max_retries=3
):
    """Download a file from peers by requesting segments concurrently."""
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

    segments = [
        (i, min(i + piece_length, file_size)) for i in range(0, file_size, piece_length)
    ]
    file_data = bytearray(file_size)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(peers)) as executor:
        future_to_segment = {}

        for idx, (start, end) in enumerate(segments):
            future = executor.submit(
                download_segment_with_retry_and_verify,
                info_hash,
                start,
                end,
                peers,
                max_retries,
                pieces[idx],
            )
            future_to_segment[future] = (start, end)

        for future in concurrent.futures.as_completed(future_to_segment):
            start, end = future_to_segment[future]
            try:
                segment_data = future.result()
                if segment_data:
                    file_data[start:end] = segment_data
                    logger.info(f"Segment {start}-{end} downloaded and verified.")
                else:
                    logger.error(f"Failed to download segment {start}-{end} after retries")
            except Exception as e:
                logger.error(f"Error downloading segment {start}-{end}: {e}")

    download_path = os.path.join(DOWNLOAD_DIR, file_name)
    with open(download_path, "wb") as f:
        f.write(file_data)
    logger.info(f"File downloaded and saved to {download_path}")



def download_segment_with_retry_and_verify(info_hash, start, end, peers, max_retries, expected_hash):
    """Attempt to download a segment from multiple peers with retries and verify its hash."""
    for attempt in range(max_retries):
        for peer in peers:
            try:
                segment_data = download_segment(peer, info_hash, start, end)  # Placeholder for actual download logic
                if segment_data:
                    # Verify the segment hash
                    calculated_hash = hash_segment(segment_data)
                    if calculated_hash == expected_hash:
                        logger.info(f"Successfully downloaded and verified segment {start}-{end} from {peer} on attempt {attempt + 1}")
                        return segment_data
                    else:
                        logger.warning(f"Hash mismatch for segment {start}-{end} from {peer} on attempt {attempt + 1}")
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed for segment {start}-{end} from {peer}: {e}")
    logger.error(f"Failed to download segment {start}-{end} after {max_retries} attempts.")
    return None

def download_segment(peer, info_hash, start, end):
    """Download a segment of a file from a peer."""
    try:
        peer_host, peer_port = peer.split(":")
        total_bytes_to_receive = end - start
        data = bytearray()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_host, int(peer_port)))
            request = f"GET_FILE:{info_hash}:{start}:{end}"
            s.sendall(request.encode("utf-8"))

            while len(data) < total_bytes_to_receive:
                packet = s.recv(4096)
                if not packet:
                    # Connection closed prematurely
                    logger.error(f"Connection closed before receiving all data for segment {start}-{end}")
                    return None
                data.extend(packet)

            return bytes(data)
    except socket.error as e:
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
    parser.add_argument(
        "--port", type=int, default=6881, help="Specify the peer port. Default is 6881."
    )

    args = parser.parse_args()

    tracker_host, tracker_port = args.tracker.split(":")[1][2:], int(
        args.tracker.split(":")[2].split("/")[0]
    )
    

    if args.list_files:
        request_file_list(tracker_host, tracker_port)
    elif args.file_path:
        process_torrent_file(args.file_path, args.tracker,peer_port=args.port)
    elif args.serve:
        serve_file_requests(port=args.port)
    elif args.download:
        if not args.info_hash:
            logger.error("--info_hash is required for downloading.")
            return
        peers, file_name, file_size, pieces = request_file_metadata(
            args.info_hash, tracker_host, tracker_port
        )

        print(peers, file_name, file_size, pieces) 
        if not file_name or file_size == 0:
            logger.error("Could not determine file metadata.")
            return

        if not peers:
            logger.error("No peers available for download.")
            return

        download_file_from_peers(args.info_hash, file_name, file_size, peers, pieces)


if __name__ == "__main__":
    main()
