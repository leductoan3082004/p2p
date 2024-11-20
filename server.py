import socket
import logging
import colorlog
import argparse
import os
import bencodepy

DATA_DIR = "server"
TORRENT_DIR = "torrents"

handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)

logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def ensure_data_directory():
    """Ensure the data directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        logger.info(f"Created directory: {DATA_DIR}")


def save_peer_info(info_hash, peer_id, peer_port, file_name, file_size):
    """Save the peer information to a file named after the info_hash and file_name."""
    # Create a safe file name by combining info_hash and file_name
    safe_file_name = f"{info_hash}:{file_name}:{file_size}.txt"
    file_path = os.path.join(DATA_DIR, safe_file_name)
    peer_info = f"{peer_id}:{peer_port}"

    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            existing_peers = file.read().splitlines()
    else:
        existing_peers = []

    # Check for duplicate
    if peer_info in existing_peers:
        logger.info(f"Peer {peer_info} already exists for {info_hash} and {file_name} and {file_size}.")
    else:
        with open(file_path, "a") as file:
            file.write(f"{peer_info}\n")
        logger.info(f"Saved peer info to {file_path}")


def list_files():
    """List all files available in the DATA_DIR."""
    try:
        files = os.listdir(DATA_DIR)
        if not files:
            return "No files available."
        return "\n".join(files)
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return "ERROR: Could not list files."


def start_tracker_server(host="0.0.0.0", port=6881):
    ensure_data_directory()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        logger.info(f"Tracker server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                logger.info(f"Connected by {addr}")
                data = conn.recv(1024).decode("utf-8").strip()
                if not data:
                    break

                if data == "LIST_FILES":
                    files_list = list_files()
                    conn.sendall(files_list.encode("utf-8"))
                elif data.startswith("LIST_PEERS_FOR_HASH_INFO:"):
                    try:
                        _, info_hash = data.split(":")
                        peers, file_name, file_size, hashed_pieces = get_metatdata_from_info_hash(info_hash)
                        response = f"peers:{peers};name:{file_name};size:{file_size};pieces:{hashed_pieces}"
                        conn.sendall(response.encode("utf-8"))
                    except ValueError:
                        logger.error("Invalid LIST_PEERS_FOR_HASH_INFO request format.")
                        conn.sendall(b"ERROR: Invalid request format.")
                else:
                    try:
                        params = dict(param.split("=") for param in data.split("&"))
                        info_hash = params.get("info_hash")
                        peer_id = params.get("peer_id")
                        peer_port = params.get("peer_port")
                        file_name = params.get("file_name")
                        file_size = params.get("file_size")

                        if info_hash and peer_id and peer_port and file_name and file_size:
                            save_peer_info(info_hash, peer_id, peer_port, file_name, file_size)
                        else:
                            logger.error("Invalid data format received.")
                    except Exception as e:
                        logger.error(f"Error processing data: {e}")

def is_peer_alive(peer):
    """Check if a peer is alive by attempting to connect to its host and port."""
    try:
        host, port = peer.split(":")
        port = int(port)
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception as e:
        logger.warning(f"Peer {peer} is dead")
        return False
      

def get_alive_peers_and_file_detail(info_hash):
    """Return only alive peers from the peer files for the specified info_hash."""
    try:
        matching_peer_files = [
            f for f in os.listdir(DATA_DIR) if f.startswith(info_hash)
        ]

        if not matching_peer_files:
            raise ValueError(f"No peer files found for info_hash {info_hash}.")

        all_peers = []
        file_name = ""
        file_size = 0
        for peer_file in matching_peer_files:
            peers_file_path = os.path.join(DATA_DIR, peer_file)
            
            # Read peers data from the file
            with open(peers_file_path, "r") as file:
                peers = file.readlines()
                all_peers.extend(peers)
                
            base_name = os.path.splitext(peer_file)[0] 
            _, file_name, file_size_str = base_name.split(":")
            file_size = int(file_size_str)

        # Filter alive peers
        alive_peers = [peer for peer in all_peers if is_peer_alive(peer)]

        if not alive_peers:
            raise RuntimeError(f"No alive peers found.")

        return alive_peers, file_name, file_size
      
    except Exception as e:
        logger.error(f"Error retrieving alive peers for info_hash {info_hash}: {e}")
        raise

def get_metatdata_from_info_hash(info_hash):
    try:
        # Get alive peers
        all_peers, file_name, file_size = get_alive_peers_and_file_detail(info_hash)
        hashed_pieces = ""

        # Find .torrent file
        matching_torrent_files = [
            f for f in os.listdir(TORRENT_DIR) if f.startswith(info_hash)
        ]

        if not matching_torrent_files:
            logger.error(f"No .torrent files found for info_hash {info_hash}.")
            return "", "", 0, ""

        # Open and parse the .torrent file
        for torrent_file in matching_torrent_files:
            torrent_file_path = os.path.join(TORRENT_DIR, torrent_file)

            with open(torrent_file_path, "rb") as file:
                torrent_content = file.read()
                try:
                    torrent_data = bencodepy.decode(torrent_content)
                    info = torrent_data.get(b"info", {})
                    pieces = info.get(b"pieces", b"")

                    # Each SHA-1 hash is 20 bytes
                    hashed_pieces_list = [
                        pieces[i:i + 20].hex() for i in range(0, len(pieces), 20)
                    ]
                    hashed_pieces = ",".join(hashed_pieces_list)

                    file_name = info.get(b"name", b"").decode("utf-8")
                    file_size = info.get(b"length", 0)

                except (ValueError, KeyError) as e:
                    logger.error(f"Failed to decode torrent file {torrent_file_path}: {e}")
                    continue

        # Return peers as a comma-separated string
        return ",".join(all_peers), file_name, file_size, hashed_pieces
    except Exception as e:
        logger.error(f"Error while getting metadata from info hash \'{info_hash}\': {e}")
        return "", "", 0, ""


def main():
    parser = argparse.ArgumentParser(description="Start the tracker server.")
    parser.add_argument("--port", type=int, default=3000, help="Port to listen on.")
    args = parser.parse_args()

    start_tracker_server(port=args.port)


if __name__ == "__main__":
    main()
