import bencodepy, hashlib, requests, random, string, struct
import socket, threading, sys, os, logging, time, queue
from urllib.parse import urlparse, urlencode
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QMessageBox, QHBoxLayout, QPushButton, QLineEdit, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QObject, QSize
from PyQt5.QtGui import QIcon, QFont

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_peer_id():
    return '-PC0001-' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))

class TorrentSignals(QObject):
    progress_updated = pyqtSignal(str, int, int, float)
    status_updated = pyqtSignal(str, str)
    peer_count_updated = pyqtSignal(str, int)

class Torrent:
    def __init__(self, torrent_file):
        self.torrent_file = torrent_file
        self.peer_id = generate_peer_id()
        self.parse_torrent_file()
        self.parse_torrent_file()
        self.prioritize_files()
        self.max_connections = 100
        self.active_peers = set()
        self.peers = []
        self.downloaded = 0
        self.uploaded = 0
        self.running = False
        self.piece_rarity = [0] * (self.length // self.piece_length)
        self.length = sum(file_length for _, file_length in self.files)
        self.downloaded_pieces = set()
        self.upload_limiter = RateLimiter(5000000)
        self.download_limiter = RateLimiter(10000000)
        self.folder_path = os.path.join(os.getcwd(), self.name)
        os.makedirs(self.folder_path, exist_ok=True)
        logger.info(f"Created folder for torrent: {self.folder_path}")
        self.initialize_files()
        self.choked = True
        self.status = "Initialized"
        self.active_peer_count = 0
        self.signals = TorrentSignals()
        self.signals_holder = []
        self.signals_holder.append(self.signals)
        self.start_time = time.time()
        self.last_progress_update = time.time()
        self.download_speed = 0
        self.piece_status = ['missing'] * (self.length // self.piece_length)
        logger.debug(f"Initialized torrent with {len(self.piece_status)} pieces")
        self.downloaded_pieces = set()
        self.written_pieces = set()
        self.piece_data = {}
        self.write_queue = queue.Queue()
        self.writing = True
        threading.Thread(target=self.write_pieces_thread, daemon=True).start()
        self.total_pieces = len(self.pieces) // 20
    
    def format_size(self, size):
        size_mb = size / (1024 * 1024)
        return f"{size_mb:.2f} MB"

    def update_active_peer_count(self, delta):
        self.active_peer_count += delta
        self.signals.peer_count_updated.emit(self.name, self.active_peer_count)
        
    def initialize_files(self):
        for file_path, file_length in self.files:
            full_path = os.path.join(self.folder_path, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'wb') as f:
                f.truncate(file_length)
        logger.info(f"Initialized output files in {self.folder_path}")

    def parse_torrent_file(self):
        logger.info(f"Parsing torrent file: {self.torrent_file}")
        with open(self.torrent_file, 'rb') as f:
            torrent_data = f.read()
        self.torrent_info = bencodepy.decode(torrent_data)
        self.info_hash = hashlib.sha1(bencodepy.encode(self.torrent_info[b'info'])).digest()
        self.piece_length = self.torrent_info[b'info'][b'piece length']
        self.pieces = self.torrent_info[b'info'][b'pieces']
        self.name = self.torrent_info[b'info'][b'name'].decode('utf-8')
        self.announce = self.torrent_info[b'announce'].decode('utf-8')
    
        if b'files' in self.torrent_info[b'info']:
            self.files = []
            self.length = 0
            for file_info in self.torrent_info[b'info'][b'files']:
                file_length = file_info[b'length']
                file_path = '/'.join([part.decode('utf-8') for part in file_info[b'path']])
                self.files.append((file_path, file_length))
                self.length += file_length
            logger.info(f"Multi-file torrent parsed: {self.name}, total length: {self.length}, files: {len(self.files)}")
        else:
            self.length = self.torrent_info[b'info'][b'length']
            self.files = [(self.name, self.length)]
            logger.info(f"Single-file torrent parsed: {self.name}, length: {self.length}")
    
        logger.info(f"Torrent parsed: {self.name}, total length: {self.length}, pieces: {len(self.pieces)//20}")
    
    def update_debug_log(self, message):
      log_file_path = os.path.join(self.folder_path, "debug_log.txt")
      with open(log_file_path, 'a') as f:
          f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

    def connect_to_tracker(self):
        logger.info(f"Connecting to tracker: {self.announce}")
        trackers = [self.announce]
        announce_list = self.torrent_info.get(b'announce-list', [])
        for tier in announce_list:
            trackers.extend([t.decode() if isinstance(t, bytes) else t for t in tier])

        https_trackers = [t for t in trackers if t.startswith('https://')]

        for tracker in https_trackers:
            try:
                params = {
                    'info_hash': self.info_hash,
                    'peer_id': self.peer_id,
                    'port': 6881,
                    'uploaded': self.uploaded,
                    'downloaded': self.downloaded,
                    'left': self.length - self.downloaded,
                    'compact': 1,
                    'event': 'started'
                }
                url = f"{tracker}?{urlencode(params)}"
                logger.debug(f"Tracker URL: {url}")
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    tracker_response = bencodepy.decode(response.content)
                    self.interval = tracker_response.get(b'interval', 1800)
                    peers_data = tracker_response.get(b'peers', b'')
                    new_peers = []
                    for i in range(0, len(peers_data), 6):
                        ip = socket.inet_ntoa(peers_data[i:i+4])
                        port = struct.unpack("!H", peers_data[i+4:i+6])[0]
                        new_peers.append((ip, port))
                    self.peers.extend(new_peers)
                    logger.info(f"Received {len(new_peers)} peers from tracker {tracker}")
                    self.update_status(f"Peers received from tracker {tracker}")
                    if len(self.peers) >= 50:
                        break
                else:
                    logger.warning(f"HTTP tracker {tracker} returned status code {response.status_code}")
            except Exception as e:
                logger.error(f"Error connecting to tracker {tracker}: {e}")

        if not self.peers:
            self.update_status("No peers available")
        else:
            logger.info(f"Total peers gathered: {len(self.peers)}")
    
    def udp_tracker_request(self, tracker_url, info_hash, peer_id, port, uploaded, downloaded, left, event='started'):
      parsed_url = urlparse(tracker_url)
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(8)
      
      try:
          conn = (socket.gethostbyname(parsed_url.hostname), parsed_url.port)
          
          transaction_id = random.randint(0, 2**32 - 1)
          connection_id = 0x41727101980
          action = 0  # connect
          buf = struct.pack("!qii", connection_id, action, transaction_id)
          sock.sendto(buf, conn)
          
          response = sock.recv(16)
          action, transaction_id, connection_id = struct.unpack("!iiq", response)
          
          if action != 0 or transaction_id != transaction_id:
              raise RuntimeError("Invalid connection response")
          
          action = 1
          transaction_id = random.randint(0, 2**32 - 1)
          
          event_dict = {'started': 2, 'completed': 1, 'stopped': 3}
          event_int = event_dict.get(event, 0)
          
          buf = struct.pack("!qii20s20sqqqi", 
                            connection_id, action, transaction_id, info_hash, peer_id.encode(),
                            downloaded, left, uploaded, event_int)
          buf += struct.pack("!i", 0)
          buf += struct.pack("!i", -1)
          buf += struct.pack("!H", port)
          
          sock.sendto(buf, conn)
          
          response = sock.recv(1024)
          action, transaction_id, interval, leechers, seeders = struct.unpack("!iiiii", response[:20])
          
          if action != 1:
              raise RuntimeError("Invalid announce response")
          
          peers = []
          for i in range(20, len(response), 6):
              ip = socket.inet_ntoa(response[i:i+4])
              port = struct.unpack("!H", response[i+4:i+6])[0]
              peers.append((ip, port))
          
          return {
              'interval': interval,
              'peers': peers
          }
      finally:
          sock.close()

    def send_keepalive(self, sock):
        try:
            self.send_message(sock, struct.pack(">I", 0))
            self.update_debug_log("Sent keep-alive message")
            logger.debug("Sent keep-alive message")
        except Exception as e:
            self.update_debug_log(f"Failed to send keep-alive: {e}")
            logger.error(f"Failed to send keep-alive: {e}")
    
    def send_message(self, sock, message):
        try:
            self.upload_limiter.limit(len(message))
            sock.send(message)
            logger.debug(f"Sent message: {message[:10]}...")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
  
    def start_download(self):
        logger.info("Starting download")
        self.running = True
        self.status = "Connecting to tracker"
        self.connect_to_tracker()
        if self.peers:
            self.status = "Connecting to peers"
            for peer in self.peers:
                thread = threading.Thread(target=self.connect_to_peer, args=(peer,))
                thread.start()
        else:
            self.status = "No peers available"
        self.connect_to_tracker()
        self.manage_peers()
        threading.Thread(target=self.write_pieces_thread, daemon=True).start()
        threading.Thread(target=self.periodic_tracker_update, daemon=True).start()
    
    def manage_peers(self):
        while self.running:
            if len(self.active_peers) < self.max_connections:
                for peer in self.peers:
                    if peer not in self.active_peers:
                        threading.Thread(target=self.connect_to_peer, args=(peer,)).start()
                        break
            time.sleep(5)

    def update_status(self, status):
        self.status = status
        logger.info(f"Torrent status: {self.name} - {status}")

    def connect_to_peer(self, peer):
        self.update_debug_log(f"Attempting to connect to peer {peer}")
        logger.info(f"Attempting to connect to peer {peer}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        try:
            sock.connect(peer)
            self.update_debug_log(f"Connected to peer {peer}")
            logger.info(f"Connected to peer {peer}")

            self.send_handshake(sock)
            self.update_debug_log("Handshake sent")
            logger.debug("Handshake sent")

            if self.receive_handshake(sock):
                self.update_debug_log("Handshake received successfully")
                logger.debug("Handshake received successfully")
                self.send_interested(sock)
                self.update_debug_log("Sent interested message")
                logger.debug("Sent interested message")

                self.active_peers.add(peer)
                self.update_active_peer_count(1)
                self.sock = sock

                buffer = b""
                while self.running:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            logger.warning(f"Peer {peer} closed connection")
                            break
                        buffer += data
                        logger.debug(f"Received {len(data)} bytes from peer {peer}")
                        while len(buffer) >= 4:
                            if len(buffer) < 4:
                                break
                            length = struct.unpack(">I", buffer[:4])[0]
                            if len(buffer) < length + 4:
                                break
                            message = buffer[4:length+4]
                            self.handle_message(sock, message)
                            buffer = buffer[length+4:]
                    except socket.timeout:
                        self.update_debug_log(f"Socket timeout for peer {peer}, sending keep-alive")
                        logger.warning(f"Socket timeout for peer {peer}, sending keep-alive")
                        self.send_keepalive(sock)
                    except ConnectionResetError:
                        self.update_debug_log(f"Connection reset by peer {peer}")
                        logger.error(f"Connection reset by peer {peer}")
                        break
                    except Exception as e:
                        self.update_debug_log(f"Unexpected error with peer {peer}: {str(e)}")
                        logger.error(f"Unexpected error with peer {peer}: {str(e)}")
                        logger.exception("Stack trace:")
                        break
            else:
                self.update_debug_log(f"Failed to receive handshake from peer {peer}")
                logger.warning(f"Failed to receive handshake from peer {peer}")
        except socket.timeout:
            self.update_debug_log(f"Connection to peer {peer} timed out")
            logger.error(f"Connection to peer {peer} timed out")
        except ConnectionRefusedError:
            self.update_debug_log(f"Connection to peer {peer} refused")
            logger.error(f"Connection to peer {peer} refused")
        except Exception as e:
            self.update_debug_log(f"Error in peer connection {peer}: {str(e)}")
            logger.error(f"Error in peer connection {peer}: {str(e)}")
            logger.exception("Stack trace:")
        finally:
            if peer in self.active_peers:
                self.active_peers.remove(peer)
                self.update_active_peer_count(-1)
            sock.close()
            self.update_debug_log(f"Closed connection to peer {peer}")
            logger.info(f"Closed connection to peer {peer}")

    def send_handshake(self, sock):
        logger.debug("Sending handshake")
        pstr = b"BitTorrent protocol"
        reserved = b"\x00" * 8
        handshake = struct.pack(">B19s8s20s20s", 19, pstr, reserved, self.info_hash, self.peer_id.encode())
        sock.send(handshake)
        logger.debug("Handshake sent")

    def send_interested(self, sock):
        logger.debug("Sending interested message")
        msg = struct.pack(">IB", 1, 2)
        sock.send(msg)
        logger.debug("Interested message sent")

    def receive_handshake(self, sock):
        logger.debug("Waiting to receive handshake")
        data = sock.recv(68)
        if len(data) < 68:
            logger.warning(f"Received incomplete handshake: {len(data)} bytes")
            return False
        logger.debug("Handshake received successfully")
        return True

    def receive_message(self, sock):
        try:
            length_prefix = sock.recv(4)
            if len(length_prefix) < 4:
                return None
            length = struct.unpack(">I", length_prefix)[0]
            message = sock.recv(length)
            self.download_limiter.limit(len(message))
            return message
        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
            return None

    def request_piece(self, sock):
        if self.downloaded >= self.length:
            logger.info("Download complete, not requesting more pieces")
            return False

        piece_index = self.select_piece_to_request()
        if piece_index is None:
            logger.info("No pieces available to request")
            return False

        begin = 0
        while begin < self.piece_length:
            remaining = self.piece_length - begin
            length = min(16384, remaining, self.length - (piece_index * self.piece_length + begin))

            logger.info(f"Requesting piece: index={piece_index}, begin={begin}, length={length}")
            msg = struct.pack(">IBIII", 13, 6, piece_index, begin, length)
            try:
                sock.send(msg)
                logger.debug(f"Piece request sent: index={piece_index}, begin={begin}, length={length}")
            except Exception as e:
                logger.error(f"Failed to send piece request: {e}")
                return False

            begin += length

        return True

    def update_piece_rarity(self, have_bitfield):
        for i, has_piece in enumerate(have_bitfield):
            if has_piece:
                self.piece_rarity[i] += 1

    def select_piece_to_request(self):
        missing_pieces = [i for i, status in enumerate(self.piece_status) if status == 'missing']
        if missing_pieces:
            selected_piece = random.choice(missing_pieces)
            logger.debug(f"Selected piece to request: {selected_piece}")
            return selected_piece
        logger.debug("No missing pieces to request")
        return None
    
    def is_piece_complete(self, index):
            if index not in self.piece_data:
                return False
            piece_blocks = self.piece_data[index]
            expected_length = self.piece_length if index < self.total_pieces - 1 else (self.length % self.piece_length) or self.piece_length
            return sum(len(block) for block in piece_blocks.values()) == expected_length

    def handle_piece(self, data):
        try:
            index, begin = struct.unpack(">II", data[:8])
            block = data[8:]

            logger.debug(f"Received piece: index={index}, begin={begin}, length={len(block)}")

            if index not in self.piece_data:
                self.piece_data[index] = {}
            self.piece_data[index][begin] = block

            if self.is_piece_complete(index):
                self.downloaded_pieces.add(index)
                self.write_queue.put(index)
                logger.debug(f"Piece {index} complete, added to write queue")

            self.downloaded += len(block)

            logger.debug(f"Total downloaded: {self.downloaded}/{self.length} bytes")
            logger.debug(f"Downloaded pieces: {len(self.downloaded_pieces)}/{self.total_pieces}")

            if self.is_download_complete() and self.write_queue.empty():
                logger.info("Download and writing complete, starting verification")
                if self.verify_download():
                    logger.info("Download verified successfully")
                    self.signals.status_updated.emit(self.name, "Download complete and verified")
                else:
                    logger.warning("Download verification failed")
                    self.signals.status_updated.emit(self.name, "Download complete but verification failed")
            else:
                self.request_piece(self.sock)

        except Exception as e:
            logger.error(f"Error handling piece: {str(e)}")
            logger.exception("Stack trace:")

    def handle_message(self, sock, message):
        if not message:
            return

        msg_id = message[0]
        self.update_debug_log(f"Received message type: {msg_id}")
        logger.debug(f"Received message type: {msg_id}")

        try:
            if msg_id == 0:  # Choke
                self.update_debug_log("Peer choked us")
                logger.info("Peer choked us")
                self.choked = True
            elif msg_id == 1:  # Unchoke
                self.update_debug_log("Peer unchoked us, requesting piece")
                logger.info("Peer unchoked us, requesting piece")
                self.choked = False
                self.request_piece(sock)
            elif msg_id == 2:  # Interested
                self.update_debug_log("Peer is interested")
                logger.info("Peer is interested")
                self.send_unchoke(sock)
            elif msg_id == 3:  # Not Interested
                self.update_debug_log("Peer is not interested")
                logger.info("Peer is not interested")
                self.send_choke(sock)
            elif msg_id == 4:  # Have
                piece_index = struct.unpack(">I", message[1:5])[0]
                self.update_debug_log(f"Peer has piece: {piece_index}")
                self.update_piece_rarity([piece_index])
                if not self.have_piece(piece_index):
                    self.send_interested(sock)
            elif msg_id == 5:  # Bitfield
                bitfield = message[1:]
                self.update_debug_log("Received bitfield from peer")
                self.update_piece_rarity(bitfield)
                if any(not self.have_piece(i) for i in range(len(bitfield) * 8) if bitfield[i // 8] & (1 << (7 - (i % 8)))):
                    self.send_interested(sock)
            elif msg_id == 6:  # Request
                index, begin, length = struct.unpack(">III", message[1:13])
                self.update_debug_log(f"Received piece request: index={index}, begin={begin}, length={length}")
                logger.info("Received piece request")
                if self.have_piece(index):
                    self.send_piece(sock, index, begin, length)
                else:
                    logger.warning(f"Received request for piece {index} which we don't have")
            elif msg_id == 7:  # Piece
                index, begin = struct.unpack(">II", message[1:9])
                block = message[9:]
                self.update_debug_log(f"Received piece data: index={index}, begin={begin}, length={len(block)}")
                logger.info(f"Received piece data: index={index}, begin={begin}, length={len(block)}")
                self.handle_piece(message[1:])
                self.request_piece(sock)
            elif msg_id == 8:  # Cancel
                index, begin, length = struct.unpack(">III", message[1:13])
                self.update_debug_log(f"Received cancel request: index={index}, begin={begin}, length={length}")
                logger.info("Received cancel request")
            else:
                self.update_debug_log(f"Received unknown message type: {msg_id}")
                logger.warning(f"Received unknown message type: {msg_id}")
            if not self.choked:
                self.request_piece(sock)
        except Exception as e:
            self.update_debug_log(f"Error handling message: {str(e)}")
            logger.error(f"Error handling message: {str(e)}")

    def send_unchoke(self, sock):
        msg = struct.pack(">IB", 1, 1)
        self.send_message(sock, msg)
        logger.debug("Sent unchoke message")

    def send_choke(self, sock):
        msg = struct.pack(">IB", 1, 0)
        self.send_message(sock, msg)
        logger.debug("Sent choke message")
    
    def send_piece(self, sock, index, begin, length):
        piece_data = self.read_piece(index, begin, length)
        if piece_data:
            msg = struct.pack(">IBII", 9 + len(piece_data), 7, index, begin) + piece_data
            self.send_message(sock, msg)
            logger.debug(f"Sent piece: index={index}, begin={begin}, length={length}")
        else:
            logger.warning(f"Failed to read piece: index={index}, begin={begin}, length={length}")

    def read_piece(self, piece_index):
        piece_length = self.piece_length
        piece_offset = piece_index * piece_length
        piece_data = b''

        for file_path, file_length in self.files:
            if piece_offset >= file_length:
                piece_offset -= file_length
                continue

            read_length = min(piece_length - len(piece_data), file_length - piece_offset)
            full_path = os.path.join(self.folder_path, file_path)

            with open(full_path, 'rb') as f:
                f.seek(piece_offset)
                piece_data += f.read(read_length)

            piece_offset = 0

            if len(piece_data) == piece_length:
                break

        return piece_data
    
    def write_piece_to_files(self, index):
        if index in self.written_pieces:
            return

        piece_data = b''.join(self.piece_data[index].values())
        piece_offset = index * self.piece_length
        remaining = len(piece_data)
        data_offset = 0

        for file_path, file_length in self.files:
            if piece_offset >= file_length:
                piece_offset -= file_length
                continue

            write_length = min(remaining, file_length - piece_offset)
            full_path = os.path.join(self.folder_path, file_path)

            try:
                with open(full_path, 'r+b') as f:
                    f.seek(piece_offset)
                    f.write(piece_data[data_offset:data_offset + write_length])

                logger.debug(f"Wrote {write_length} bytes to file: {full_path}")

                piece_offset = (piece_offset + write_length) % file_length
                data_offset += write_length
                remaining -= write_length

                if remaining == 0:
                    break
            except IOError as e:
                logger.error(f"IOError writing to file {full_path}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error writing to file {full_path}: {str(e)}")
                logger.exception("Stack trace:")

        self.written_pieces.add(index)
        del self.piece_data[index]
        logger.debug(f"Piece {index} written to files")

        self.signals.progress_updated.emit(self.name, len(self.written_pieces), self.total_pieces, self.get_estimated_time())

        if self.is_download_complete() and len(self.written_pieces) == self.total_pieces:
            logger.info("All pieces written, stopping write thread")
            self.writing = False
  
    def stop_download(self):
        logger.info("Stopping download")
        self.running = False
        self.writing = False
        self.write_queue.join()
      
    def have_piece(self, piece_index):
          return piece_index in self.downloaded_pieces

    def verify_piece(self, piece_index, piece_data):
        start = piece_index * 20
        end = start + 20
        expected_hash = self.pieces[start:end]
        actual_hash = hashlib.sha1(piece_data).digest()
        if actual_hash == expected_hash:
            logger.debug(f"Piece {piece_index} verified successfully")
            return True
        else:
            logger.warning(f"Piece {piece_index} failed verification")
            return False
    
    def verify_file(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        file_hash = hashlib.sha1(file_data).hexdigest()
        expected_hash = self.torrent_info[b'info'][b'pieces'].hex()
        return file_hash == expected_hash
    
    def verify_download(self):
        if len(self.written_pieces) != self.total_pieces:
            logger.warning(f"Not all pieces written: {len(self.written_pieces)}/{self.total_pieces}")
            return False

        for i in range(self.total_pieces):
            piece_data = self.read_piece(i)
            if not self.verify_piece(i, piece_data):
                logger.warning(f"Piece {i} failed verification")
                return False
        return True
    
    def prioritize_files(self):
        if len(self.files) > 1:
            self.files.sort(key=lambda x: x[1])
            logger.info("Files prioritized by size (smallest to largest)")
            for i, (file_path, file_size) in enumerate(self.files):
                logger.info(f"Priority {i+1}: {file_path} ({self.format_size(file_size)})")
   
    def is_download_complete(self):
        complete = len(self.downloaded_pieces) == self.total_pieces
        logger.debug(f"Download complete check: {complete}")
        return complete
    
    def check_file_integrity(self):
        for file_path, file_length in self.files:
            full_path = os.path.join(self.folder_path, file_path)
            try:
                with open(full_path, 'rb') as f:
                    file_data = f.read()
                if len(file_data) != file_length:
                    logger.error(f"File size mismatch for {full_path}. Expected {file_length}, got {len(file_data)}")
                    return False
                logger.info(f"File integrity check passed for {full_path}")
            except IOError as e:
                logger.error(f"IOError checking file {full_path}: {str(e)}")
                return False
            except Exception as e:
                logger.error(f"Unexpected error checking file {full_path}: {str(e)}")
                logger.exception("Stack trace:")
                return False
        return True
    
    def update_download_speed(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_progress_update
        if elapsed_time > 0:
            downloaded_since_last = self.downloaded - (self.last_progress_update_downloaded if hasattr(self, 'last_progress_update_downloaded') else 0)
            self.download_speed = downloaded_since_last / elapsed_time
        self.last_progress_update = current_time
        self.last_progress_update_downloaded = self.downloaded

    def get_estimated_time(self):
        if self.download_speed > 0:
            remaining_bytes = self.length - self.downloaded
            remaining_seconds = remaining_bytes / self.download_speed
            return remaining_seconds
        return float('inf')

    def periodic_tracker_update(self):
        while self.running and not self.is_download_complete():
            self.connect_to_tracker()
            time.sleep(3000)
  
    def update_piece_availability(self, bitfield):
        for i in range(len(self.piece_status)):
            if bitfield[i // 8] & (1 << (7 - (i % 8))):
                if self.piece_status[i] == 'missing':
                    self.piece_status[i] = 'available'
        logger.debug(f"Updated piece availability. Available: {self.piece_status.count('available')}, Downloaded: {self.piece_status.count('downloaded')}, Missing: {self.piece_status.count('missing')}")

    def write_pieces_thread(self):
        while self.writing:
            try:
                index = self.write_queue.get(timeout=1)
                self.write_piece_to_files(index)
                self.write_queue.task_done()

                progress = (len(self.written_pieces) / self.total_pieces) * 100
                self.signals.progress_updated.emit(self.name, len(self.written_pieces), self.total_pieces, self.get_estimated_time())

                if self.is_download_complete() and len(self.written_pieces) == self.total_pieces:
                    logger.info("All pieces written, stopping write thread")
                    self.writing = False
                    break
            except queue.Empty:
                continue
        logger.info("Piece writing thread finished")

class TorrentClient:
    def __init__(self):
        self.torrents = {}

    def add_torrent(self, torrent_file):
        logger.info(f"Adding torrent: {torrent_file}")
        torrent = Torrent(torrent_file)
        torrent.status = "Added"
        self.torrents[torrent.name] = torrent
        logger.info(f"Torrent added: {torrent.name}")
        return torrent.name

    def start_torrent(self, name):
        if name in self.torrents:
            logger.info(f"Starting torrent: {name}")
            self.torrents[name].start_download()

    def stop_torrent(self, name):
        if name in self.torrents:
            logger.info(f"Stopping torrent: {name}")
            self.torrents[name].stop_download()

    def remove_torrent(self, name):
        if name in self.torrents:
            logger.info(f"Removing torrent: {name}")
            self.stop_torrent(name)
            del self.torrents[name]
            return True
        return False

    def get_torrent_status(self, name):
        if name in self.torrents:
            torrent = self.torrents[name]
            progress = (len(torrent.downloaded_pieces) / (len(torrent.pieces) // 20)) * 100
            return {
                'name': name,
                'progress': progress,
                'downloaded_pieces': len(torrent.downloaded_pieces),
                'total_pieces': len(torrent.pieces) // 20,
                'peers': len(torrent.peers),
                'active_peers': torrent.active_peer_count,
                'state': 'Downloading' if torrent.running else 'Stopped',
                'status': getattr(torrent, 'status', 'Initializing')
            }
        return None

class DownloadThread(QThread):
    progress_updated = pyqtSignal(str, float, int, int)
    status_updated = pyqtSignal(str, str)

    def __init__(self, torrent):
        super().__init__()
        self.torrent = torrent

    def run(self):
        self.torrent.start_download()
        while self.torrent.running:
            progress = (self.torrent.downloaded / self.torrent.length) * 100 if self.torrent.length > 0 else 0
            self.progress_updated.emit(self.torrent.name, progress, self.torrent.downloaded, self.torrent.length)
            time.sleep(1)
        if self.torrent.verify_download():
            logger.info("Download completed and verified successfully")
        else:
            logger.error("Download completed but failed verification")

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.client = TorrentClient()
        self.download_threads = {}
        self.client = TorrentClient()
        self.initUI()
        for torrent in self.client.torrents.values():
            torrent.signals.progress_updated.connect(self.update_torrent_progress)
            torrent.signals.status_updated.connect(self.update_torrent_status)

    def initUI(self):
        self.setWindowTitle('tClient')
        self.setGeometry(100, 100, 1150, 600)

        font = QFont("Segoe UI", 10)
        QApplication.setFont(font)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        central_widget.setStyleSheet("background-color: #f0f0f0;")

        controls_layout = QHBoxLayout()
        self.torrent_input = QLineEdit()
        self.torrent_input.setPlaceholderText('Select .torrent file')
        self.torrent_input.setStyleSheet("padding: 5px; border: 1px solid #ccc; border-radius: 3px;")
        controls_layout.addWidget(self.torrent_input)

        icon_size = QSize(16, 16)

        add_button = QPushButton('Add Torrent')
        add_button.setIcon(QIcon('icons/add_icon.png'))
        add_button.setIconSize(icon_size)
        add_button.clicked.connect(self.add_torrent)
        add_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 10px; border: none; border-radius: 3px;")
        controls_layout.addWidget(add_button)

        select_file_button = QPushButton('Select File')
        select_file_button.setIcon(QIcon('icons/file_icon.png'))
        select_file_button.setIconSize(icon_size)
        select_file_button.clicked.connect(self.select_torrent_file)
        select_file_button.setStyleSheet("background-color: #2196F3; color: white; padding: 5px 10px; border: none; border-radius: 3px;")
        controls_layout.addWidget(select_file_button)

        layout.addLayout(controls_layout)

        button_layout = QHBoxLayout()

        start_button = QPushButton('Start')
        start_button.setIcon(QIcon('icons/play_icon.png'))
        start_button.setIconSize(icon_size)
        start_button.clicked.connect(self.start_selected_torrent)
        start_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 10px; border: none; border-radius: 3px;")
        button_layout.addWidget(start_button)

        stop_button = QPushButton('Stop')
        stop_button.setIcon(QIcon('icons/pause_icon.png'))
        stop_button.setIconSize(icon_size)
        stop_button.clicked.connect(self.stop_selected_torrent)
        stop_button.setStyleSheet("background-color: #FFC107; color: white; padding: 5px 10px; border: none; border-radius: 3px;")
        button_layout.addWidget(stop_button)

        remove_button = QPushButton('Remove')
        remove_button.setIcon(QIcon('icons/delete_icon.png'))
        remove_button.setIconSize(icon_size)
        remove_button.clicked.connect(self.remove_selected_torrent)
        remove_button.setStyleSheet("background-color: #F44336; color: white; padding: 5px 10px; border: none; border-radius: 3px;")
        button_layout.addWidget(remove_button)

        layout.addLayout(button_layout)

        self.torrent_table = QTableWidget()
        self.torrent_table.setColumnCount(6)
        self.torrent_table.setHorizontalHeaderLabels(['Name', 'Progress', 'Pieces', 'Status', 'Peers', 'Active Peers'])
        self.torrent_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.torrent_table.setSelectionMode(QTableWidget.SingleSelection)

        header = self.torrent_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)

        self.torrent_table.setAlternatingRowColors(True)
        self.torrent_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d3d3d3;
                background-color: white;
                alternate-background-color: #f9f9f9;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                padding: 5px;
                border: 1px solid #d3d3d3;
                font-weight: bold;
            }
        """)

        self.torrent_table.setColumnWidth(0, 200)
        self.torrent_table.setColumnWidth(1, 200)
        self.torrent_table.setColumnWidth(2, 100)
        self.torrent_table.setColumnWidth(3, 350)
        self.torrent_table.setColumnWidth(4, 100)
        self.torrent_table.setColumnWidth(5, 100)

        layout.addWidget(self.torrent_table)

        self.update_thread = UpdateThread(5)
        self.update_thread.update_signal.connect(self.update_torrents)
        self.update_thread.start()

        self.statusBar().showMessage('Ready')
        self.statusBar().setStyleSheet("background-color: #e0e0e0; padding: 5px;")

    def add_torrent(self):
        torrent_file = self.torrent_input.text()
        if torrent_file:
            if torrent_file.startswith('magnet:'):
                name = self.client.add_torrent(torrent_file)
            elif os.path.isfile(torrent_file):
                name = self.client.add_torrent(torrent_file)
            else:
                logger.warning(f"Invalid torrent file or magnet link: {torrent_file}")
                return

            torrent = self.client.torrents[name]
            torrent.signals.progress_updated.connect(self.update_torrent_progress)
            
            row = self.torrent_table.rowCount()
            self.torrent_table.insertRow(row)
            self.torrent_table.setItem(row, 0, QTableWidgetItem(name))
            
            progress_bar = QProgressBar()
            self.torrent_table.setCellWidget(row, 1, progress_bar)
            
            self.torrent_table.setItem(row, 2, QTableWidgetItem("0 B/0 B"))
            self.torrent_table.setItem(row, 3, QTableWidgetItem(self.format_size(self.client.torrents[name].length)))
            self.torrent_table.setItem(row, 4, QTableWidgetItem("Added"))
            self.torrent_table.setItem(row, 5, QTableWidgetItem("0"))
            self.torrent_table.setItem(row, 6, QTableWidgetItem("0"))
            
            logger.info(f"Added torrent: {name}")
        self.torrent_input.clear()

    def update_torrent_peer_count(self, name, count):
            for row in range(self.torrent_table.rowCount()):
                if self.torrent_table.item(row, 0).text() == name:
                    self.torrent_table.setItem(row, 6, QTableWidgetItem(str(count)))
                    self.torrent_table.viewport().update()
                    break

    def select_torrent_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Torrent File", "", "Torrent Files (*.torrent)")
        if file_name:
            logger.info(f"Selected torrent file: {file_name}")
            self.torrent_input.setText(file_name)

    def update_torrents(self):
        logger.debug("Updating torrent list")
        self.torrent_table.setRowCount(len(self.client.torrents))
        for row, name in enumerate(self.client.torrents):
                status = self.client.get_torrent_status(name)
                if status:
                    self.torrent_table.setItem(row, 0, QTableWidgetItem(status['name']))
                    progress_bar = QProgressBar()
                    progress_bar.setValue(int(status['progress']))
                    self.torrent_table.setCellWidget(row, 1, progress_bar)
                    self.torrent_table.setItem(row, 2, QTableWidgetItem(f"{status['downloaded_pieces']}/{status['total_pieces']}"))
                    self.torrent_table.setItem(row, 3, QTableWidgetItem(f"{status['state']} - {status['status']}"))
                    self.torrent_table.setItem(row, 4, QTableWidgetItem(str(status['peers'])))
                    self.torrent_table.setItem(row, 5, QTableWidgetItem(str(status['active_peers'])))
        logger.debug("Torrent list updated")

    def start_selected_torrent(self):
        selected_items = self.torrent_table.selectedItems()
        if selected_items:
            name = selected_items[0].text()
            if name not in self.download_threads:
                torrent = self.client.torrents[name]
                thread = DownloadThread(torrent)
                progress_thread = ProgressUpdateThread(torrent)
                progress_thread.update_signal.connect(self.update_torrent_progress)
                self.download_threads[name] = (thread, progress_thread)
                thread.start()
                progress_thread.start()
                logger.info(f"Started download and progress threads for torrent: {name}")
    
    def update_torrent_progress(self, name, downloaded_pieces, total_pieces, estimated_time):
        for row in range(self.torrent_table.rowCount()):
            if self.torrent_table.item(row, 0).text() == name:
                progress = (downloaded_pieces / total_pieces) * 100 if total_pieces > 0 else 0
                progress_bar = self.torrent_table.cellWidget(row, 1)
                progress_bar.setValue(int(progress))

                self.torrent_table.setItem(row, 2, QTableWidgetItem(f"{downloaded_pieces} / {total_pieces}"))

                status = f"Downloading - {progress:.2f}%"
                self.torrent_table.setItem(row, 3, QTableWidgetItem(status))

                estimated_time_str = f"ETA: {self.format_time(estimated_time)}" if estimated_time != float('inf') else "ETA: Unknown"
                self.torrent_table.setItem(row, 4, QTableWidgetItem(estimated_time_str))

                self.torrent_table.viewport().update()
                logger.debug(f"Updated UI for torrent {name}: pieces={downloaded_pieces}/{total_pieces}, ETA={estimated_time_str}")
                break
    
    def update_torrent_status(self, name, status):
        for row in range(self.torrent_table.rowCount()):
            if self.torrent_table.item(row, 0).text() == name:
                self.torrent_table.setItem(row, 5, QTableWidgetItem(status))
                self.torrent_table.viewport().update()
                logger.debug(f"Updated status for torrent {name}: {status}")
                break

        if "Download complete" in status:
            QMessageBox.information(self, "Download Complete", f"Torrent '{name}' has finished downloading.")
    
    def format_size(self, size):
        size_mb = size / (1024 * 1024)
        return f"{size_mb:.2f} MB"

    def stop_selected_torrent(self):
        selected_items = self.torrent_table.selectedItems()
        if selected_items:
            name = selected_items[0].text()
            self.client.stop_torrent(name)

            if name in self.download_threads:
                thread, progress_thread = self.download_threads[name]
                thread.quit()
                progress_thread.quit()
                thread.wait()
                progress_thread.wait()
                del self.download_threads[name]

            for row in range(self.torrent_table.rowCount()):
                if self.torrent_table.item(row, 0).text() == name:
                    self.torrent_table.removeRow(row)
                    break

            logger.info(f"Stopped and removed torrent: {name}")

    def remove_selected_torrent(self):
        selected_items = self.torrent_table.selectedItems()
        if selected_items:
            name = selected_items[0].text()
            self.stop_selected_torrent()
            if self.client.remove_torrent(name):
                for row in range(self.torrent_table.rowCount()):
                    if self.torrent_table.item(row, 0).text() == name:
                        self.torrent_table.removeRow(row)
                        break
            logger.info(f"Removed torrent: {name}")
    
    def format_time(self, seconds):
        if seconds < 60:
            return f"{seconds:.0f} sec"
        elif seconds < 3600:
            return f"{seconds/60:.1f} min"
        else:
            return f"{seconds/3600:.1f} hours"

class RateLimiter:
    def __init__(self, rate_limit):
        self.rate_limit = rate_limit  # bytes per second
        self.last_check = time.time()
        self.data_sent = 0

    def limit(self, data_size):
        current_time = time.time()
        time_passed = current_time - self.last_check
        self.data_sent += data_size

        if self.data_sent > self.rate_limit * time_passed:
            sleep_time = self.data_sent / self.rate_limit - time_passed
            time.sleep(max(0, sleep_time))
            self.last_check = time.time()
            self.data_sent = 0
        elif time_passed > 1:
            self.last_check = current_time
            self.data_sent = 0

class UpdateThread(QThread):
    update_signal = pyqtSignal()

    def __init__(self, interval):
        super().__init__()
        self.interval = interval

    def run(self):
        while True:
            time.sleep(self.interval)
            self.update_signal.emit()

class ProgressUpdateThread(QThread):
    update_signal = pyqtSignal(str, int, int, float)

    def __init__(self, torrent):
        super().__init__()
        self.torrent = torrent

    def run(self):
        while self.torrent.running:
            downloaded_pieces = len(self.torrent.downloaded_pieces)
            total_pieces = len(self.torrent.pieces) // 20
            self.torrent.update_download_speed()
            estimated_time = self.torrent.get_estimated_time()
            self.update_signal.emit(self.torrent.name, downloaded_pieces, total_pieces, estimated_time)
            time.sleep(1)

def main():
    logger.info("Starting application")
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    QTimer.singleShot(0, main_window.update_torrents)
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()