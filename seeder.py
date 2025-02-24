import bencodepy
import hashlib
import requests
import time
from urllib.parse import urlencode

def create_torrent_file(file_path, tracker_url):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    info = {
        b'length': len(file_data),
        b'name': file_path.encode(),
        b'piece length': 16384,
        b'pieces': b''.join([hashlib.sha1(file_data[i:i+16384]).digest() for i in range(0, len(file_data), 16384)])
    }
    
    torrent = {
        b'announce': tracker_url.encode(),
        b'info': info
    }
    
    with open(f"{file_path}.torrent", 'wb') as f:
        f.write(bencodepy.encode(torrent))
    
    return hashlib.sha1(bencodepy.encode(info)).digest()

def seed_file(file_path, tracker_url):
    info_hash = create_torrent_file(file_path, tracker_url)
    peer_id = b'-PY0001-' + bytes([0]*12)
    
    while True:
        params = {
            'info_hash': info_hash,
            'peer_id': peer_id,
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': 0,
            'event': 'started'
        }
        
        try:
            response = requests.get(f"{tracker_url}?{urlencode(params)}")
            print(f"Tracker response: {response.content}")
        except Exception as e:
            print(f"Error connecting to tracker: {e}")
        
        time.sleep(30)

if __name__ == "__main__":
    file_path = "folder/testfile.txt"
    tracker_url = "http://localhost:8000/announce"
    seed_file(file_path, tracker_url)