from flask import Flask, request, Response
import bencodepy

app = Flask(__name__)

peers = {}

@app.route('/announce', methods=['GET'])
def announce():
    info_hash = request.args.get('info_hash')
    peer_id = request.args.get('peer_id')
    ip = request.remote_addr
    port = request.args.get('port')

    if info_hash not in peers:
        peers[info_hash] = {}
    peers[info_hash][peer_id] = (ip, port)

    response = {
        'interval': 3,
        'peers': [f"{ip}:{port}".encode() for ip, port in peers[info_hash].values()]
    }

    return Response(bencodepy.encode(response), mimetype='text/plain')

if __name__ == '__main__':
    app.run(port=8000)