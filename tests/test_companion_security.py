import http.client
import socket
import threading
import time

from rsat.interfaces import serve_api


def test_companion_requires_exact_host_origin_bearer_and_contract():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    token = "a" * 40
    origin = "https://workspace.example.org"
    called = []

    def callback(name, data):
        called.append((name, data))
        return {"read_only": True}

    thread = threading.Thread(target=serve_api, args=(callback, token, port, 3, origin))
    thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.01)

    def post(headers, body='{"name":"findings","arguments":{}}'):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("POST", "/capability", body, headers)
        response = connection.getresponse()
        status = response.status
        response.read()
        connection.close()
        return status

    base = {
        "Host": f"127.0.0.1:{port}",
        "Origin": origin,
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }
    assert post(base) == 200
    assert post({**base, "Host": "attacker.example"}) == 403
    assert post({**base, "Origin": "https://attacker.example"}) == 403
    assert post({**base, "Authorization": "Bearer wrong"}) == 403
    assert post(base, '{"command":"evil"}') == 400
    assert post({**base, "Content-Type": "text/plain"}) == 400
    assert len(called) == 1
    thread.join(5)
    assert not thread.is_alive()
