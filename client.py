import socket, simplecoin, ecdsa, time

HOST = "192.168.0.127"  # The server's hostname or IP address
PORT = 8000  # The port used by the server
rpk = []
for i in range(2000):
    sk, vk = simplecoin.generate_keys()
    rpk.append((sk, vk))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    txid = "2edb9ef779e0fa1b0d496addebfdbd3b6dfa588ef584ba33e36f0f1926fb9654"
    ssk = "45a267f0968f016a01ab8561f8ff374454e7683dd6bb903e25dcadcdea10d56d"
    s.sendall(('get_raw_tx' + txid).encode('utf-8'))
    tid = s.recv(1024)
    print(tid)
    sign = (ecdsa.SigningKey.from_string(bytearray.fromhex(ssk), curve=ecdsa.SECP256k1)).sign(tid)
    print(sign)

for i in range(2000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        trans = simplecoin.make_tx([simplecoin.to_hex(bytes(tid))],
                                [0],
                                [simplecoin.to_hex(sign)],
                                [3000],
                                [rpk[i][1].to_string().hex()])

        tid = simplecoin.to_bytes(trans)
        sign = rpk[i][0].sign(tid)
        s.sendall(("write_tx").encode("utf-8") + simplecoin.to_bytes(trans))
        try:
            data = s.recv(1024)
        except:
            for i in range(20):
                print(f"\033[31m[ERROR]\033[0m Node is down.. attempting to restablish in {20-i}s")
                time.sleep(1)
        print(f"\033[32m[DEBUG]\033[0m Sent transaction data: {trans}")
        if "Accepted transaction" in data.decode('utf-8'):
            print(f"\033[32;1m[TX ACCEPTED]\033[0mFee: {int(data.decode('utf-8').split(':')[1])/1000000} GDC")
        else:
            print(f"\033[31;1m[TX REJECTED]\033[0m Node error: {data.decode('utf-8')}", end="\n\n")
    time.sleep(0.1)
print(f"\033[36m[INFO]\033[0m TCP socket closed.")
