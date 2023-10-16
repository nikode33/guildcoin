try:
    from simplecoin import *
    import redis, hashlib, threading, socket, json, sys, platform
except ModuleNotFoundError as e:
    module = str(e).split("'")[1]
    if module != "redis" and module != "simplecoin":
        print(f"\033[31;1m[ERROR]\033[0m You don't currently have {module} installed on your system. Install it with 'pip3 install {module}'.")
    elif module == "simplecoin":
        print("\033[31;1m[HOW?]\033[0m You were supposed to 'git clone' the whole thing, buddy.")
    else:
        print(f"\033[31;1m[ERROR]\033[0m You don't have redis installed. There's two possibilities here.\nA) You don't have redis installed, in which case, all I can say is \033[3;4;1mGood luck.\033[0m\nB) Or you don't have redis-py installed. That's easy, just do 'pip3 install redis'.\nIf you don't know whether or not you have redis installed, just run 'redis-server'.")
    exit()


r = redis.Redis()
pool = []
rates = {}
keys = [generate_keys() for i in range(20)]
ctid = make_coinbase_tx(keys[0][1].to_string().hex(), 50000, 0, "Hello World!")
r.mset({hashlib.sha256(to_bytes(ctid)).hexdigest(): str(get_tx_info(ctid))})
print("\033[33m[DEBUG] Private Key: \033[0m " + keys[0][0].to_string().hex())
print("\033[33m[DEBUG] Coinbase TxID: \033[0m " + hashlib.sha256(to_bytes(ctid)).hexdigest())
utx0 = []
with open('assets/utx0.json', 'r') as f:
    utx0 = json.load(f)['utx0']

def removeutx0(txid, vout):
    try:
        utx0.remove([txid, vout])
    except:
        pass
    with open('assets/utx0.json', 'w') as f:
        json.dump({"utx0": utx0}, f)

def addutx0(txid, vout):
    utx0.append([txid, vout])
    with open('assets/utx0.json', 'w') as f:
        json.dump({"utx0": utx0}, f)
def flushutx0():
    open('assets/utx0.json', 'w').close()
    with open('assets/utx0.json', 'w') as f:
        f.write('{"utx0": []}')

flushutx0()
addutx0(hashlib.sha256(to_bytes(ctid)).hexdigest(), "00")
def handle_client(client_socket, addr):
    try:
        response = ""
        request = client_socket.recv(4096)
        print(f"\033[32m[SERVER]\033[0m Received: {request}")

        # Commands
        if request[0:11].decode('utf-8') == "get_tx_json": # Get json-formatted tx data
            client_socket.send(r.get(request[11:].decode('utf-8')))
        elif request[0:8].decode('utf-8') == "write_tx": # Write transaction to database
            try:
                tx_info = get_tx_info(to_hex(request[8:]))
                svalue = 0
                input_txs = []
                pks = []
                for i in range(tx_info['incount']):
                    if not (tx_info['inputs'][i][0].encode('utf-8') in r.keys()):
                        response = f"Error 3: TxID in input {i} does not exist."
                        break
                    else:
                        input_tx = json.loads(r.get(tx_info['inputs'][i][0]).decode('utf-8').replace("'", '"'))
                        input_txs.append(tx_info['inputs'][i][0])

                    if int(tx_info['inputs'][i][1], 16) > (input_tx['outcount']-1):
                        response = f"Error 4: Output does not exist in input {i}"
                        break
                    else:
                        pks = []
                        for i in range(input_tx['outcount']):
                            pks.append(pubkeygen(input_tx['outputs'][i][1]))
                            svalue += int(reverse_byte(input_tx['outputs'][i][0]), 16)

                    try:
                        if pks[i].verify(to_bytes(tx_info['inputs'][i][2]), json_to_binary(input_tx)):
                            response = "Accepted tx."
                    except ecdsa.BadSignatureError:
                        response = "Error 7: Bad signature."
                        break

                if response == "Accepted tx.":
                    ovalue = 0
                    for i in range(tx_info['outcount']):
                        ovalue += int(reverse_byte(tx_info['outputs'][i][0]), 16)

                    for i in range(tx_info['outcount']):
                        if svalue >= ovalue:
                            response = f"Accepted transaction. Fee: {svalue-ovalue}"

                        if svalue < ovalue:
                            response = f"Error 6: Input value exceeds output {i}'s value."
                            break
                        
                        if not ([input_txs[i], to_hex(i.to_bytes(1, 'big'))] in utx0):
                            response = "Error 5: Already spent"
                            break

                        addutx0(hashlib.sha256(request[8:]).hexdigest(), to_hex(i.to_bytes(1, 'big')))
                        removeutx0(input_txs[i], to_hex(i.to_bytes(1, 'big')))
                if "Accepted transaction." in response:
                    r.mset({hashlib.sha256(request[8:]).hexdigest(): str(tx_info)})
                    pool.append(tx_info)
            except Exception as error:
                response = f"Error 2: Invaild formatting. {error}"

        elif request.decode('utf-8')[0:10] == "get_raw_tx": # Get raw tx binary data
            decode = request[10:].decode('utf-8')
            try:
                tx_decoded = json.loads(r.get(decode).decode('utf-8').replace("'", "\""))
                client_socket.send(bytes(json_to_binary(tx_decoded)))
            except:
                response = "Error 3: TxID does not exist." 

        elif request.decode('utf-8')[0:9] == "get_block": # Get a certain block by depth or ID
            pass
        elif request.decode('utf-8')[0:9] == "get_tx_pk": # Get all transactions with a certain public key
            pass
        elif request.decode('utf-8')[0:12] == "write_block": # Write block to disk (for nodes)
            pass
        else:
            response = "Error 1: Invalid header."
        
        client_socket.send(response.encode("utf-8"))
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0m Error when hanlding client: {e}. Passed.")
    finally:
        client_socket.close()
        print(f"\033[32m[SERVER]\033[0m Connection to client ({addr[0]}:{addr[1]}) closed", end="\n\n")


def run_server():
    server_ip = "192.168.0.127"  # server hostname or IP address
    port = 8000  # server port number
    if len(sys.argv) == 1:
        print("\033[31;1m[ERROR] No IP was passed. Next time, type: python3 transserver.py <ip> <port>\033[0m")
        exit() 
    if len(sys.argv) == 2:
        print("\033[33m[WARNING]\033[0m No port was passed. That's ok, it doesn't matter. Using default port 8000 (TCP), and 6379 (Redis).")
        server_ip = sys.argv[1]

    if len(sys.argv) == 3:
        server_ip = sys.argv[1]
        port = int(sys.argv[2])

    if int(platform.python_version_tuple()[1]) < 11 and int(platform.python_version_tuple()[0]) == 3:
        print(f"\033[33;1m[WARNING]\033[0m You're running this on Python 3.{platform.python_version_tuple()[1]}. Python 3.11 is highly recommended.")

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((server_ip, port))
        server.listen()
        print(f"\033[36m[INFO]\033[0m Listening on {server_ip}:{port}")
        tm = time.time()
        while True:
            client_socket, addr = server.accept()

            if time.time() - tm > 60:
                for key in rates.keys():
                    rates[key] = 0
                tm = time.time()
                time.sleep(2)
                print("\033[36;1m[INFO]\033[0m Rate limits have been reset.")

            if not (addr[0] in rates.keys()):
                rates[addr[0]] = 1
                thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
                thread.start()
            elif rates[addr[0]] < 100:
                print(f"\033[32m[SERVER]\033[0m Accepted connection from {addr[0]}:{addr[1]}")
                rates[addr[0]] += 1
                thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
                thread.start()
            else:
                client_socket.send(b"Error 8: Too many requests per min")
                client_socket.close()
                rates[addr[0]] += 1
                print(f"\033[32m[SERVER]\033[0m {addr[0]} is overpinging. They have sent {rates[addr[0]]} requests in the last minute.")
    except KeyboardInterrupt:
        print('\n\n')
        print("\033[36m[INFO]\033[0m Received Ctrl-C. Stopping TCP server...")
        time.sleep(2) # No, this isn't useless! It's to provide a delay for the ports to shut down, just in case.
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0m Error: {e}. Passed.")
    finally:
        server.close()
        print("\033[36m[INFO]\033[0m Stopped TCP server.. exiting.")
        print("\033[33;1m[WARNING] redis-server is still running. Stop it with 'sudo systemctl stop redis-server'.\033[0m")


run_server()
