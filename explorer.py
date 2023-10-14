import simplecoin, random, hashlib, os, getkey

sk, vk = simplecoin.generate_keys()
mp = [simplecoin.make_coinbase_tx(vk.to_string().hex(), 5000, 0, "Hello World!")]
mp.append(simplecoin.make_tx([mp[0]], [0], [simplecoin.to_hex(sk.sign(simplecoin.to_bytes(mp[0])))], [random.randint(0, 10000) for i in range(10)], [vk.to_string().hex() for i in range(10)]))
for i in range(2251):
    mp.append(simplecoin.make_tx([mp[i-1]], [0], [simplecoin.to_hex(sk.sign(simplecoin.to_bytes(mp[i-1])))], [random.randint(0, 10000)], [vk.to_string().hex()])) 

cursor = 0
m = hashlib.new('sha256')
while True:
    for i in range(cursor, cursor+20):
        print(hashlib.sha256(simplecoin.to_bytes(mp[i])).hexdigest())
    key = getkey.getkey()
    if key == getkey.keys.DOWN:
        cursor -= 1
    if key == getkey.keys.UP:
        cursor += 1
    if key == getkey.keys.ENTER:
        os.system('clear')
        a = simplecoin.get_tx_info(mp[cursor])
        print(f"TxID: {hashlib.sha256(simplecoin.to_bytes(mp[i])).hexdigest()}\n\n")
        print(f"There are {a['incount']} inputs: ")
        for c in a['inputs']:
            print(f"TxID: {c[0]}")
            print(f"Output Select: {c[1]}")
            print(f"Unlocking Signature: {c[2]}")

        print("\n\n")
        print(f"There are {a['outcount']} outputs: ")
        for c in a['outputs']:
            print(f"Value: {int(simplecoin.reverse_byte(c[0]), 16)} satoshis.")
            print(f"Reciever Public Key: {c[1]}\n")

        input()
    if key == getkey.keys.ESC:
        exit()
    os.system('clear')
