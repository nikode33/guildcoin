import time, ecdsa, hashlib, random
'''
TX FORMAT:
VERSION IN_COUNT [TXID VOUT SIGNATURE] OUT_COUNT [VALUE RPK] LOCKTIME
   4       1       32    1      64         1        8    64      4
'''
def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return sk, vk
def to_hex(a):
    return bytes.hex(a)

def to_bytes(a):
    return bytearray.fromhex(a)

def make_tx(tid, vout, sign, value, rpk, locktime="00000000"):
    version = "10000000"
    intx = ""
    outx = ""
    for i in range(len(tid)):
        txid = hashlib.sha256(to_bytes(tid[i])).hexdigest()
        vk = ecdsa.VerifyingKey.from_string(to_bytes(get_tx_info(tid[i])['outputs'][vout[i]][1]), curve=ecdsa.SECP256k1)
        outx = ""
        try:
            vk.verify(to_bytes(sign[i]), to_bytes(tid[i]))
            for j in range(len(value)):
                outx += to_hex(value[j].to_bytes(8, 'little')) + rpk[j]
            intx += txid + to_hex(vout[i].to_bytes(1, 'little')) + sign[i]
        except ecdsa.BadSignatureError:
            return 1
    return version + to_hex(len(tid).to_bytes(1, 'big')) + intx + to_hex(len(value).to_bytes(1, 'big')) + outx + locktime

def make_coinbase_tx(rpk, value, depth, message, locktime="00000000"):
    depth = to_hex(depth.to_bytes(4, 'big'))
    message = to_hex(message.encode('utf-8')) + "0"*(120-len(to_hex(message.encode('utf-8'))))
    return "10000000010000000000000000000000000000000000000000000000000000000000000000ff" + depth + message + "01" + bytes.hex(value.to_bytes(8, 'little')) + rpk + locktime

def get_tx_info(trans):
    incount = int(trans[8:10], 16)
    outcount = int(trans[(incount*194)+10:(incount*194)+12], 16)
    ins = []
    for i in range(incount):
        s = []
        intx = trans[10+(i*194):10+(194*(i+1))]
        s.append(intx[0:64])
        s.append(intx[64:66])
        s.append(intx[66:194])
        ins.append(s)
    
    ous = []
    for i in range(outcount):
        s = []
        outx = trans[(144*i)+12+(194*(incount)):(144*(i+1))+12+(194*(incount))]
        s.append(outx[0:16])
        s.append(outx[16:144])
        ous.append(s)

    return {"version": trans[0:8], "incount": incount, "inputs": ins, "outcount": outcount, "outputs": ous, "locktime": trans[-8:]}

def get_merkle_root(tids):
    r = []
    while 1:
        if len(tids) % 2 == 1:
            tids.append(tids[-1])
        for i in range(0, len(tids), 2):
            r.append(hashlib.sha256(bytearray.fromhex(tids[i] + tids[i-1])).hexdigest())
        tids = r
        r = []
        if len(tids) == 1:
            return tids[0]

def reverse_byte(s):
    return "".join(map(str.__add__, s[-2::-2] ,s[-1::-2]))

def generate_header(block, pbh, target, nonce):
    for i in range(1, len(target)):
        if target[-i:] != "0"*i:
            ex = i-1
            break
    bits = bytes.hex(ex.to_bytes(1, 'big')) + target[(64-ex)-6:(64-ex)]
    return "10000000" + pbh + get_merkle_root(block) + to_hex(int(time.time()).to_bytes(4, 'big')) + bits + to_hex(nonce.to_bytes(4, 'big'))

def chop_block():
    pass

if __name__ == "__main__":
    sk, vk = generate_keys()
    mp = [make_coinbase_tx(vk.to_string().hex(), 5000, 0, "Hello World!")]
    mp.append(make_tx([mp[0]], [0], [to_hex(sk.sign(to_bytes(mp[0])))], [random.randint(0, 10000) for i in range(10)], [vk.to_string().hex() for i in range(10)]))
    for i in range(2251):
        mp.append(make_tx([mp[i-1]], [0], [to_hex(sk.sign(to_bytes(mp[i-1])))], [random.randint(0, 10000) for i in range(10)], [vk.to_string().hex() for i in range(10)]))

    m = hashlib.sha256()
    m.update(to_bytes(random.choice(mp)))
    t = m.hexdigest()
    print(generate_header(mp, m.hexdigest(), "000000000000000000050f7b0000000000000000000000000000000000000000", 0))
    for i in range(2251):
        m = hashlib.sha256()
        m.update(to_bytes(mp[i]))
        if m.hexdigest() == t:
            print(f"Found! TxID #{i}: \033[34m{m.hexdigest()}\033[0m")

    print("Writing to file..")
    with open("block.bin", "wb") as file:
        file.write(to_bytes("".join(mp)))


