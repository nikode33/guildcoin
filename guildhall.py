import time, ecdsa, hashlib, random
def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return sk, vk

def generate_tx_old(sk, vk, incount=1, outcount=1, transdata = None, coinbase = False, depth=0, message="coinbase"): # Create function for multiple inputs and outputs
    for i in range(outcount):
        lock = vk.to_string()
    for i in range(incount):
        if transdata == None:
            unlock = sk.sign(vk.to_string())
        else:
            unlock = sk.sign(transdata)

    intx = ""
    outx = ""
    for i in range(incount):
        if coinbase == False:
            intx += bytes.hex(random.randint(0, 2**256).to_bytes(32, 'little')) + bytes.hex(random.randint(0, 20).to_bytes(4, 'little')) + unlock.hex()
        if coinbase == True:
            incount = 1
            outcount = 1
            add = bytes.hex(depth.to_bytes(4, 'little')) + bytes.hex(message.encode('utf-8'))
            add += "0"*(128 - len(add))
            intx = bytes.hex((0).to_bytes(32, 'little')) + "ffffffff" + add
    for i in range(outcount):
        outx += lock.hex() + bytes.hex(random.randint(0, 10000000).to_bytes(8, 'little'))
    version = (0).to_bytes(4, 'little')
    incount = incount.to_bytes(1, 'little')
    outcount = outcount.to_bytes(1, 'little')
    trans = bytes.hex(version) + bytes.hex(incount) + intx + bytes.hex(outcount) + outx + bytes.hex(int(time.time()).to_bytes(4, 'little'))
    return trans
def make_tx(txd, vout, signature, rpk, value, locktime="00000000"):
    '''
    Make transaction with:
    TXD - Transaction data to source coins from 
    Vout - Output of that transaction that the sender owns
    Signature - Verify sender owns that output by verifying this signature with the output's (therefore sender's) public key (sk.sign(original_txd))
    RPK - Receiver's public key, to lock the output.
    Value - Amount of bitcoins transferred.
    All arguments have to be iterables and a string (hex strings), so that multiple inputs can be sourced from and/or multiple outputs can be given to.
    '''
    for i in range(0, len(txd)):
        original_txd = bytearray.fromhex(txd[i])
        txdi = get_tx_info(txd[i])
        vk = ecdsa.VerifyingKey.from_string(bytearray.fromhex(txdi['out'][vout[i]]['pk']), curve=ecdsa.SECP256k1)
        intx = ""
        outx = ""
        for j in range(len(value)):
            try:
                vk.verify(bytearray.fromhex(signature[i]), original_txd)
                m = hashlib.sha256()
                m.update(txd)
                intx += m.hexdigest() + bytes.hex(vout[i]) + bytes.hex(signature[i]) # Signature that unlocks the input
                outx += rpk[j] + value[j]
            except BadSignatureError:
                return 1

    version = (1).to_bytes(4, 'little')
    incount = len(txd).to_bytes(1, 'little')
    outcount = len(value).to_bytes(1, 'little')
    trans = bytes.hex(version) + bytes.hex(incount) + intx + bytes.hex(outcount) + outx + locktime
    return trans

def make_coinbase_tx(pk, value, depth, message="coinbase", locktime="00000000"): # Make coinbase transaction
    start = "10000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
    depth = bytes.hex(depth.to_bytes(4, 'big'))
    message = bytes.hex(message.encode('utf-8')) + "0"*(120-len(bytes.hex(message.encode('utf-8'))))
    return start + depth + message + "01" + bytes.hex(value.to_bytes(8, 'little')) + pk.to_string().hex() + locktime
def get_merkle_root(tids):
    r = []
    while 1:
        m = hashlib.sha256()
        if len(tids) % 2 == 1:
            tids.append(tids[-1])
        for i in range(0, len(tids), 2):
            m.update(bytearray.fromhex(tids[i] + tids[i-1]))
            r.append(m.hexdigest())
        tids = r
        r = []
        if len(tids) == 1:
            return tids[0]
def reverse_byte(s):
    return "".join(map(str.__add__, s[-2::-2] ,s[-1::-2]))

def get_tx_info(trans):
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(trans))
    txid = sha.hexdigest()
    version = trans[0:8]
    incount = trans[8:10]
    locktime = trans[-8:]
    inend = (200*int(incount, 16)) + 10
    outcount = int(trans[inend:inend+2], 16)
    intx = []
    outx = []
    for i in range(inend+2, (outcount*144)+2+inend, 144):
        s = []
        a = trans[i:i+144]
        s.append(a[:128])
        s.append(int(reverse_byte(a[128:]), 16))
        outx.append(s)
    for i in range(10, 200*int(incount, 16), 200):
        t = []
        a = trans[i:i+200]
        t.append(reverse_byte(a[0:64]))
        t.append(int(reverse_byte(a[64:72]), 16))
        t.append(a[72:])
        intx.append(t)
    
    # intx = [txid, out_select, signature]
    # outx = [public_key, value]
    # output: {"version": version, "in_count": incount, "out_count": outcount, "in": [{"txid": txid, "out_select": outselect, "
    output = {"version": version, "in_count": int(incount, 16), "out_count": outcount, "in": [], "out": [], "locktime": locktime, "txid": txid}
    in_keys = ["txid", "out_select", "sign"]
    out_keys = ["pk", "value"]
    for j in range(len(intx)):
        output['in'].append({in_keys[i]: intx[j][i] for i in range(len(in_keys))})
    for j in range(len(outx)):
        output['out'].append({out_keys[i]: outx[j][i] for i in range(len(out_keys))})
    return output
def chop_block(block):
    i = 0
    tids = []
    while i < len(block):
        incount = int(block[i+8:i+10], 16)
        inend = (200*incount) + 10
        outcount = int(block[inend+i:inend+2+i], 16)
        tids.append(block[i:((incount*200 + outcount*144)+i+20)])
        i = incount*200 + outcount*144 + i + 20
    return tids

def generate_header(block, pbh, target, nonce):
    m = hashlib.sha256()
    version = (0).to_bytes(4, 'little')
    cb = chop_block(block)
    for i in range(1, len(target)):
        if target[-i:] != "0"*i:
            ex = i-1
            break
    bits = bytes.hex(ex.to_bytes(1, 'big')) + target[(64-ex)-6:(64-ex)]
    return bytes.hex(version) + pbh + get_merkle_root(cb) + bytes.hex(int(time.time()).to_bytes(4, 'big')) + bits + bytes.hex(nonce.to_bytes(4, 'big'))

if __name__ == "__main__":
    print("Hi.")
