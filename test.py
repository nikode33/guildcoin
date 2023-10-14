import time, ecdsa, hashlib, random
block = ""
tids = []
for i in range(0, 2000):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    sha = hashlib.sha256()

    lock = vk.to_string()
    unlock = sk.sign(vk.to_string())
    version = (0).to_bytes(4, 'little')
    incount = (1).to_bytes(1, 'little')
    outcount = (1).to_bytes(1, 'little')
    outselect = (0).to_bytes(2, 'little')
    value = random.randint(0, 2**10).to_bytes(8, 'little')
    tid = (0).to_bytes(32, 'little')
    trans = bytes.hex(version) + bytes.hex(incount) + bytes.hex(tid) + bytes.hex(outselect) + unlock.hex() + bytes.hex(outcount) + lock.hex()
    sha.update(bytearray.fromhex(trans))
    block += trans
    tids.append(trans)
    lockvk = ecdsa.VerifyingKey.from_string(bytearray.fromhex(lock.hex()), curve=ecdsa.SECP256k1)
pblock = (0).to_bytes(32, 'little')
version = (0).to_bytes(4, 'big')
times = int(time.time()).to_bytes(4, 'big')
rtids = [block[i:i+336] for i in range(0, len(block), 336)]

def merkle(tids):
    m = hashlib.sha256()
    r = []
    if len(tids) % 2 == 1:
        tids.append(tids[-1])
    for i in range(0, len(tids), 2):
        m.update(bytearray.fromhex(tids[i] + tids[i-1]))
        r.append(m.hexdigest())
    return r

while 1:
    rtids = merkle(rtids)
    if len(rtids) == 1:
        merkleroot = rtids[0]
        break
for i in range(10000):
    nonce = (i).to_bytes(4, 'big')
    header = bytes.hex(version) + bytes.hex(pblock) + merkleroot + bytes.hex(times) + "0cfffffc" + bytes.hex(nonce)
    sha.update(bytearray.fromhex(header))
    if sha.hexdigest()[0:3] == "000":
        print(sha.hexdigest(), header)
        break

print("Length of block: " + str(len(block)))
print("The mined block: " + header + block)


