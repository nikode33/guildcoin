import guildhall, ecdsa
keys = [guildhall.generate_keys() for i in range(20)]
a = guildhall.make_coinbase_tx(keys[0][1], 34533, 2)

# sk = ecdsa.SigningKey.from_string(bytearray.fromhex(keys[0][0]), curve=ecdsa.SECP256k1)
# rpk = ecdsa.VerifyingKey.from_string(bytearray.fromhex(keys[1][1]), curve=ecdsa.SECP256k1)
print(guildhall.get_tx_info(a))
b = guildhall.generate_tx_old(keys[0][0], keys[0][1])
print(len(a), len(b))
print(guildhall.get_tx_info(b))
print(guildhall.make_tx([a], [0], [keys[0][0].sign(bytearray.fromhex(a))], [keys[1][1]], [50494]))
