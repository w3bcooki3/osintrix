"""Writes the transaction files for the money-flow tests: one made-up scam, in the exact
shapes the explorers return (Esplora, blockchain.com, BlockCypher, Etherscan JSON and CSV,
Tronscan). Addresses are made up in the right formats; amounts in each chain's base units."""
import json, hashlib, os, random
random.seed(7)
D = os.path.dirname(os.path.abspath(__file__))
B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'; B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def bc1(tag): h = hashlib.sha512(tag.encode()).digest(); return 'bc1q' + ''.join(B32[b % 32] for b in h)[:38]
def eth(tag): return '0x' + hashlib.sha256(tag.encode()).hexdigest()[:40]
def tron(tag): h = hashlib.sha512(tag.encode()).digest(); return 'T' + ''.join(B58[b % 58] for b in h)[:33]
def txid(tag): return hashlib.sha256(('tx' + tag).encode()).hexdigest()
def ts(day, hh=12, mm=0): return 1709251200 + (day - 1) * 86400 + hh * 3600 + mm * 60   # 2024-03-01 00:00 UTC
S1, S2, S3, P1, P2, P3, X = bc1('scam-1'), bc1('scam-2'), bc1('scam-change'), bc1('peel-1'), bc1('peel-2'), bc1('peel-3'), bc1('exchange-deposit')
V = [bc1('victim-%d' % i) for i in range(1, 7)]; Q = [bc1('peel-pay-%d' % i) for i in range(1, 4)]
def etx(tag, day, ins, outs, hh=12, fee=1500):
    return {'txid': txid(tag), 'version': 2, 'locktime': 0, 'size': 222, 'weight': 561, 'fee': fee,
            'vin': [{'txid': txid(tag + 'prev%d' % i), 'vout': 0, 'prevout': {'scriptpubkey': '0014' + 'ab' * 20, 'scriptpubkey_asm': 'OP_0 OP_PUSHBYTES_20 ' + 'ab' * 20, 'scriptpubkey_type': 'v0_p2wpkh', 'scriptpubkey_address': a, 'value': v}, 'scriptsig': '', 'scriptsig_asm': '', 'witness': ['30' * 36, '02' + 'cd' * 32], 'is_coinbase': False, 'sequence': 4294967293} for i, (a, v) in enumerate(ins)],
            'vout': [{'scriptpubkey': '0014' + 'ef' * 20, 'scriptpubkey_asm': 'OP_0 OP_PUSHBYTES_20 ' + 'ef' * 20, 'scriptpubkey_type': 'v0_p2wpkh', 'scriptpubkey_address': a, 'value': v} for a, v in outs],
            'status': {'confirmed': True, 'block_height': 832100 + day * 144 + hh, 'block_hash': hashlib.sha256(tag.encode()).hexdigest(), 'block_time': ts(day, hh)}}
pays = [5000000, 12000000, 3100000, 20000000, 8000000]
victim_txs = [etx('v%d' % i, i, [(V[i - 1], p + 30000)], [(S1, p), (bc1('victim-change-%d' % i), 29000)]) for i, p in enumerate(pays, 1)]
v6 = etx('v6', 5, [(V[5], 4000000)], [(S2, 3900000)], hh=15)
consol = etx('consolidate', 6, [(S1, p) for p in pays] + [(S2, 3900000)], [(X, 40000000), (S3, 8090000)], hh=9, fee=10000)
peel = [etx('peel1', 7, [(S3, 8090000)], [(P1, 7000000), (Q[0], 1000000)], hh=10, fee=90000),
        etx('peel2', 7, [(P1, 7000000)], [(P2, 5900000), (Q[1], 1100000)], hh=13, fee=0),
        etx('peel3', 8, [(P2, 5900000)], [(P3, 4800000), (Q[2], 1050000)], hh=8, fee=50000)]
cj = etx('coinjoin', 9, [(bc1('cj-in-%d' % i), 10400000) for i in range(5)], [(bc1('cj-out-%d' % i), 10000000) for i in range(5)] + [(bc1('cj-coord'), 1500000)], hh=18)
json.dump(list(reversed(victim_txs + [consol, cj])), open(os.path.join(D, 'esplora-scam1.json'), 'w'), indent=1)
def bcom(t): return {'hash': t['txid'], 'ver': 2, 'vin_sz': len(t['vin']), 'vout_sz': len(t['vout']), 'size': 222, 'fee': t['fee'], 'time': t['status']['block_time'], 'block_height': t['status']['block_height'], 'result': 0, 'balance': 0,
                     'inputs': [{'sequence': 4294967293, 'witness': '', 'script': '', 'index': i, 'prev_out': {'addr': x['prevout']['scriptpubkey_address'], 'value': x['prevout']['value'], 'spent': True, 'type': 0, 'n': 0, 'tx_index': 1000 + i, 'script': '0014'}} for i, x in enumerate(t['vin'])],
                     'out': [{'type': 0, 'spent': False, 'value': o['value'], 'addr': o['scriptpubkey_address'], 'n': n, 'tx_index': 2000 + n, 'script': '0014'} for n, o in enumerate(t['vout'])]}
json.dump({'hash160': 'aa' * 20, 'address': S2, 'n_tx': 2, 'n_unredeemed': 0, 'total_received': 3900000, 'total_sent': 3900000, 'final_balance': 0, 'txs': [bcom(consol), bcom(v6)]}, open(os.path.join(D, 'blockchain-scam2.json'), 'w'), indent=1)
def bcy(t): return {'block_height': t['status']['block_height'], 'hash': t['txid'], 'total': sum(o['value'] for o in t['vout']), 'fees': t['fee'], 'size': 222, 'preference': 'low',
                    'confirmed': '2024-03-%02dT%02d:00:00Z' % ((t['status']['block_time'] - 1709251200) // 86400 + 1, (t['status']['block_time'] % 86400) // 3600), 'received': '2024-03-01T00:00:00Z', 'ver': 2, 'double_spend': False, 'vin_sz': 1, 'vout_sz': 2, 'confirmations': 30000,
                    'inputs': [{'prev_hash': txid('x'), 'output_index': 0, 'output_value': x['prevout']['value'], 'sequence': 4294967293, 'addresses': [x['prevout']['scriptpubkey_address']], 'script_type': 'pay-to-witness-pubkey-hash', 'age': 832000} for x in t['vin']],
                    'outputs': [{'value': o['value'], 'script': '0014', 'addresses': [o['scriptpubkey_address']], 'script_type': 'pay-to-witness-pubkey-hash'} for o in t['vout']]}
json.dump({'address': S3, 'total_received': 8090000, 'total_sent': 8090000, 'balance': 0, 'n_tx': 3, 'txs': [bcy(t) for t in reversed(peel)]}, open(os.path.join(D, 'blockcypher-peel.json'), 'w'), indent=1)
# Ethereum: two victims pay E1; within two hours E1 forwards almost all of it to E2; E2 pays an exchange deposit address
E1, E2, VA, VB, VC, EX = eth('eth-scam'), eth('eth-forward'), eth('eth-victim-a'), eth('eth-victim-b'), eth('eth-victim-c'), eth('eth-exchange')
def etxn(tag, t, f, to, wei, err='0'):
    return {'blockNumber': str(19350000 + t % 100000), 'timeStamp': str(t), 'hash': '0x' + txid(tag), 'nonce': '3', 'blockHash': '0x' + txid(tag + 'b'), 'transactionIndex': '41', 'from': f, 'to': to, 'value': str(wei), 'gas': '21000', 'gasPrice': '31000000000', 'isError': err, 'txreceipt_status': '1' if err == '0' else '0', 'input': '0x', 'contractAddress': '', 'cumulativeGasUsed': '3100000', 'gasUsed': '21000', 'confirmations': '1700000', 'methodId': '0x', 'functionName': ''}
eth_list = [etxn('ea', ts(10, 9), VA, E1, 1500000000000000000), etxn('eb', ts(10, 10), VB, E1.upper().replace('0X', '0x'), 800000000000000000), etxn('ef', ts(10, 11, 40), E1, E2, 2250000000000000000), etxn('efail', ts(10, 11, 50), E1, E2, 9000000000000000000, err='1')]
json.dump({'status': '1', 'message': 'OK', 'result': eth_list}, open(os.path.join(D, 'etherscan-txlist.json'), 'w'), indent=1)
tok = [{'blockNumber': '19351000', 'timeStamp': str(ts(11, 14)), 'hash': '0x' + txid('usdt1'), 'nonce': '7', 'blockHash': '0x' + txid('usdt1b'), 'from': VC, 'contractAddress': '0xdac17f958d2ee523a2206206994597c13d831ec7', 'to': E1, 'value': '5000000000', 'tokenName': 'Tether USD', 'tokenSymbol': 'USDT', 'tokenDecimal': '6', 'transactionIndex': '12', 'gas': '65000', 'gasPrice': '30000000000', 'gasUsed': '46000', 'cumulativeGasUsed': '900000', 'input': 'deprecated', 'confirmations': '1690000'}]
json.dump({'status': '1', 'message': 'OK', 'result': tok}, open(os.path.join(D, 'etherscan-tokentx.json'), 'w'), indent=1)
with open(os.path.join(D, 'etherscan-forward.csv'), 'w') as f:
    f.write('"Transaction Hash","Blockno","UnixTimestamp","DateTime (UTC)","From","To","ContractAddress","Value_IN(ETH)","Value_OUT(ETH)","CurrentValue @ $3412.55/Eth","TxnFee(ETH)","TxnFee(USD)","Historical $Price/Eth","Status","ErrCode","Method"\n')
    f.write('"0x%s","19350500","%d","2024-03-10 11:40:00","%s","%s","","2.25","0","7678.24","0.000651","1.99","3051.10","","","Transfer"\n' % (txid('ef'), ts(10, 11, 40), E1, E2))
    f.write('"0x%s","19350560","%d","2024-03-10 13:05:00","%s","%s","","0","2.2","7507.61","0.000651","1.99","3051.10","","","Transfer"\n' % (txid('ex'), ts(10, 13, 5), E2, EX))
# TRON: USDT (TRC20) into a TRON wallet from two payers, then out to one address
T1, TA, TB, TX = tron('tron-scam'), tron('tron-victim-a'), tron('tron-victim-b'), tron('tron-exchange')
tr = [{'transaction_id': txid('t%d' % i), 'status': 0, 'block_ts': ts(12, h) * 1000, 'from_address': f, 'to_address': t, 'block': 60000000 + i, 'contract_address': 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', 'quant': q, 'confirmed': True, 'contractRet': 'SUCCESS', 'finalResult': 'SUCCESS', 'revert': False,
       'tokenInfo': {'tokenId': 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', 'tokenAbbr': 'USDT', 'tokenName': 'Tether USD', 'tokenDecimal': 6, 'tokenCanShow': 1, 'tokenType': 'trc20', 'vip': True}}
      for i, (f, t, q, h) in enumerate([(TA, T1, '700000000', 8), (TB, T1, '500000000', 9), (T1, TX, '1195000000', 10)])]
json.dump({'total': 3, 'rangeTotal': 3, 'contractInfo': {}, 'token_transfers': list(reversed(tr))}, open(os.path.join(D, 'tronscan-trc20.json'), 'w'), indent=1)
json.dump({'S1': S1, 'S2': S2, 'S3': S3, 'P': [P1, P2, P3], 'X': X, 'V': V, 'E1': E1, 'E2': E2, 'EX': EX, 'VA': VA, 'VB': VB, 'VC': VC, 'T1': T1, 'TX': TX}, open(os.path.join(D, 'addresses.json'), 'w'), indent=1)
