<img align="center" width="1000" height="100%" src="img/stars-only.png" alt="keykeeper-logo">

# obsidian keykeeper - anonymous digital rights management

**obsidian.st:**
- **clearnet:** [obsidian.st](https://obsidian.st)
- **i2p:** [obsidian.i2p](http://obsidian.i2p/?i2paddresshelper=edexepj4bnni4ct5otbivq73tjmyontztz5qa56qrni2rdldh4rq.b32.i2p)
- **tor:** `obsidiand244wsh2jnmqvnim2becs73dims5wc5hzse3o5ywvw6ryoyd.onion`

---

a cryptocurrency-based software licensing and digital rights management platform built with privacy-first principles. users can purchase software licenses using monero (xmr) or litecoin (ltc), with licenses bound to hardware ids for copy-protection. it is the backend of the obsidian pro and commerical licensing, but can be adapted for any application that requires securely handling licensing and drm.

security features include: tor-over-clearnet backend, recently configured to also work tor-over-clearnet-over-i2p, and a site pgp key with pgp signed ltc and xmr addresses to protect from phishing. users are identified with an account number. keykeeper does not support email sign-up at this time. this way, licensing protections can be upheld without collecting excessive user data. there are also automatic suspensions for any detected tampering with the licensing code using cryptographically secure SPECK-CBC-MAC hashes which prevent spoofing. 

this model requires that the stub (the small section of code that executes the obsidian-packed payload) contact keykeeper first, in order to acquire the decryption key for the obsidian pro/commerical product. this happens through the clearnet proxy, redirecting them through tor to the keykeeper server. 

the server receives both the stubs calculated hash as well as the components that make up the hash. it then calculates the hash independently and compares across three domains: database hardware id, server-calculated hardware id, and the stubs returned hardware id. any mismatch and the server will refuse to issue the key.

---
## features

- **security and privacy:**
  - pgp-signed payment address
  - encrypted user/license database (AES-256)
  - rate limiting and connection filtering
  - extensive input validation and regex
  - SPECK-128-CBC-MAC for hwid integrity verification
  - auto-delete XMR transactions after 7 days
  - no emails, users identified by account numbers

- **tor-over-clearnet:**
  - http -> socks5 proxy routes clearnet traffic through tor
  - websockets allow for real-time, low-latency interactions
  - increases privacy and security of the backend
  - doesn't require tor browser

- **tor-over-clearnet-over-i2p:**
  - website accessible over i2p
  - websockets over i2p fully functional
  - wireguard protects inter-server communication

- **admin shell:**
  - local-only admin ipc shell
  - directly manipulate the database
  - withdraw from the server wallet
  - create/discard licenses
  - view user info, suspend accounts, etc

- **hardware-bound tor-over-clearnet licensing:**
  - hwid verification using SPECK-128-CBC-MAC
  - client packer stub connects to proxy on frontend port 8888
  - accesses backend through proxy (which routes through tor)
  - license relinking for hardware changes (max 3 times)
  - per-user SPECK encryption keys
  - takes 2-5 seconds on average round trip + computation
 
- **license types (configurable):**
  - **pro license**: 6-month subscription for individual users
  - **commercial license**: 6-month subscription for commercial use

- **payment options:**
  - monero (xmr)
  - litecoin (ltc)

---

## tor-over-clearnet-over-i2p architecture


```  
 ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
 │ i2p client  │◄────│  i2p p2p    │◄────│   nginx     │◄────│  proxy      │◄─────┐
 │  browser    │────►│  network    │────►│(port 443/80)│────►│ (port 8888) │────┐ │      
 └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘    │ │ tor 
                     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    │ │ circuit
                     │  admin      │────►│  backend    │◄────│  tor        │◄───┘ │
                     │ ipc shell   │  ┌─►│ (node.js)   │────►│ rendezvous  │──────┘
                     └─────────────┘  │  └──────▲──────┘     └─────────────┘
                            ┌─────────┘     ┌───┴───────┬────────────┐
 ┌─────────────┐ tor ┌──────▼──────┐   ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
 │ client      │◄────│ obsidian    │◄──│ sqlite  │  │ monero  │  │litecoin │
 │(tor browser)│────►│ onion site  │──►│database │  │  wallet │  │ wallet  │
 └─────────────┘     └──────▲──────┘   └─────────┘  └────▲────┘  └────▲────┘
                            └────────────────────────────┴────────────┘
```

## clearnet architecture

```  
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
  │  client     │◄────│   nginx     │◄────│  proxy      │◄─────┐
  │  (browser)  │────►│(port 443/80)│────►│ (port 8888) │────┐ │      
  └─────────────┘     └─────────────┘     └─────────────┘    │ │ tor 
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    │ │ circuit
  │  admin      │────►│  backend    │◄────│  tor        │◄───┘ │
  │ ipc shell   │     │ (node.js)   │────►│ rendezvous  │──────┘
  └─────────────┘     └──────▲──────┘     └─────────────┘
                ┌────────────┼────────────┐          
           ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
           │ sqlite  │  │ monero  │  │litecoin │
           │database │  │  wallet │  │ wallet  │
           └─────────┘  └─────────┘  └─────────┘
```

**socket.io websockets:**
1. client opens a websocket to `obsidian.st/socket.io/...` or `obsidian.i2p/socket.io/...`
2. proxy routes request through socks5 (tor) to the hidden service
3. hidden service accepts connection and keeps circuit alive

**GET/POST requests:**
1. client sents http request to `obsidian.st/keykeeper/...` or `obsidian.i2p/keykeeper/...`
2. proxy routes request to specified endpoint through tor
3. hidden service responds with requested data

## obsidian pro verification process:
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   client    │────►│ verify      │────►│  proxy      │────►│ tor network │────►│  keykeeper  │
│ (obsidian)  │◄────│ subdomain   │◄────│ (port 8888) │◄────│ (3 relays)  │◄────│ (rendezvous)│
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```
**hardware ids are computed from client machine information:**
1. stub collects machine info (hardware serials, cpuid, tpm-ek)
2. compute SPECK-128-CBC-MAC using the user's integrity key
3. constructs a json payload with the machine info and MAC
4. transmits json payload over tor to keykeeper via clearnet subdomain
5. hwid is verified by re-computing the MAC serverside
6. stub receives speck key and decrypts payload

---
### SPECK-128

SPECK is a lightweight block cipher designed by the NSA. it is up to 5x faster than AES as it uses a simple ARX (add-rotate-xor) set of operations rather than the expensive AES-NI operations that require special hardware to properly execute. obsidian pro uses this algorithm to encrypt/decrypt the payload, and as part of its CBC-MAC integrity and license verification checks. see more about CBC-MAC below.

**parameters:**
- block size: 128 bits
- key size: 128 bits
- rounds: 34

### SPECK encrypt rounds

the encrypt function has 34 rounds where it operates on two 64-bit words (x, y) using:
1. **right rotation** (ror64): `(x >> r) | (x << (64 - r))`
2. **modular addition**: `(x + y) mod 2^64`
3. **xor**: `x ^ k`
4. **left rotation** (rol64): `(x << r) | (x >> (64 - r))`
5. **xor** `x ^ y`

```javascript
function speckEncryptBlock(x, y, roundKeys) {
  for (let i = 0; i < SPECK_ROUNDS; i++) {
    x = (ror64(x, 8n) + y) & 0xFFFFFFFFFFFFFFFFn;
    x = (x ^ roundKeys[i]);
    y = (rol64(y, 3n) ^ x);
  }
  return [x, y];
}
```

### key schedule

the key schedule expands a 128-bit key into 34 round keys:

```javascript
function speckKeySchedule(key) {
  const roundKeys = new Array(SPECK_ROUNDS);
  let b = key[1];
  roundKeys[0] = key[0];
  
  for (let i = 0; i < SPECK_ROUNDS - 1; i++) {
    b = (ror64(b, 8n) + roundKeys[i]) & 0xFFFFFFFFFFFFFFFFn;
    b = (b ^ BigInt(i));
    roundKeys[i + 1] = (rol64(roundKeys[i], 3n) ^ b);
  }
  
  return roundKeys;
}
```
---
### CBC-MAC

obsidian keykeeper uses a custom SPECK-based 128bit CBC-MAC (Cipher Block Chaining Message Authentication Code) to ensure license verification integrity:

1. data is padded to a multiple of 128 bits (16 bytes)
2. each 128-bit block is XORed with the previous ciphertext
3. the block is encrypted with SPECK-128
4. the final 128-bit output is the MAC

```javascript
function speckCbcMac(data, keyHex) { // simplified
  let chain0 = 0n, chain1 = 0n;
  
  for (let i = 0; i < fullBlocks; i++) {
    block0 = block0 ^ chain0;
    block1 = block1 ^ chain1;
    [chain0, chain1] = speckEncryptBlock(block0, block1, roundKeys);
  }
  
  return [chain0, chain1]; // 128-bit MAC
}
```
