# obsidian keykeeper

a cryptocurrency software licensing platform built with privacy-first principles. users can purchase software licenses using monero (xmr) or litecoin (ltc), with licenses bound to hardware ids for copy-protection. it is the backend of the obsidian pro and commerical licensing, but can be adapted for any application that requires securely handling licensing and drm.

## features

- **license types (configurable)**
  - **pro license**: 6-month subscription for individual users
  - **commercial license**: 6-month subscription for commercial use

- **payment options**
  - monero (xmr)
  - litecoin (ltc)

- **hardware-bound licensing**
  - hwid verification using SPECK-128-CBC-MAC
  - license relinking for hardware changes (max 3 times)
  - per-user SPECK encryption keys

- **security and privacy:**
  - pgp-signed payment address
  - tor-over-clearnet backend
  - rate limiting and connection filtering
  - extensive input validation and regex
  - SPECK-128-CBC-MAC for hwid integrity verification
  - auto-delete XMR transactions after 7 days

- **tor-over-clearnet**
  - socks5 proxy routes clearnet traffic through tor
  - increases privacy and security of the backend
  - doesn't require tor browser

## architecture

```
                    ┌─────────────┐
                    │   client    │
                    │ (browser)   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐      ┌─────────────┐
                    │   nginx     │─────►│   proxy     │
                    │   (port 80) │      │ (socks5/tor)│
                    └─────────────┘      └──────┬──────┘
                                                │
                    ┌─────────────┐      ┌──────▼──────┐
                    │  backend    │◄─────│ onion       │
                    │ (node.js)   │      │ network     │
                    └──────┬──────┘      └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
         │ sqlite  │  │ monero  │  │litecoin │
         │database │  │  wallet │  │ wallet  │
         └─────────┘  └─────────┘  └─────────┘
```

1. client sends request to `proxy:8080/api/...`
2. proxy authenticates via api key
3. proxy routes request through socks5 (tor) to the hidden service
4. hidden service processes request and returns response

### SPECK-128

SPECK is a lightweight block cipher designed by the NSA. 

obsidian keykeeper uses a custom implementation of SPECK-128 with CBC-MAC for hardware id verification. this ensures that license bindings cannot be spoofed.

**parameters:**
- block size: 128 bits
- key size: 128 bits
- rounds: 34

### round function

the round function operates on two 64-bit words (x, y) using:
- **right rotation** (ror64): `(x >> r) | (x << (64 - r))`
- **left rotation** (rol64): `(x << r) | (x >> (64 - r))`
- **modular addition**: `(x + y) mod 2^64`
- **xor**: `x ^ k`

```javascript
function speckRound(x, y, k) {
  x = ror64(x, 8);
  x = (x + y) mod 2^64;
  x = x ^ k;
  y = rol64(y, 3);
  y = y ^ x;
  return [x, y];
}
```

### key schedule

the key schedule expands a 128-bit key into 34 round keys:

```javascript
function speckKeySchedule(key) {
  // key[0], key[1] are the initial 64-bit key words
  roundKeys[0] = key[0];
  b = key[1];
  
  for (let i = 0; i < 33; i++) {
    b = ror64(b, 8) + roundKeys[i];
    b = b ^ i;
    roundKeys[i + 1] = rol64(roundKeys[i], 3) ^ b;
  }
  return roundKeys;
}
```

### CBC-MAC

CBC-MAC (cipher block chaining message authentication code) ensures message integrity:

1. data is padded to a multiple of 128 bits (16 bytes)
2. each 128-bit block is XORed with the previous ciphertext
3. the block is encrypted with SPECK-128
4. the final 128-bit output is the MAC

```javascript
function speckCbcMac(data, keyHex) {
  // Initialize chaining variables
  let chain0 = 0n, chain1 = 0n;
  
  // Process 16-byte blocks
  for (let i = 0; i < fullBlocks; i++) {
    block0 = block0 ^ chain0;
    block1 = block1 ^ chain1;
    [chain0, chain1] = speckEncryptBlock(block0, block1, roundKeys);
  }
  
  return [chain0, chain1]; // 128-bit MAC
}
```

### hwid generation

hardware ids are computed from client machine information:
1. collect machine info (CPU, memory, OS details)
2. generate a json payload with the machine info
3. compute SPECK-128-CBC-MAC using the user's unique SPECK key
4. store the resulting MAC as the hardware id

The hwid is verified by re-computing the MAC and comparing against the stored value using a time safe funtion to prevent timing attacks.

### prerequisites

- node.js 18+
- tor daemon (for proxy)
- monerod + monero-wallet-rpc
- electrum-ltc

## api reference

### http endpoints

| method | endpoint | description |
|--------|----------|-------------|
| POST | `/api/register` | register new user |
| POST | `/api/login` | user login |
| POST | `/api/logout` | user logout |
| POST | `/api/verify` | verify license (requires HWID) |

### socket.io events

**authentication:**
| event | description |
|-------|-------------|
| `auth:register` | register via socket |
| `auth:login` | login via socket |
| `auth:logout` | logout via socket |
| `user:getProfile` | get user profile |

**licenses:**
| event | description |
|-------|-------------|
| `license:verify` | verify license validity |
| `license:create` | create new license (via payment) |
| `license:initRelink` | begin license relink process |
| `license:relink` | complete hardware relink |
| `license:canRelink` | check remaining relinks |

**transactions:**
| event | description |
|-------|-------------|
| `tx:create` | create purchase transaction |
| `tx:withdraw` | create withdrawal request |
| `history:get` | get transaction + license history |

**account:**
| event | description |
|-------|-------------|
| `account:getInfo` | get account info |
| `account:updateEmail` | update email |
| `account:requestPgpKey` | get pgp-encrypted payment info |

## license

Apache 2.0
