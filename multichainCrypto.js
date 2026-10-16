(function (EXPORTS) {
  "use strict";
  const multichainCrypto = EXPORTS;

  // Helper functions
  function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Generate a new random key
  function generateNewID() {
    var key = new Bitcoin.ECKey(false);
    key.setCompressed(true);
    return {
      floID: key.getBitcoinAddress(),
      pubKey: key.getPubKeyHex(),
      privKey: key.getBitcoinWalletImportFormat(),
    };
  }

  // Calculate CRC16-XModem checksum (shared function)
  function crc16XModem(data) {
    let crc = 0x0000;
    for (let i = 0; i < data.length; i++) {
      crc ^= data[i] << 8;
      for (let j = 0; j < 8; j++) {
        if (crc & 0x8000) {
          crc = (crc << 1) ^ 0x1021;
        } else {
          crc = crc << 1;
        }
      }
    }
    return crc & 0xFFFF;
  }

  // --- Multi-chain Generator (BTC, FLO, XLM) ---
  multichainCrypto.generateMultiChain = async function (inputWif) {
    const versions = {
      BTC: { pub: 0x00, priv: 0x80 },
      FLO: { pub: 0x23, priv: 0xa3 },
    };

    const origBitjsPub = bitjs.pub;
    const origBitjsPriv = bitjs.priv;
    const origBitjsCompressed = bitjs.compressed;
    const origCoinJsCompressed = coinjs.compressed;

    bitjs.compressed = true;
    coinjs.compressed = true;

    let privKeyHex;
    let compressed = true;

    if (typeof inputWif === "string" && inputWif.trim().length > 0) {
      const trimmedInput = inputWif.trim();
      const hexOnly = /^[0-9a-fA-F]+$/.test(trimmedInput);
      
      // Check if it's a Stellar secret key (starts with 'S' and is 56 chars)
      if (trimmedInput.startsWith('S') && trimmedInput.length === 56) {
        try {
          // Decode Stellar secret key (Base32)
          const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
          const decoded = [];
          let bits = 0;
          let value = 0;
          
          for (let i = 0; i < trimmedInput.length; i++) {
            const char = trimmedInput[i];
            const charValue = BASE32_ALPHABET.indexOf(char);
            if (charValue === -1) throw new Error('Invalid Base32 character');
            
            value = (value << 5) | charValue;
            bits += 5;
            
            while (bits >= 8) {
              decoded.push((value >>> (bits - 8)) & 0xFF);
              bits -= 8;
            }
          }
          
          const decodedBytes = new Uint8Array(decoded);
          
          // Validate checksum 
          if (decodedBytes.length < 35) {
            throw new Error('Invalid Stellar secret key: too short');
          }
          
          // Extract components: [version(1)] + [seed(32)] + [checksum(2)]
          const payload = decodedBytes.slice(0, 33); // version + seed
          const providedChecksum = (decodedBytes[34] << 8) | decodedBytes[33]; // little-endian
          
          // Calculate expected checksum
          const expectedChecksum = crc16XModem(payload);
          
          // Verify checksum matches
          if (providedChecksum !== expectedChecksum) {
            throw new Error(`Invalid Stellar secret key: checksum mismatch (expected ${expectedChecksum.toString(16)}, got ${providedChecksum.toString(16)})`);
          }
          
          // Verify version byte
          if (decodedBytes[0] !== 0x90) {
            throw new Error(`Invalid Stellar secret key: wrong version byte (expected 0x90, got 0x${decodedBytes[0].toString(16)})`);
          }
          
          // Extract seed (skip version byte, take 32 bytes)
          const seed = decodedBytes.slice(1, 33);
          privKeyHex = bytesToHex(seed);
        } catch (e) {
          console.error("Invalid Stellar secret key:", e.message);
          throw new Error(`Failed to recover Stellar secret key: ${e.message}`);
        }
      } else if (hexOnly && (trimmedInput.length === 64 || trimmedInput.length === 128)) {
        privKeyHex =
          trimmedInput.length === 128 ? trimmedInput.substring(0, 64) : trimmedInput;
      } else {
        try {
          const decode = Bitcoin.Base58.decode(trimmedInput);
          
          // Validate WIF checksum 
          if (decode.length < 37) {
            throw new Error('Invalid WIF key: too short');
          }
          
          // WIF format: [version(1)] + [private_key(32)] + [compression_flag(0-1)] + [checksum(4)]
          const payload = decode.slice(0, decode.length - 4);
          const providedChecksum = decode.slice(decode.length - 4);
          
          // Calculate expected checksum using double SHA256
          const hash1 = Crypto.SHA256(payload, { asBytes: true });
          const hash2 = Crypto.SHA256(hash1, { asBytes: true });
          const expectedChecksum = hash2.slice(0, 4);
          
          // Verify checksum matches
          let checksumMatch = true;
          for (let i = 0; i < 4; i++) {
            if (providedChecksum[i] !== expectedChecksum[i]) {
              checksumMatch = false;
              break;
            }
          }
          
          if (!checksumMatch) {
            const providedHex = providedChecksum.map(b => b.toString(16).padStart(2, '0')).join('');
            const expectedHex = expectedChecksum.map(b => b.toString(16).padStart(2, '0')).join('');
            throw new Error(`Invalid WIF key: checksum mismatch (expected ${expectedHex}, got ${providedHex})`);
          }
          
          const keyWithVersion = decode.slice(0, decode.length - 4);
          let key = keyWithVersion.slice(1);
          if (key.length >= 33 && key[key.length - 1] === 0x01) {
            key = key.slice(0, key.length - 1);
            compressed = true;
          }
          privKeyHex = bytesToHex(key);
        } catch (e) {
          console.error("Invalid WIF key:", e.message);
          throw new Error(`Failed to recover from WIF key: ${e.message}`);
        }
      }
    } else {
      // Generate new key if no input
      const newKey = generateNewID();
      const decode = Bitcoin.Base58.decode(newKey.privKey);
      const keyWithVersion = decode.slice(0, decode.length - 4);
      let key = keyWithVersion.slice(1);
      if (key.length >= 33 && key[key.length - 1] === 0x01)
        key = key.slice(0, key.length - 1);
      privKeyHex = bytesToHex(key);
    }

    // --- Derive addresses for each chain ---
    const result = { BTC: {}, FLO: {}, XLM: {} };

    // BTC
    bitjs.pub = versions.BTC.pub;
    bitjs.priv = versions.BTC.priv;
    const pubKeyBTC = bitjs.newPubkey(privKeyHex);
    result.BTC.address = coinjs.bech32Address(pubKeyBTC).address;
    result.BTC.privateKey = bitjs.privkey2wif(privKeyHex);

    // FLO
    bitjs.pub = versions.FLO.pub;
    bitjs.priv = versions.FLO.priv;
    const pubKeyFLO = bitjs.newPubkey(privKeyHex);
    result.FLO.address = bitjs.pubkey2address(pubKeyFLO);
    result.FLO.privateKey = bitjs.privkey2wif(privKeyHex);

    // XLM (Stellar)
    try {
      const privBytes = hexToBytes(privKeyHex.substring(0, 64));
      const seed = new Uint8Array(privBytes.slice(0, 32));

      // Generate Ed25519 keypair from seed
      const keyPair = nacl.sign.keyPair.fromSeed(seed);
      const pubKey = keyPair.publicKey;

      // Stellar address encoding: version byte (0x30 for public key 'G') + public key + CRC16-XModem checksum
      const versionByte = 0x30; // Results in 'G' prefix for public keys
      const payload = new Uint8Array([versionByte, ...pubKey]);
      
      const checksum = crc16XModem(payload);
      // Checksum is stored in little-endian format
      const checksumBytes = new Uint8Array([checksum & 0xFF, (checksum >> 8) & 0xFF]);
      const addressBytes = new Uint8Array([...payload, ...checksumBytes]);

      // Base32 encode the address (RFC 4648)
      const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = 0;
      let value = 0;
      let output = '';

      for (let i = 0; i < addressBytes.length; i++) {
        value = (value << 8) | addressBytes[i];
        bits += 8;

        while (bits >= 5) {
          output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
          bits -= 5;
        }
      }

      if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
      }

      const xlmAddress = output;
      
      // Stellar secret key format: version byte (0x90 for secret key 'S') + seed + CRC16
      const secretVersionByte = 0x90; // Results in 'S' prefix for secret keys
      const secretPayload = new Uint8Array([secretVersionByte, ...seed]);
      const secretChecksum = crc16XModem(secretPayload);
      const secretChecksumBytes = new Uint8Array([secretChecksum & 0xFF, (secretChecksum >> 8) & 0xFF]);
      const secretKeyBytes = new Uint8Array([...secretPayload, ...secretChecksumBytes]);

      // Base32 encode the secret key
      bits = 0;
      value = 0;
      let secretOutput = '';

      for (let i = 0; i < secretKeyBytes.length; i++) {
        value = (value << 8) | secretKeyBytes[i];
        bits += 8;

        while (bits >= 5) {
          secretOutput += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
          bits -= 5;
        }
      }

      if (bits > 0) {
        secretOutput += BASE32_ALPHABET[(value << (5 - bits)) & 31];
      }

      const xlmPrivateKey = secretOutput;

      result.XLM.address = xlmAddress;
      result.XLM.privateKey = xlmPrivateKey;
    } catch (error) {
      console.error("Error generating XLM address:", error);
      result.XLM.address = "Error generating address";
      result.XLM.privateKey = privKeyHex;
    }

    bitjs.pub = origBitjsPub;
    bitjs.priv = origBitjsPriv;
    bitjs.compressed = origBitjsCompressed;
    coinjs.compressed = origCoinJsCompressed;

    return result;
  };

  // Sign Stellar Transaction 
  multichainCrypto.signXlm = async function (txBytes, xlmPrivateKey) {
    const privKeyOnly = xlmPrivateKey.substring(0, 64);
    const privBytes = hexToBytes(privKeyOnly);
    const seed = new Uint8Array(privBytes.slice(0, 32));

    const keypair = nacl.sign.keyPair.fromSeed(seed);

    let txData;
    if (typeof txBytes === 'string') {
      txData = new Uint8Array(atob(txBytes).split('').map(c => c.charCodeAt(0)));
    } else {
      txData = new Uint8Array(txBytes);
    }

    const signature = nacl.sign.detached(txData, keypair.secretKey);

    return signature;
  };

})("object" === typeof module ? module.exports : (window.multichainCrypto = {}));