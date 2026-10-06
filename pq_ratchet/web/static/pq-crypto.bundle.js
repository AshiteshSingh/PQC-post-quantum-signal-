var PQC_MODULE = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod2) => __copyProps(__defProp({}, "__esModule", { value: true }), mod2);

  // src/pqc-engine.js
  var pqc_engine_exports = {};
  __export(pqc_engine_exports, {
    AEAD_NONCE_BYTES: () => AEAD_NONCE_BYTES,
    AEAD_TAG_BYTES: () => AEAD_TAG_BYTES,
    CHAIN_KEY_BYTES: () => CHAIN_KEY_BYTES,
    DOMAIN_ASYM_RATCHET: () => DOMAIN_ASYM_RATCHET,
    DOMAIN_AUTH_INITIATOR: () => DOMAIN_AUTH_INITIATOR,
    DOMAIN_AUTH_RESPONDER: () => DOMAIN_AUTH_RESPONDER,
    DOMAIN_AUTH_TRANSCRIPT: () => DOMAIN_AUTH_TRANSCRIPT,
    DOMAIN_CHAIN_ADVANCE: () => DOMAIN_CHAIN_ADVANCE,
    DOMAIN_HYBRID_KEM: () => DOMAIN_HYBRID_KEM,
    DOMAIN_MESSAGE_KEY: () => DOMAIN_MESSAGE_KEY,
    DOMAIN_ROOT_INIT: () => DOMAIN_ROOT_INIT,
    HandshakeInitPacket: () => HandshakeInitPacket,
    HandshakeRespPacket: () => HandshakeRespPacket,
    HybridKEMCiphertext: () => HybridKEMCiphertext,
    HybridKEMPrivateKey: () => HybridKEMPrivateKey,
    HybridKEMPublicKey: () => HybridKEMPublicKey,
    IdentityPrivateKey: () => IdentityPrivateKey,
    IdentityPublicKey: () => IdentityPublicKey,
    MAGIC_BYTES: () => MAGIC_BYTES,
    MAX_PACKET_PAYLOAD_BYTES: () => MAX_PACKET_PAYLOAD_BYTES,
    MAX_RATCHET_SKIP_GAP: () => MAX_RATCHET_SKIP_GAP,
    MAX_SKIPPED_KEYS_CACHE: () => MAX_SKIPPED_KEYS_CACHE,
    MLDSA65_PUBLIC_KEY_BYTES: () => MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES: () => MLDSA65_SIGNATURE_BYTES,
    MLKEM768_CIPHERTEXT_BYTES: () => MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES: () => MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_SHARED_SECRET_BYTES: () => MLKEM768_SHARED_SECRET_BYTES,
    MSG_TYPE_HANDSHAKE_INIT: () => MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESP: () => MSG_TYPE_HANDSHAKE_RESP,
    MSG_TYPE_RATCHET_DATA: () => MSG_TYPE_RATCHET_DATA,
    MSG_TYPE_TERMINATE: () => MSG_TYPE_TERMINATE,
    PQRatchetSession: () => PQRatchetSession,
    PROTOCOL_VERSION: () => PROTOCOL_VERSION,
    ROOT_KEY_BYTES: () => ROOT_KEY_BYTES,
    RatchetDataPacket: () => RatchetDataPacket,
    SYMMETRIC_KEY_BYTES: () => SYMMETRIC_KEY_BYTES,
    X25519_KEY_BYTES: () => X25519_KEY_BYTES,
    X25519_SHARED_SECRET_BYTES: () => X25519_SHARED_SECRET_BYTES,
    asymmetric_ratchet_kdf: () => asymmetric_ratchet_kdf,
    base64ToBytes: () => base64ToBytes,
    bytesToBase64: () => bytesToBase64,
    bytesToHex: () => bytesToHex3,
    computeInitiatorTranscript: () => computeInitiatorTranscript,
    computeResponderTranscript: () => computeResponderTranscript,
    concatBytes: () => concatBytes3,
    constantTimeCompare: () => constantTimeCompare,
    dual_prf_combine: () => dual_prf_combine,
    hexToBytes: () => hexToBytes3,
    symmetric_chain_step: () => symmetric_chain_step,
    zeroize: () => zeroize
  });

  // node_modules/@noble/hashes/_u64.js
  var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
  var _32n = /* @__PURE__ */ BigInt(32);
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }

  // node_modules/@noble/hashes/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  var atitle = (title) => title ? `"${title}" ` : "";
  function anumber(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abool(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function abytes(value, length, title = "") {
    if (isBytes(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber(length, "length");
    const bytes = isBytes(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  function ahash(h) {
    if (typeof h !== "function" || typeof h.create !== "function")
      throw new TypeError("expected hash wrapped by utils.createHasher");
    anumber(h.outputLen);
    anumber(h.blockLen);
    if (h.outputLen < 1 || h.blockLen < 1)
      throw new Error("hash blockLen / outputLen must be >= 1");
  }
  var aobject = (value, label) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
  };
  var aopts = (value, label) => {
    aobject(value, label);
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`"${label}" expected plain object`);
    if (Object.hasOwn(value, "__proto__"))
      throw new TypeError(`"${label}.__proto__" is not allowed`);
  };
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;
  var hasHexBuiltin = /* @__PURE__ */ (() => (
    // @ts-ignore
    typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
  ))();
  var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  function bytesToHex(bytes) {
    abytes(bytes);
    if (hasHexBuiltin)
      return bytes.toHex();
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += hexes[bytes[i]];
    }
    return hex;
  }
  function asciiToBase16(ch) {
    return ch >= 48 && ch <= 57 ? ch - 48 : ch >= 65 && ch <= 70 ? ch - (65 - 10) : ch >= 97 && ch <= 102 ? ch - (97 - 10) : void 0;
  }
  function hexToBytes(hex) {
    if (typeof hex !== "string")
      throw new TypeError("hex string expected, got " + typeof hex);
    if (hasHexBuiltin) {
      try {
        return Uint8Array.fromHex(hex);
      } catch (error) {
        if (error instanceof SyntaxError)
          throw new RangeError(error.message);
        throw error;
      }
    }
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
      throw new RangeError("hex string expected, got unpadded hex of length " + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
      const n1 = asciiToBase16(hex.charCodeAt(hi));
      const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
      if (n1 === void 0 || n2 === void 0) {
        const char = hex[hi] + hex[hi + 1];
        throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
      }
      array[ai] = n1 * 16 + n2;
    }
    return array;
  }
  function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
      const a = arrays[i];
      abytes(a);
      sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
      const a = arrays[i];
      res.set(a, pad);
      pad += a.length;
    }
    return res;
  }
  function checkOpts(defaults, opts2, title = "opts") {
    aopts(defaults, "defaults");
    if (opts2 !== void 0)
      aopts(opts2, title);
    const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts2);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    if (typeof hashCons !== "function")
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    info = checkOpts({}, info, "info");
    const hashC = (msg, opts2) => hashCons(opts2).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts2) => hashCons(opts2);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  function randomBytes(bytesLength = 32) {
    anumber(bytesLength, "bytesLength");
    const cr = typeof globalThis === "object" ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined");
    if (bytesLength > 65536)
      throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
    return cr.getRandomValues(new Uint8Array(bytesLength));
  }
  var oidNist = (suffix) => ({
    // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
    // Larger suffix values would need base-128 OID encoding and a different length byte.
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
  });

  // node_modules/@noble/hashes/sha3.js
  var _0n = BigInt(0);
  var _1n = BigInt(1);
  var _2n = BigInt(2);
  var _7n = BigInt(7);
  var _256n = BigInt(256);
  var _0x71n = BigInt(113);
  var SHA3_PI = [];
  var SHA3_ROTL = [];
  var _SHA3_IOTA = [];
  for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n)
        t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
  }
  var IOTAS = split(_SHA3_IOTA, true);
  var SHA3_IOTA_H = IOTAS[0];
  var SHA3_IOTA_L = IOTAS[1];
  var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
  var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  var B = new Uint32Array(5 * 2);
  function keccakP(s, rounds = 24) {
    if (!(s instanceof Uint32Array))
      throw new TypeError('"s" expected Uint32Array(50), got type=' + typeof s);
    if (s.length !== 50)
      throw new RangeError('"s" expected Uint32Array(50), got length=' + s.length);
    anumber(rounds, "rounds");
    if (rounds < 1 || rounds > 24)
      throw new Error('"rounds" expected integer 1..24');
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++)
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      for (let x = 0; x < 10; x += 2) {
        const idx1 = (x + 8) % 10;
        const idx0 = (x + 2) % 10;
        const B0 = B[idx0];
        const B1 = B[idx0 + 1];
        const Th = rotlH(B0, B1, 1) ^ B[idx1];
        const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
        for (let y = 0; y < 50; y += 10) {
          s[x + y] ^= Th;
          s[x + y + 1] ^= Tl;
        }
      }
      let curH = s[2];
      let curL = s[3];
      for (let t = 0; t < 24; t++) {
        const shift = SHA3_ROTL[t];
        const Th = rotlH(curH, curL, shift);
        const Tl = rotlL(curH, curL, shift);
        const PI = SHA3_PI[t];
        curH = s[PI];
        curL = s[PI + 1];
        s[PI] = Th;
        s[PI + 1] = Tl;
      }
      for (let y = 0; y < 50; y += 10) {
        const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
        s[y] ^= ~s[y + 2] & s[y + 4];
        s[y + 1] ^= ~s[y + 3] & s[y + 5];
        s[y + 2] ^= ~s[y + 4] & s[y + 6];
        s[y + 3] ^= ~s[y + 5] & s[y + 7];
        s[y + 4] ^= ~s[y + 6] & s[y + 8];
        s[y + 5] ^= ~s[y + 7] & s[y + 9];
        s[y + 6] ^= ~s[y + 8] & b0;
        s[y + 7] ^= ~s[y + 9] & b1;
        s[y + 8] ^= ~b0 & b2;
        s[y + 9] ^= ~b1 & b3;
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
  }
  var Keccak = class _Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    canXOF;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
      anumber(blockLen, "blockLen");
      anumber(suffix, "suffix");
      anumber(rounds, "rounds");
      abool(enableXOF, "enableXOF");
      this.blockLen = blockLen;
      this.suffix = suffix;
      this.outputLen = outputLen;
      this.enableXOF = enableXOF;
      this.canXOF = enableXOF;
      this.rounds = rounds;
      anumber(outputLen, "outputLen");
      if (!(0 < blockLen && blockLen < 200))
        throw new Error('"blockLen" must be 1..199');
      this.state = new Uint8Array(200);
      this.state32 = u32(this.state);
    }
    clone() {
      return this._cloneInto();
    }
    keccak() {
      swap32IfBE(this.state32);
      keccakP(this.state32, this.rounds);
      swap32IfBE(this.state32);
      this.posOut = 0;
      this.pos = 0;
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { blockLen, state, state32 } = this;
      const len = data.length;
      const canUseU32 = blockLen % 4 === 0 && data.byteOffset % 4 === 0;
      const blockLen32 = blockLen / 4;
      const data32 = canUseU32 && len >= blockLen ? u32(data) : void 0;
      for (let pos = 0; pos < len; ) {
        if (data32 !== void 0 && this.pos === 0 && pos % 4 === 0 && len - pos >= blockLen) {
          for (let i = 0, o = pos / 4; i < blockLen32; i++)
            state32[i] ^= data32[o + i];
          pos += blockLen;
          this.pos = blockLen;
          this.keccak();
          continue;
        }
        const take = Math.min(blockLen - this.pos, len - pos);
        for (let i = 0; i < take; i++)
          state[this.pos++] ^= data[pos++];
        if (this.pos === blockLen)
          this.keccak();
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      const { state, suffix, pos, blockLen } = this;
      state[pos] ^= suffix;
      if ((suffix & 128) !== 0 && pos === blockLen - 1)
        this.keccak();
      state[blockLen - 1] ^= 128;
      this.keccak();
    }
    writeInto(out) {
      aexists(this, false);
      abytes(out);
      this.finish();
      const bufferOut = this.state;
      const { blockLen } = this;
      for (let pos = 0, len = out.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.keccak();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out;
    }
    xofInto(out) {
      if (!this.enableXOF)
        throw new Error("XOF is not enabled");
      return this.writeInto(out);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
      aoutput(out, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.writeInto(out.length === this.outputLen ? out : out.subarray(0, this.outputLen));
      this.destroy();
    }
    digest() {
      const out = new Uint8Array(this.outputLen);
      this.digestInto(out);
      return out;
    }
    destroy() {
      this.destroyed = true;
      clean(this.state);
    }
    _cloneInto(to) {
      const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
      to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
      to.blockLen = blockLen;
      to.state32.set(this.state32);
      to.pos = this.pos;
      to.posOut = this.posOut;
      to.finished = this.finished;
      to.rounds = rounds;
      to.suffix = suffix;
      to.outputLen = outputLen;
      to.enableXOF = enableXOF;
      to.canXOF = this.canXOF;
      to.destroyed = this.destroyed;
      return to;
    }
  };
  var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
  var sha3_256 = /* @__PURE__ */ genKeccak(
    6,
    136,
    32,
    /* @__PURE__ */ oidNist(8)
  );
  var sha3_512 = /* @__PURE__ */ genKeccak(
    6,
    72,
    64,
    /* @__PURE__ */ oidNist(10)
  );
  var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts2 = {}) => {
    opts2 = checkOpts({}, opts2);
    return new Keccak(blockLen, suffix, opts2.dkLen === void 0 ? outputLen : opts2.dkLen, true);
  }, info);
  var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
  var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

  // node_modules/@noble/curves/utils.js
  function aarray(item, title, inner = () => {
  }) {
    if (!Array.isArray(item))
      throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
    for (let i = 0; i < item.length; i++)
      inner(item[i], `${title}[${i}]`);
    return item;
  }
  var abytes2 = (value, length, title) => abytes(value, length, title);
  var anumber2 = anumber;
  function aobject2(value, title = "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
    return value;
  }
  function afunction(value, title) {
    if (typeof value !== "function")
      throw new TypeError(`"${title}" is invalid: expected function, got ${typeof value}`);
    return value;
  }
  var bytesToHex2 = bytesToHex;
  var hexToBytes2 = (hex) => hexToBytes(hex);
  var isBytes2 = isBytes;
  var randomBytes2 = (bytesLength) => randomBytes(bytesLength);
  var _0n2 = /* @__PURE__ */ BigInt(0);
  var _1n2 = /* @__PURE__ */ BigInt(1);
  var atitle2 = (title) => title ? `"${title}" ` : "";
  function abool2(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function abignumber(n) {
    if (typeof n === "bigint") {
      if (!isPosBig(n))
        throw new RangeError("positive bigint expected, got " + n);
    } else
      anumber2(n);
    return n;
  }
  function asafenumber(value, title = "") {
    if (typeof value !== "number") {
      const prefix = title && `"${title}" `;
      throw new TypeError(prefix + "expected number, got type=" + typeof value);
    }
    if (!Number.isSafeInteger(value)) {
      const prefix = title && `"${title}" `;
      throw new RangeError(prefix + "expected safe integer, got " + value);
    }
  }
  function hexToNumber(hex) {
    if (typeof hex !== "string")
      throw new TypeError("hex string expected, got " + typeof hex);
    return hex === "" ? _0n2 : BigInt("0x" + hex);
  }
  function bytesToNumberBE(bytes) {
    return hexToNumber(bytesToHex(bytes));
  }
  function bytesToNumberLE(bytes) {
    return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
  }
  function numberToBytesBE(n, len) {
    anumber(len);
    if (len === 0)
      throw new Error("zero output length is invalid");
    n = abignumber(n);
    const expectedLen = len * 2;
    const hex = n.toString(16);
    if (hex.length > expectedLen)
      throw new RangeError("number is too large");
    return hexToBytes(hex.padStart(expectedLen, "0"));
  }
  function numberToBytesLE(n, len) {
    return numberToBytesBE(n, len).reverse();
  }
  function copyBytes(bytes) {
    return Uint8Array.from(abytes2(bytes));
  }
  function isPosBig(n) {
    return typeof n === "bigint" && _0n2 <= n;
  }
  function inRange(n, min, max) {
    return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
  }
  function aInRange(title, n, min, max) {
    if (!inRange(n, min, max))
      throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
  }
  function bitLen(n) {
    if (n < _0n2)
      throw new Error("expected non-negative bigint, got " + n);
    return n === _0n2 ? 0 : n.toString(2).length;
  }
  var bitMask = (n) => {
    asafenumber(n, "n");
    return (_1n2 << BigInt(n)) - _1n2;
  };
  function validateObject(object, fields = {}, optFields = {}, title = "object") {
    aobject2(object, title);
    aobject2(fields, "fields");
    aobject2(optFields, "optFields");
    function checkField(fieldName, expectedType, isOpt) {
      const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
      const val = object[fieldName];
      if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
        throw new TypeError(`${label} is invalid: expected own property`);
      }
      if (isOpt && val === void 0)
        return;
      const current = typeof val;
      if (current !== expectedType || val === null)
        throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
    }
    const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
    iter(fields, false);
    iter(optFields, true);
  }

  // node_modules/@noble/curves/abstract/modular.js
  var _0n3 = /* @__PURE__ */ BigInt(0);
  var _1n3 = /* @__PURE__ */ BigInt(1);
  var _2n2 = /* @__PURE__ */ BigInt(2);
  var _3n = /* @__PURE__ */ BigInt(3);
  var _4n = /* @__PURE__ */ BigInt(4);
  var _5n = /* @__PURE__ */ BigInt(5);
  var _7n2 = /* @__PURE__ */ BigInt(7);
  var _8n = /* @__PURE__ */ BigInt(8);
  var _9n = /* @__PURE__ */ BigInt(9);
  var _15n = /* @__PURE__ */ BigInt(15);
  var _16n = /* @__PURE__ */ BigInt(16);
  var POW_WINDOWED_MIN = /* @__PURE__ */ BigInt("0x10000000000000000");
  function mod(a, b) {
    if (b <= _0n3)
      throw new Error("mod: expected positive modulus, got " + b);
    const result = a % b;
    return result >= _0n3 ? result : b + result;
  }
  function pow(num, power, modulo) {
    if (modulo <= _1n3)
      throw new Error("pow: expected modulus > 1, got " + modulo);
    if (typeof power !== "bigint")
      throw new TypeError("invalid exponent: expected bigint, got " + typeof power);
    if (power < _0n3)
      throw new Error("invalid exponent, negatives unsupported");
    if (power === _0n3)
      return _1n3;
    if (power === _1n3)
      return num;
    let d = num % modulo;
    if (d < _0n3)
      d += modulo;
    if (power < POW_WINDOWED_MIN) {
      let p2 = _1n3;
      while (power > _0n3) {
        if (power & _1n3)
          p2 = p2 * d % modulo;
        d = d * d % modulo;
        power >>= _1n3;
      }
      return p2;
    }
    const digits = [];
    while (power > _0n3) {
      digits.push(Number(power & _15n));
      power >>= _4n;
    }
    const table = new Array(16);
    table[0] = _1n3;
    table[1] = d;
    for (let i = 2; i < 16; i++)
      table[i] = table[i - 1] * d % modulo;
    let p = table[digits[digits.length - 1]];
    for (let w = digits.length - 2; w >= 0; w--) {
      p = p * p % modulo;
      p = p * p % modulo;
      p = p * p % modulo;
      p = p * p % modulo;
      const digit = digits[w];
      if (digit !== 0)
        p = p * table[digit] % modulo;
    }
    return p;
  }
  function pow2(x, power, modulo) {
    if (modulo <= _1n3)
      throw new Error("pow2: expected modulus > 1, got " + modulo);
    if (power < _0n3)
      throw new Error("pow2: expected non-negative exponent, got " + power);
    let res = x;
    while (power-- > _0n3) {
      res *= res;
      res %= modulo;
    }
    return res;
  }
  function invert(number, modulo) {
    if (number === _0n3)
      throw new Error("invert: expected non-zero number");
    if (modulo <= _1n3)
      throw new Error("invert: expected modulus > 1, got " + modulo);
    let a = mod(number, modulo);
    let b = modulo;
    let x = _0n3, u = _1n3;
    while (a !== _0n3) {
      const q = b / a;
      const r = b - a * q;
      const m = x - u * q;
      b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== _1n3)
      throw new Error("invert: does not exist");
    return mod(x, modulo);
  }
  function assertIsSquare(Fp, root, n) {
    const F3 = Fp;
    if (!F3.eql(F3.sqr(root), n))
      throw new Error("Cannot find square root");
  }
  function aoddModulus(order, fnName) {
    if ((order & _1n3) === _0n3)
      throw new Error(fnName + ": expected odd modulus, got " + order);
  }
  function sqrt3mod4(Fp, n) {
    const F3 = Fp;
    const p1div4 = (F3.ORDER + _1n3) / _4n;
    const root = F3.pow(n, p1div4);
    assertIsSquare(F3, root, n);
    return root;
  }
  function sqrt5mod8(Fp, n) {
    const F3 = Fp;
    const p5div8 = (F3.ORDER - _5n) / _8n;
    const n2 = F3.mul(n, _2n2);
    const v = F3.pow(n2, p5div8);
    const nv = F3.mul(n, v);
    const i = F3.mul(F3.mul(nv, _2n2), v);
    const root = F3.mul(nv, F3.sub(i, F3.ONE));
    assertIsSquare(F3, root, n);
    return root;
  }
  function sqrt9mod16(P) {
    const Fp_ = Field(P);
    const tn = tonelliShanks(P);
    const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
    const c2 = tn(Fp_, c1);
    const c3 = tn(Fp_, Fp_.neg(c1));
    const c4 = (P + _7n2) / _16n;
    return ((Fp, n) => {
      const F3 = Fp;
      let tv1 = F3.pow(n, c4);
      let tv2 = F3.mul(tv1, c1);
      const tv3 = F3.mul(tv1, c2);
      const tv4 = F3.mul(tv1, c3);
      const e1 = F3.eql(F3.sqr(tv2), n);
      const e2 = F3.eql(F3.sqr(tv3), n);
      tv1 = F3.cmov(tv1, tv2, e1);
      tv2 = F3.cmov(tv4, tv3, e2);
      const e3 = F3.eql(F3.sqr(tv2), n);
      const root = F3.cmov(tv1, tv2, e3);
      assertIsSquare(F3, root, n);
      return root;
    });
  }
  function tonelliShanks(P) {
    if (P < _3n)
      throw new Error("sqrt is not defined for small field");
    aoddModulus(P, "tonelliShanks");
    let Q3 = P - _1n3;
    let S = 0;
    while (Q3 % _2n2 === _0n3) {
      Q3 /= _2n2;
      S++;
    }
    let Z = _2n2;
    const _Fp = Field(P);
    while (FpLegendre(_Fp, Z) === 1) {
      if (Z++ > 1e3)
        throw new Error("Cannot find square root: probably non-prime P");
    }
    if (S === 1)
      return sqrt3mod4;
    let cc = _Fp.pow(Z, Q3);
    const Q1div2 = (Q3 + _1n3) / _2n2;
    return function tonelliSlow(Fp, n) {
      const F3 = Fp;
      if (F3.is0(n))
        return n;
      if (FpLegendre(F3, n) !== 1)
        throw new Error("Cannot find square root");
      let M = S;
      let c = F3.mul(F3.ONE, cc);
      let t = F3.pow(n, Q3);
      let R = F3.pow(n, Q1div2);
      while (!F3.eql(t, F3.ONE)) {
        if (F3.is0(t))
          throw new Error("Cannot find square root: probably non-prime P");
        let i = 1;
        let t_tmp = F3.sqr(t);
        while (!F3.eql(t_tmp, F3.ONE)) {
          i++;
          t_tmp = F3.sqr(t_tmp);
          if (i === M)
            throw new Error("Cannot find square root");
        }
        const exponent = _1n3 << BigInt(M - i - 1);
        const b = F3.pow(c, exponent);
        M = i;
        c = F3.sqr(b);
        t = F3.mul(t, c);
        R = F3.mul(R, b);
      }
      return R;
    };
  }
  function FpSqrt(P) {
    aoddModulus(P, "Fp.sqrt");
    if (P % _4n === _3n)
      return sqrt3mod4;
    if (P % _8n === _5n)
      return sqrt5mod8;
    if (P % _16n === _9n)
      return sqrt9mod16(P);
    return tonelliShanks(P);
  }
  var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n3) === _1n3;
  var FIELD_FIELDS = [
    "create",
    "isValid",
    "is0",
    "neg",
    "inv",
    "sqrt",
    "sqr",
    "eql",
    "add",
    "sub",
    "mul",
    "pow",
    "div",
    "addN",
    "subN",
    "mulN",
    "sqrN"
  ];
  function validateField(field) {
    aobject2(field, "field");
    if (typeof field.ORDER !== "bigint")
      throw new TypeError('param "ORDER" is invalid: expected bigint, got ' + typeof field.ORDER);
    asafenumber(field.BYTES, "BYTES");
    asafenumber(field.BITS, "BITS");
    for (const name of FIELD_FIELDS)
      afunction(field[name], "field." + name);
    if (field.BYTES < 1 || field.BITS < 1)
      throw new Error("invalid field: expected BYTES/BITS > 0");
    if (field.ORDER <= _1n3)
      throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
    return field;
  }
  function FpInvertBatch(Fp, nums, passZero = false) {
    validateField(Fp);
    aarray(nums, "nums");
    abool2(passZero, "passZero");
    const F3 = Fp;
    const inverted = new Array(nums.length).fill(passZero ? F3.ZERO : void 0);
    const multipliedAcc = nums.reduce((acc, num, i) => {
      if (F3.is0(num))
        return acc;
      inverted[i] = acc;
      return F3.mul(acc, num);
    }, F3.ONE);
    const invertedAcc = F3.inv(multipliedAcc);
    nums.reduceRight((acc, num, i) => {
      if (F3.is0(num))
        return acc;
      inverted[i] = F3.mul(acc, inverted[i]);
      return F3.mul(acc, num);
    }, invertedAcc);
    return inverted;
  }
  function FpLegendre(Fp, n) {
    validateField(Fp);
    const F3 = Fp;
    aoddModulus(F3.ORDER, "FpLegendre");
    const p1mod2 = (F3.ORDER - _1n3) / _2n2;
    const powered = F3.pow(n, p1mod2);
    const yes = F3.eql(powered, F3.ONE);
    const zero = F3.eql(powered, F3.ZERO);
    const no = F3.eql(powered, F3.neg(F3.ONE));
    if (!yes && !zero && !no)
      throw new Error("invalid Legendre symbol result");
    return yes ? 1 : zero ? 0 : -1;
  }
  function nLength(n, nBitLength) {
    if (nBitLength !== void 0)
      anumber2(nBitLength);
    if (n <= _0n3)
      throw new Error("invalid n length: expected positive n, got " + n);
    if (nBitLength !== void 0 && nBitLength < 1)
      throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
    const bits = bitLen(n);
    if (nBitLength !== void 0 && nBitLength < bits)
      throw new Error(`invalid n length: expected nBitLength (${nBitLength}) >= bitLen(n) (${bits})`);
    const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
    const nByteLength = Math.ceil(_nBitLength / 8);
    return { nBitLength: _nBitLength, nByteLength };
  }
  var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
  var _Field = class {
    ORDER;
    BITS;
    BYTES;
    isLE;
    ZERO = _0n3;
    ONE = _1n3;
    _lengths;
    _mod;
    constructor(ORDER, opts2 = {}) {
      if (ORDER <= _1n3)
        throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
      let _nbitLength = void 0;
      this.isLE = false;
      if (opts2 != null && typeof opts2 === "object") {
        if (typeof opts2.BITS === "number")
          _nbitLength = opts2.BITS;
        if (typeof opts2.sqrt === "function")
          Object.defineProperty(this, "sqrt", { value: opts2.sqrt, enumerable: true });
        if (typeof opts2.isLE === "boolean")
          this.isLE = opts2.isLE;
        if (opts2.allowedLengths)
          this._lengths = Object.freeze(opts2.allowedLengths.slice());
        if (typeof opts2.modFromBytes === "boolean")
          this._mod = opts2.modFromBytes;
      }
      const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
      if (nByteLength > 2048)
        throw new Error("invalid field: expected ORDER of <= 2048 bytes");
      this.ORDER = ORDER;
      this.BITS = nBitLength;
      this.BYTES = nByteLength;
      Object.freeze(this);
    }
    create(num) {
      return mod(num, this.ORDER);
    }
    isValid(num) {
      if (typeof num !== "bigint")
        throw new TypeError("invalid field element: expected bigint, got " + typeof num);
      return _0n3 <= num && num < this.ORDER;
    }
    is0(num) {
      return num === _0n3;
    }
    // is valid and invertible
    isValidNot0(num) {
      return !this.is0(num) && this.isValid(num);
    }
    isOdd(num) {
      return (num & _1n3) === _1n3;
    }
    neg(num) {
      return mod(-num, this.ORDER);
    }
    eql(lhs, rhs) {
      return lhs === rhs;
    }
    sqr(num) {
      return mod(num * num, this.ORDER);
    }
    add(lhs, rhs) {
      return mod(lhs + rhs, this.ORDER);
    }
    sub(lhs, rhs) {
      return mod(lhs - rhs, this.ORDER);
    }
    mul(lhs, rhs) {
      return mod(lhs * rhs, this.ORDER);
    }
    pow(num, power) {
      return pow(num, power, this.ORDER);
    }
    div(lhs, rhs) {
      return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
    }
    // Same as above, but doesn't normalize
    sqrN(num) {
      return num * num;
    }
    addN(lhs, rhs) {
      return lhs + rhs;
    }
    subN(lhs, rhs) {
      return lhs - rhs;
    }
    mulN(lhs, rhs) {
      return lhs * rhs;
    }
    inv(num) {
      return invert(num, this.ORDER);
    }
    sqrt(num) {
      let sqrt = FIELD_SQRT.get(this);
      if (!sqrt)
        FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
      return sqrt(this, num);
    }
    toBytes(num) {
      return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
    }
    fromBytes(bytes, skipValidation = false) {
      abytes2(bytes);
      const { _lengths: allowedLengths, BYTES, isLE: isLE3, ORDER, _mod: modFromBytes } = this;
      if (allowedLengths) {
        if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE3 ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      let scalar = isLE3 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      if (modFromBytes)
        scalar = mod(scalar, ORDER);
      if (!skipValidation) {
        if (!this.isValid(scalar))
          throw new Error("invalid field element: outside of range 0..ORDER");
      }
      return scalar;
    }
    // TODO: we don't need it here, move out to separate fn
    invertBatch(lst) {
      return FpInvertBatch(this, lst, true);
    }
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov(a, b, condition) {
      abool2(condition, "condition");
      return condition ? b : a;
    }
  };
  function Field(ORDER, opts2 = {}) {
    Object.freeze(_Field.prototype);
    return new _Field(ORDER, opts2);
  }

  // node_modules/@noble/curves/abstract/fft.js
  function checkU32(n, title = "n") {
    if (typeof n !== "number")
      throw new TypeError(`wrong u32 integer "${title}": expected number, got type=${typeof n}`);
    if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
      throw new RangeError(`wrong u32 integer "${title}": expected 0..4294967295, got ${n}`);
    return n;
  }
  function isPowerOfTwo(x) {
    checkU32(x, "x");
    return (x & x - 1) === 0 && x !== 0;
  }
  function reverseBits(n, bits) {
    checkU32(n);
    if (typeof bits !== "number")
      throw new TypeError('"bits" expected number, got type=' + typeof bits);
    if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
      throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
    let reversed = 0;
    for (let i = 0; i < bits; i++, n >>>= 1)
      reversed = reversed << 1 | n & 1;
    return reversed >>> 0;
  }
  function log2(n) {
    checkU32(n);
    return 31 - Math.clz32(n);
  }
  function bitReversalInplace(values) {
    if (!values || typeof values !== "object" || typeof values.length !== "number")
      throw new TypeError('"values" expected array-like, got type=' + typeof values);
    const n = values.length;
    if (!isPowerOfTwo(n))
      throw new Error("expected positive power-of-two length, got " + n);
    const bits = log2(n);
    for (let i = 0; i < n; i++) {
      const j = reverseBits(i, bits);
      if (i < j) {
        const tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
      }
    }
    return values;
  }
  var FFTCore = (F3, coreOpts) => {
    validateObject(coreOpts, { N: "number", roots: "object", dit: "boolean" }, { invertButterflies: "boolean", skipStages: "number", brp: "boolean" }, "coreOpts");
    const { N: N3, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
    checkU32(N3, "coreOpts.N");
    const bits = log2(N3);
    if (!isPowerOfTwo(N3))
      throw new Error("FFT: Polynomial size should be power of two");
    checkU32(skipStages, "coreOpts.skipStages");
    const maxSkipStages = bits === 0 ? 0 : bits - 1;
    if (skipStages > maxSkipStages)
      throw new Error(`FFT: wrong skipStages: expected 0 <= skipStages <= ${maxSkipStages}`);
    if (roots.length !== N3)
      throw new Error(`FFT: wrong roots length: expected ${N3}, got ${roots.length}`);
    const isDit = dit !== invertButterflies;
    return (values) => {
      if (values.length !== N3)
        throw new Error("FFT: wrong Polynomial length");
      if (dit && brp)
        bitReversalInplace(values);
      for (let i = 0, g = 1; i < bits - skipStages; i++) {
        const s = dit ? i + 1 + skipStages : bits - i;
        const m = 1 << s;
        const m2 = m >> 1;
        const stride = N3 >> s;
        for (let k = 0; k < N3; k += m) {
          for (let j = 0, grp = g++; j < m2; j++) {
            const rootPos = invertButterflies ? dit ? N3 - grp : grp : j * stride;
            const i0 = k + j;
            const i1 = k + j + m2;
            const omega = roots[rootPos];
            const b = values[i1];
            const a = values[i0];
            if (isDit) {
              const t = F3.mul(b, omega);
              values[i0] = F3.add(a, t);
              values[i1] = F3.sub(a, t);
            } else if (invertButterflies) {
              values[i0] = F3.add(b, a);
              values[i1] = F3.mul(F3.sub(b, a), omega);
            } else {
              values[i0] = F3.add(a, b);
              values[i1] = F3.mul(F3.sub(a, b), omega);
            }
          }
        }
      }
      if (!dit && brp)
        bitReversalInplace(values);
      return values;
    };
  };

  // node_modules/@noble/post-quantum/utils.js
  var abytesDoc = abytes;
  var randomBytes3 = randomBytes;
  function aarray2(item, title, inner = () => {
  }) {
    if (!Array.isArray(item))
      throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
    for (let i = 0; i < item.length; i++)
      inner(item[i], `${title}[${i}]`);
    return item;
  }
  function aobject3(value, title = "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
    return value;
  }
  function equalBytes(a, b) {
    a = abytes(a);
    b = abytes(b);
    if (a.length !== b.length)
      return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
      diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function copyBytes2(bytes) {
    return new Uint8Array(abytes(bytes));
  }
  function validateOpts(opts2) {
    if (isBytes(opts2))
      throw new TypeError('"opts" expected object, got Uint8Array');
    aobject3(opts2, "opts");
    const proto = Object.getPrototypeOf(opts2);
    if (proto !== null && proto !== Object.prototype)
      throw new TypeError('"opts" expected a plain object');
  }
  var VER_OPT_KEYS = /* @__PURE__ */ Object.freeze([
    "context"
  ]);
  var SIG_OPT_KEYS = /* @__PURE__ */ Object.freeze([
    "context",
    "extraEntropy"
  ]);
  function checkOptKeys(opts2, allowed) {
    validateOpts(opts2);
    const normalized = Object.assign(/* @__PURE__ */ Object.create(null), opts2);
    for (const [k, v] of Object.entries(normalized)) {
      if (v === void 0)
        continue;
      if (!allowed.includes(k))
        throw new TypeError('unexpected option "' + String(k) + '"; expected one of: ' + allowed.join(", "));
    }
    return Object.freeze(normalized);
  }
  function validateVerOpts(opts2, allowed = VER_OPT_KEYS) {
    const normalized = checkOptKeys(opts2, allowed);
    if (normalized.context !== void 0)
      abytes(normalized.context, void 0, "opts.context");
    return normalized;
  }
  function validateSigOpts(opts2, allowed = SIG_OPT_KEYS) {
    const normalized = checkOptKeys(opts2, allowed);
    if (normalized.context !== void 0)
      abytes(normalized.context, void 0, "opts.context");
    if (normalized.extraEntropy !== false && normalized.extraEntropy !== void 0)
      abytes(normalized.extraEntropy, void 0, "opts.extraEntropy");
    return normalized;
  }
  function splitCoder(label, ...lengths) {
    const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
    const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
    return {
      bytesLen,
      encode: (bufs) => {
        const res = new Uint8Array(bytesLen);
        for (let i = 0, pos = 0; i < lengths.length; i++) {
          const c = lengths[i];
          const l = getLength(c);
          const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
          abytes(b, l, label);
          res.set(b, pos);
          if (typeof c !== "number")
            b.fill(0);
          pos += l;
        }
        return res;
      },
      decode: (buf) => {
        abytes(buf, bytesLen, label);
        const res = [];
        for (const c of lengths) {
          const l = getLength(c);
          const b = buf.subarray(0, l);
          res.push(typeof c === "number" ? b : c.decode(b));
          buf = buf.subarray(l);
        }
        return res;
      }
    };
  }
  function vecCoder(c, vecLen) {
    const coder = c;
    const bytesLen = vecLen * coder.bytesLen;
    return {
      bytesLen,
      encode: (u) => {
        const uArr = aarray2(u, "u");
        if (uArr.length !== vecLen)
          throw new RangeError(`vecCoder.encode: wrong length=${uArr.length}. Expected: ${vecLen}`);
        const res = new Uint8Array(bytesLen);
        for (let i = 0, pos = 0; i < uArr.length; i++) {
          const b = coder.encode(uArr[i]);
          res.set(b, pos);
          b.fill(0);
          pos += b.length;
        }
        return res;
      },
      decode: (a) => {
        abytes(a, bytesLen);
        const r = [];
        for (let i = 0; i < a.length; i += coder.bytesLen)
          r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
        return r;
      }
    };
  }
  function cleanBytes(...list) {
    for (const t of list) {
      if (Array.isArray(t))
        for (const b of t)
          b.fill(0);
      else
        t.fill(0);
    }
  }
  function getMask(bits) {
    anumber(bits, "bits");
    if (bits > 32)
      throw new RangeError('"bits" expected <= 32, got ' + bits);
    return bits === 32 ? 4294967295 : ~(-1 << bits) >>> 0;
  }
  var EMPTY = /* @__PURE__ */ Uint8Array.of();
  function getMessage(msg, ctx = EMPTY) {
    abytes(msg, void 0, "msg");
    abytes(ctx, void 0, "ctx");
    if (ctx.length > 255)
      throw new RangeError("context should be 255 bytes or less");
    return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
  }
  var oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2]);
  var XOF_OID_OUTPUT_LEN = /* @__PURE__ */ (() => ({
    "060960864801650304020b": 32,
    // id-shake128, SHAKE128(M, 256)
    "060960864801650304020c": 64
    // id-shake256, SHAKE256(M, 512)
  }))();
  function checkHash(hash, requiredStrength = 0) {
    if (typeof hash !== "function" || typeof hash.create !== "function")
      throw new TypeError('"hash" expected hash function, got type=' + typeof hash);
    ahash(hash);
    anumber(requiredStrength, "requiredStrength");
    const oid = hash.oid;
    abytes(oid, void 0, "hash.oid");
    if (!equalBytes(oid.subarray(0, 10), oidNistP))
      throw new Error('"hash.oid" is invalid: expected NIST hash');
    const xofLen = XOF_OID_OUTPUT_LEN[bytesToHex(oid)];
    if (xofLen !== void 0 && hash.outputLen !== xofLen) {
      throw new Error("Pre-hash XOF output length must be " + xofLen + " bytes for this OID, got: " + hash.outputLen);
    }
    const collisionResistance = hash.outputLen * 8 / 2;
    if (requiredStrength > collisionResistance) {
      throw new Error("Pre-hash security strength too low: " + collisionResistance + ", required: " + requiredStrength);
    }
  }
  function getMessagePrehash(hash, msg, ctx = EMPTY) {
    checkHash(hash);
    abytes(msg, void 0, "msg");
    abytes(ctx, void 0, "ctx");
    if (ctx.length > 255)
      throw new RangeError("context should be 255 bytes or less");
    const hashed = hash(msg);
    return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid, hashed);
  }

  // node_modules/@noble/post-quantum/_crystals.js
  var genCrystals = (opts2) => {
    const { newPoly: newPoly2, N: N3, Q: Q3, F: F3, ROOT_OF_UNITY: ROOT_OF_UNITY3, brvBits, isKyber } = opts2;
    const mod2 = (a, modulo = Q3) => {
      const result = a % modulo | 0;
      return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
    };
    const smod = (a, modulo = Q3) => {
      const r = mod2(a, modulo) | 0;
      return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
    };
    function getZettas() {
      const out = newPoly2(N3);
      for (let i = 0; i < N3; i++) {
        const b = reverseBits(i, brvBits);
        const p = BigInt(ROOT_OF_UNITY3) ** BigInt(b) % BigInt(Q3);
        out[i] = Number(p) | 0;
      }
      return out;
    }
    const nttZetas = getZettas();
    const inv = (_a) => {
      throw new Error("not implemented");
    };
    const field = isKyber ? {
      add: (a, b) => {
        const r = a + b | 0;
        return r >= Q3 ? r - Q3 | 0 : r;
      },
      sub: (a, b) => {
        const r = a - b | 0;
        return r < 0 ? r + Q3 | 0 : r;
      },
      mul: (a, b) => mod2((a | 0) * (b | 0)) | 0,
      inv
    } : {
      add: (a, b) => mod2((a | 0) + (b | 0)) | 0,
      sub: (a, b) => mod2((a | 0) - (b | 0)) | 0,
      mul: (a, b) => mod2((a | 0) * (b | 0)) | 0,
      inv
    };
    const nttOpts = {
      N: N3,
      roots: nttZetas,
      invertButterflies: true,
      skipStages: isKyber ? 1 : 0,
      brp: false
    };
    const dif = FFTCore(field, { dit: false, ...nttOpts });
    const dit = FFTCore(field, { dit: true, ...nttOpts });
    const NTT = {
      encode: (r) => {
        return dif(r);
      },
      decode: (r) => {
        dit(r);
        for (let i = 0; i < r.length; i++)
          r[i] = mod2(F3 * r[i]);
        return r;
      }
    };
    const bitsCoder = (d, c) => {
      for (let i = 0, bufLen = 0; i < N3; i++) {
        bufLen += d;
        if (bufLen > 32)
          getMask(bufLen);
        bufLen %= 8;
      }
      const mask = getMask(d);
      const bytesLen = d * (N3 / 8);
      return {
        bytesLen,
        encode: (poly_) => {
          const poly = poly_;
          const r = new Uint8Array(bytesLen);
          for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
            buf |= (c.encode(poly[i]) & mask) << bufLen;
            bufLen += d;
            for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
              r[pos++] = buf & 255;
          }
          return r;
        },
        decode: (bytes) => {
          const r = newPoly2(N3);
          for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
            buf |= bytes[i] << bufLen;
            bufLen += 8;
            for (; bufLen >= d; bufLen -= d, buf >>= d)
              r[pos++] = c.decode(buf & mask);
          }
          return r;
        }
      };
    };
    return {
      mod: mod2,
      smod,
      nttZetas,
      NTT: {
        encode: (r) => NTT.encode(r),
        decode: (r) => NTT.decode(r)
      },
      bitsCoder
    };
  };
  var createXofShake = (shake) => (seed, blockLen) => {
    if (!blockLen)
      blockLen = shake.blockLen;
    const _seed = new Uint8Array(seed.length + 2);
    _seed.set(seed);
    const seedLen = seed.length;
    const buf = new Uint8Array(blockLen);
    let h = shake.create({});
    let calls = 0;
    let xofs = 0;
    return {
      stats: () => ({ calls, xofs }),
      get: (x, y) => {
        _seed[seedLen + 0] = x;
        _seed[seedLen + 1] = y;
        h.destroy();
        h = shake.create({}).update(_seed);
        calls++;
        return () => {
          xofs++;
          return h.xofInto(buf);
        };
      },
      clean: () => {
        h.destroy();
        cleanBytes(buf, _seed);
      }
    };
  };
  var XOF128 = /* @__PURE__ */ createXofShake(shake128);
  var XOF256 = /* @__PURE__ */ createXofShake(shake256);

  // node_modules/@noble/post-quantum/ml-kem.js
  var N = 256;
  var Q = 3329;
  var F = 3303;
  var ROOT_OF_UNITY = 17;
  var crystals = /* @__PURE__ */ genCrystals({
    N,
    Q,
    F,
    ROOT_OF_UNITY,
    newPoly: (n) => new Uint16Array(n),
    brvBits: 7,
    isKyber: true
  });
  var PARAMS = /* @__PURE__ */ (() => Object.freeze({
    512: Object.freeze({ N, Q, K: 2, ETA1: 3, ETA2: 2, du: 10, dv: 4, RBGstrength: 128 }),
    768: Object.freeze({ N, Q, K: 3, ETA1: 2, ETA2: 2, du: 10, dv: 4, RBGstrength: 192 }),
    1024: Object.freeze({ N, Q, K: 4, ETA1: 2, ETA2: 2, du: 11, dv: 5, RBGstrength: 256 })
  }))();
  var compress = (d) => {
    if (d >= 12)
      return { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i };
    const a = 2 ** (d - 1);
    return {
      // This only matches standalone Compress_d after bitsCoder masks the result into Z_(2^d).
      encode: (i) => ((i << d) + Q / 2) / Q,
      // const decompress = (i: number) => round((Q / 2 ** d) * i);
      decode: (i) => i * Q + a >>> d
    };
  };
  var byteCoder = (d) => crystals.bitsCoder(d, d === 12 ? { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i } : { encode: (i) => i, decode: (i) => i });
  var polyCoder = (d) => d === 12 ? byteCoder(12) : crystals.bitsCoder(d, compress(d));
  function polyAdd(a_, b_) {
    const a = a_;
    const b = b_;
    for (let i = 0; i < N; i++) {
      const r = a[i] + b[i];
      a[i] = r >= Q ? r - Q : r;
    }
  }
  function polySub(a_, b_) {
    const a = a_;
    const b = b_;
    for (let i = 0; i < N; i++) {
      const r = a[i] - b[i];
      a[i] = r < 0 ? r + Q : r;
    }
  }
  function BaseCaseMultiply(a0, a1, b0, b1, zeta) {
    const c0 = crystals.mod(crystals.mod(a1 * b1) * zeta + a0 * b0);
    const c1 = crystals.mod(a0 * b1 + a1 * b0);
    return { c0, c1 };
  }
  function MultiplyNTTs(f_, g_) {
    const f = f_;
    const g = g_;
    for (let i = 0; i < N / 2; i++) {
      let z = crystals.nttZetas[64 + (i >> 1)];
      if (i & 1)
        z = -z;
      const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
      f[2 * i + 0] = c0;
      f[2 * i + 1] = c1;
    }
    return f;
  }
  function SampleNTT(xof_) {
    const xof = xof_;
    const r = new Uint16Array(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      if (b.length % 3)
        throw new Error("SampleNTT: unaligned block");
      for (let i = 0; j < N && i + 3 <= b.length; i += 3) {
        const d1 = (b[i + 0] >> 0 | b[i + 1] << 8) & 4095;
        const d2 = (b[i + 1] >> 4 | b[i + 2] << 4) & 4095;
        if (d1 < Q)
          r[j++] = d1;
        if (j < N && d2 < Q)
          r[j++] = d2;
      }
    }
    return r;
  }
  var sampleCBDBytes = (buf, eta) => {
    const r = new Uint16Array(N);
    const b32 = u32(buf);
    swap32IfBE(b32);
    let len = 0;
    for (let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++) {
      let b = b32[i];
      for (let j = 0; j < 32; j++) {
        bb += b & 1;
        b >>= 1;
        len += 1;
        if (len === eta) {
          t0 = bb;
          bb = 0;
        } else if (len === 2 * eta) {
          r[p++] = crystals.mod(t0 - bb);
          bb = 0;
          len = 0;
        }
      }
    }
    swap32IfBE(b32);
    if (len)
      throw new Error(`sampleCBD: leftover bits: ${len}`);
    return r;
  };
  function sampleCBD(PRF_, seed, nonce, eta) {
    const PRF = PRF_;
    return sampleCBDBytes(PRF(eta * N / 4, seed, nonce), eta);
  }
  var genKPKE = (opts_) => {
    const opts2 = opts_;
    const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts2;
    const poly1 = polyCoder(1);
    const polyV = polyCoder(dv);
    const polyU = polyCoder(du);
    const publicCoder = splitCoder("publicKey", vecCoder(polyCoder(12), K), 32);
    const secretCoder = vecCoder(polyCoder(12), K);
    const cipherCoder = splitCoder("ciphertext", vecCoder(polyU, K), polyV);
    const seedCoder = splitCoder("seed", 32, 32);
    const encryptCore = (tHat, getA, msg, seed) => {
      const rHat = [];
      for (let i = 0; i < K; i++)
        rHat.push(crystals.NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
      const tmp2 = new Uint16Array(N);
      const u = [];
      for (let i = 0; i < K; i++) {
        const e1 = sampleCBD(PRF, seed, K + i, ETA2);
        const tmp = new Uint16Array(N);
        for (let j = 0; j < K; j++) {
          const aij = getA(i, j);
          polyAdd(tmp, MultiplyNTTs(aij, rHat[j]));
        }
        polyAdd(e1, crystals.NTT.decode(tmp));
        u.push(e1);
        polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i]));
        cleanBytes(tmp);
      }
      const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
      polyAdd(e2, crystals.NTT.decode(tmp2));
      const v = poly1.decode(msg);
      polyAdd(v, e2);
      cleanBytes(tHat, rHat, tmp2, e2);
      return cipherCoder.encode([u, v]);
    };
    return {
      secretCoder,
      lengths: {
        secretKey: secretCoder.bytesLen,
        publicKey: publicCoder.bytesLen,
        cipherText: cipherCoder.bytesLen
      },
      keygen: (seed) => {
        abytesDoc(seed, 32, "seed");
        const seedDst = new Uint8Array(33);
        seedDst.set(seed);
        seedDst[32] = K;
        const seedHash = HASH512(seedDst);
        const [rho, sigma] = seedCoder.decode(seedHash);
        const sHat = [];
        const tHat = [];
        for (let i = 0; i < K; i++)
          sHat.push(crystals.NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
        const x = XOF(rho);
        for (let i = 0; i < K; i++) {
          const e = crystals.NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
          for (let j = 0; j < K; j++) {
            const aji = SampleNTT(x.get(j, i));
            polyAdd(e, MultiplyNTTs(aji, sHat[j]));
          }
          tHat.push(e);
        }
        x.clean();
        const res = {
          publicKey: publicCoder.encode([tHat, rho]),
          secretKey: secretCoder.encode(sHat)
        };
        cleanBytes(rho, sigma, sHat, tHat, seedDst, seedHash);
        return res;
      },
      encrypt: (publicKey, msg, seed) => {
        const [tHat, rho] = publicCoder.decode(publicKey);
        const x = XOF(rho);
        const res = encryptCore(tHat, (i, j) => SampleNTT(x.get(i, j)), msg, seed);
        x.clean();
        return res;
      },
      // Expands the full Â matrix (public data derived from rho) once, so repeated encryptions
      // against the same ek skip the K² SampleNTT XOF expansions. Cached polys are copied per
      // call because encryptCore mutates its inputs in place.
      prepare: (publicKey) => {
        const [tHat, rho] = publicCoder.decode(publicKey);
        const x = XOF(rho);
        const A = [];
        for (let i = 0; i < K; i++)
          for (let j = 0; j < K; j++)
            A.push(SampleNTT(x.get(i, j)));
        x.clean();
        return {
          encrypt: (msg, seed) => encryptCore(tHat.map((p) => p.slice()), (i, j) => A[i * K + j].slice(), msg, seed),
          clean: () => cleanBytes(tHat, A)
        };
      },
      decrypt: (cipherText, privateKey) => {
        const [u, v] = cipherCoder.decode(cipherText);
        const sk = secretCoder.decode(privateKey);
        const tmp = new Uint16Array(N);
        for (let i = 0; i < K; i++)
          polyAdd(tmp, MultiplyNTTs(sk[i], crystals.NTT.encode(u[i])));
        polySub(v, crystals.NTT.decode(tmp));
        const res = poly1.encode(v);
        cleanBytes(tmp, sk, u, v);
        return res;
      }
    };
  };
  function createKyber(opts2) {
    const rawOpts = opts2;
    const KPKE = genKPKE(rawOpts);
    const { HASH256, HASH512, KDF } = rawOpts;
    const { secretCoder: KPKESecretCoder, lengths } = KPKE;
    const secretCoder = splitCoder("secretKey", lengths.secretKey, lengths.publicKey, 32, 32);
    const msgLen = 32;
    const seedLen = 64;
    const validateModulus = (publicKey, fn) => {
      const eke = publicKey.subarray(0, 384 * rawOpts.K);
      const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes2(eke)));
      const ok = equalBytes(ek, eke);
      cleanBytes(ek);
      if (!ok)
        throw new Error(`ML-KEM.${fn}: wrong publicKey modulus`);
    };
    const kemLengths = Object.freeze({
      ...lengths,
      seed: 64,
      msg: msgLen,
      msgRand: msgLen,
      secretKey: secretCoder.bytesLen
    });
    return Object.freeze({
      info: Object.freeze({ type: "ml-kem" }),
      lengths: kemLengths,
      keygen: (seed) => {
        const ownSeed = seed === void 0;
        const s = ownSeed ? randomBytes3(seedLen) : seed;
        let sk;
        let publicKeyHash;
        try {
          abytesDoc(s, seedLen, "seed");
          const keys = KPKE.keygen(s.subarray(0, 32));
          const publicKey = keys.publicKey;
          sk = keys.secretKey;
          publicKeyHash = HASH256(publicKey);
          const secretKey = secretCoder.encode([sk, publicKey, publicKeyHash, s.subarray(32)]);
          return {
            publicKey,
            secretKey
          };
        } finally {
          if (sk !== void 0)
            cleanBytes(sk);
          if (publicKeyHash !== void 0)
            cleanBytes(publicKeyHash);
          if (ownSeed)
            cleanBytes(s);
        }
      },
      getPublicKey: (secretKey) => {
        const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
        return Uint8Array.from(publicKey);
      },
      encapsulate: (publicKey, msg) => {
        const ownMsg = msg === void 0;
        const m = ownMsg ? randomBytes3(msgLen) : msg;
        let kr;
        try {
          abytesDoc(publicKey, lengths.publicKey, "publicKey");
          abytesDoc(m, msgLen, "message");
          validateModulus(publicKey, "encapsulate");
          kr = HASH512.create().update(m).update(HASH256(publicKey)).digest();
          const cipherText = KPKE.encrypt(publicKey, m, kr.subarray(32, 64));
          return {
            cipherText,
            sharedSecret: kr.subarray(0, 32)
          };
        } finally {
          if (kr !== void 0)
            cleanBytes(kr.subarray(32));
          if (ownMsg)
            cleanBytes(m);
        }
      },
      decapsulate: (cipherText, secretKey) => {
        abytesDoc(secretKey, secretCoder.bytesLen, "secretKey");
        abytesDoc(cipherText, lengths.cipherText, "cipherText");
        const k768 = secretCoder.bytesLen - 96;
        const start = k768 + 32;
        const test = HASH256(secretKey.subarray(k768 / 2, start));
        if (!equalBytes(test, secretKey.subarray(start, start + 32)))
          throw new Error("invalid secretKey: hash check failed");
        const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
        const msg = KPKE.decrypt(cipherText, sk);
        const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
        const Khat = kr.subarray(0, 32);
        const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
        const isValid = equalBytes(cipherText, cipherText2);
        const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
        cleanBytes(msg, cipherText2, kr.subarray(32), !isValid ? Khat : Kbar);
        return isValid ? Khat : Kbar;
      },
      /**
       * Experimental prototype: pre-expand a public key so repeated encapsulate/decapsulate
       * against the same key skip re-validation, H(ek), t̂ decoding and the K² SampleNTT
       * XOF expansions of Â. Only public data is cached; see {@link KEMPrepared}.
       */
      prepare: (publicKey) => {
        abytesDoc(publicKey, lengths.publicKey, "publicKey");
        validateModulus(publicKey, "prepare");
        const ek = copyBytes2(publicKey);
        const publicKeyHash = HASH256(ek);
        const cached = KPKE.prepare(ek);
        return Object.freeze({
          publicKey: ek,
          encapsulate: (msg) => {
            const ownMsg = msg === void 0;
            const m = ownMsg ? randomBytes3(msgLen) : msg;
            let kr;
            try {
              abytesDoc(m, msgLen, "message");
              kr = HASH512.create().update(m).update(publicKeyHash).digest();
              const cipherText = cached.encrypt(m, kr.subarray(32, 64));
              return {
                cipherText,
                sharedSecret: kr.subarray(0, 32)
              };
            } finally {
              if (kr !== void 0)
                cleanBytes(kr.subarray(32));
              if (ownMsg)
                cleanBytes(m);
            }
          },
          decapsulate: (cipherText, secretKey) => {
            abytesDoc(secretKey, secretCoder.bytesLen, "secretKey");
            abytesDoc(cipherText, lengths.cipherText, "cipherText");
            const [sk, ekEmbedded, storedHash, z] = secretCoder.decode(secretKey);
            if (!equalBytes(ekEmbedded, ek) || !equalBytes(storedHash, publicKeyHash))
              throw new Error("ML-KEM.decapsulate: secretKey does not match prepared publicKey");
            const msg = KPKE.decrypt(cipherText, sk);
            const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
            const Khat = kr.subarray(0, 32);
            const cipherText2 = cached.encrypt(msg, kr.subarray(32, 64));
            const isValid = equalBytes(cipherText, cipherText2);
            const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
            cleanBytes(msg, cipherText2, kr.subarray(32), !isValid ? Khat : Kbar);
            return isValid ? Khat : Kbar;
          },
          clean: cached.clean
        });
      }
    });
  }
  function shakePRF(dkLen, key, nonce) {
    return shake256.create({ dkLen }).update(key).update(new Uint8Array([nonce])).digest();
  }
  var opts = /* @__PURE__ */ (() => ({
    HASH256: sha3_256,
    HASH512: sha3_512,
    KDF: shake256,
    XOF: XOF128,
    PRF: shakePRF
  }))();
  var mk = (params) => createKyber({
    ...opts,
    ...params
  });
  var ml_kem768 = /* @__PURE__ */ (() => mk(PARAMS[768]))();

  // node_modules/@noble/post-quantum/ml-dsa.js
  var INTERNAL_SIG_OPT_KEYS = /* @__PURE__ */ Object.freeze([
    "extraEntropy",
    "externalMu"
  ]);
  var INTERNAL_VER_OPT_KEYS = /* @__PURE__ */ Object.freeze(["externalMu"]);
  function validateInternalOpts(opts2, allowed) {
    const normalized = checkOptKeys(opts2, allowed);
    if (normalized.externalMu !== void 0)
      abool2(normalized.externalMu, "opts.externalMu");
    return normalized;
  }
  var N2 = 256;
  var Q2 = 8380417;
  var ROOT_OF_UNITY2 = 1753;
  var F2 = 8347681;
  var D = 13;
  var GAMMA2_1 = Math.floor((Q2 - 1) / 88) | 0;
  var GAMMA2_2 = Math.floor((Q2 - 1) / 32) | 0;
  var PARAMS2 = /* @__PURE__ */ (() => Object.freeze({
    2: Object.freeze({
      K: 4,
      L: 4,
      D,
      GAMMA1: 2 ** 17,
      GAMMA2: GAMMA2_1,
      TAU: 39,
      ETA: 2,
      OMEGA: 80
    }),
    3: Object.freeze({
      K: 6,
      L: 5,
      D,
      GAMMA1: 2 ** 19,
      GAMMA2: GAMMA2_2,
      TAU: 49,
      ETA: 4,
      OMEGA: 55
    }),
    5: Object.freeze({
      K: 8,
      L: 7,
      D,
      GAMMA1: 2 ** 19,
      GAMMA2: GAMMA2_2,
      TAU: 60,
      ETA: 2,
      OMEGA: 75
    })
  }))();
  var newPoly = (n) => new Int32Array(n);
  var crystals2 = /* @__PURE__ */ genCrystals({
    N: N2,
    Q: Q2,
    F: F2,
    ROOT_OF_UNITY: ROOT_OF_UNITY2,
    newPoly,
    isKyber: false,
    brvBits: 8
  });
  var id = (n) => n;
  var polyCoder2 = (d, compress2 = id, verify = id) => crystals2.bitsCoder(d, {
    encode: (i) => compress2(verify(i)),
    decode: (i) => verify(compress2(i))
  });
  var polyAdd2 = (a_, b_) => {
    const a = a_;
    const b = b_;
    for (let i = 0; i < a.length; i++)
      a[i] = crystals2.mod(a[i] + b[i]);
    return a;
  };
  var polySub2 = (a_, b_) => {
    const a = a_;
    const b = b_;
    for (let i = 0; i < a.length; i++)
      a[i] = crystals2.mod(a[i] - b[i]);
    return a;
  };
  var polyShiftl = (p_) => {
    const p = p_;
    for (let i = 0; i < N2; i++)
      p[i] <<= D;
    return p;
  };
  var polyChknorm = (p_, B2) => {
    const p = p_;
    for (let i = 0; i < N2; i++)
      if (Math.abs(crystals2.smod(p[i])) >= B2)
        return true;
    return false;
  };
  var MultiplyNTTs2 = (a_, b_) => {
    const a = a_;
    const b = b_;
    const c = newPoly(N2);
    for (let i = 0; i < a.length; i++)
      c[i] = crystals2.mod(a[i] * b[i]);
    return c;
  };
  function RejNTTPoly(xof_) {
    const xof = xof_;
    const r = newPoly(N2);
    for (let j = 0; j < N2; ) {
      const b = xof();
      if (b.length % 3)
        throw new Error("RejNTTPoly: unaligned block");
      for (let i = 0; j < N2 && i <= b.length - 3; i += 3) {
        const t = (b[i + 0] | b[i + 1] << 8 | b[i + 2] << 16) & 8388607;
        if (t < Q2)
          r[j++] = t;
      }
    }
    return r;
  }
  function getDilithium(opts_) {
    const opts2 = opts_;
    const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts2;
    const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562, securityLevel } = opts2;
    if (![2, 4].includes(ETA))
      throw new Error("Wrong ETA");
    if (![1 << 17, 1 << 19].includes(GAMMA1))
      throw new Error("Wrong GAMMA1");
    if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
      throw new Error("Wrong GAMMA2");
    const BETA = TAU * ETA;
    const decompose = (r) => {
      const rPlus = crystals2.mod(r);
      const r0 = crystals2.smod(rPlus, 2 * GAMMA2) | 0;
      if (rPlus - r0 === Q2 - 1)
        return { r1: 0 | 0, r0: r0 - 1 | 0 };
      const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
      return { r1, r0 };
    };
    const HighBits = (r) => decompose(r).r1;
    const LowBits = (r) => decompose(r).r0;
    const MakeHint = (z, r) => {
      const res0 = z <= GAMMA2 || z > Q2 - GAMMA2 || z === Q2 - GAMMA2 && r === 0 ? 0 : 1;
      return res0;
    };
    const HINT_M = Math.floor((Q2 - 1) / (2 * GAMMA2));
    const UseHint = (h, r) => {
      const { r1, r0 } = decompose(r);
      if (h === 1)
        return r0 > 0 ? crystals2.mod(r1 + 1, HINT_M) | 0 : crystals2.mod(r1 - 1, HINT_M) | 0;
      return r1 | 0;
    };
    const Power2Round = (r) => {
      const rPlus = crystals2.mod(r);
      const r0 = crystals2.smod(rPlus, 2 ** D) | 0;
      return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
    };
    const hintCoder = {
      bytesLen: OMEGA + K,
      encode: (h_) => {
        const h = h_;
        if (h === false)
          throw new Error("hint.encode: hint is false");
        const res = new Uint8Array(OMEGA + K);
        for (let i = 0, k = 0; i < K; i++) {
          for (let j = 0; j < N2; j++)
            if (h[i][j] !== 0)
              res[k++] = j;
          res[OMEGA + i] = k;
        }
        return res;
      },
      decode: (buf) => {
        const h = [];
        let k = 0;
        for (let i = 0; i < K; i++) {
          const hi = newPoly(N2);
          if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA)
            return false;
          for (let j = k; j < buf[OMEGA + i]; j++) {
            if (j > k && buf[j] <= buf[j - 1])
              return false;
            hi[buf[j]] = 1;
          }
          k = buf[OMEGA + i];
          h.push(hi);
        }
        for (let j = k; j < OMEGA; j++)
          if (buf[j] !== 0)
            return false;
        return h;
      }
    };
    const ETACoder = polyCoder2(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
      if (!(-ETA <= i && i <= ETA))
        throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
      return i;
    });
    const T0Coder = polyCoder2(13, (i) => (1 << D - 1) - i);
    const T1Coder = polyCoder2(10);
    const ZCoder = polyCoder2(GAMMA1 === 1 << 17 ? 18 : 20, (i) => crystals2.smod(GAMMA1 - i));
    const W1Coder = polyCoder2(GAMMA2 === GAMMA2_1 ? 6 : 4);
    const W1Vec = vecCoder(W1Coder, K);
    const publicCoder = splitCoder("publicKey", 32, vecCoder(T1Coder, K));
    const secretCoder = splitCoder("secretKey", 32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
    const sigCoder = splitCoder("signature", C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
    const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
    function RejBoundedPoly(xof_) {
      const xof = xof_;
      const r = newPoly(N2);
      for (let j = 0; j < N2; ) {
        const b = xof();
        for (let i = 0; j < N2 && i < b.length; i += 1) {
          const d1 = CoefFromHalfByte(b[i] & 15);
          const d2 = CoefFromHalfByte(b[i] >> 4 & 15);
          if (d1 !== false)
            r[j++] = d1;
          if (j < N2 && d2 !== false)
            r[j++] = d2;
        }
      }
      return r;
    }
    const SampleInBall = (seed) => {
      const pre = newPoly(N2);
      const s = shake256.create({}).update(seed);
      const buf = new Uint8Array(shake256.blockLen);
      s.xofInto(buf);
      const masks = buf.slice(0, 8);
      for (let i = N2 - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N2; i++) {
        let b = i + 1;
        for (; b > i; ) {
          b = buf[pos++];
          if (pos < shake256.blockLen)
            continue;
          s.xofInto(buf);
          pos = 0;
        }
        pre[i] = pre[b];
        pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
        if (maskBit >= 8) {
          maskPos++;
          maskBit = 0;
        }
      }
      return pre;
    };
    const polyPowerRound = (p_) => {
      const p = p_;
      const res0 = newPoly(N2);
      const res1 = newPoly(N2);
      for (let i = 0; i < p.length; i++) {
        const { r0, r1 } = Power2Round(p[i]);
        res0[i] = r0;
        res1[i] = r1;
      }
      return { r0: res0, r1: res1 };
    };
    const polyUseHint = (u_, h_) => {
      const u = u_;
      const h = h_;
      for (let i = 0; i < N2; i++)
        u[i] = UseHint(h[i], u[i]);
      return u;
    };
    const polyMakeHint = (a_, b_) => {
      const a = a_;
      const b = b_;
      const v = newPoly(N2);
      let cnt = 0;
      for (let i = 0; i < N2; i++) {
        const h = MakeHint(a[i], b[i]);
        v[i] = h;
        cnt += h;
      }
      return { v, cnt };
    };
    const signRandBytes = 32;
    const seedCoder = splitCoder("seed", 32, 64, 32);
    const internal = Object.freeze({
      info: Object.freeze({ type: "internal-ml-dsa" }),
      lengths: Object.freeze({
        secretKey: secretCoder.bytesLen,
        publicKey: publicCoder.bytesLen,
        seed: 32,
        signature: sigCoder.bytesLen,
        signRand: signRandBytes
      }),
      keygen: (seed) => {
        const seedDst = new Uint8Array(32 + 2);
        const randSeed = seed === void 0;
        if (randSeed)
          seed = randomBytes3(32);
        abytesDoc(seed, 32, "seed");
        seedDst.set(seed);
        if (randSeed)
          cleanBytes(seed);
        seedDst[32] = K;
        seedDst[33] = L;
        const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
        const xofPrime = XOF2562(rhoPrime);
        const s1 = [];
        for (let i = 0; i < L; i++)
          s1.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
        const s2 = [];
        for (let i = L; i < L + K; i++)
          s2.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
        const s1Hat = s1.map((i) => crystals2.NTT.encode(i.slice()));
        const t0 = [];
        const t1 = [];
        const xof = XOF1282(rho);
        const t = newPoly(N2);
        for (let i = 0; i < K; i++) {
          cleanBytes(t);
          for (let j = 0; j < L; j++) {
            const aij = RejNTTPoly(xof.get(j, i));
            polyAdd2(t, MultiplyNTTs2(aij, s1Hat[j]));
          }
          crystals2.NTT.decode(t);
          const { r0, r1 } = polyPowerRound(polyAdd2(t, s2[i]));
          t0.push(r0);
          t1.push(r1);
        }
        const publicKey = publicCoder.encode([rho, t1]);
        const tr = shake256(publicKey, { dkLen: TR_BYTES });
        const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
        xof.clean();
        xofPrime.clean();
        cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
        return {
          publicKey,
          secretKey
        };
      },
      getPublicKey: (secretKey) => {
        const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey);
        const xof = XOF1282(rho);
        const s1Hat = s1.map((p) => crystals2.NTT.encode(p.slice()));
        const t1 = [];
        const tmp = newPoly(N2);
        for (let i = 0; i < K; i++) {
          tmp.fill(0);
          for (let j = 0; j < L; j++) {
            const aij = RejNTTPoly(xof.get(j, i));
            polyAdd2(tmp, MultiplyNTTs2(aij, s1Hat[j]));
          }
          crystals2.NTT.decode(tmp);
          polyAdd2(tmp, s2[i]);
          const { r1 } = polyPowerRound(tmp);
          t1.push(r1);
        }
        xof.clean();
        cleanBytes(tmp, s1Hat, _t0, s1, s2);
        return publicCoder.encode([rho, t1]);
      },
      // NOTE: random is optional.
      sign: (msg, secretKey, opts3 = {}) => {
        opts3 = validateSigOpts(opts3, INTERNAL_SIG_OPT_KEYS);
        opts3 = validateInternalOpts(opts3, INTERNAL_SIG_OPT_KEYS);
        const { extraEntropy: random, externalMu = false } = opts3;
        if (externalMu)
          abytesDoc(msg, CRH_BYTES, "mu");
        const ownRnd = random === false || random === void 0;
        const rnd = random === false ? new Uint8Array(32) : random === void 0 ? randomBytes3(signRandBytes) : random;
        abytesDoc(rnd, 32, "extraEntropy");
        const decoded = (() => {
          try {
            return secretCoder.decode(secretKey);
          } catch (error) {
            if (ownRnd)
              cleanBytes(rnd);
            throw error;
          }
        })();
        const [rho, _K, tr, s1, s2, t0] = decoded;
        const A = [];
        const xof = XOF1282(rho);
        for (let i = 0; i < K; i++) {
          const pv = [];
          for (let j = 0; j < L; j++)
            pv.push(RejNTTPoly(xof.get(j, i)));
          A.push(pv);
        }
        xof.clean();
        for (let i = 0; i < L; i++)
          crystals2.NTT.encode(s1[i]);
        for (let i = 0; i < K; i++) {
          crystals2.NTT.encode(s2[i]);
          crystals2.NTT.encode(t0[i]);
        }
        const mu = externalMu ? msg : (
          // 6: µ ← H(tr||M, 512)
          //    ▷ Compute message representative µ
          shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
        );
        const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
        if (ownRnd)
          cleanBytes(rnd);
        abytesDoc(rhoprime, CRH_BYTES);
        const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
        main_loop: for (let kappa = 0; ; ) {
          const y = [];
          for (let i = 0; i < L; i++, kappa++)
            y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
          const z = y.map((i) => crystals2.NTT.encode(i.slice()));
          const w = [];
          for (let i = 0; i < K; i++) {
            const wi = newPoly(N2);
            for (let j = 0; j < L; j++)
              polyAdd2(wi, MultiplyNTTs2(A[i][j], z[j]));
            crystals2.NTT.decode(wi);
            w.push(wi);
          }
          const w1 = w.map((j) => j.map(HighBits));
          const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
          const cHat = crystals2.NTT.encode(SampleInBall(cTilde));
          const cs1 = s1.map((i) => MultiplyNTTs2(i, cHat));
          for (let i = 0; i < L; i++) {
            polyAdd2(crystals2.NTT.decode(cs1[i]), y[i]);
            if (polyChknorm(cs1[i], GAMMA1 - BETA)) {
              cleanBytes(cTilde, cs1, cHat, w1, w, z, y);
              continue main_loop;
            }
          }
          let cnt = 0;
          const h = [];
          for (let i = 0; i < K; i++) {
            const cs2 = crystals2.NTT.decode(MultiplyNTTs2(s2[i], cHat));
            const r0 = polySub2(w[i], cs2).map(LowBits);
            if (polyChknorm(r0, GAMMA2 - BETA)) {
              cleanBytes(cTilde, cs1, cHat, w1, w, z, y, h, cs2, r0);
              continue main_loop;
            }
            const ct0 = crystals2.NTT.decode(MultiplyNTTs2(t0[i], cHat));
            if (polyChknorm(ct0, GAMMA2)) {
              cleanBytes(cTilde, cs1, cHat, w1, w, z, y, h, cs2, r0, ct0);
              continue main_loop;
            }
            polyAdd2(r0, ct0);
            const hint = polyMakeHint(r0, w1[i]);
            h.push(hint.v);
            cnt += hint.cnt;
          }
          if (cnt > OMEGA) {
            cleanBytes(cTilde, cs1, cHat, w1, w, z, y, h);
            continue;
          }
          x256.clean();
          const res = sigCoder.encode([cTilde, cs1, h]);
          cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, s1, s2, t0, ...A);
          if (!externalMu)
            cleanBytes(mu);
          return res;
        }
        throw new Error("Unreachable code path reached, report this error");
      },
      verify: (sig, msg, publicKey, opts3 = {}) => {
        opts3 = validateInternalOpts(opts3, INTERNAL_VER_OPT_KEYS);
        const { externalMu = false } = opts3;
        if (externalMu)
          abytesDoc(msg, CRH_BYTES, "mu");
        const [rho, t1] = publicCoder.decode(publicKey);
        const tr = shake256(publicKey, { dkLen: TR_BYTES });
        if (sig.length !== sigCoder.bytesLen)
          return false;
        const [cTilde, z, h] = sigCoder.decode(sig);
        if (h === false)
          return false;
        for (let i = 0; i < L; i++)
          if (polyChknorm(z[i], GAMMA1 - BETA))
            return false;
        const mu = externalMu ? msg : (
          // 7: µ ← H(tr||M, 512)
          shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
        );
        const c = crystals2.NTT.encode(SampleInBall(cTilde));
        const zNtt = z.map((i) => i.slice());
        for (let i = 0; i < L; i++)
          crystals2.NTT.encode(zNtt[i]);
        const wTick1 = [];
        const xof = XOF1282(rho);
        for (let i = 0; i < K; i++) {
          const ct12d = MultiplyNTTs2(crystals2.NTT.encode(polyShiftl(t1[i])), c);
          const Az = newPoly(N2);
          for (let j = 0; j < L; j++) {
            const aij = RejNTTPoly(xof.get(j, i));
            polyAdd2(Az, MultiplyNTTs2(aij, zNtt[j]));
          }
          const wApprox = crystals2.NTT.decode(polySub2(Az, ct12d));
          wTick1.push(polyUseHint(wApprox, h[i]));
        }
        xof.clean();
        const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
        for (const t of h) {
          const sum = t.reduce((acc, i) => acc + i, 0);
          if (!(sum <= OMEGA))
            return false;
        }
        for (const t of z)
          if (polyChknorm(t, GAMMA1 - BETA))
            return false;
        return equalBytes(cTilde, c2);
      }
    });
    return Object.freeze({
      info: Object.freeze({ type: "ml-dsa" }),
      internal,
      securityLevel,
      keygen: internal.keygen,
      lengths: internal.lengths,
      getPublicKey: internal.getPublicKey,
      sign: (msg, secretKey, opts3 = {}) => {
        opts3 = validateSigOpts(opts3);
        const M = getMessage(msg, opts3.context);
        const res = internal.sign(M, secretKey, {
          extraEntropy: opts3.extraEntropy,
          externalMu: false
        });
        cleanBytes(M);
        return res;
      },
      verify: (sig, msg, publicKey, opts3 = {}) => {
        opts3 = validateVerOpts(opts3);
        abytesDoc(sig, void 0, "signature");
        return internal.verify(sig, getMessage(msg, opts3.context), publicKey, { externalMu: false });
      },
      prehash: (hash) => {
        checkHash(hash, securityLevel);
        const rawHash = hash;
        return Object.freeze({
          info: Object.freeze({ type: "hashml-dsa" }),
          securityLevel,
          lengths: internal.lengths,
          keygen: internal.keygen,
          getPublicKey: internal.getPublicKey,
          sign: (msg, secretKey, opts3 = {}) => {
            opts3 = validateSigOpts(opts3);
            const M = getMessagePrehash(rawHash, msg, opts3.context);
            const res = internal.sign(M, secretKey, {
              extraEntropy: opts3.extraEntropy,
              externalMu: false
            });
            cleanBytes(M);
            return res;
          },
          verify: (sig, msg, publicKey, opts3 = {}) => {
            opts3 = validateVerOpts(opts3);
            abytesDoc(sig, void 0, "signature");
            return internal.verify(sig, getMessagePrehash(rawHash, msg, opts3.context), publicKey, {
              externalMu: false
            });
          }
        });
      }
    });
  }
  var ml_dsa65 = /* @__PURE__ */ (() => getDilithium({
    ...PARAMS2[3],
    CRH_BYTES: 64,
    TR_BYTES: 64,
    C_TILDE_BYTES: 48,
    XOF128,
    XOF256,
    securityLevel: 192
  }))();

  // node_modules/@noble/curves/abstract/curve.js
  var _0n4 = /* @__PURE__ */ BigInt(0);
  var _1n4 = /* @__PURE__ */ BigInt(1);
  var _4n2 = /* @__PURE__ */ BigInt(4);
  var BLIND_BYTES = 16;
  var BLIND_BITS = 128;
  var FW_WINDOW = 5;
  var TABLE_BYTES_MAX = /* @__PURE__ */ (() => 2 ** 31)();
  function validatePointCons(Point) {
    const pc = Point;
    if (typeof pc !== "function")
      throw new TypeError('"Point" expected constructor, got type=' + typeof Point);
    afunction(pc.fromAffine, "Point.fromAffine");
    afunction(pc.fromBytes, "Point.fromBytes");
    afunction(pc.fromHex, "Point.fromHex");
    aobject2(pc.BASE, "Point.BASE");
    aobject2(pc.ZERO, "Point.ZERO");
    validateField(pc.Fp);
    validateField(pc.Fn);
  }
  function normalizeZ(c, points) {
    validatePointCons(c);
    validateMSMPoints(points, c);
    const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
    return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
  }
  function validateW(W, bits, min = 1) {
    if (!Number.isSafeInteger(W) || W < min || W > bits)
      throw new Error("invalid window size, expected [" + min + ".." + bits + "], got W=" + W);
  }
  function validateTableBytes(numPoints, fpBytes) {
    const bytes = numPoints * (4 * fpBytes + 128);
    if (bytes > TABLE_BYTES_MAX)
      throw new Error("invalid window size: table would need ~" + Math.ceil(bytes / 2 ** 20) + " MiB, max " + TABLE_BYTES_MAX / 2 ** 20 + " MiB");
  }
  function probeRandomBytes(randomBytes5, length) {
    if (randomBytes5 === void 0)
      return void 0;
    afunction(randomBytes5, "randomBytes");
    try {
      const probe = randomBytes5(length);
      if (!isBytes2(probe) || probe.length !== length)
        return void 0;
    } catch {
      return void 0;
    }
    return randomBytes5;
  }
  function validateMSMPoints(points, c) {
    aarray(points, "points");
    points.forEach((p, i) => {
      if (!(p instanceof c))
        throw new Error("invalid point at index " + i);
    });
  }
  function validateMSMScalars(scalars, field, maxScalar) {
    if (!Array.isArray(scalars))
      throw new Error("array of scalars expected");
    scalars.forEach((s, i) => {
      const ok = maxScalar === void 0 ? field.isValid(s) : isPosBig(s) && s < maxScalar;
      if (!ok)
        throw new Error("invalid scalar at index " + i);
    });
  }
  var pointWindowSizes = /* @__PURE__ */ new WeakMap();
  function getWindowSize(P) {
    return pointWindowSizes.get(P) || 1;
  }
  function oddMultiples(p, size) {
    const dbl = p.double();
    const t = [p];
    for (let j = 1; j < size; j++)
      t.push(t[j - 1].add(dbl));
    return t;
  }
  function wnafDigits(n, W) {
    const size = 2 ** W;
    const half = size / 2;
    const mask = BigInt(size - 1);
    const d = [];
    while (n > _0n4) {
      let w = 0;
      if (n & _1n4) {
        w = Number(n & mask);
        if (w >= half)
          w -= size;
        n -= BigInt(w);
      }
      d.push(w);
      n >>= _1n4;
    }
    return d;
  }
  function signedWindowDigits(n, W, windows) {
    const size = 2 ** W;
    const half = size / 2;
    const mask = BigInt(size - 1);
    const shiftBy = BigInt(W);
    const d = [];
    for (let w = 0; w < windows; w++) {
      let v = Number(n & mask);
      n >>= shiftBy;
      if (v > half) {
        v -= size;
        n += _1n4;
      }
      d.push(v);
    }
    if (n !== _0n4)
      throw new Error("invalid wnaf");
    return d;
  }
  function wnafWalk(zero, tables, digits) {
    let max = 0;
    for (const d of digits)
      max = Math.max(max, d.length);
    let acc = zero;
    for (let bit = max - 1; bit >= 0; bit--) {
      if (bit !== max - 1)
        acc = acc.double();
      for (let i = 0; i < digits.length; i++) {
        const w = digits[i][bit];
        if (w) {
          const item = tables[i][Math.abs(w) - 1 >> 1];
          acc = acc.add(w < 0 ? item.negate() : item);
        }
      }
    }
    return acc;
  }
  var ScalarMultiplier = class {
    Point;
    BASE;
    ZERO;
    randomBytes;
    wnafPrecomputes = /* @__PURE__ */ new WeakMap();
    baseCanBeBlinded;
    bits;
    // Parametrized with a given Point class (not individual point)
    constructor(Point, randomBytes5) {
      validatePointCons(Point);
      this.randomBytes = probeRandomBytes(randomBytes5, BLIND_BYTES);
      this.Point = Point;
      this.BASE = Point.BASE;
      this.ZERO = Point.ZERO;
      this.bits = Point.Fn.BITS;
    }
    /**
     * Creates a signed fixed-window wNAF precomputation table: for every window w, the
     * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
     * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
     * window absorbs the final carry of signed-digit recoding.
     * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
     * @param point - Point instance
     * @param W - window size
     * @param bits - scalar bitlength the table must cover
     */
    buildWnafTable(point, W, bits) {
      const windows = Math.ceil(bits / W) + 1;
      const half = 2 ** (W - 1);
      const comp = [];
      let base = point;
      for (let w = 0; w < windows; w++) {
        let acc = base;
        for (let i = 0; i < half; i++) {
          comp.push(acc);
          acc = acc.add(base);
        }
        base = comp[comp.length - 1].double();
      }
      return { W, bits, windows, comp };
    }
    /**
     * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
     * Constant-time: fixed window count with one table addition per window — zero digits feed
     * the fake accumulator — and no doublings; the lookup scans the whole window slice.
     * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
     * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
     * signedWindowDigits throws if `n` exceeds the table.
     * @returns real and fake (for const-time) points
     */
    wnafCachedCT(precomputes, n) {
      const { W, windows, comp } = precomputes;
      const half = 2 ** (W - 1);
      const digits = signedWindowDigits(n, W, windows);
      let p = this.ZERO;
      let f = this.BASE;
      for (let w = 0; w < windows; w++) {
        const digit = digits[w];
        const start = w * half;
        const idx = Math.abs(digit) - 1;
        let sel = comp[start];
        for (let i = 1; i < half; i++)
          sel = i === idx ? comp[start + i] : sel;
        const neg = sel.negate();
        if (digit === 0)
          f = f.add(comp[start]);
        else
          p = p.add(digit < 0 ? neg : sel);
      }
      return { p, f };
    }
    // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
    // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
    // incompatible `transform(...)` layouts and expect a separate cache entry.
    getWnafPrecomputes(W, point, bits, transform) {
      let entries = this.wnafPrecomputes.get(point);
      let comp = entries?.find((entry) => entry.W === W && entry.bits === bits);
      if (!comp) {
        comp = this.buildWnafTable(point, W, bits);
        if (typeof transform === "function")
          comp = { ...comp, comp: transform(comp.comp) };
        if (!entries) {
          entries = [];
          this.wnafPrecomputes.set(point, entries);
        }
        entries.push(comp);
      }
      return comp;
    }
    assertPoint(point) {
      if (!(point instanceof this.Point))
        throw new TypeError('"point" expected Point instance, got type=' + typeof point);
    }
    // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
    // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
    // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
    validateMulInput(point, scalar) {
      this.assertPoint(point);
      if (!inRange(scalar, _1n4, this.Point.Fn.ORDER))
        throw new Error("invalid scalar");
    }
    // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
    // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
    // multiply. `n` must be < 2^bits.
    runCT(point, n, bits, transform) {
      const W = getWindowSize(point);
      if (W === 1)
        return this.fixedWindowCT(point, n, bits);
      return this.wnafCachedCT(this.getWnafPrecomputes(W, point, bits, transform), n);
    }
    mulCT(point, scalar, transform) {
      this.validateMulInput(point, scalar);
      return this.runCT(point, scalar, this.bits, transform);
    }
    mulCTBlinded(point, scalar, transform) {
      this.validateMulInput(point, scalar);
      if (this.randomBytes === void 0)
        throw new Error("randomBytes is required for scalar blinding");
      const bits = this.Point.Fn.BITS + BLIND_BITS;
      const blind = this.randomBytes(BLIND_BYTES);
      if (!isBytes2(blind) || blind.length !== BLIND_BYTES)
        throw new Error("randomBytes returned invalid byte array");
      blind[0] = blind[0] & 63 | 128;
      const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
      return this.runCT(point, n, bits, transform);
    }
    /**
     * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
     * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is
     * far cheaper to build for a single use. The point-operation sequence is independent of `n`:
     * build the table, then per window exactly FW_WINDOW doublings, a data-oblivious scan over
     * every table entry, and one addition (adds the identity when the window digit is 0 — never
     * skipped).
     *
     * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same as any
     * add), which holds for the Weierstrass/Edwards point types used here. The table is left in
     * projective form (no normalizeZ): normalizing this small a table costs more than the
     * mixed-add savings it would buy for a single multiply.
     * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape
     * (this path needs no fake accumulator — its op-count is already scalar-independent).
     */
    fixedWindowCT(point, n, bits) {
      const W = FW_WINDOW;
      const size = 1 << W;
      const mask = bitMask(W);
      const table = new Array(size);
      table[0] = this.ZERO;
      for (let i = 1; i < size; i++)
        table[i] = table[i - 1].add(point);
      const windows = Math.ceil(bits / W);
      let acc = this.ZERO;
      for (let window2 = windows - 1; window2 >= 0; window2--) {
        if (window2 !== windows - 1)
          for (let d = 0; d < W; d++)
            acc = acc.double();
        const digit = Number(n >> BigInt(window2 * W) & mask);
        let sel = table[0];
        for (let i = 1; i < size; i++)
          sel = i === digit ? table[i] : sel;
        acc = acc.add(sel);
      }
      return { p: acc, f: acc };
    }
    shouldBlind(point, cofactor) {
      if (this.randomBytes === void 0)
        return false;
      if (cofactor === _1n4)
        return true;
      if (point !== this.BASE)
        return false;
      if (this.baseCanBeBlinded === void 0)
        this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
      return this.baseCanBeBlinded;
    }
    mulSecret(point, scalar, cofactor, transform) {
      return this.shouldBlind(point, cofactor) ? this.mulCTBlinded(point, scalar, transform) : this.mulCT(point, scalar, transform);
    }
    mulUnsafe(point, scalar, transform) {
      this.assertPoint(point);
      if (!isPosBig(scalar))
        throw new Error("invalid scalar");
      const W = getWindowSize(point);
      if (W === 1 || scalar >= this.Point.Fn.ORDER)
        return mulAddUnsafe(this.Point, [point], [scalar], true);
      const precomputes = this.getWnafPrecomputes(W, point, this.bits, transform);
      return this.wnafCachedCT(precomputes, scalar).p;
    }
    // Remembers the window size used for precomputed wNAF multiplication of the given point
    // and drops any previously built tables. Usually only the base point is precomputed.
    // W=1 resets the point to the un-precomputed (table-less) paths.
    // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
    setWindowSize(point, W) {
      this.assertPoint(point);
      validateW(W, this.bits);
      const windows = Math.ceil((this.bits + BLIND_BITS) / W) + 1;
      validateTableBytes(windows * 2 ** (W - 1), this.Point.Fp.BYTES);
      pointWindowSizes.set(point, W);
      this.wnafPrecomputes.delete(point);
    }
    // True when a window size is set: tables themselves are built lazily on first multiply.
    hasWindowSize(point) {
      return getWindowSize(point) !== 1;
    }
  };
  function mulAddUnsafe(c, points, scalars, allowOversized = false) {
    validatePointCons(c);
    validateMSMPoints(points, c);
    abool2(allowOversized, "allowOversized");
    validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n2 : void 0);
    if (points.length !== scalars.length)
      throw new Error("arrays of points and scalars must have equal length");
    const tables = points.map((p) => oddMultiples(p, 4));
    const digits = scalars.map((n) => wnafDigits(n, 4));
    return wnafWalk(c.ZERO, tables, digits);
  }
  function createField(order, field, isLE3) {
    if (field) {
      if (field.ORDER !== order)
        throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
      validateField(field);
      return field;
    } else {
      return Field(order, { isLE: isLE3 });
    }
  }
  function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
    if (type !== "weierstrass" && type !== "edwards")
      throw new Error('expected curve type "weierstrass" or "edwards"');
    if (FpFnLE === void 0)
      FpFnLE = type === "edwards";
    if (!CURVE || typeof CURVE !== "object")
      throw new Error(`expected valid ${type} CURVE object`);
    validateObject(curveOpts);
    for (const p of ["p", "n", "h"]) {
      const val = CURVE[p];
      if (!(isPosBig(val) && val !== _0n4))
        throw new Error(`CURVE.${p} must be positive bigint`);
    }
    const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
    const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
    const _b = type === "weierstrass" ? "b" : "d";
    const params = ["Gx", "Gy", "a", _b];
    for (const p of params) {
      if (!Fp.isValid(CURVE[p]))
        throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
    }
    CURVE = Object.freeze(Object.assign({}, CURVE));
    return { CURVE, Fp, Fn };
  }
  function createKeygen(randomSecretKey, getPublicKey) {
    return function keygen(seed) {
      const secretKey = randomSecretKey(seed);
      return { secretKey, publicKey: getPublicKey(secretKey) };
    };
  }

  // node_modules/@noble/curves/abstract/edwards.js
  var _0n5 = /* @__PURE__ */ BigInt(0);
  var _1n5 = /* @__PURE__ */ BigInt(1);
  var _2n3 = /* @__PURE__ */ BigInt(2);
  var _4n3 = /* @__PURE__ */ BigInt(4);
  var _8n2 = /* @__PURE__ */ BigInt(8);
  function isEdValidXY(Fp, CURVE, x, y) {
    const x2 = Fp.sqr(x);
    const y2 = Fp.sqr(y);
    const left = Fp.add(Fp.mul(CURVE.a, x2), y2);
    const right = Fp.add(Fp.ONE, Fp.mul(CURVE.d, Fp.mul(x2, y2)));
    return Fp.eql(left, right);
  }
  function edwards(params, extraOpts = {}) {
    validateObject(extraOpts, {}, {}, "extraOpts");
    const opts2 = extraOpts;
    const validated = createCurveFields("edwards", params, opts2, opts2.FpFnLE);
    const { Fp, Fn } = validated;
    let CURVE = validated.CURVE;
    const { h: cofactor } = CURVE;
    if (FpLegendre(Fp, CURVE.a) !== 1)
      throw new Error("edwards: CURVE.a must be a square in Fp for complete addition formulas");
    if (FpLegendre(Fp, CURVE.d) !== -1)
      throw new Error("edwards: CURVE.d must be a non-square in Fp for complete addition formulas");
    validateObject(opts2, {}, { uvRatio: "function", randomBytes: "function" });
    const randomBytes5 = opts2.randomBytes === void 0 ? randomBytes2 : opts2.randomBytes;
    const MASK = _2n3 << BigInt(Fp.BYTES * 8) - _1n5;
    function isOdd(n) {
      if (!Fp.isOdd)
        throw new Error("Field does not have .isOdd()");
      return Fp.isOdd(n);
    }
    const uvRatio2 = opts2.uvRatio === void 0 ? (u, v) => {
      try {
        return { isValid: true, value: Fp.sqrt(Fp.div(u, v)) };
      } catch (e) {
        return { isValid: false, value: _0n5 };
      }
    } : opts2.uvRatio;
    if (!isEdValidXY(Fp, CURVE, CURVE.Gx, CURVE.Gy))
      throw new Error("bad curve params: generator point");
    const mulA = Fp.eql(CURVE.a, Fp.neg(Fp.ONE)) ? (x) => Fp.neg(x) : Fp.eql(CURVE.a, Fp.ONE) ? (x) => x : (x) => Fp.mul(CURVE.a, x);
    function acoord(title, n, banZero = false) {
      const min = banZero ? _1n5 : _0n5;
      aInRange("coordinate " + title, n, min, MASK);
      return n;
    }
    function aedpoint(other) {
      if (!(other instanceof Point))
        throw new Error("EdwardsPoint expected");
    }
    class Point {
      static BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE, Fp.mul(CURVE.Gx, CURVE.Gy));
      static ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ONE, Fp.ZERO);
      static Fp = Fp;
      static Fn = Fn;
      X;
      Y;
      Z;
      T;
      constructor(X, Y, Z, T) {
        this.X = acoord("x", X);
        this.Y = acoord("y", Y);
        this.Z = acoord("z", Z, true);
        this.T = acoord("t", T);
        Object.freeze(this);
      }
      static CURVE() {
        return CURVE;
      }
      /**
       * Create one extended Edwards point from affine coordinates.
       * Does NOT validate that the point is on-curve or torsion-free.
       * Use `.assertValidity()` on adversarial inputs.
       */
      static fromAffine(p) {
        if (p instanceof Point)
          throw new Error("extended point not allowed");
        const { x, y } = p || {};
        acoord("x", x);
        acoord("y", y);
        return new Point(x, y, Fp.ONE, Fp.mul(x, y));
      }
      // Uses algo from RFC8032 5.1.3.
      static fromBytes(bytes, zip215 = false) {
        const len = Fp.BYTES;
        const { a, d } = CURVE;
        bytes = copyBytes(abytes2(bytes, len, "point"));
        abool2(zip215, "zip215");
        const normed = copyBytes(bytes);
        const lastByte = bytes[len - 1];
        normed[len - 1] = lastByte & ~128;
        const y = bytesToNumberLE(normed);
        const max = zip215 ? MASK : Fp.ORDER;
        aInRange("point.y", y, _0n5, max);
        const y2 = Fp.sqr(y);
        const u = Fp.sub(y2, Fp.ONE);
        const v = Fp.sub(Fp.mulN(d, y2), a);
        let { isValid, value: x } = uvRatio2(u, v);
        if (!isValid)
          throw new Error("bad point: invalid y coordinate");
        const isXOdd = isOdd(x);
        const isLastByteOdd = (lastByte & 128) !== 0;
        if (!zip215 && Fp.is0(x) && isLastByteOdd)
          throw new Error("bad point: x=0 and x_0=1");
        if (isLastByteOdd !== isXOdd)
          x = Fp.neg(x);
        return Point.fromAffine({ x, y });
      }
      static fromHex(hex, zip215 = false) {
        return Point.fromBytes(hexToBytes2(hex), zip215);
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      precompute(windowSize = 6, isLazy = true) {
        wnaf.setWindowSize(this, windowSize);
        if (!isLazy)
          this.multiply(_2n3);
        return this;
      }
      // Useful in fromAffine() - not for fromBytes(), which always created valid points.
      assertValidity() {
        const p = this;
        const { a, d } = CURVE;
        if (p.is0())
          throw new Error("bad point: ZERO");
        const { X, Y, Z, T } = p;
        const X2 = Fp.sqr(X);
        const Y2 = Fp.sqr(Y);
        const Z2 = Fp.sqr(Z);
        const Z4 = Fp.sqr(Z2);
        const aX2 = Fp.mul(X2, a);
        const left = Fp.mul(Fp.add(aX2, Y2), Z2);
        const right = Fp.add(Z4, Fp.mul(d, Fp.mul(X2, Y2)));
        if (!Fp.eql(left, right))
          throw new Error("bad point: equation left != right (1)");
        const XY = Fp.mul(X, Y);
        const ZT = Fp.mul(Z, T);
        if (!Fp.eql(XY, ZT))
          throw new Error("bad point: equation left != right (2)");
      }
      // Compare one point to another.
      equals(other) {
        aedpoint(other);
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const { X: X2, Y: Y2, Z: Z2 } = other;
        const X1Z2 = Fp.mul(X1, Z2);
        const X2Z1 = Fp.mul(X2, Z1);
        const Y1Z2 = Fp.mul(Y1, Z2);
        const Y2Z1 = Fp.mul(Y2, Z1);
        return Fp.eql(X1Z2, X2Z1) && Fp.eql(Y1Z2, Y2Z1);
      }
      is0() {
        return this.equals(Point.ZERO);
      }
      negate() {
        return new Point(Fp.neg(this.X), this.Y, this.Z, Fp.neg(this.T));
      }
      // Fast algo for doubling Extended Point.
      // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
      // Cost: 4M + 4S + 1*a + 6add + 1*2.
      double() {
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const A = Fp.sqr(X1);
        const B2 = Fp.sqr(Y1);
        const C = Fp.mul(Fp.sqr(Z1), _2n3);
        const D2 = mulA(A);
        const x1y1 = Fp.addN(X1, Y1);
        const E = Fp.sub(Fp.subN(Fp.sqr(x1y1), A), B2);
        const G = Fp.addN(D2, B2);
        const F3 = Fp.subN(G, C);
        const H = Fp.subN(D2, B2);
        const X3 = Fp.mul(E, F3);
        const Y3 = Fp.mul(G, H);
        const T3 = Fp.mul(E, H);
        const Z3 = Fp.mul(F3, G);
        return new Point(X3, Y3, Z3, T3);
      }
      // Fast algo for adding 2 Extended Points.
      // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
      // Cost: 9M + 1*a + 1*d + 7add.
      add(other) {
        aedpoint(other);
        const { d } = CURVE;
        const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
        const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
        const A = Fp.mul(X1, X2);
        const B2 = Fp.mul(Y1, Y2);
        const C = Fp.mul(Fp.mulN(T1, d), T2);
        const D2 = Fp.mul(Z1, Z2);
        const E = Fp.sub(Fp.subN(Fp.mulN(Fp.addN(X1, Y1), Fp.addN(X2, Y2)), A), B2);
        const F3 = Fp.subN(D2, C);
        const G = Fp.addN(D2, C);
        const H = Fp.sub(B2, mulA(A));
        const X3 = Fp.mul(E, F3);
        const Y3 = Fp.mul(G, H);
        const T3 = Fp.mul(E, H);
        const Z3 = Fp.mul(F3, G);
        return new Point(X3, Y3, Z3, T3);
      }
      subtract(other) {
        aedpoint(other);
        return this.add(other.negate());
      }
      // Constant-time multiplication.
      multiply(scalar) {
        if (!Fn.isValidNot0(scalar))
          throw new RangeError("invalid scalar: expected 1 <= sc < curve.n");
        const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);
        return normalize([p, f])[0];
      }
      // Non-constant-time multiplication. Uses double-and-add algorithm.
      // It's faster, but should only be used when you don't care about
      // an exposed private key e.g. sig verification.
      // Keeps the same subgroup-scalar contract: 0 is allowed for public-scalar callers, but
      // n and larger values are rejected instead of being reduced mod n to the identity point.
      multiplyUnsafe(scalar) {
        if (!Fn.isValid(scalar))
          throw new RangeError("invalid scalar: expected 0 <= sc < curve.n");
        if (scalar === _0n5)
          return Point.ZERO;
        if (this.is0() || scalar === _1n5)
          return this;
        return wnaf.mulUnsafe(this, scalar, normalize);
      }
      // Checks if point is of small order.
      // If you add something to small order point, you will have "dirty"
      // point with torsion component.
      // Clears cofactor and checks if the result is 0.
      isSmallOrder() {
        return this.clearCofactor().is0();
      }
      // Multiplies point by curve order and checks if the result is 0.
      // Returns `false` is the point is dirty.
      isTorsionFree() {
        return wnaf.mulUnsafe(this, CURVE.n).is0();
      }
      // Converts Extended point to default (x, y) coordinates.
      // Can accept precomputed Z^-1 - for example, from invertBatch.
      toAffine(invertedZ) {
        const p = this;
        let iz = invertedZ;
        if (iz != null && typeof iz !== "bigint")
          throw new TypeError('"invertedZ" expected bigint, got type=' + typeof iz);
        const { X, Y, Z } = p;
        const is0 = p.is0();
        if (iz == null)
          iz = is0 ? Fp.create(_8n2) : Fp.inv(Z);
        const x = Fp.mul(X, iz);
        const y = Fp.mul(Y, iz);
        const zz = Fp.mul(Z, iz);
        if (is0)
          return { x: Fp.ZERO, y: Fp.ONE };
        if (!Fp.eql(zz, Fp.ONE))
          throw new Error("invZ was invalid");
        return { x, y };
      }
      clearCofactor() {
        if (cofactor === _1n5)
          return this;
        if (cofactor === _2n3)
          return this.double();
        if (cofactor === _4n3)
          return this.double().double();
        if (cofactor === _8n2)
          return this.double().double().double();
        return this.multiplyUnsafe(cofactor);
      }
      toBytes() {
        const { x, y } = this.toAffine();
        const bytes = Fp.toBytes(y);
        bytes[bytes.length - 1] |= isOdd(x) ? 128 : 0;
        return bytes;
      }
      toHex() {
        return bytesToHex2(this.toBytes());
      }
      toString() {
        return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
      }
    }
    const normalize = (points) => normalizeZ(Point, points);
    const wnaf = new ScalarMultiplier(Point, randomBytes5);
    if (wnaf.bits >= 6)
      Point.BASE.precompute(6);
    Object.freeze(Point.prototype);
    Object.freeze(Point);
    return Point;
  }

  // node_modules/@noble/curves/abstract/montgomery.js
  var _0n6 = /* @__PURE__ */ BigInt(0);
  var _1n6 = /* @__PURE__ */ BigInt(1);
  var _2n4 = /* @__PURE__ */ BigInt(2);
  function cmask(P, swap) {
    return P + swap - (swap >> _1n6 << _1n6);
  }
  function cswap(P) {
    const offset = BigInt(6) * P;
    return (mask, x_2, x_3) => {
      const sum = x_2 + x_3;
      const d = offset + x_3 - x_2;
      const a = (d * mask + x_2) % P;
      return { x_2: a, x_3: sum - a };
    };
  }
  function validateOpts2(curve) {
    validateObject(curve, {
      P: "bigint",
      type: "string",
      adjustScalarBytes: "function",
      powPminus2: "function"
    }, {
      randomBytes: "function",
      scalarMultBase: "function"
    });
    return Object.freeze({ ...curve });
  }
  function montgomery(curveDef) {
    const CURVE = validateOpts2(curveDef);
    const { P, type, adjustScalarBytes: adjustScalarBytes2, powPminus2, randomBytes: rand } = CURVE;
    const mulBaseHook = CURVE.scalarMultBase;
    const is25519 = type === "x25519";
    if (!is25519 && type !== "x448")
      throw new Error("invalid type");
    const randomBytes_ = rand === void 0 ? randomBytes2 : rand;
    const montgomeryBits = is25519 ? 255 : 448;
    const swap = cswap(P);
    const fieldLen = is25519 ? 32 : 56;
    const Gu = is25519 ? BigInt(9) : BigInt(5);
    const a24 = is25519 ? BigInt(121665) : BigInt(39081);
    const minScalar = is25519 ? _2n4 ** BigInt(254) : _2n4 ** BigInt(447);
    const maxAdded = is25519 ? BigInt(8) * (_2n4 ** BigInt(251) - _1n6) : BigInt(4) * (_2n4 ** BigInt(445) - _1n6);
    const maxScalar = minScalar + maxAdded + _1n6;
    const modP = (n) => mod(n, P);
    const GuBytes = encodeU(Gu);
    function encodeU(u) {
      return numberToBytesLE(modP(u), fieldLen);
    }
    function decodeU(u) {
      const _u = copyBytes(abytes2(u, fieldLen, "uCoordinate"));
      if (is25519)
        _u[31] &= 127;
      return modP(bytesToNumberLE(_u));
    }
    function decodeScalar(scalar) {
      return bytesToNumberLE(adjustScalarBytes2(copyBytes(abytes2(scalar, fieldLen, "scalar"))));
    }
    const lowOrderU = new Set(is25519 ? [
      _0n6,
      _1n6,
      P - _1n6,
      BigInt("325606250916557431795983626356110631294008115727848805560023387167927233504"),
      BigInt("39382357235489614581723060781553021112529911719440698176882885853963445705823")
    ] : [_0n6, _1n6, P - _1n6]);
    function scalarMult(scalar, u) {
      const pointU = decodeU(u);
      if (lowOrderU.has(pointU))
        throw new Error("invalid private or public key received");
      const pu = montgomeryLadder(pointU, decodeScalar(scalar));
      if (pu === _0n6)
        throw new Error("invalid private or public key received");
      return encodeU(pu);
    }
    function scalarMultBase(scalar) {
      if (mulBaseHook === void 0)
        return scalarMult(scalar, GuBytes);
      const k = decodeScalar(scalar);
      aInRange("scalar", k, minScalar, maxScalar);
      const pu = modP(mulBaseHook(k));
      if (pu === _0n6)
        throw new Error("invalid private or public key received");
      return encodeU(pu);
    }
    const getPublicKey = scalarMultBase;
    const getSharedSecret = scalarMult;
    function montgomeryLadder(u, scalar) {
      aInRange("u", u, _0n6, P);
      aInRange("scalar", scalar, minScalar, maxScalar);
      const k = scalar;
      const x_1 = u;
      let x_2 = _1n6;
      let z_2 = _0n6;
      let x_3 = u;
      let z_3 = _1n6;
      const kx = k ^ k >> _1n6;
      for (let t = BigInt(montgomeryBits - 1); t >= _0n6; t--) {
        const mask2 = cmask(P, kx >> t);
        ({ x_2, x_3 } = swap(mask2, x_2, x_3));
        ({ x_2: z_2, x_3: z_3 } = swap(mask2, z_2, z_3));
        const A = x_2 + z_2;
        const AA = modP(A * A);
        const B2 = x_2 - z_2;
        const BB = modP(B2 * B2);
        const E = AA - BB;
        const C = x_3 + z_3;
        const D2 = x_3 - z_3;
        const DA = modP(D2 * A);
        const CB = modP(C * B2);
        const dacb = DA + CB;
        const da_cb = DA - CB;
        x_3 = modP(dacb * dacb);
        z_3 = modP(x_1 * modP(da_cb * da_cb));
        x_2 = modP(AA * BB);
        z_2 = modP(E * (AA + modP(a24 * E)));
      }
      const mask = cmask(P, k);
      ({ x_2, x_3 } = swap(mask, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));
      const z2 = powPminus2(z_2);
      return modP(x_2 * z2);
    }
    const lengths = {
      secretKey: fieldLen,
      publicKey: fieldLen,
      seed: fieldLen
    };
    const randomSecretKey = (seed) => {
      seed = seed === void 0 ? randomBytes_(fieldLen) : seed;
      abytes2(seed, lengths.seed, "seed");
      return seed;
    };
    const utils = { randomSecretKey };
    Object.freeze(lengths);
    Object.freeze(utils);
    return Object.freeze({
      keygen: createKeygen(randomSecretKey, getPublicKey),
      getSharedSecret,
      getPublicKey,
      scalarMult,
      scalarMultBase,
      utils,
      GuBytes: GuBytes.slice(),
      lengths
    });
  }

  // node_modules/@noble/curves/ed25519.js
  var _0n7 = /* @__PURE__ */ BigInt(0);
  var _1n7 = /* @__PURE__ */ BigInt(1);
  var _2n5 = /* @__PURE__ */ BigInt(2);
  var _3n2 = /* @__PURE__ */ BigInt(3);
  var _5n2 = /* @__PURE__ */ BigInt(5);
  var _8n3 = /* @__PURE__ */ BigInt(8);
  var ed25519_CURVE_p = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
  var ed25519_CURVE = /* @__PURE__ */ (() => ({
    p: ed25519_CURVE_p,
    n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
    h: _8n3,
    a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
    d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
    Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
    Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
  }))();
  function ed25519_pow_2_252_3(x) {
    const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
    const P = ed25519_CURVE_p;
    const x2 = x * x % P;
    const b2 = x2 * x % P;
    const b4 = pow2(b2, _2n5, P) * b2 % P;
    const b5 = pow2(b4, _1n7, P) * x % P;
    const b10 = pow2(b5, _5n2, P) * b5 % P;
    const b20 = pow2(b10, _10n, P) * b10 % P;
    const b40 = pow2(b20, _20n, P) * b20 % P;
    const b80 = pow2(b40, _40n, P) * b40 % P;
    const b160 = pow2(b80, _80n, P) * b80 % P;
    const b240 = pow2(b160, _80n, P) * b80 % P;
    const b250 = pow2(b240, _10n, P) * b10 % P;
    const pow_p_5_8 = pow2(b250, _2n5, P) * x % P;
    return { pow_p_5_8, b2 };
  }
  function adjustScalarBytes(bytes) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  }
  var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
  function uvRatio(u, v) {
    const P = ed25519_CURVE_p;
    const v3 = mod(v * v * v, P);
    const v7 = mod(v3 * v3 * v, P);
    const pow3 = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
    let x = mod(u * v3 * pow3, P);
    const vx2 = mod(v * x * x, P);
    const root1 = x;
    const root2 = mod(x * ED25519_SQRT_M1, P);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === mod(-u, P);
    const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
    if (useRoot1)
      x = root1;
    if (useRoot2 || noRoot)
      x = root2;
    if (isNegativeLE(x, P))
      x = mod(-x, P);
    return { isValid: useRoot1 || useRoot2, value: x };
  }
  var ed25519_Point = /* @__PURE__ */ edwards(ed25519_CURVE, { uvRatio });
  var x25519 = /* @__PURE__ */ (() => {
    const P = ed25519_CURVE_p;
    const powPminus2 = (x) => {
      const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
      return mod(pow2(pow_p_5_8, _3n2, P) * b2, P);
    };
    return montgomery({
      P,
      type: "x25519",
      powPminus2,
      adjustScalarBytes,
      // ~3x faster fixed-base: [k]B on the birationally-equivalent Edwards curve using cached
      // base tables, mapped back via u = (1+y)/(1-y) = (Z+Y)/(Z-Y) with one Fermat inversion.
      // Same construction as libsodium's crypto_scalarmult_curve25519_base.
      scalarMultBase: (k) => {
        const kn = mod(k, ed25519_Point.Fn.ORDER);
        if (kn === _0n7)
          return _0n7;
        const p = ed25519_Point.BASE.multiply(kn);
        return mod((p.Z + p.Y) * powPminus2(mod(p.Z - p.Y, P)), P);
      }
    });
  })();

  // node_modules/@noble/hashes/hmac.js
  var _HMAC = class {
    oHash;
    iHash;
    blockLen;
    outputLen;
    canXOF = false;
    finished = false;
    destroyed = false;
    constructor(hash, key) {
      ahash(hash);
      abytes(key, void 0, "key");
      this.iHash = hash.create();
      if (typeof this.iHash.update !== "function")
        throw new Error("expected Hash instance");
      this.blockLen = this.iHash.blockLen;
      this.outputLen = this.iHash.outputLen;
      const blockLen = this.blockLen;
      const pad = new Uint8Array(blockLen);
      pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
      for (let i = 0; i < pad.length; i++)
        pad[i] ^= 54;
      this.iHash.update(pad);
      this.oHash = hash.create();
      for (let i = 0; i < pad.length; i++)
        pad[i] ^= 54 ^ 92;
      this.oHash.update(pad);
      clean(pad);
    }
    update(buf) {
      aexists(this);
      this.iHash.update(buf);
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const buf = out.subarray(0, this.outputLen);
      this.iHash.digestInto(buf);
      this.oHash.update(buf);
      this.oHash.digestInto(buf);
      this.destroy();
    }
    digest() {
      const out = new Uint8Array(this.oHash.outputLen);
      this.digestInto(out);
      return out;
    }
    _cloneInto(to) {
      to ||= Object.create(Object.getPrototypeOf(this), {});
      const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
      to = to;
      to.finished = finished;
      to.destroyed = destroyed;
      to.blockLen = blockLen;
      to.outputLen = outputLen;
      to.canXOF = canXOF;
      to.oHash = oHash._cloneInto(to.oHash);
      to.iHash = iHash._cloneInto(to.iHash);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
    destroy() {
      this.destroyed = true;
      this.oHash.destroy();
      this.iHash.destroy();
    }
  };
  var hmac = /* @__PURE__ */ (() => {
    const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
    hmac_.create = (hash, key) => new _HMAC(hash, key);
    return hmac_;
  })();

  // node_modules/@noble/hashes/hkdf.js
  var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
  var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
  function expand(hash, prk, info, length = 32, _recycled) {
    ahash(hash);
    anumber(length, "length");
    abytes(prk, void 0, "prk");
    const olen = hash.outputLen;
    if (prk.length < olen)
      throw new Error('"prk" must be at least HashLen octets');
    if (length > 255 * olen)
      throw new Error("Length must be <= 255*HashLen");
    const blocks = Math.ceil(length / olen);
    if (info === void 0)
      info = EMPTY_BUFFER;
    else
      abytes(info, void 0, "info");
    if (!blocks) {
      if (_recycled)
        clean(prk);
      return new Uint8Array();
    }
    const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
    const { iHash, oHash } = hmac.create(hash, prk);
    const T = _recycled ? prk : new Uint8Array(olen);
    const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
    for (let counter = 0; counter < blocks - 1; counter++) {
      HKDF_COUNTER[0] = counter + 1;
      const iWork = iHash._cloneInto(worker);
      if (counter)
        iWork.update(T);
      iWork.update(info).update(HKDF_COUNTER).digestInto(T);
      oHash._cloneInto(worker).update(T).digestInto(T);
      okm.set(T, olen * counter);
    }
    HKDF_COUNTER[0] = blocks;
    if (blocks > 1)
      iHash.update(T);
    iHash.update(info).update(HKDF_COUNTER).digestInto(T);
    oHash.update(T).digestInto(T);
    okm.set(T, olen * (blocks - 1));
    iHash.destroy();
    oHash.destroy();
    worker?.destroy();
    if (T !== okm)
      clean(T);
    clean(HKDF_COUNTER);
    if (length === okm.length)
      return okm;
    const res = okm.slice(0, length);
    clean(okm);
    return res;
  }
  var hkdf = (hash, ikm, salt, info, length) => {
    ahash(hash);
    if (salt === void 0)
      salt = new Uint8Array(hash.outputLen);
    const HMAC = hmac.create(hash, salt).update(ikm);
    return expand(hash, HMAC.digest(), info, length, HMAC);
  };

  // node_modules/@noble/ciphers/utils.js
  function isBytes3(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  var atitle3 = (title) => title ? `"${title}" ` : "";
  function abool3(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle3(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function anumber3(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle3(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle3(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abytes3(value, length, title = "") {
    if (isBytes3(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber3(length, "length");
    const bytes = isBytes3(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle3(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  var aobject4 = (value, label) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError(label === "object" ? "expected valid options object" : `"${label}" expected object, got type=${typeof value}`);
  };
  function aexists2(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput2(out, instance) {
    abytes3(out, void 0, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function u322(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean2(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  var isLE2 = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap2(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap322(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap2(arr[i]);
    }
    return arr;
  }
  var swap32IfBE2 = isLE2 ? (u) => u : byteSwap322;
  function overlapBytes(a, b) {
    if (!a.byteLength || !b.byteLength)
      return false;
    return a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
    a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
    b.byteOffset < a.byteOffset + a.byteLength;
  }
  function complexOverlapBytes(input, output) {
    if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
      throw new Error("complex overlap of input and output is not supported");
  }
  function checkOpts2(defaults, opts2) {
    aobject4(defaults, "defaults");
    aobject4(opts2, "opts");
    const merged = Object.assign(defaults, opts2);
    return merged;
  }
  function equalBytes2(a, b) {
    a = abytes3(a);
    b = abytes3(b);
    if (a.length !== b.length)
      return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
      diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function wrapMacConstructor(keyLen, macCons, fromMsg) {
    const mac = macCons;
    const getArgs = fromMsg || (() => []);
    const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
    const tmp = mac(new Uint8Array(keyLen), ...getArgs(new Uint8Array(0)));
    macC.outputLen = tmp.outputLen;
    macC.blockLen = tmp.blockLen;
    macC.create = (key, ...args) => mac(key, ...args);
    return macC;
  }
  var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
    function wrappedCipher(key, ...args) {
      abytes3(key, void 0, "key");
      if (params.nonceLength !== void 0) {
        const nonce = args[0];
        abytes3(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
      }
      const tagl = params.tagLength;
      const aadStart = params.nonceLength !== void 0 ? 1 : 0;
      if (!params.withAAD) {
        for (let i = aadStart; i < args.length; i++)
          if (isBytes3(args[i]))
            throw new Error("AAD not supported");
      }
      if (params.withAAD && args[aadStart] !== void 0)
        abytes3(args[aadStart], void 0, "AAD");
      const cipher = constructor(key, ...args);
      const checkOutput = (fnLength, output) => {
        if (output !== void 0) {
          if (fnLength !== 2)
            throw new Error("cipher output not supported");
          abytes3(output, void 0, "output");
        }
      };
      let called = false;
      const wrCipher = {
        encrypt(data, output) {
          if (called)
            throw new Error("cannot encrypt() twice with same key + nonce");
          called = true;
          abytes3(data, void 0, "data");
          checkOutput(cipher.encrypt.length, output);
          return cipher.encrypt(data, output);
        },
        decrypt(data, output) {
          abytes3(data, void 0, "data");
          if (tagl && data.length < tagl)
            throw new Error('"ciphertext" expected length >= tagLength=' + tagl);
          checkOutput(cipher.decrypt.length, output);
          return cipher.decrypt(data, output);
        }
      };
      return wrCipher;
    }
    Object.assign(wrappedCipher, params);
    return wrappedCipher;
  };
  function getOutput(expectedLength, out, onlyAligned = true) {
    if (out === void 0)
      return new Uint8Array(expectedLength);
    abytes3(out, expectedLength, "output");
    if (onlyAligned && !isAligned32(out))
      throw new Error("invalid output, must be aligned");
    return out;
  }
  function u64Lengths(dataLength, aadLength, isLE3) {
    anumber3(dataLength);
    anumber3(aadLength);
    abool3(isLE3);
    const num = new Uint8Array(16);
    const view = createView(num);
    view.setBigUint64(0, BigInt(aadLength), isLE3);
    view.setBigUint64(8, BigInt(dataLength), isLE3);
    return num;
  }
  function isAligned32(bytes) {
    return bytes.byteOffset % 4 === 0;
  }
  function copyBytes3(bytes) {
    return Uint8Array.from(abytes3(bytes));
  }

  // node_modules/@noble/ciphers/_arx.js
  var encodeStr = (str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0));
  var sigma16_32 = /* @__PURE__ */ (() => swap32IfBE2(u322(encodeStr("expand 16-byte k"))))();
  var sigma32_32 = /* @__PURE__ */ (() => swap32IfBE2(u322(encodeStr("expand 32-byte k"))))();
  function rotl(a, b) {
    return a << b | a >>> 32 - b;
  }
  var BLOCK_LEN = 64;
  var BLOCK_LEN32 = 16;
  var MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
  var U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
  function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
    const len = data.length;
    const block = new Uint8Array(BLOCK_LEN);
    const b32 = u322(block);
    const isAligned = isLE2 && isAligned32(data) && isAligned32(output);
    const d32 = isAligned ? u322(data) : U32_EMPTY;
    const o32 = isAligned ? u322(output) : U32_EMPTY;
    if (!isLE2) {
      for (let pos = 0; pos < len; counter++) {
        core(sigma, key, nonce, b32, counter, rounds);
        swap32IfBE2(b32);
        if (counter >= MAX_COUNTER)
          throw new Error("arx: counter overflow");
        const take = Math.min(BLOCK_LEN, len - pos);
        for (let j = 0, posj; j < take; j++) {
          posj = pos + j;
          output[posj] = data[posj] ^ block[j];
        }
        pos += take;
      }
      return;
    }
    for (let pos = 0; pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      if (isAligned && take === BLOCK_LEN) {
        const pos32 = pos / 4;
        if (pos % 4 !== 0)
          throw new Error("arx: invalid block position");
        for (let j = 0, posj; j < BLOCK_LEN32; j++) {
          posj = pos32 + j;
          o32[posj] = d32[posj] ^ b32[j];
        }
        pos += BLOCK_LEN;
        continue;
      }
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
  }
  function createCipher(core, opts2) {
    const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts2({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts2);
    if (typeof core !== "function")
      throw new Error("core must be a function");
    anumber3(counterLength);
    anumber3(rounds);
    abool3(counterRight);
    abool3(allowShortKeys);
    return (key, nonce, data, output, counter = 0) => {
      abytes3(key, void 0, "key");
      abytes3(nonce, void 0, "nonce");
      abytes3(data, void 0, "data");
      const len = data.length;
      const hasOutput = output !== void 0;
      output = getOutput(len, output, false);
      if (hasOutput)
        complexOverlapBytes(data, output);
      anumber3(counter);
      if (counter < 0 || counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const toClean = [];
      let l = key.length;
      let k;
      let sigma;
      if (l === 32) {
        toClean.push(k = copyBytes3(key));
        sigma = sigma32_32;
      } else if (l === 16 && allowShortKeys) {
        k = new Uint8Array(32);
        k.set(key);
        k.set(key, 16);
        sigma = sigma16_32;
        toClean.push(k);
      } else {
        abytes3(key, 32, "arx key");
        throw new Error("invalid key size");
      }
      if (!isLE2 || !isAligned32(nonce))
        toClean.push(nonce = copyBytes3(nonce));
      let k32 = u322(k);
      if (extendNonceFn) {
        if (nonce.length !== 24)
          throw new Error("arx: extended nonce must be 24 bytes");
        const n16 = nonce.subarray(0, 16);
        if (isLE2)
          extendNonceFn(sigma, k32, u322(n16), k32);
        else {
          const sigmaRaw = swap32IfBE2(Uint32Array.from(sigma));
          extendNonceFn(sigmaRaw, k32, u322(n16), k32);
          clean2(sigmaRaw);
          swap32IfBE2(k32);
        }
        nonce = nonce.subarray(16);
      } else if (!isLE2)
        swap32IfBE2(k32);
      const nonceNcLen = 16 - counterLength;
      if (nonceNcLen !== nonce.length)
        throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
      if (nonceNcLen !== 12) {
        const nc = new Uint8Array(12);
        nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
        nonce = nc;
        toClean.push(nonce);
      }
      const n32 = swap32IfBE2(u322(nonce));
      try {
        runCipher(core, sigma, k32, n32, data, output, counter, rounds);
        return output;
      } finally {
        clean2(...toClean);
      }
    };
  }

  // node_modules/@noble/ciphers/_poly1305.js
  function u8to16(a, i) {
    return a[i++] & 255 | (a[i++] & 255) << 8;
  }
  var Poly1305 = class {
    blockLen = 16;
    outputLen = 16;
    buffer = new Uint8Array(16);
    r = new Uint16Array(10);
    // Allocating 1 array with .subarray() here is slower than 3
    h = new Uint16Array(10);
    pad = new Uint16Array(8);
    pos = 0;
    finished = false;
    destroyed = false;
    // Can be speed-up using BigUint64Array, at the cost of complexity
    constructor(key) {
      key = copyBytes3(abytes3(key, 32, "key"));
      const t0 = u8to16(key, 0);
      const t1 = u8to16(key, 2);
      const t2 = u8to16(key, 4);
      const t3 = u8to16(key, 6);
      const t4 = u8to16(key, 8);
      const t5 = u8to16(key, 10);
      const t6 = u8to16(key, 12);
      const t7 = u8to16(key, 14);
      this.r[0] = t0 & 8191;
      this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
      this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
      this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
      this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
      this.r[5] = t4 >>> 1 & 8190;
      this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
      this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
      this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
      this.r[9] = t7 >>> 5 & 127;
      for (let i = 0; i < 8; i++)
        this.pad[i] = u8to16(key, 16 + 2 * i);
    }
    process(data, offset, isLast = false) {
      const hibit = isLast ? 0 : 1 << 11;
      const { h, r } = this;
      const r0 = r[0];
      const r1 = r[1];
      const r2 = r[2];
      const r3 = r[3];
      const r4 = r[4];
      const r5 = r[5];
      const r6 = r[6];
      const r7 = r[7];
      const r8 = r[8];
      const r9 = r[9];
      const t0 = u8to16(data, offset + 0);
      const t1 = u8to16(data, offset + 2);
      const t2 = u8to16(data, offset + 4);
      const t3 = u8to16(data, offset + 6);
      const t4 = u8to16(data, offset + 8);
      const t5 = u8to16(data, offset + 10);
      const t6 = u8to16(data, offset + 12);
      const t7 = u8to16(data, offset + 14);
      let h0 = h[0] + (t0 & 8191);
      let h1 = h[1] + ((t0 >>> 13 | t1 << 3) & 8191);
      let h2 = h[2] + ((t1 >>> 10 | t2 << 6) & 8191);
      let h3 = h[3] + ((t2 >>> 7 | t3 << 9) & 8191);
      let h4 = h[4] + ((t3 >>> 4 | t4 << 12) & 8191);
      let h5 = h[5] + (t4 >>> 1 & 8191);
      let h6 = h[6] + ((t4 >>> 14 | t5 << 2) & 8191);
      let h7 = h[7] + ((t5 >>> 11 | t6 << 5) & 8191);
      let h8 = h[8] + ((t6 >>> 8 | t7 << 8) & 8191);
      let h9 = h[9] + (t7 >>> 5 | hibit);
      let c = 0;
      let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
      c = d0 >>> 13;
      d0 &= 8191;
      d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
      c += d0 >>> 13;
      d0 &= 8191;
      let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
      c = d1 >>> 13;
      d1 &= 8191;
      d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
      c += d1 >>> 13;
      d1 &= 8191;
      let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
      c = d2 >>> 13;
      d2 &= 8191;
      d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
      c += d2 >>> 13;
      d2 &= 8191;
      let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
      c = d3 >>> 13;
      d3 &= 8191;
      d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
      c += d3 >>> 13;
      d3 &= 8191;
      let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
      c = d4 >>> 13;
      d4 &= 8191;
      d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
      c += d4 >>> 13;
      d4 &= 8191;
      let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
      c = d5 >>> 13;
      d5 &= 8191;
      d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
      c += d5 >>> 13;
      d5 &= 8191;
      let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
      c = d6 >>> 13;
      d6 &= 8191;
      d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
      c += d6 >>> 13;
      d6 &= 8191;
      let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
      c = d7 >>> 13;
      d7 &= 8191;
      d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
      c += d7 >>> 13;
      d7 &= 8191;
      let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
      c = d8 >>> 13;
      d8 &= 8191;
      d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
      c += d8 >>> 13;
      d8 &= 8191;
      let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
      c = d9 >>> 13;
      d9 &= 8191;
      d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
      c += d9 >>> 13;
      d9 &= 8191;
      c = (c << 2) + c | 0;
      c = c + d0 | 0;
      d0 = c & 8191;
      c = c >>> 13;
      d1 += c;
      h[0] = d0;
      h[1] = d1;
      h[2] = d2;
      h[3] = d3;
      h[4] = d4;
      h[5] = d5;
      h[6] = d6;
      h[7] = d7;
      h[8] = d8;
      h[9] = d9;
    }
    finalize() {
      const { h, pad } = this;
      const g = new Uint16Array(10);
      let c = h[1] >>> 13;
      h[1] &= 8191;
      for (let i = 2; i < 10; i++) {
        h[i] += c;
        c = h[i] >>> 13;
        h[i] &= 8191;
      }
      h[0] += c * 5;
      c = h[0] >>> 13;
      h[0] &= 8191;
      h[1] += c;
      c = h[1] >>> 13;
      h[1] &= 8191;
      h[2] += c;
      g[0] = h[0] + 5;
      c = g[0] >>> 13;
      g[0] &= 8191;
      for (let i = 1; i < 10; i++) {
        g[i] = h[i] + c;
        c = g[i] >>> 13;
        g[i] &= 8191;
      }
      g[9] -= 1 << 13;
      let mask = (c ^ 1) - 1;
      for (let i = 0; i < 10; i++)
        g[i] &= mask;
      mask = ~mask;
      for (let i = 0; i < 10; i++)
        h[i] = h[i] & mask | g[i];
      h[0] = (h[0] | h[1] << 13) & 65535;
      h[1] = (h[1] >>> 3 | h[2] << 10) & 65535;
      h[2] = (h[2] >>> 6 | h[3] << 7) & 65535;
      h[3] = (h[3] >>> 9 | h[4] << 4) & 65535;
      h[4] = (h[4] >>> 12 | h[5] << 1 | h[6] << 14) & 65535;
      h[5] = (h[6] >>> 2 | h[7] << 11) & 65535;
      h[6] = (h[7] >>> 5 | h[8] << 8) & 65535;
      h[7] = (h[8] >>> 8 | h[9] << 5) & 65535;
      let f = h[0] + pad[0];
      h[0] = f & 65535;
      for (let i = 1; i < 8; i++) {
        f = (h[i] + pad[i] | 0) + (f >>> 16) | 0;
        h[i] = f & 65535;
      }
      clean2(g);
    }
    update(data) {
      aexists2(this);
      abytes3(data);
      data = copyBytes3(data);
      const { buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(data, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(buffer, 0, false);
          this.pos = 0;
        }
      }
      return this;
    }
    destroy() {
      this.destroyed = true;
      clean2(this.h, this.r, this.buffer, this.pad);
    }
    digestInto(out) {
      aexists2(this);
      aoutput2(out, this);
      this.finished = true;
      const { buffer, h } = this;
      let { pos } = this;
      if (pos) {
        buffer[pos++] = 1;
        for (; pos < 16; pos++)
          buffer[pos] = 0;
        this.process(buffer, 0, true);
      }
      this.finalize();
      let opos = 0;
      for (let i = 0; i < 8; i++) {
        out[opos++] = h[i] >>> 0;
        out[opos++] = h[i] >>> 8;
      }
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
  };
  var poly1305 = /* @__PURE__ */ wrapMacConstructor(32, (key) => new Poly1305(key));

  // node_modules/@noble/ciphers/chacha.js
  function chachaCore(s, k, n, out, cnt, rounds = 20) {
    let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let r = 0; r < rounds; r += 2) {
      x00 = x00 + x04 | 0;
      x12 = rotl(x12 ^ x00, 16);
      x08 = x08 + x12 | 0;
      x04 = rotl(x04 ^ x08, 12);
      x00 = x00 + x04 | 0;
      x12 = rotl(x12 ^ x00, 8);
      x08 = x08 + x12 | 0;
      x04 = rotl(x04 ^ x08, 7);
      x01 = x01 + x05 | 0;
      x13 = rotl(x13 ^ x01, 16);
      x09 = x09 + x13 | 0;
      x05 = rotl(x05 ^ x09, 12);
      x01 = x01 + x05 | 0;
      x13 = rotl(x13 ^ x01, 8);
      x09 = x09 + x13 | 0;
      x05 = rotl(x05 ^ x09, 7);
      x02 = x02 + x06 | 0;
      x14 = rotl(x14 ^ x02, 16);
      x10 = x10 + x14 | 0;
      x06 = rotl(x06 ^ x10, 12);
      x02 = x02 + x06 | 0;
      x14 = rotl(x14 ^ x02, 8);
      x10 = x10 + x14 | 0;
      x06 = rotl(x06 ^ x10, 7);
      x03 = x03 + x07 | 0;
      x15 = rotl(x15 ^ x03, 16);
      x11 = x11 + x15 | 0;
      x07 = rotl(x07 ^ x11, 12);
      x03 = x03 + x07 | 0;
      x15 = rotl(x15 ^ x03, 8);
      x11 = x11 + x15 | 0;
      x07 = rotl(x07 ^ x11, 7);
      x00 = x00 + x05 | 0;
      x15 = rotl(x15 ^ x00, 16);
      x10 = x10 + x15 | 0;
      x05 = rotl(x05 ^ x10, 12);
      x00 = x00 + x05 | 0;
      x15 = rotl(x15 ^ x00, 8);
      x10 = x10 + x15 | 0;
      x05 = rotl(x05 ^ x10, 7);
      x01 = x01 + x06 | 0;
      x12 = rotl(x12 ^ x01, 16);
      x11 = x11 + x12 | 0;
      x06 = rotl(x06 ^ x11, 12);
      x01 = x01 + x06 | 0;
      x12 = rotl(x12 ^ x01, 8);
      x11 = x11 + x12 | 0;
      x06 = rotl(x06 ^ x11, 7);
      x02 = x02 + x07 | 0;
      x13 = rotl(x13 ^ x02, 16);
      x08 = x08 + x13 | 0;
      x07 = rotl(x07 ^ x08, 12);
      x02 = x02 + x07 | 0;
      x13 = rotl(x13 ^ x02, 8);
      x08 = x08 + x13 | 0;
      x07 = rotl(x07 ^ x08, 7);
      x03 = x03 + x04 | 0;
      x14 = rotl(x14 ^ x03, 16);
      x09 = x09 + x14 | 0;
      x04 = rotl(x04 ^ x09, 12);
      x03 = x03 + x04 | 0;
      x14 = rotl(x14 ^ x03, 8);
      x09 = x09 + x14 | 0;
      x04 = rotl(x04 ^ x09, 7);
    }
    let oi = 0;
    out[oi++] = y00 + x00 | 0;
    out[oi++] = y01 + x01 | 0;
    out[oi++] = y02 + x02 | 0;
    out[oi++] = y03 + x03 | 0;
    out[oi++] = y04 + x04 | 0;
    out[oi++] = y05 + x05 | 0;
    out[oi++] = y06 + x06 | 0;
    out[oi++] = y07 + x07 | 0;
    out[oi++] = y08 + x08 | 0;
    out[oi++] = y09 + x09 | 0;
    out[oi++] = y10 + x10 | 0;
    out[oi++] = y11 + x11 | 0;
    out[oi++] = y12 + x12 | 0;
    out[oi++] = y13 + x13 | 0;
    out[oi++] = y14 + x14 | 0;
    out[oi++] = y15 + x15 | 0;
  }
  var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 4,
    allowShortKeys: false
  });
  var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
  var updatePadded = (h, msg) => {
    h.update(msg);
    const leftover = msg.length % 16;
    if (leftover)
      h.update(ZEROS16.subarray(leftover));
  };
  var ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
  function computeTag(fn, key, nonce, ciphertext, AAD) {
    if (AAD !== void 0)
      abytes3(AAD, void 0, "AAD");
    const authKey = fn(key, nonce, ZEROS32);
    const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);
    const h = poly1305.create(authKey);
    if (AAD)
      updatePadded(h, AAD);
    updatePadded(h, ciphertext);
    h.update(lengths);
    const res = h.digest();
    clean2(authKey, lengths);
    return res;
  }
  var _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
    const tagLength = 16;
    return {
      encrypt(plaintext, output) {
        const plength = plaintext.length;
        output = getOutput(plength + tagLength, output, false);
        output.set(plaintext);
        const oPlain = output.subarray(0, -tagLength);
        xorStream(key, nonce, oPlain, oPlain, 1);
        const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
        output.set(tag, plength);
        clean2(tag);
        return output;
      },
      decrypt(ciphertext, output) {
        output = getOutput(ciphertext.length - tagLength, output, false);
        const data = ciphertext.subarray(0, -tagLength);
        const passedTag = ciphertext.subarray(-tagLength);
        const tag = computeTag(xorStream, key, nonce, data, AAD);
        if (!equalBytes2(passedTag, tag)) {
          clean2(tag);
          throw new Error("invalid tag");
        }
        output.set(ciphertext.subarray(0, -tagLength));
        xorStream(key, nonce, output, output, 1);
        clean2(tag);
        return output;
      }
    };
  };
  var chacha20poly1305 = /* @__PURE__ */ wrapCipher(
    { blockSize: 64, nonceLength: 12, tagLength: 16, withAAD: true },
    /* @__PURE__ */ _poly1305_aead(chacha20)
  );

  // src/pqc-engine.js
  var MAGIC_BYTES = new Uint8Array([80, 81, 82, 84]);
  var PROTOCOL_VERSION = 1;
  var MSG_TYPE_HANDSHAKE_INIT = 1;
  var MSG_TYPE_HANDSHAKE_RESP = 2;
  var MSG_TYPE_RATCHET_DATA = 3;
  var MSG_TYPE_TERMINATE = 4;
  var MLKEM768_PUBLIC_KEY_BYTES = 1184;
  var MLKEM768_CIPHERTEXT_BYTES = 1088;
  var MLKEM768_SHARED_SECRET_BYTES = 32;
  var X25519_KEY_BYTES = 32;
  var X25519_SHARED_SECRET_BYTES = 32;
  var MLDSA65_PUBLIC_KEY_BYTES = 1952;
  var MLDSA65_SIGNATURE_BYTES = 3309;
  var SYMMETRIC_KEY_BYTES = 32;
  var AEAD_NONCE_BYTES = 12;
  var AEAD_TAG_BYTES = 16;
  var ROOT_KEY_BYTES = 64;
  var CHAIN_KEY_BYTES = 32;
  var DOMAIN_HYBRID_KEM = new TextEncoder().encode("PQ-RATCHET-HYBRID-KEM-MLKEM768-X25519-v1");
  var DOMAIN_ROOT_INIT = new TextEncoder().encode("PQ-RATCHET-ROOT-INIT-v1");
  var DOMAIN_ASYM_RATCHET = new TextEncoder().encode("PQ-RATCHET-ASYM-RATCHET-v1");
  var DOMAIN_CHAIN_ADVANCE = new TextEncoder().encode("PQ-RATCHET-SYM-CHAIN-v1");
  var DOMAIN_MESSAGE_KEY = new TextEncoder().encode("PQ-RATCHET-MSG-KEY-v1");
  var DOMAIN_AUTH_TRANSCRIPT = new TextEncoder().encode("PQ-RATCHET-AUTH-TRANSCRIPT-v1");
  var DOMAIN_AUTH_INITIATOR = new TextEncoder().encode("PQ-RATCHET-AUTH-INIT-v1");
  var DOMAIN_AUTH_RESPONDER = new TextEncoder().encode("PQ-RATCHET-AUTH-RESP-v1");
  var MAX_SKIPPED_KEYS_CACHE = 1e3;
  var MAX_RATCHET_SKIP_GAP = 1e3;
  var MAX_PACKET_PAYLOAD_BYTES = 16 * 1024 * 1024;
  function computeInitiatorTranscript(version, initiatorIdPK, responderIdPK, initiatorEphemKEMPK) {
    return concatBytes3(
      DOMAIN_AUTH_INITIATOR,
      new Uint8Array([version]),
      new TextEncoder().encode("INITIATOR"),
      initiatorIdPK,
      responderIdPK,
      initiatorEphemKEMPK
    );
  }
  function computeResponderTranscript(version, initiatorIdPK, responderIdPK, initiatorEphemKEMPK, kemCt, responderEphemKEMPK) {
    return concatBytes3(
      DOMAIN_AUTH_RESPONDER,
      new Uint8Array([version]),
      new TextEncoder().encode("RESPONDER"),
      initiatorIdPK,
      responderIdPK,
      initiatorEphemKEMPK,
      kemCt,
      responderEphemKEMPK
    );
  }
  function zeroize(buf) {
    if (!buf) return;
    if (buf instanceof Uint8Array || buf instanceof Array) {
      for (let i = 0; i < buf.length; i++) {
        buf[i] = 0;
      }
    }
  }
  function concatBytes3(...arrays) {
    let totalLen = 0;
    for (const arr of arrays) {
      totalLen += arr.length;
    }
    const out = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of arrays) {
      out.set(arr, offset);
      offset += arr.length;
    }
    return out;
  }
  function bytesToHex3(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function hexToBytes3(hex) {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex length");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }
  function bytesToBase64(bytes) {
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
  function writeUint32BE(val) {
    const buf = new Uint8Array(4);
    const view = new DataView(buf.buffer);
    view.setUint32(0, val, false);
    return buf;
  }
  function readUint32BE(bytes, offset) {
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
    return view.getUint32(0, false);
  }
  function dual_prf_combine(salt, ml_kem_secret, x25519_secret, context_info = DOMAIN_HYBRID_KEM, output_len = 32) {
    const ikm = concatBytes3(ml_kem_secret, x25519_secret);
    try {
      const s = salt && salt.length > 0 ? salt : void 0;
      return hkdf(sha3_512, ikm, s, context_info, output_len);
    } finally {
      zeroize(ikm);
    }
  }
  function asymmetric_ratchet_kdf(root_key, combined_shared_secret, context = DOMAIN_ASYM_RATCHET) {
    const derived = hkdf(sha3_512, combined_shared_secret, root_key, context, ROOT_KEY_BYTES + CHAIN_KEY_BYTES);
    try {
      const next_root = derived.slice(0, ROOT_KEY_BYTES);
      const next_chain = derived.slice(ROOT_KEY_BYTES, ROOT_KEY_BYTES + CHAIN_KEY_BYTES);
      return [next_root, next_chain];
    } finally {
      zeroize(derived);
    }
  }
  function symmetric_chain_step(chain_key) {
    const step_adv = concatBytes3(new Uint8Array([1]), DOMAIN_CHAIN_ADVANCE);
    const h_next = hmac(sha3_512, chain_key, step_adv);
    const next_chain_key = h_next.slice(0, CHAIN_KEY_BYTES);
    const step_msg = concatBytes3(new Uint8Array([2]), DOMAIN_MESSAGE_KEY);
    const h_msg = hmac(sha3_512, chain_key, step_msg);
    const message_key = h_msg.slice(0, SYMMETRIC_KEY_BYTES);
    return [next_chain_key, message_key];
  }
  var IdentityPublicKey = class _IdentityPublicKey {
    constructor(raw_bytes) {
      if (raw_bytes.length !== MLDSA65_PUBLIC_KEY_BYTES) {
        throw new Error(`Invalid ML-DSA-65 public key size: expected ${MLDSA65_PUBLIC_KEY_BYTES}, got ${raw_bytes.length}`);
      }
      this.raw_bytes = new Uint8Array(raw_bytes);
    }
    toBytes() {
      return new Uint8Array(this.raw_bytes);
    }
    static fromBytes(data) {
      return new _IdentityPublicKey(data);
    }
    verify(signature, message) {
      if (signature.length !== MLDSA65_SIGNATURE_BYTES) return false;
      try {
        return ml_dsa65.verify(signature, message, this.raw_bytes);
      } catch (e) {
        return false;
      }
    }
    fingerprint() {
      const digest = sha3_256(this.raw_bytes);
      return `mldsa65:${bytesToHex3(digest)}`;
    }
  };
  var IdentityPrivateKey = class _IdentityPrivateKey {
    constructor(publicKey, secretKey) {
      this.publicKeyBytes = publicKey;
      this.secretKeyBytes = secretKey;
    }
    static generate() {
      const kp = ml_dsa65.keygen();
      return new _IdentityPrivateKey(kp.publicKey, kp.secretKey);
    }
    publicKey() {
      return new IdentityPublicKey(this.publicKeyBytes);
    }
    sign(message) {
      return ml_dsa65.sign(message, this.secretKeyBytes);
    }
    sign_prekey(hybrid_kem_pk_bytes) {
      const payload = concatBytes3(DOMAIN_AUTH_TRANSCRIPT, hybrid_kem_pk_bytes);
      return this.sign(payload);
    }
    zeroize() {
      zeroize(this.secretKeyBytes);
    }
  };
  var HybridKEMCiphertext = class _HybridKEMCiphertext {
    constructor(mlkem_ct, x25519_ephem_pk_bytes) {
      this.mlkem_ct = mlkem_ct;
      this.x25519_ephem_pk_bytes = x25519_ephem_pk_bytes;
    }
    toBytes() {
      return concatBytes3(this.mlkem_ct, this.x25519_ephem_pk_bytes);
    }
    static fromBytes(data) {
      const expected = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
      if (data.length !== expected) {
        throw new Error(`Invalid ciphertext length: expected ${expected}, got ${data.length}`);
      }
      const ct = data.slice(0, MLKEM768_CIPHERTEXT_BYTES);
      const ephem = data.slice(MLKEM768_CIPHERTEXT_BYTES);
      return new _HybridKEMCiphertext(ct, ephem);
    }
  };
  var HybridKEMPublicKey = class _HybridKEMPublicKey {
    constructor(mlkem_pk_bytes, x25519_pk_bytes) {
      this.mlkem_pk = mlkem_pk_bytes;
      this.x25519_pk = x25519_pk_bytes;
    }
    toBytes() {
      return concatBytes3(this.mlkem_pk, this.x25519_pk);
    }
    static fromBytes(data) {
      const expected = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
      if (data.length !== expected) {
        throw new Error(`Invalid public key length: expected ${expected}, got ${data.length}`);
      }
      const mlkem_bytes = data.slice(0, MLKEM768_PUBLIC_KEY_BYTES);
      const x25519_bytes = data.slice(MLKEM768_PUBLIC_KEY_BYTES);
      return new _HybridKEMPublicKey(mlkem_bytes, x25519_bytes);
    }
    encapsulate() {
      let ss_kem, ct_kem, ss_ec;
      const ephem_ec_priv = x25519.utils.randomSecretKey();
      try {
        const kem_enc = ml_kem768.encapsulate(this.mlkem_pk);
        ss_kem = kem_enc.sharedSecret;
        ct_kem = kem_enc.cipherText;
        const ephem_ec_pub = x25519.getPublicKey(ephem_ec_priv);
        ss_ec = x25519.getSharedSecret(ephem_ec_priv, this.x25519_pk);
        const combined_ss = dual_prf_combine(new Uint8Array(0), ss_kem, ss_ec, DOMAIN_HYBRID_KEM, 32);
        const ct = new HybridKEMCiphertext(ct_kem, ephem_ec_pub);
        return [ct, combined_ss];
      } finally {
        zeroize(ss_kem);
        zeroize(ss_ec);
        zeroize(ephem_ec_priv);
      }
    }
  };
  var HybridKEMPrivateKey = class _HybridKEMPrivateKey {
    constructor(mlkem_sk, mlkem_pk, x25519_sk, x25519_pk) {
      this.mlkem_sk = mlkem_sk;
      this.mlkem_pk = mlkem_pk;
      this.x25519_sk = x25519_sk;
      this.x25519_pk = x25519_pk;
    }
    static generate() {
      const kem = ml_kem768.keygen();
      const ec_kp = x25519.keygen();
      return new _HybridKEMPrivateKey(kem.secretKey, kem.publicKey, ec_kp.secretKey, ec_kp.publicKey);
    }
    publicKey() {
      return new HybridKEMPublicKey(this.mlkem_pk, this.x25519_pk);
    }
    decapsulate(ciphertext) {
      let ss_kem, ss_ec;
      try {
        ss_kem = ml_kem768.decapsulate(ciphertext.mlkem_ct, this.mlkem_sk);
        ss_ec = x25519.getSharedSecret(this.x25519_sk, ciphertext.x25519_ephem_pk_bytes);
        return dual_prf_combine(new Uint8Array(0), ss_kem, ss_ec, DOMAIN_HYBRID_KEM, 32);
      } finally {
        zeroize(ss_kem);
        zeroize(ss_ec);
      }
    }
    zeroize() {
      zeroize(this.mlkem_sk);
      zeroize(this.x25519_sk);
    }
  };
  var HandshakeInitPacket = class _HandshakeInitPacket {
    constructor(sender_identity_pk_bytes, ephemeral_kem_pk_bytes, signature) {
      this.sender_identity_pk_bytes = sender_identity_pk_bytes;
      this.ephemeral_kem_pk_bytes = ephemeral_kem_pk_bytes;
      this.signature = signature;
    }
    serialize() {
      const header = new Uint8Array(6);
      header.set(MAGIC_BYTES, 0);
      header[4] = PROTOCOL_VERSION;
      header[5] = MSG_TYPE_HANDSHAKE_INIT;
      return concatBytes3(header, this.sender_identity_pk_bytes, this.ephemeral_kem_pk_bytes, this.signature);
    }
    static deserialize(data) {
      if (data.length < 6) throw new Error("Packet underflow: missing header");
      if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
      if (data[4] !== PROTOCOL_VERSION) throw new Error(`Unsupported protocol version: ${data[4]}`);
      if (data[5] !== MSG_TYPE_HANDSHAKE_INIT) throw new Error(`Unexpected message type: ${data[5]}`);
      let offset = 6;
      const id_pk = data.slice(offset, offset + MLDSA65_PUBLIC_KEY_BYTES);
      offset += MLDSA65_PUBLIC_KEY_BYTES;
      const kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
      const kem_pk = data.slice(offset, offset + kem_pk_len);
      offset += kem_pk_len;
      const sig = data.slice(offset, offset + MLDSA65_SIGNATURE_BYTES);
      if (id_pk.length !== MLDSA65_PUBLIC_KEY_BYTES || kem_pk.length !== kem_pk_len || sig.length !== MLDSA65_SIGNATURE_BYTES) {
        throw new Error("Malformed handshake init packet length");
      }
      return new _HandshakeInitPacket(id_pk, kem_pk, sig);
    }
  };
  var HandshakeRespPacket = class _HandshakeRespPacket {
    constructor(responder_identity_pk_bytes, kem_ct_bytes, ephemeral_kem_pk_bytes, signature) {
      this.responder_identity_pk_bytes = responder_identity_pk_bytes;
      this.kem_ct_bytes = kem_ct_bytes;
      this.ephemeral_kem_pk_bytes = ephemeral_kem_pk_bytes;
      this.signature = signature;
    }
    serialize() {
      const header = new Uint8Array(6);
      header.set(MAGIC_BYTES, 0);
      header[4] = PROTOCOL_VERSION;
      header[5] = MSG_TYPE_HANDSHAKE_RESP;
      return concatBytes3(header, this.responder_identity_pk_bytes, this.kem_ct_bytes, this.ephemeral_kem_pk_bytes, this.signature);
    }
    static deserialize(data) {
      if (data.length < 6) throw new Error("Packet underflow: missing header");
      if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
      if (data[4] !== PROTOCOL_VERSION || data[5] !== MSG_TYPE_HANDSHAKE_RESP) throw new Error("Malformed handshake response header");
      let offset = 6;
      const id_pk = data.slice(offset, offset + MLDSA65_PUBLIC_KEY_BYTES);
      offset += MLDSA65_PUBLIC_KEY_BYTES;
      const ct_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
      const kem_ct = data.slice(offset, offset + ct_len);
      offset += ct_len;
      const kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
      const kem_pk = data.slice(offset, offset + kem_pk_len);
      offset += kem_pk_len;
      const sig = data.slice(offset, offset + MLDSA65_SIGNATURE_BYTES);
      return new _HandshakeRespPacket(id_pk, kem_ct, kem_pk, sig);
    }
  };
  var RatchetDataPacket = class _RatchetDataPacket {
    constructor(epoch, seq, kem_ct, next_kem_pk, ciphertext) {
      this.epoch = epoch;
      this.seq = seq;
      this.kem_ct = kem_ct;
      this.next_kem_pk = next_kem_pk;
      this.ciphertext = ciphertext;
    }
    static deriveNonce(epoch, seq) {
      const nonce = new Uint8Array(12);
      nonce.set(writeUint32BE(epoch), 0);
      nonce.set(writeUint32BE(seq), 4);
      nonce.set(writeUint32BE(0), 8);
      return nonce;
    }
    serialize() {
      let flags = 0;
      if (this.kem_ct) flags |= 1;
      if (this.next_kem_pk) flags |= 2;
      const header = new Uint8Array(15);
      header.set(MAGIC_BYTES, 0);
      header[4] = PROTOCOL_VERSION;
      header[5] = MSG_TYPE_RATCHET_DATA;
      header.set(writeUint32BE(this.epoch), 6);
      header.set(writeUint32BE(this.seq), 10);
      header[14] = flags;
      const parts = [header];
      if (this.kem_ct) parts.push(this.kem_ct);
      if (this.next_kem_pk) parts.push(this.next_kem_pk);
      parts.push(writeUint32BE(this.ciphertext.length));
      parts.push(this.ciphertext);
      return concatBytes3(...parts);
    }
    static deserialize(data) {
      if (data.length < 15) throw new Error("Packet underflow: missing ratchet header");
      if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
      if (data[4] !== PROTOCOL_VERSION || data[5] !== MSG_TYPE_RATCHET_DATA) throw new Error("Invalid ratchet packet header");
      const epoch = readUint32BE(data, 6);
      const seq = readUint32BE(data, 10);
      const flags = data[14];
      let offset = 15;
      let kem_ct = null;
      if (flags & 1) {
        const ct_len2 = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
        kem_ct = data.slice(offset, offset + ct_len2);
        if (kem_ct.length !== ct_len2) throw new Error("Truncated KEM ciphertext");
        offset += ct_len2;
      }
      let next_kem_pk = null;
      if (flags & 2) {
        const pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
        next_kem_pk = data.slice(offset, offset + pk_len);
        if (next_kem_pk.length !== pk_len) throw new Error("Truncated next KEM public key");
        offset += pk_len;
      }
      if (data.length < offset + 4) throw new Error("Missing ciphertext length");
      const ct_len = readUint32BE(data, offset);
      offset += 4;
      const ciphertext = data.slice(offset, offset + ct_len);
      if (ciphertext.length !== ct_len) throw new Error("Incomplete ciphertext payload");
      return new _RatchetDataPacket(epoch, seq, kem_ct, next_kem_pk, ciphertext);
    }
    getAssociatedData() {
      let flags = 0;
      if (this.kem_ct) flags |= 1;
      if (this.next_kem_pk) flags |= 2;
      const header = new Uint8Array(15);
      header.set(MAGIC_BYTES, 0);
      header[4] = PROTOCOL_VERSION;
      header[5] = MSG_TYPE_RATCHET_DATA;
      header.set(writeUint32BE(this.epoch), 6);
      header.set(writeUint32BE(this.seq), 10);
      header[14] = flags;
      const parts = [header];
      if (this.kem_ct) parts.push(this.kem_ct);
      if (this.next_kem_pk) parts.push(this.next_kem_pk);
      return concatBytes3(...parts);
    }
  };
  var PQRatchetSession = class _PQRatchetSession {
    constructor(localIdentity, remoteIdentity, isInitiator) {
      this.localIdentity = localIdentity;
      this.remoteIdentity = remoteIdentity;
      this.isInitiator = isInitiator;
      this.rootKey = new Uint8Array(ROOT_KEY_BYTES);
      this.sendingChainKey = null;
      this.receivingChainKey = null;
      this.localEphemSK = null;
      this.remoteEphemPK = null;
      this.epoch = 0;
      this.sendingSeq = 0;
      this.receivingSeq = 0;
      this._pendingKemCt = null;
      this._pendingNextKemPk = null;
      this.skippedKeys = /* @__PURE__ */ new Map();
    }
    static initiateHandshake(localIdentity, remoteIdentity) {
      if (!remoteIdentity) {
        throw new Error("remoteIdentity is required for authenticated handshake");
      }
      const ephemSK = HybridKEMPrivateKey.generate();
      const ephemPK = ephemSK.publicKey();
      const ephemPKBytes = ephemPK.toBytes();
      const localIdPKBytes = localIdentity.publicKey().toBytes();
      const remoteIdPKBytes = remoteIdentity.toBytes();
      const initTranscript = computeInitiatorTranscript(
        PROTOCOL_VERSION,
        localIdPKBytes,
        remoteIdPKBytes,
        ephemPKBytes
      );
      const sig = localIdentity.sign(initTranscript);
      const initPacket = new HandshakeInitPacket(
        localIdPKBytes,
        ephemPKBytes,
        sig
      );
      const session = new _PQRatchetSession(localIdentity, remoteIdentity, true);
      session.localEphemSK = ephemSK;
      return [session, initPacket.serialize()];
    }
    static respondHandshake(localIdentity, initPacketBytes, expectedRemoteIdentity) {
      if (!expectedRemoteIdentity) {
        throw new Error("expectedRemoteIdentity is required for authenticated handshake");
      }
      const initPkt = HandshakeInitPacket.deserialize(initPacketBytes);
      const senderIdPK = IdentityPublicKey.fromBytes(initPkt.sender_identity_pk_bytes);
      if (!constantTimeCompare(senderIdPK.toBytes(), expectedRemoteIdentity.toBytes())) {
        throw new Error("Initiator identity does not match expected peer public key");
      }
      const expectedInitTranscript = computeInitiatorTranscript(
        PROTOCOL_VERSION,
        senderIdPK.toBytes(),
        localIdentity.publicKey().toBytes(),
        initPkt.ephemeral_kem_pk_bytes
      );
      if (!senderIdPK.verify(initPkt.signature, expectedInitTranscript)) {
        throw new Error("Cryptographic verification failure: invalid initiator prekey signature");
      }
      const aliceEphemPK = HybridKEMPublicKey.fromBytes(initPkt.ephemeral_kem_pk_bytes);
      const [kemCt, sharedSecret] = aliceEphemPK.encapsulate();
      const bobEphemSK = HybridKEMPrivateKey.generate();
      const bobEphemPK = bobEphemSK.publicKey();
      const bobEphemPKBytes = bobEphemPK.toBytes();
      const respTranscript = computeResponderTranscript(
        PROTOCOL_VERSION,
        senderIdPK.toBytes(),
        localIdentity.publicKey().toBytes(),
        initPkt.ephemeral_kem_pk_bytes,
        kemCt.toBytes(),
        bobEphemPKBytes
      );
      const respSig = localIdentity.sign(respTranscript);
      const [rootKey, chainKey] = asymmetric_ratchet_kdf(DOMAIN_ROOT_INIT, sharedSecret, DOMAIN_ASYM_RATCHET);
      const session = new _PQRatchetSession(localIdentity, senderIdPK, false);
      session.rootKey = rootKey;
      session.sendingChainKey = chainKey;
      session.localEphemSK = bobEphemSK;
      session.remoteEphemPK = aliceEphemPK;
      const respPacket = new HandshakeRespPacket(
        localIdentity.publicKey().toBytes(),
        kemCt.toBytes(),
        bobEphemPKBytes,
        respSig
      );
      return [session, respPacket.serialize()];
    }
    validateHandshakeResponse(respPacketBytes) {
      if (!this.isInitiator || !this.localEphemSK) {
        return false;
      }
      try {
        const respPkt = HandshakeRespPacket.deserialize(respPacketBytes);
        const respIdPK = IdentityPublicKey.fromBytes(respPkt.responder_identity_pk_bytes);
        if (this.remoteIdentity) {
          if (!constantTimeCompare(respIdPK.toBytes(), this.remoteIdentity.toBytes())) {
            return false;
          }
        }
        const expectedRespTranscript = computeResponderTranscript(
          PROTOCOL_VERSION,
          this.localIdentity.publicKey().toBytes(),
          respIdPK.toBytes(),
          this.localEphemSK.publicKey().toBytes(),
          respPkt.kem_ct_bytes,
          respPkt.ephemeral_kem_pk_bytes
        );
        if (!respIdPK.verify(respPkt.signature, expectedRespTranscript)) {
          return false;
        }
        HybridKEMCiphertext.fromBytes(respPkt.kem_ct_bytes);
        HybridKEMPublicKey.fromBytes(respPkt.ephemeral_kem_pk_bytes);
        return true;
      } catch (e) {
        return false;
      }
    }
    completeHandshake(respPacketBytes) {
      if (!this.isInitiator || !this.localEphemSK) {
        throw new Error("Session state is not in a pending initiator handshake");
      }
      const respPkt = HandshakeRespPacket.deserialize(respPacketBytes);
      const respIdPK = IdentityPublicKey.fromBytes(respPkt.responder_identity_pk_bytes);
      if (this.remoteIdentity) {
        if (!constantTimeCompare(respIdPK.toBytes(), this.remoteIdentity.toBytes())) {
          throw new Error("Responder identity does not match expected peer public key");
        }
      }
      const expectedRespTranscript = computeResponderTranscript(
        PROTOCOL_VERSION,
        this.localIdentity.publicKey().toBytes(),
        respIdPK.toBytes(),
        this.localEphemSK.publicKey().toBytes(),
        respPkt.kem_ct_bytes,
        respPkt.ephemeral_kem_pk_bytes
      );
      if (!respIdPK.verify(respPkt.signature, expectedRespTranscript)) {
        throw new Error("Cryptographic verification failure: invalid responder signature");
      }
      if (!this.remoteIdentity) {
        this.remoteIdentity = respIdPK;
      }
      const kemCt = HybridKEMCiphertext.fromBytes(respPkt.kem_ct_bytes);
      const sharedSecret = this.localEphemSK.decapsulate(kemCt);
      const [rootKey, recvChain] = asymmetric_ratchet_kdf(DOMAIN_ROOT_INIT, sharedSecret, DOMAIN_ASYM_RATCHET);
      this.rootKey = rootKey;
      this.receivingChainKey = recvChain;
      const bobEphemPK = HybridKEMPublicKey.fromBytes(respPkt.ephemeral_kem_pk_bytes);
      this.remoteEphemPK = bobEphemPK;
      this.localEphemSK.zeroize();
      this.localEphemSK = null;
      const aliceNextSK = HybridKEMPrivateKey.generate();
      const aliceNextPK = aliceNextSK.publicKey();
      const [nextKemCt, nextSS] = bobEphemPK.encapsulate();
      const [newRoot, sendChain] = asymmetric_ratchet_kdf(this.rootKey, nextSS, DOMAIN_ASYM_RATCHET);
      this.rootKey = newRoot;
      this.sendingChainKey = sendChain;
      this.localEphemSK = aliceNextSK;
      this._pendingKemCt = nextKemCt.toBytes();
      this._pendingNextKemPk = aliceNextPK.toBytes();
      this.epoch += 1;
    }
    ratchetEncrypt(plaintextBytes) {
      if (plaintextBytes.length > MAX_PACKET_PAYLOAD_BYTES) {
        throw new Error("Plaintext exceeds maximum bound");
      }
      if (!this.sendingChainKey) {
        throw new Error("Sending chain key not initialized");
      }
      const [nextChain, messageKey] = symmetric_chain_step(this.sendingChainKey);
      zeroize(this.sendingChainKey);
      this.sendingChainKey = nextChain;
      const seq = this.sendingSeq;
      const epoch = this.epoch;
      this.sendingSeq += 1;
      const kemCt = this._pendingKemCt;
      const nextKemPk = this._pendingNextKemPk;
      this._pendingKemCt = null;
      this._pendingNextKemPk = null;
      const prelimPacket = new RatchetDataPacket(epoch, seq, kemCt, nextKemPk, new Uint8Array(0));
      const ad = prelimPacket.getAssociatedData();
      const nonce = RatchetDataPacket.deriveNonce(epoch, seq);
      const cipher = chacha20poly1305(messageKey, nonce, ad);
      const ciphertext = cipher.encrypt(plaintextBytes);
      zeroize(messageKey);
      const packet = new RatchetDataPacket(epoch, seq, kemCt, nextKemPk, ciphertext);
      return packet.serialize();
    }
    ratchetDecrypt(packetBytes) {
      const packet = RatchetDataPacket.deserialize(packetBytes);
      const nonce = RatchetDataPacket.deriveNonce(packet.epoch, packet.seq);
      const ad = packet.getAssociatedData();
      const cacheKey = `${packet.epoch}:${packet.seq}`;
      if (this.skippedKeys.has(cacheKey)) {
        const mk2 = this.skippedKeys.get(cacheKey);
        const cipher2 = chacha20poly1305(mk2, nonce, ad);
        let pt;
        try {
          pt = cipher2.decrypt(packet.ciphertext);
        } catch (e) {
          throw new Error("Cryptographic verification failure: invalid AEAD tag on skipped key");
        }
        this.skippedKeys.delete(cacheKey);
        zeroize(mk2);
        return pt;
      }
      let draftRootKey = this.rootKey ? new Uint8Array(this.rootKey) : null;
      let draftRecvChain = this.receivingChainKey ? new Uint8Array(this.receivingChainKey) : null;
      let draftSendChain = this.sendingChainKey ? new Uint8Array(this.sendingChainKey) : null;
      let draftRemoteEphemPK = this.remoteEphemPK;
      let draftLocalEphemSK = this.localEphemSK;
      let draftPendingKemCt = this._pendingKemCt;
      let draftPendingNextKemPk = this._pendingNextKemPk;
      let draftEpoch = this.epoch;
      let draftRecvSeq = this.receivingSeq;
      let draftSendSeq = this.sendingSeq;
      if (packet.kem_ct && draftLocalEphemSK) {
        const kemCt = HybridKEMCiphertext.fromBytes(packet.kem_ct);
        const sharedSecret = draftLocalEphemSK.decapsulate(kemCt);
        const [newRootRecv, recvChain] = asymmetric_ratchet_kdf(draftRootKey, sharedSecret, DOMAIN_ASYM_RATCHET);
        draftRootKey = newRootRecv;
        draftRecvChain = recvChain;
        draftRecvSeq = 0;
        draftEpoch = packet.epoch;
        draftLocalEphemSK = null;
        if (packet.next_kem_pk) {
          draftRemoteEphemPK = HybridKEMPublicKey.fromBytes(packet.next_kem_pk);
        }
        if (draftRemoteEphemPK) {
          const localNextSK = HybridKEMPrivateKey.generate();
          const localNextPK = localNextSK.publicKey();
          const [nextKemCt, nextSS] = draftRemoteEphemPK.encapsulate();
          const [newRootSend, sendChain] = asymmetric_ratchet_kdf(draftRootKey, nextSS, DOMAIN_ASYM_RATCHET);
          draftRootKey = newRootSend;
          draftSendChain = sendChain;
          draftLocalEphemSK = localNextSK;
          draftSendSeq = 0;
          draftPendingKemCt = nextKemCt.toBytes();
          draftPendingNextKemPk = localNextPK.toBytes();
        }
      }
      if (!draftRecvChain) {
        throw new Error("Receiving chain key not initialized");
      }
      if (packet.seq < draftRecvSeq) {
        throw new Error(`Monotonicity violation: inbound seq ${packet.seq} < receiving seq ${draftRecvSeq}`);
      }
      const gap = packet.seq - draftRecvSeq;
      if (gap > MAX_RATCHET_SKIP_GAP) {
        throw new Error(`Sequence gap ${gap} exceeds safety bound ${MAX_RATCHET_SKIP_GAP}`);
      }
      const draftPendingSkipped = [];
      let currChain = draftRecvChain;
      let currSeq = draftRecvSeq;
      while (currSeq < packet.seq) {
        const [nextChain, skippedMk] = symmetric_chain_step(currChain);
        zeroize(currChain);
        currChain = nextChain;
        draftPendingSkipped.push([`${packet.epoch}:${currSeq}`, skippedMk]);
        currSeq += 1;
      }
      const [finalRecvChain, targetMessageKey] = symmetric_chain_step(currChain);
      zeroize(currChain);
      draftRecvChain = finalRecvChain;
      draftRecvSeq = packet.seq + 1;
      const cipher = chacha20poly1305(targetMessageKey, nonce, ad);
      let plaintext;
      try {
        plaintext = cipher.decrypt(packet.ciphertext);
      } catch (e) {
        for (const [_, mk2] of draftPendingSkipped) {
          zeroize(mk2);
        }
        zeroize(targetMessageKey);
        zeroize(draftRecvChain);
        if (draftSendChain && draftSendChain !== this.sendingChainKey) zeroize(draftSendChain);
        if (draftRootKey && draftRootKey !== this.rootKey) zeroize(draftRootKey);
        if (draftLocalEphemSK && draftLocalEphemSK !== this.localEphemSK) draftLocalEphemSK.zeroize();
        throw new Error("Cryptographic verification failure: invalid AEAD authentication tag");
      }
      zeroize(targetMessageKey);
      if (this.rootKey) zeroize(this.rootKey);
      if (this.receivingChainKey) zeroize(this.receivingChainKey);
      if (this.sendingChainKey && this.sendingChainKey !== draftSendChain) zeroize(this.sendingChainKey);
      if (this.localEphemSK && this.localEphemSK !== draftLocalEphemSK) this.localEphemSK.zeroize();
      this.rootKey = draftRootKey;
      this.receivingChainKey = draftRecvChain;
      this.sendingChainKey = draftSendChain;
      this.remoteEphemPK = draftRemoteEphemPK;
      this.localEphemSK = draftLocalEphemSK;
      this._pendingKemCt = draftPendingKemCt;
      this._pendingNextKemPk = draftPendingNextKemPk;
      this.epoch = draftEpoch;
      this.receivingSeq = draftRecvSeq;
      this.sendingSeq = draftSendSeq;
      for (const [key, mk2] of draftPendingSkipped) {
        if (this.skippedKeys.size >= MAX_SKIPPED_KEYS_CACHE) {
          const oldestKey = this.skippedKeys.keys().next().value;
          const oldestMk = this.skippedKeys.get(oldestKey);
          zeroize(oldestMk);
          this.skippedKeys.delete(oldestKey);
        }
        this.skippedKeys.set(key, mk2);
      }
      return plaintext;
    }
    close() {
      if (this.localIdentity) this.localIdentity.zeroize();
      if (this.localEphemSK) this.localEphemSK.zeroize();
      if (this.sendingChainKey) zeroize(this.sendingChainKey);
      if (this.receivingChainKey) zeroize(this.receivingChainKey);
      if (this.rootKey) zeroize(this.rootKey);
      for (const [_, mk2] of this.skippedKeys) {
        zeroize(mk2);
      }
      this.skippedKeys.clear();
    }
  };
  if (typeof window !== "undefined") {
    window.PQC = {
      IdentityPrivateKey,
      IdentityPublicKey,
      HybridKEMPrivateKey,
      HybridKEMPublicKey,
      HybridKEMCiphertext,
      HandshakeInitPacket,
      HandshakeRespPacket,
      RatchetDataPacket,
      PQRatchetSession,
      computeInitiatorTranscript,
      computeResponderTranscript,
      dual_prf_combine,
      asymmetric_ratchet_kdf,
      symmetric_chain_step,
      bytesToBase64,
      base64ToBytes,
      bytesToHex: bytesToHex3,
      hexToBytes: hexToBytes3,
      zeroize,
      constants: {
        MAGIC_BYTES,
        PROTOCOL_VERSION,
        MLKEM768_PUBLIC_KEY_BYTES,
        MLKEM768_CIPHERTEXT_BYTES,
        MLDSA65_PUBLIC_KEY_BYTES,
        MLDSA65_SIGNATURE_BYTES,
        X25519_KEY_BYTES,
        DOMAIN_AUTH_INITIATOR,
        DOMAIN_AUTH_RESPONDER,
        MAX_RATCHET_SKIP_GAP
      }
    };
  }
  return __toCommonJS(pqc_engine_exports);
})();
/*! Bundled license information:

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/edwards.js:
@noble/curves/abstract/montgomery.js:
@noble/curves/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/utils.js:
@noble/post-quantum/_crystals.js:
@noble/post-quantum/ml-kem.js:
@noble/post-quantum/ml-dsa.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)

@noble/ciphers/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
