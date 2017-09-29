declare const Buffer;

declare function require(name:string);
var RSA = require('node-rsa');
var crypto = require('crypto');
var http = require('http');
var util = require('util');
var net = require('net');

var securityTable = {
  open: 0,
  none: 0,
  wep_psk: 1,
  wep_shared: 0x8001,
  wpa_tkip: 0x00200002,
  wpa_aes: 0x00200004,
  wpa2_aes: 0x00400004,
  wpa2_tkip: 0x00400002,
  wpa2_mixed: 0x00400006,
  wpa2: 0x00400006,
  wpa_enterprise_aes: 0x02200004,
  wpa_enterprise_tkip: 0x02200002,
  wpa2_enterprise_aes: 0x02400004,
  wpa2_enterprise_tkip: 0x02400002,
  wpa2_enterprise_mixed: 0x02400006,
  wpa2_enterprise: 0x02400006,
  enterprise: 0x02000000
};

var eapTypeTable = {
  peap: 25,
  'peap/mschapv2': 25,
  'eap-tls': 13,
  tls: 13
};

function is(cb:Function) {
  if (cb) {
    return true;
  }
  throw new Error('Invalid callback function provided.');
}

function formatPem(data:string) {
  return data.trim() + '\r\n';
}

function checkResponse(err:any, dat:any, cb:Function) {
  if (err) {
    return cb(err);
  }
  if (!dat) {
    return cb(new Error('No data received'));
  }
  if (dat.r !== 0) {
    return cb(new Error('Received non-zero response code'));
  }
}

var SoftAPOptions:any = {};
SoftAPOptions.defaultOptions = () => {
  return {
    host: '192.168.0.1',
    keepAlive: true,
    timeout: 8000,
    noDelay: true,
    channel: 6
  };
};
SoftAPOptions.assign = (opts:any, options:any) => {
  if (options && typeof options == 'object') {
    Object.keys(options).forEach((key) => {
      opts[key] = options[key];
    });
  }
}
export { SoftAPOptions };

export class SoftAP {
  __publicKey:any;
  keepAlive:boolean;
  noDelay:boolean;
  timeout:number;
  host:string;
  port:number;
  warmedUp:boolean;
  protocol:string;

  constructor(options:any) {
    this.keepAlive = options.keepAlive;
    this.noDelay = options.noDelay;
    this.timeout = options.timeout;
    this.host = options.host;
    this.protocol = options.protocol;
    this.port = options.port;

    this.__publicKey = undefined;

    return this;
  }

  _sendProtocolCommand(cmd:any, cb:Function) {
    if (this.protocol === 'tcp') {
      this._sendProtocolCommandTcp(cmd, cb);
    } else if (this.protocol === 'http') {
      this._sendProtocolCommandHttp(cmd, cb);
    } else {
      throw new Error('unknown protocol');
    }
  }
  _sendProtocolCommandTcp(cmd:any, cb:Function) {
    var that = this;

    function sendRealCommand() {
      sendCommand.bind(that)(cmd, cb);
    }

    /**
     * The first command sent to the device seems to keep the socket open, so we send a no-op
     * command and throw it away.
     */
    if (!this.warmedUp) {
      this.warmedUp = true;
      sendCommand.bind(that)({name: 'device-id'}, sendRealCommand, true, 2000);
    }
    else {
      sendRealCommand();
    }

    function sendCommand(cmd:any, cb:Function, forceClose:boolean, timeoutOverride:Number) {
      var err, json;
      var data = '';

      var sock = net.createConnection(this.port, this.host);
      sock.setNoDelay(this.noDelay);
      sock.setTimeout(timeoutOverride || this.timeout);
      sock.setKeepAlive(this.keepAlive);

      var to = setTimeout(function socketTimedOut() {
        err = new Error('TCP socket timed out');
        sock.destroy();
      }, this.timeout);

      sock.once('connect', function socketConnected() {
        var send;
        if (cmd.body && typeof cmd.body === 'object') {
          var body = JSON.stringify(cmd.body);
          var length = body.length;
          send = util.format('%s\n%s\n\n%s', cmd.name, length, body);
        } else {
          send = util.format('%s\n0\n\n', cmd.name);
        }

        sock.write(send);
      });

      sock.on('data', function socketData(chunk) {
        data += chunk.toString();
        try {
          json = JSON.parse(data);
          clearTimeout(to);
          if (forceClose) {
            sock.end();
          }
        } catch (e) {
          // Wait for more data to come in
        }
      });

      sock.once('error', function socketError(error) {
        err = error;
        clearTimeout(to);
      });

      sock.once('timeout', function socketTimeout() {
        clearTimeout(to);
        err = new Error('TCP socket timed out');
        sock.destroy();
      });

      sock.once('close', function socketClose(hadError) {
        if (!err && hadError) {
          err = new Error('unknown socket error');
        }
        cb(err, json);
      });
    }
  }

  _sendProtocolCommandHttp(cmd:any, cb:Function) {
    var payload;

    if (!cmd || typeof cmd !== 'object') {
      throw new Error('Invalid command object specified.');
    }

    var opts:any = {};
    opts.method = 'GET';
    opts.path = '/' + cmd.name;
    opts.hostname = this.host;
    opts.port = this.port;
    opts.protocol = 'http:';

    if ((cmd.body) && typeof cmd.body === 'object') {
      payload = JSON.stringify(cmd.body);
      // NOTE: 'Content-Type' is set here to make this a "simple" cross-site
      // request, as per the HTTP CORS docs:
      //   https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Simple_requests
      // According to the spec, this means that POST can be made directly
      // without an OPTIONS request being made first.
      opts.headers = {
        'Content-Length': payload.length,
        'Content-Type': 'application/x-www-form-urlencoded'
      };
      opts.method = 'POST';
    }

    var req = http.request(opts);
    req.setTimeout(this.timeout);

    var to = setTimeout(function socketTimedOut() {
      req.abort();
      cb(new Error('HTTP timed out'));
    }, this.timeout);

    req.on('response', function responseHandler(res) {
      var results = '';
      res.on('data', function dataHandler(chunk) {
        if (chunk) {
          results += chunk.toString();
        }
      });
      res.once('end', function httpEnd() {
        clearTimeout(to);

        var json;
        try {
          json = JSON.parse(results.toString());
        } catch (e) {
          return cb(new Error('Invalid JSON received from device.'));
        }
        cb(null, json);
      });
    });

    req.once('error', function httpError(err) {
      clearTimeout(to);
      cb(err);
    });

    if (payload) {
      req.write(payload);
    }
    req.end();
  }

  __sendCommand(cmd:any, cb:Function) {
    is(cb);
    if (typeof cmd == 'object') {
      if (!cmd.name) {
        throw new Error('Command object has no name property');
      }
    } else {
      throw new Error('Invalid command');
    }

    return this._sendProtocolCommand(cmd, cb);
  }

  scan(cb:Function) {
    is(cb);
    this.__sendCommand({ name: 'scan-ap' }, function response(err, json) {
      if (err) {
        return cb(err);
      }
      cb(null, json.scans);
    });
  }

  connect(index:any, cb?:any) {
    var cbFormated:Function;
    var indexFormated:number;
    if (!cb) {
      if (Object.prototype.toString.call( index ) === "[object Function]") {
        cbFormated = index;
      }
      else {
        cbFormated = () => {};
      }
      indexFormated = 0;
    }
    is(cb);
    this.__sendCommand({ name: 'connect-ap', body: { idx: indexFormated } }, function response(err, dat) {
      checkResponse(err, dat, cbFormated);
      cbFormated();
    });
  }

  deviceInfo(cb:Function) {
    is(cb);
    this.__sendCommand({ name: 'device-id' }, function response(err, dat) {
      if (err) {
        return cb(err);
      }

      var claimed = dat.c === '1';
      var id = dat.id && dat.id.toLowerCase();
      this.__deviceID = id;

      cb(null, {
        id : id,
        claimed : claimed
      });
    }.bind(this));
  }

  publicKey(cb:Function) {
    is(cb);
    this.__sendCommand({ name: 'public-key' }, function response(err, dat) {
      checkResponse(err, dat, cb);
      var buff = new Buffer(dat.b, 'hex');
      this.__publicKey = new RSA(buff.slice(22), 'pkcs1-public-der', {
        encryptionScheme: 'pkcs1'
      });
      cb(null, this.__publicKey.exportKey('pkcs8-public'));
    }.bind(this));
  }

  set(data:any, cb:Function) {
   is(cb);
   this.__sendCommand({ name: 'set', body: data }, function response(err, dat) {
     checkResponse(err, dat, cb);
     cb();
   });
  }

  setClaimCode(code:string, cb:Function) {
    is(cb);
    if (!code) {
      throw new Error('Must provide claim code string as first parameter');
    }
    var claim = {
      k: 'cc',
      v: code
    };
    this.set(claim, cb);
  }

  aesEncrypt(data:any, kiv?:any) {
    if (!kiv) {
      kiv = crypto.randomBytes(32);
    }
    var kivEncrypted = this.__publicKey.encrypt(kiv, 'hex');
    var cipher = crypto.createCipheriv('aes-128-cbc', kiv.slice(0, 16), kiv.slice(16, 32));
    var encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      kiv: kivEncrypted,
      encrypted: encrypted
    };
  }

  configure(opts:any, cb:Function) {
    is(cb);

    var securePass = undefined;

    if (!this.__publicKey) {
      throw new Error('Must retrieve public key of device prior to AP configuration');
    }
    if (!opts || typeof opts !== 'object') {
      throw new Error('Missing configuration options object as first parameter');
    }
    if (!opts.ssid) {
      if (!opts.name) {
        throw new Error('Configuration options contain no ssid property');
      }
      opts.ssid = opts.name;
    }

    if ((opts.enc || opts.sec) && !opts.security) {
      opts.security = opts.sec || opts.enc;
    }
    if (!opts.security) {
      opts.security = 'open';
      opts.password = null;
    }
    if (opts.password || opts.pass) {
      if (!opts.security) {
        throw new Error('Password provided but no security type specified');
      }
      if (opts.pass && !opts.password) {
        opts.password = opts.pass;
      }
      securePass = this.__publicKey.encrypt(opts.password, 'hex');
    }
    if (typeof opts.security === 'string') {
      opts.security = securityTable[opts.security];
    }

    var apConfig:any = {};
    apConfig.idx = opts.index || 0;
    apConfig.ssid = opts.ssid;
    apConfig.sec = opts.security;
    apConfig.ch = parseInt(opts.channel);

    if (opts.security & securityTable.enterprise) {
      if (!opts.eap)
        throw new Error('Security is set to Enterprise, but no EAP type provided');
      if (typeof opts.eap === 'string') {
        opts.eap = eapTypeTable[opts.eap.toLowerCase()];
      }
      if (opts.eap === undefined) {
        throw new Error('Unknown EAP type provided');
      }
      if (opts.eap == eapTypeTable.peap) {
        // inner identity and password are mandatory
        opts.inner_identity = opts.inner_identity || opts.username;
        if (!opts.inner_identity || !opts.password) {
          throw new Error('PEAP credentials missing');
        }
        apConfig.ii = opts.inner_identity;
        // Password is set later on
      } else if (opts.eap == eapTypeTable.tls) {
        // client certificate and private key are mandatory
        if (!opts.private_key || !opts.client_certificate) {
          throw new Error('EAP-TLS credentials missing');
        }
        apConfig.crt = formatPem(opts.client_certificate);
        var enc = this.aesEncrypt(formatPem(opts.private_key));
        apConfig.key = enc.encrypted;
        apConfig.ek = enc.kiv;
      }
      apConfig.eap = opts.eap;
      if (opts.outer_identity) {
        apConfig.oi = opts.outer_identity;
      }
      opts.ca = opts.ca || opts.root_ca;
      if (opts.ca) {
        apConfig.ca = formatPem(opts.ca);
      }
    }

    if (securePass) {
      apConfig.pwd = securePass;
    }


    this.__sendCommand({ name: 'configure-ap', body: apConfig }, cb);
  }

  version(cb:Function) {
    is(cb);
    this.__sendCommand({ name: 'version' }, cb);
  }

  securityValue(name:string) {
    return securityTable[name.toLowerCase()];
  }

  securityLookup(dec:string) {
    var match = null;
    Object.keys(securityTable).forEach(function securityType(key) {
      if (parseInt(dec) === securityTable[key]) {
        match = key;
      }
    });
    return match;
  }

  eapTypeValue(name:string) {
    return eapTypeTable[name.toLowerCase()];
  }
}