"use strict";

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function utf8Encode(o) {
    return utf8Encoder.encode(o);
}

function utf8Decode(o) {
    return utf8Decoder.decode(o);
}

const uint8ArrayTag = "__bytes";
const hashTag = "__hash";
const boxTag = "__box";
const signatureTypeName = "anychain.signature";
const revocationTypeName = "anychain.revoke";


function blake2b(opt, o) {
    return sodium.crypto_generichash(opt.hashLength, o, opt.key);
}

function blake2bStr(opt, s) {
    return blake2b(opt, utf8Encode(s));
}

function blake2bInit(opt) {
    return sodium.crypto_generichash_init(opt.key, opt.hashLength);
}

function blake2bUpdate(state, o) {
    return sodium.crypto_generichash_update(state, o);
}

function blake2bFinal(opt, state) {
    return sodium.crypto_generichash_final(state, opt.hashLength);
}

/***/

class Hash {
    constructor(raw) {
        this._raw = raw;
    }

    base64() {
        return sodium.to_base64(this._raw);
    }

    hex() {
        return sodium.to_hex(this._raw);
    }
}

class Box {
    constructor(raw) {
        this._raw = raw;
    }

    base64() {
        return sodium.to_base64(this._raw);
    }
}

/***/

function isDict(o) {
    return (
        o !== null &&
        typeof(o) == "object" &&
        o.constructor != Uint8Array &&
        o.constructor != Hash &&
        o.constructor != Box
    );
}

function seedOf(opt, args) {
    if (args.length < 3) {
        throw "Anychain.seedOf(rootSeed, length, path, [to, [seed, [...]]])"
    }

    let seed = args[0];
    let length = args[1];
    for (let i=2; i<args.length; ++i) {
        const isLast = args.length - 1 == i;
        let key = args[i];
        let pathH = sodium.crypto_generichash(64, key, opt.key);
        seed = sodium.crypto_generichash(isLast ? length : 64, seed, opt.key);
    }

    return seed;
};

function passwordSeed(pwd, salt) {
    return sodium.crypto_pwhash(
        64,
        pwd,
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT
    );
}

const defaultValidators = {
    [signatureTypeName]: (chain, o) => {
        if (!("signature" in o && "signer" in o && "date" in o && "body" in o)) {
            throw "missing fields";
        }

        // XXX check o.date is a date

        const hash = chain._fold({
            type: o.type,
            body: o.body,
            date: o.date,
            signer: o.signer,
        });

        const ok = sodium.crypto_sign_verify_detached(o.signature, hash, o.signer);
        if (!ok) {
            throw "bad signature or forged document";
        }
    },

    [revocationTypeName]: (chain, o) => {
        if (!("revocation" in o && "signature" in o)) {
            throw "missing fields";
        }

        const hash = chain._fold({
            type: o.type,
            signature: o.signature,
        });

        const ok = sodium.crypto_sign_verify_detached(o.revocation, hash, o.signature.signer);
        if (!ok) {
            throw "bad revocation's signature";
        }
    },
};

class Chain {
    constructor(options) {
        const defaultOptions = {
            hashLength: 64,
            key: null,
        };

        this.options = options || {};
        for (const [k, v] of Object.entries(defaultOptions)) {
            if (!(k in this.options)) {
                this.options[k] = v;
            }
        }

        this.validators = {};
        this.ready = sodium.ready;

        this.registerValidator(defaultValidators);
    }

    //// CHAIN VERIFICATION & SAFETY

    registerValidator(validators) {
        for (const [k, v] of Object.entries(validators)) {
            if (k in this.validators) {
                throw `model '${k}' already registered`;
            }

            this.validators[k] = v;
        }
    }

    // Check if o has the expectedType and the chain is valid
    verify(o, expectedType) {
        if (o === undefined) {
            throw "undefined value";
        }

        if (expectedType === undefined) {
            throw "not expected type defined";
        }

        if (!(isDict(o) && 'type' in o && o.type == expectedType)) {
            throw `invalid chain: expected type '${expectedType}', got '${o.type}'`
        }

        this._verify(o);
    }

    _verify(o) {
        if (Array.isArray(o)) {
            for (const i of o) {
                this._verify(i);
            }
        }

        else if (isDict(o)) {
            for (const [k, v] of Object.entries(o)) {
                this._verify(k);
                this._verify(v);
            }
        }

        // if object is a chain piece
        if (isDict(o) && typeof o.type == "string") {
            const validator = this.validators[o.type];
            if (validator === undefined) {
                throw `potentially invalid chain: no defined validator for type '${o.type}'`;
            }

            try {
                validator(this, o);
            } catch(e) {
                throw `invalid chain: ${e}`;
            }
        }
    }

    //// CHAIN FOLDING & HASHING

    _fold(o) {
        let type = typeof o;

        let h = null;
        if (o == null) {
            h = blake2bStr(this.options, "null:null");

        } else if (type == "boolean") {
            if (o) {
                h = blake2bStr(this.options, "boolean:true");
            } else {
                h = blake2bStr(this.options, "boolean:false");
            }
        } else if (type == "number") {
            h = blake2bStr(this.options, "number:" + JSON.stringify(o));

        } else if (type == "string") {
            h = blake2bStr(this.options, "string:" + o);

        } else if (type != "object") {
            // pass
            //
        } else if (o.constructor == Uint8Array) {
            let state = blake2bInit(this.options);
            blake2bUpdate(state, utf8Encode("bytes:"));
            blake2bUpdate(state, o);
            h = blake2bFinal(this.options, state);

        } else if (o.constructor == Hash) {
            h = o._raw;

        } else if (o.constructor == Box) {
            let state = blake2bInit(this.options);
            blake2bUpdate(state, utf8Encode("box:"));
            blake2bUpdate(state, o._raw);
            h = blake2bFinal(this.options, state);

        } else if (Array.isArray(o)) {
            let state = blake2bInit(this.options);
            blake2bUpdate(state, utf8Encode("list:"));
            for (let i in o) {
                let v = o[i];
                blake2bUpdate(state, this._fold(v));
            }
            h = blake2bFinal(this.options, state);
        } else {
            let stateK = blake2bInit(this.options);
            blake2bUpdate(stateK, utf8Encode("keys:"));
            let stateV = blake2bInit(this.options);
            blake2bUpdate(stateV, utf8Encode("values:"));

            let entries = Object.entries(o).sort();
            for (let i in entries) {
                let k, v = entries[i];
                blake2bUpdate(stateK, this._fold(k));
                blake2bUpdate(stateV, this._fold(v));
            }

            let state = blake2bInit(this.options);
            blake2bUpdate(state, utf8Encode("dict:"));
            blake2bUpdate(state, blake2bFinal(this.options, stateK));
            blake2bUpdate(state, blake2bFinal(this.options, stateV));
            h = blake2bFinal(this.options, state);
        }

        if (h == null) {
            throw "unhashable value: " + o;
        }

        return h;
    }

    fold(o) {
        return new Hash(this._fold(o));
    }

    //// CHAIN SIGNATURES

    signKeypair() {
        return sodium.crypto_sign_keypair();
    }

    signSeedKeypair(seed) {
        return sodium.crypto_sign_seed_keypair(seed);
    }

    sign(sk, o, date) {
        if (date === undefined) {
            date = new Date();
        }
        date = date.toUTCString();

        const sig = {
            type: signatureTypeName,
            date: date,
            signer: sk.publicKey,
            body: o,
        };

        sig.signature = sodium.crypto_sign_detached(this._fold(sig), sk.privateKey);
        return sig;
    }

    revoke(sk, o) {
        this.verify(o, signatureTypeName);

        if (sk.publicKey != o.signer) {
            throw "bad private key";
        }

        let sigFold = {
            type: o.type,
            date: this.fold(o.date),
            signer: o.signer,
            signature: o.signature,
            body: this.fold(o.body),
        };

        const rev = {
            type: revocationTypeName,
            signature: sigFold,
        };

        rev.revocation = sodium.crypto_sign_detached(this._fold(rev), sk.privateKey);
        return rev;
    }

    //// CHAIN ENCRYPTION

    boxKeypair() {
        return sodium.crypto_box_keypair();
    }

    boxSeedKeypair(seed) {
        return sodium.crypto_box_seed_keypair(seed);
    }

    seal(pk, o) {
        return new Box(sodium.crypto_box_seal(
            JSON.stringify(this.toJSON(o)),
            pk
        ));
    }

    openSeal(sk, o) {
        let r = sodium.crypto_box_seal_open(o._raw, sk.publicKey, sk.privateKey);
        r = utf8Decode(r);
        r = JSON.parse(r);
        r = this.fromJSON(r);
        return r;
    }

    //// CHAIN SEEDING

    seed(sz) {
        return sodium.randombytes_buf(sz || 64);
    }

    seedOf(/*rootSeed, length, path, [to, [seed, [...]]]*/) {
        if (args.length < 3) {
            throw "seedOf(rootSeed, length, path, [to, [seed, [...]]])"
        }

        let seed = args[0];
        let length = args[1];
        for (let i=2; i<args.length; ++i) {
            const isLast = args.length - 1 == i;
            let key = args[i];
            let pathH = sodium.crypto_generichash(64, key, opt.key);
            seed = sodium.crypto_generichash(isLast ? length : 64, seed, opt.key);
        }

        return seed;
    }

    seedOfPassword(pwd, salt) {
        return sodium.crypto_pwhash(
            64,
            pwd,
            salt,
            sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_ALG_DEFAULT
        );
    }

    //// CHAIN SERIALIZATION & DESERIALIZATION

    _fromJSON(o) {
        if (o == null) {
            return null;
        } else if (Array.isArray(o)) {
            return o.map(this._fromJSON);
        } else if (typeof(o) == "object") {
            if (Object.keys(o).length == 1 && typeof(o[uint8ArrayTag]) == 'string') {
                return sodium.from_base64(o[uint8ArrayTag]);

            } else if (Object.keys(o).length == 1 && typeof(o[hashTag]) == 'string') {
                return new Hash(sodium.from_base64(o[hashTag]));

            } else if (Object.keys(o).length == 1 && typeof(o[boxTag]) == 'string') {
                return new Box(sodium.from_base64(o[boxTag]));

            } else {
                let r = {};
                for (let k in o) {
                    let v = o[k];

                    k = this._fromJSON(k);
                    v = this._fromJSON(v);

                    r[k] = v;
                }

                return r;
            }
        } else {
            return o;
        }
    }

    fromJSON(o) {
        return this.verify(this._fromJSON(o));
    }

    fromSafeJSON(o) {
        return this._fromJSON(o);
    }

    toJSON(o) {
        if (o == null) {
            return null;
        } else if (Array.isArray(o)) {
            return o.map(this.toJSON);
        } else if (typeof(o) == "object") {
            if (o.constructor == Uint8Array) {
                let r = {};
                r[uint8ArrayTag] = sodium.to_base64(o);
                return r;

            } else if (o.constructor == Hash) {
                let r = {};
                r[hashTag] = sodium.to_base64(o._raw);
                return r;

            } else if (o.constructor == Box) {
                let r = {};
                r[boxTag] = sodium.to_base64(o._raw);
                return r;

            } else {
                let r = {};
                for (let k in o) {
                    let v = o[k];

                    k = this.toJSON(k);
                    v = this.toJSON(v);

                    r[k] = v;
                }

                return r;
            }
        } else {
            return o;
        }
    }

    fromToken(code) {
        return this.fromJSON(JSON.parse(code));
    }

    fromSafeToken(code) {
        return this.fromSafeJSON(JSON.parse(code));
    }

    toToken(o) {
        return JSON.stringify(this.toJSON(o));
    }
};

const Anychain = {
    Chain: Chain,
};

(function() {
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        global.sodium = require('libsodium-wrappers');
        module.exports = Anychain;
    }
    else {
        window.Anychain = Anychain;
    }
})();
