(function () {
    'use strict';
    // CryptoProxy — Hook_Combined.js (CryptoJS + RSA + HMAC)

    const _toString = Function.prototype.toString;
    const _nativeMap = new WeakMap();

    function makeNative(hookFunc, originalFunc) {
        try {
            Object.defineProperty(hookFunc, 'name', { value: originalFunc.name });
            Object.defineProperty(hookFunc, 'length', { value: originalFunc.length });
        } catch (e) {}
        _nativeMap.set(hookFunc, originalFunc);
        return hookFunc;
    }

    Function.prototype.toString = function toString() {
        if (_nativeMap.has(this)) return _toString.call(_nativeMap.get(this));
        return _toString.call(this);
    };
    makeNative(Function.prototype.toString, _toString);

    function hasEncryptProp(obj) {
        const requiredProps = ['ciphertext', 'key', 'iv', 'algorithm', 'mode', 'padding', 'blockSize', 'formatter'];
        if (!obj || typeof obj !== 'object') return false;
        for (const prop of requiredProps) if (!(prop in obj)) return false;
        return true;
    }
    function hasDecryptProp(obj) {
        const requiredProps = ['sigBytes', 'words'];
        if (!obj || typeof obj !== 'object') return false;
        for (const prop of requiredProps) if (!(prop in obj)) return false;
        return true;
    }
    function get_sigBytes(size) {
        switch (size) {
            case 8: return "64bits"; case 16: return "128bits";
            case 24: return "192bits"; case 32: return "256bits";
            default: return "未知";
        }
    }
    function hexToBase64(hex) {
        if (!hex) return '';
        try {
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
            return btoa(String.fromCharCode.apply(null, bytes));
        } catch (e) { return ''; }
    }
    function wordsToHex(words, sigBytes) {
        if (!words || !Array.isArray(words)) return '';
        const hexChars = [];
        for (let i = 0; i < sigBytes; i++) {
            const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            hexChars.push((byte >>> 4).toString(16), (byte & 0x0f).toString(16));
        }
        return hexChars.join('');
    }
    function formatKey(keyObj) {
        if (!keyObj) return { string: '', hex: '', base64: '' };
        let hexKey = '', strKey = '';
        if (keyObj.toString && keyObj.toString() !== "[object Object]") hexKey = keyObj.toString();
        else if (keyObj.words && keyObj.sigBytes) hexKey = wordsToHex(keyObj.words, keyObj.sigBytes);
        const base64Key = hexToBase64(hexKey);
        try { strKey = decodeURIComponent(hexKey.replace(/[0-9a-f]{2}/g, '%$&')); } catch (e) { strKey = hexKey; }
        return { string: strKey, hex: hexKey, base64: base64Key };
    }

    let temp_apply = Function.prototype.apply;
    const applyHook = function () {
        if (arguments.length === 2 && arguments[0] && arguments[1] && typeof arguments[1] === 'object'
            && arguments[1].length === 1 && hasEncryptProp(arguments[1][0])) {
            if (Object.hasOwn(arguments[0], "$super") && Object.hasOwn(arguments[1], "callee")) {
                const callerStr = this.toString();
                if (callerStr.indexOf('function()') !== -1 || /^\s*function/.test(callerStr)) {
                    console.log("[debug] ========== CryptoJS 对称加密 ==========");
                    const keyData = formatKey(arguments[1][0]["key"]);
                    console.log("[debug] Key (String):", keyData.string);
                    console.log("[debug] Key (Hex):", keyData.hex);
                    console.log("[debug] Key (Base64):", keyData.base64);
                    const iv = arguments[1][0]["iv"];
                    if (iv) {
                        const ivData = formatKey(iv);
                        console.log("[debug] IV (String):", ivData.string);
                        console.log("[debug] IV (Hex):", ivData.hex);
                    }
                    if (arguments[1][0]["key"] && Object.hasOwn(arguments[1][0]["key"], "sigBytes")) {
                        console.log("[debug] 密钥长度:", get_sigBytes(arguments[1][0]["key"]["sigBytes"]));
                    }
                    if (arguments[1][0]["padding"]) console.log("[debug] 填充模式:", arguments[1][0]["padding"]);
                    try {
                        let encrypt_text = arguments[0].$super.toString.call(arguments[1][0]);
                        if (encrypt_text !== "[object Object]") console.log("[debug] 明文/密文:", encrypt_text);
                    } catch (e) {}
                }
            }
        } else if (arguments.length === 2 && arguments[0] && arguments[1] && typeof arguments[1] === 'object'
            && arguments[1].length === 3 && hasDecryptProp(arguments[1][1])) {
            if (Object.hasOwn(arguments[0], "$super") && arguments[1][0] === 2) {
                console.log("[debug] ========== CryptoJS 对称解密 ==========");
                const keyData = formatKey(arguments[1][1]);
                console.log("[debug] Key (String):", keyData.string);
                console.log("[debug] Key (Hex):", keyData.hex);
            }
        } else if (arguments.length === 2 && arguments[0] && arguments[1] && typeof arguments[0] === 'object') {
            try {
                if (arguments[0].__proto__ && Object.hasOwn(arguments[0].__proto__, "_doFinalize")
                    && arguments[0].__proto__.__proto__ && Object.hasOwn(arguments[0].__proto__.__proto__, "finalize")
                    && !_nativeMap.has(arguments[0].__proto__.__proto__.finalize)) {
                    let temp_finalize = arguments[0].__proto__.__proto__.finalize;
                    const finalizeHook = function () {
                        if (!Object.hasOwn(this, "init")) {
                            let hash = temp_finalize.call(this, ...arguments);
                            console.log("[debug] ========== CryptoJS 哈希/HMAC ==========");
                            try {
                                console.log("[debug] 原始数据:", ...arguments);
                                console.log("[debug] 结果:", hash.toString());
                            } catch (e) {}
                            return hash;
                        }
                        return temp_finalize.call(this, ...arguments);
                    };
                    arguments[0].__proto__.__proto__.finalize = makeNative(finalizeHook, temp_finalize);
                }
            } catch (e) {}
        }
        return temp_apply.call(this, ...arguments);
    };
    Function.prototype.apply = makeNative(applyHook, temp_apply);

    let c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    function hexToBase64RSA(t) {
        let e, i, r = "";
        for (e = 0; e + 3 <= t.length; e += 3) {
            i = parseInt(t.substring(e, e + 3), 16);
            r += c.charAt(i >> 6) + c.charAt(63 & i);
        }
        if (e + 1 == t.length) { i = parseInt(t.substring(e, e + 1), 16); r += c.charAt(i << 2); }
        else if (e + 2 == t.length) { i = parseInt(t.substring(e, e + 2), 16); r += c.charAt(i >> 2) + c.charAt((3 & i) << 4); }
        while ((3 & r.length) > 0) r += "=";
        return r;
    }
    function hasRSAProp(obj) {
        const requiredProps = ['getPublicKey', 'getPrivateKey', 'parseKey'];
        if (!obj || typeof obj !== 'object') return false;
        for (const prop of requiredProps) if (!(prop in obj)) return false;
        return true;
    }
    let temp_call = Function.prototype.call;
    const callHook = function () {
        if (arguments.length === 1 && arguments[0] && arguments[0].__proto__
            && hasRSAProp(arguments[0].__proto__)) {
            try {
                const proto = arguments[0].__proto__.__proto__;
                if (proto && Object.hasOwn(proto, "encrypt") && !_nativeMap.has(proto.encrypt)) {
                    let temp_encrypt = proto.encrypt;
                    proto.encrypt = makeNative(function () {
                        let encrypt_text = temp_encrypt.bind(this, ...arguments)();
                        console.log("[debug] ========== RSA 加密 ==========");
                        try {
                            console.log("[debug] 公钥:\n", this.getPublicKey());
                            console.log("[debug] 原始数据:", ...arguments);
                            console.log("[debug] 密文 (Hex):", encrypt_text);
                        } catch (e) {}
                        return encrypt_text;
                    }, temp_encrypt);
                }
            } catch (e) {}
        }
        return temp_call.bind(this, ...arguments)();
    };
    Function.prototype.call = makeNative(callHook, temp_call);

    try {
        console.log('[debug] CryptoProxy crypto_hook 已注入 @ ' + location.href);
    } catch (e) { /* ignore */ }
})();
