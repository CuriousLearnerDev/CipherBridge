(function () {

    'use strict';

    /** Hook XHR/Fetch → Playwright binding（优先）或 console 回传。 */



    var MAX_BODY = 200000;

    var MAX_HDR_VAL = 8000;

    var MAX_HDRS = 80;



    function trunc(s, n) {

        s = s == null ? '' : String(s);

        return s.length > n ? s.slice(0, n) : s;

    }



    function trimHeaders(obj) {

        var out = {};

        if (!obj) return out;

        var keys = Object.keys(obj);

        for (var i = 0; i < keys.length && i < MAX_HDRS; i++) {

            out[keys[i]] = trunc(obj[keys[i]], MAX_HDR_VAL);

        }

        return out;

    }



    function headersToObj(h) {

        var o = {};

        if (!h) return o;

        try {

            if (typeof Headers !== 'undefined' && h instanceof Headers) {

                h.forEach(function (v, k) { o[k] = v; });

            } else if (Array.isArray(h)) {

                h.forEach(function (pair) {

                    if (pair && pair.length >= 2) o[pair[0]] = pair[1];

                });

            } else if (typeof h === 'object') {

                for (var k in h) {

                    if (Object.prototype.hasOwnProperty.call(h, k)) o[k] = h[k];

                }

            }

        } catch (e) { /* ignore */ }

        return trimHeaders(o);

    }



    function parseXhrResponseHeaders(xhr) {

        var o = {};

        try {

            var raw = xhr.getAllResponseHeaders() || '';

            raw.split('\n').forEach(function (line) {

                var idx = line.indexOf(':');

                if (idx > 0) {

                    o[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();

                }

            });

        } catch (e) { /* ignore */ }

        return trimHeaders(o);

    }



    function enrichBrowserHeaders(hdrs) {

        var out = {};

        if (hdrs) {

            for (var k in hdrs) {

                if (Object.prototype.hasOwnProperty.call(hdrs, k)) out[k] = hdrs[k];

            }

        }

        function has(name) {

            var low = String(name).toLowerCase();

            for (var k in out) {

                if (k.toLowerCase() === low) return true;

            }

            return false;

        }

        try {

            if (!has('User-Agent') && typeof navigator !== 'undefined' && navigator.userAgent) {

                out['User-Agent'] = navigator.userAgent;

            }

            if (!has('Accept')) {

                out['Accept'] = '*/*';

            }

            if (!has('Accept-Language') && navigator.language) {

                out['Accept-Language'] = navigator.language;

            }

            if (!has('Referer') && typeof location !== 'undefined' && location.href) {

                out['Referer'] = location.href;

            }

            if (!has('Origin') && typeof location !== 'undefined' && location.origin) {

                out['Origin'] = location.origin;

            }

            if (!has('Cookie') && typeof document !== 'undefined' && document.cookie) {

                out['Cookie'] = document.cookie;

            }

        } catch (e) { /* ignore */ }

        return trimHeaders(out);

    }



    function emitCapture(payload) {

        try {

            payload.request_body = trunc(payload.request_body, MAX_BODY);

            payload.response_body = trunc(payload.response_body, MAX_BODY);

            if (payload.request_headers) {

                payload.request_headers = enrichBrowserHeaders(payload.request_headers);

            }

            if (payload.response_headers) {

                payload.response_headers = trimHeaders(payload.response_headers);

            }

            var s = JSON.stringify(payload);

            if (typeof cpCapture === 'function') {

                cpCapture(s);

            } else if (typeof window.cpCapture === 'function') {

                window.cpCapture(s);

            } else {

                console.log('[capture] ' + s);

            }

        } catch (e) { /* ignore */ }

    }



    function resolveUrl(url) {

        try {

            return new URL(url, location.href).href;

        } catch (e) {

            return String(url || '');

        }

    }



    function bodyToStr(body) {

        if (body == null) return '';

        if (typeof body === 'string') return body;

        try {

            if (body instanceof URLSearchParams) return body.toString();

            if (body instanceof FormData) return '[FormData]';

            if (body instanceof ArrayBuffer) return '[ArrayBuffer]';

            return String(body);

        } catch (e) {

            return '';

        }

    }



    function notifyRequest(method, url, reqBody, reqHeaders) {

        emitCapture({

            method: method,

            url: url,

            request_body: reqBody,

            response_body: '',

            request_headers: reqHeaders || {},

            response_headers: {},

            status: 0,

            source: 'xhr-hook',

            phase: 'request',

        });

    }



    var XHR = XMLHttpRequest.prototype;

    var origOpen = XHR.open;

    var origSend = XHR.send;

    var origSetRequestHeader = XHR.setRequestHeader;



    XHR.open = function (method, url) {

        this.__cp = { method: (method || 'GET').toUpperCase(), url: resolveUrl(url) };

        this.__cp_headers = {};

        return origOpen.apply(this, arguments);

    };



    XHR.setRequestHeader = function (name, value) {

        if (!this.__cp_headers) this.__cp_headers = {};

        this.__cp_headers[name] = value;

        return origSetRequestHeader.apply(this, arguments);

    };



    XHR.send = function (body) {

        var meta = this.__cp || { method: 'GET', url: location.href };

        var reqBody = bodyToStr(body);

        var reqHeaders = trimHeaders(this.__cp_headers || {});

        notifyRequest(meta.method, meta.url, reqBody, reqHeaders);

        this.addEventListener('load', function () {

            emitCapture({

                method: meta.method,

                url: meta.url,

                request_body: reqBody,

                response_body: (this.responseType === '' || this.responseType === 'text')

                    ? (this.responseText || '') : '',

                request_headers: reqHeaders,

                response_headers: parseXhrResponseHeaders(this),

                status: this.status || 0,

                source: 'xhr-hook',

                phase: 'response',

            });

        });

        return origSend.apply(this, arguments);

    };



    var origFetch = window.fetch;

    if (typeof origFetch === 'function') {

        window.fetch = function (input, init) {

            var req = input instanceof Request ? input : null;

            var url = resolveUrl(req ? req.url : input);

            var method = ((init && init.method) || (req && req.method) || 'GET').toUpperCase();

            var reqBody = bodyToStr((init && init.body) || null);

            var reqHeaders = headersToObj((init && init.headers) || (req && req.headers));

            notifyRequest(method, url, reqBody, reqHeaders);

            return origFetch.apply(this, arguments).then(function (resp) {

                try {

                    var clone = resp.clone();

                    clone.text().then(function (text) {

                        emitCapture({

                            method: method,

                            url: url,

                            request_body: reqBody,

                            response_body: text || '',

                            request_headers: reqHeaders,

                            response_headers: headersToObj(resp.headers),

                            status: resp.status || 0,

                            source: 'fetch-hook',

                            phase: 'response',

                        });

                    }).catch(function () {});

                } catch (e) { /* ignore */ }

                return resp;

            });

        };

    }



    try {

        console.log('[debug] CryptoProxy network_capture 已注入 @ ' + location.href);

    } catch (e) { /* ignore */ }

})();


