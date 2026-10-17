/*!
 * upkeep form protection - invisible spam protection for YForm frontend forms.
 * Solves the self-hosted ALTCHA proof-of-work in the background (on first interaction or on submit)
 * and counts interaction signals (only counters, never coordinates or contents).
 * No cookies, no storage, no third party.
 */
(function () {
    'use strict';

    var MAX_COUNT = 500;
    var SOLVE_TIMEOUT = 8000;

    // ---------------------------------------------------------------- SHA-256

    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Pure JS fallback (non-secure contexts without crypto.subtle). Input: ASCII string.
    function sha256Hex(str) {
        var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var bytes = [], i, j;
        for (i = 0; i < str.length; i++) { bytes.push(str.charCodeAt(i) & 0xff); }
        var bitLen = bytes.length * 8;
        bytes.push(0x80);
        while (bytes.length % 64 !== 56) { bytes.push(0); }
        for (i = 7; i >= 0; i--) { bytes.push(i > 3 ? 0 : (bitLen >>> (i * 8)) & 0xff); }
        var w = new Array(64);
        for (i = 0; i < bytes.length; i += 64) {
            for (j = 0; j < 16; j++) {
                w[j] = (bytes[i + j * 4] << 24) | (bytes[i + j * 4 + 1] << 16) | (bytes[i + j * 4 + 2] << 8) | bytes[i + j * 4 + 3];
            }
            for (j = 16; j < 64; j++) {
                var s0 = ror(w[j - 15], 7) ^ ror(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                var s1 = ror(w[j - 2], 17) ^ ror(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (j = 0; j < 64; j++) {
                var S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
                var ch = (e & f) ^ (~e & g);
                var t1 = (hh + S1 + ch + K[j] + w[j]) | 0;
                var S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var t2 = (S0 + maj) | 0;
                hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
            h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
        }
        var out = '';
        for (i = 0; i < 8; i++) { out += ('00000000' + (h[i] >>> 0).toString(16)).slice(-8); }
        return out;
    }

    function ror(x, n) { return (x >>> n) | (x << (32 - n)); }

    function toHex(buf) {
        var arr = new Uint8Array(buf), s = '';
        for (var i = 0; i < arr.length; i++) { s += (arr[i] < 16 ? '0' : '') + arr[i].toString(16); }
        return s;
    }

    var subtle = (window.crypto && window.crypto.subtle && window.isSecureContext) ? window.crypto.subtle : null;
    var encoder = window.TextEncoder ? new TextEncoder() : null;

    function solve(ch) {
        var max = parseInt(ch.maxnumber, 10) || 100000;
        var started = Date.now();
        return new Promise(function (resolve) {
            var n = 0;
            function step() {
                if (Date.now() - started > SOLVE_TIMEOUT) { resolve(null); return; }
                if (subtle && encoder) {
                    var batch = [];
                    for (var k = 0; k < 200 && n <= max; k++, n++) {
                        batch.push(subtle.digest('SHA-256', encoder.encode(ch.salt + n)));
                    }
                    var base = n - batch.length;
                    Promise.all(batch).then(function (res) {
                        for (var r = 0; r < res.length; r++) {
                            if (toHex(res[r]) === ch.challenge) { resolve(base + r); return; }
                        }
                        if (n > max) { resolve(null); return; }
                        setTimeout(step, 0);
                    }, function () { subtle = null; n = 0; setTimeout(step, 0); });
                } else {
                    var until = Date.now() + 40;
                    while (n <= max && Date.now() < until) {
                        if (sha256Hex(ch.salt + n) === ch.challenge) { resolve(n); return; }
                        n++;
                    }
                    if (n > max) { resolve(null); return; }
                    setTimeout(step, 0);
                }
            }
            step();
        });
    }

    function expired(ch) {
        var m = /[?&]expires=(\d+)/.exec(ch.salt || '');
        return m ? parseInt(m[1], 10) * 1000 < Date.now() + 5000 : false;
    }

    function getChallenge(input) {
        var ch = null;
        try { ch = JSON.parse(input.getAttribute('data-upkeep-pow') || 'null'); } catch (e) { ch = null; }
        if (ch && !expired(ch)) { return Promise.resolve(ch); }
        var url = input.getAttribute('data-upkeep-endpoint');
        if (!url || !window.fetch) { return Promise.resolve(null); }
        return fetch(url, { credentials: 'omit', cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .catch(function () { return null; });
    }

    // ---------------------------------------------------------------- per form

    function setup(form) {
        if (!form || form.__upkeepFp) { return; }
        form.__upkeepFp = true;

        var powInput = form.querySelector('input[data-upkeep-pow]');
        var sigInput = form.querySelector('input[data-upkeep-signals]');
        var hp = form.querySelector('[data-upkeep-fp]');
        if (hp) {
            // also apply via CSSOM (works under strict CSP that blocks style attributes)
            var st = hp.style;
            st.setProperty('position', 'absolute', 'important');
            st.setProperty('left', '-10000px', 'important');
            st.setProperty('width', '1px', 'important');
            st.setProperty('height', '1px', 'important');
            st.setProperty('overflow', 'hidden', 'important');
        }

        var c = { k: 0, i: 0, p: 0, t: 0, f: 0, c: 0 };
        var solving = null;
        var done = !powInput;

        function inc(key) { if (c[key] < MAX_COUNT) { c[key]++; } }

        function writeSignals() {
            if (!sigInput) { return; }
            sigInput.value = 'v1;k=' + c.k + ';i=' + c.i + ';p=' + c.p + ';t=' + c.t + ';f=' + c.f + ';c=' + c.c +
                ';w=' + (navigator.webdriver ? 1 : 0);
        }

        function start() {
            if (solving || done) { return solving; }
            solving = getChallenge(powInput).then(function (ch) {
                if (!ch) { return null; }
                return solve(ch).then(function (number) {
                    if (number === null) { return null; }
                    powInput.value = btoa(JSON.stringify({
                        algorithm: ch.algorithm,
                        challenge: ch.challenge,
                        number: number,
                        salt: ch.salt,
                        signature: ch.signature
                    }));
                    return true;
                });
            }).catch(function () { return null; }).then(function (r) { done = true; return r; });
            return solving;
        }

        var moves = 0;
        form.addEventListener('keydown', function () { inc('k'); start(); }, true);
        form.addEventListener('input', function () { inc('i'); }, true);
        form.addEventListener('paste', function () { inc('c'); start(); }, true);
        form.addEventListener('focusin', function () { inc('f'); start(); }, true);
        form.addEventListener('pointerdown', function (e) {
            inc(e.pointerType === 'touch' ? 't' : 'p');
            start();
        }, true);
        form.addEventListener('touchstart', function () { inc('t'); start(); }, { capture: true, passive: true });
        form.addEventListener('mousemove', function () {
            if (++moves % 10 === 0) { inc('p'); }
        }, { capture: true, passive: true });

        form.addEventListener('submit', function (ev) {
            writeSignals();
            if (done || !powInput) { return; }
            ev.preventDefault();
            var submitter = ev.submitter || null;
            var timer = new Promise(function (r) { setTimeout(r, SOLVE_TIMEOUT); });
            Promise.race([start(), timer]).then(function () {
                done = true;
                writeSignals();
                if (form.requestSubmit) {
                    try { form.requestSubmit(submitter && submitter.form === form ? submitter : undefined); return; } catch (e) { /* fall through */ }
                }
                form.submit();
            });
        }, false);

        writeSignals();
    }

    function init() {
        var inputs = document.querySelectorAll('input[data-upkeep-signals]');
        for (var i = 0; i < inputs.length; i++) { setup(inputs[i].form); }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    // forms injected later (e.g. via AJAX) can call this
    window.upkeepFormProtection = { init: init };
})();
