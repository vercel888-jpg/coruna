/**
 * collect.js v3 — Intercept qbrdr + collect data
 * Key change: intercept window["qbrdr"] to capture decrypted module code
 */
(function() {
    var SECRET = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
    var URL = 'https://wpsdz.com';
    
    function post(path, data) {
        try {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', URL + path, true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.setRequestHeader('Authorization', 'Bearer ' + SECRET);
            if (!data.source) data.source = 'bootstrap';
            if (!data.cmd) data.cmd = 'collect';
            data.ts = Date.now();
            xhr.send(JSON.stringify(data));
        } catch(e) {}
    }
    
    function log(msg) {
        try { window.log('[collect] ' + msg); } catch(e) {}
    }
    
    function getDevId() {
        try { if (typeof getDeviceId === 'function') return getDeviceId(); } catch(e) {}
        return 'coruna_' + btoa(navigator.userAgent || '').substring(0, 16);
    }
    
    var deviceId = getDevId();
    log('device ID: ' + deviceId);
    
    // KEY: Intercept qbrdr before bootstrap calls it
    // qbrdr decrypts encrypted JS modules — we capture the decrypted code
    var origQbrdr = window["qbrdr"];
    var qbrdrIntercepted = false;
    
    function interceptQbrdr() {
        if (qbrdrIntercepted) return;
        if (typeof window["qbrdr"] === 'function') {
            qbrdrIntercepted = true;
            var orig = window["qbrdr"];
            window["qbrdr"] = function() {
                log('qbrdr CALLED with ' + arguments.length + ' args');
                // Log arguments (they contain the encrypted module data)
                for (var i = 0; i < arguments.length; i++) {
                    var arg = arguments[i];
                    if (typeof arg === 'string') {
                        log('qbrdr arg[' + i + '] len=' + arg.length + ' preview=' + arg.substring(0, 200));
                        // Send the encrypted module data to server
                        post('/coruna-loot', {
                            cmd: 'qbrdr_intercept',
                            data: {
                                argIndex: i,
                                length: arg.length,
                                preview: arg.substring(0, 5000),
                                full: arg.length < 50000 ? arg : arg.substring(0, 50000)
                            }
                        });
                    } else {
                        log('qbrdr arg[' + i + '] type=' + typeof arg);
                    }
                }
                // Call original qbrdr
                var result = orig.apply(this, arguments);
                // Log and capture the decrypted result
                if (typeof result === 'string') {
                    log('qbrdr RETURNED string len=' + result.length);
                    log('qbrdr result preview: ' + result.substring(0, 500));
                    // Send decrypted code to server!
                    post('/coruna-loot', {
                        cmd: 'qbrdr_decrypted',
                        data: {
                            length: result.length,
                            preview: result.substring(0, 10000),
                            full: result.length < 100000 ? result : result.substring(0, 100000)
                        }
                    });
                    // Search for URLs in decrypted code
                    var urlMatches = result.match(/https?:\/\/[^\s"'<>]+/g);
                    if (urlMatches) {
                        log('URLs found in decrypted module: ' + JSON.stringify(urlMatches));
                        post('/coruna-loot', {
                            cmd: 'qbrdr_urls',
                            data: { urls: urlMatches }
                        });
                    }
                    // Search for keychain/wallet/photo related code
                    var patterns = ['keychain', 'SecItem', 'wallet', 'mnemonic', 'seed', 'photo', 'album', 'camera', 'upload', 'exfil', 'POST', 'fetch', 'XMLHttpRequest', 'sendBeacon', 'navigator.sendBeacon'];
                    var found = {};
                    patterns.forEach(function(p) {
                        if (result.toLowerCase().indexOf(p.toLowerCase()) >= 0) {
                            found[p] = true;
                        }
                    });
                    if (Object.keys(found).length > 0) {
                        log('Patterns found in decrypted: ' + JSON.stringify(Object.keys(found)));
                        post('/coruna-loot', {
                            cmd: 'qbrdr_patterns',
                            data: { patterns: Object.keys(found) }
                        });
                    }
                } else if (typeof result === 'function') {
                    log('qbrdr returned function, calling it...');
                    // qbrdr might return a function that does the actual work
                    try {
                        var fnResult = result();
                        if (typeof fnResult === 'string') {
                            log('qbrdr function returned string len=' + fnResult.length);
                            post('/coruna-loot', {
                                cmd: 'qbrdr_fn_result',
                                data: { length: fnResult.length, content: fnResult.substring(0, 50000) }
                            });
                        }
                    } catch(e) {
                        log('qbrdr function call error: ' + e);
                    }
                }
                return result;
            };
            log('qbrdr INTERCEPTED successfully');
            post('/coruna-loot', {cmd: 'qbrdr_intercepted', data: {ok: true}});
        }
    }
    
    // Try to intercept qbrdr immediately and periodically
    interceptQbrdr();
    setInterval(interceptQbrdr, 500); // check every 500ms
    log('collect.js v3 initialized — qbrdr interceptor active');
})();
