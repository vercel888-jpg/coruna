'use strict';

/*
 * iOS 18.6 branch compatibility module.
 *
 * The public DarkSword-RCE repository ships the 18.6 RCE implementation inside
 * rce_worker_18.6.js. The loader still fetches and evals rce_module_18.6.js
 * before sending { type: 'stage1_rce' } to that worker, so this file acts as
 * the local branch descriptor and helper surface instead of the original
 * five-line dummy placeholder.
 *
 * ios_version in rce_loader.js is an Array (from .split('_').map(parseInt)),
 * so all comparisons against string '18,6' etc. need to go through join(',').
 * This module provides normalizeVersion() to centralise that conversion.
 */

function normalizeVersion(v) {
  if (Array.isArray(v)) return v.join(',');
  return String(v || '').trim().replace(/_/g, ',').replace(/\./g, ',');
}

function isSupportedVersion(v) {
  const s = normalizeVersion(v);
  return s === '18,6' || s === '18,6,1' || s === '18,6,2';
}

function createStageMessage(desiredHost, randomValues, SERVER_LOG) {
  return {
    type: 'stage1_rce',
    desiredHost: desiredHost || location.origin,
    randomValues: randomValues || new Uint32Array(32),
    SERVER_LOG: SERVER_LOG !== undefined ? SERVER_LOG : true,
  };
}

// Backward-compatible name preserved from the public placeholder file.
function dummyy(x) {
  return '0x' + (typeof x === 'bigint' ? x : BigInt(x)).toString(16);
}

if (typeof globalThis !== 'undefined') {
  globalThis.rce186_normalizeVersion = normalizeVersion;
  globalThis.rce186_isSupportedVersion = isSupportedVersion;
  globalThis.rce186_createStageMessage = createStageMessage;
}

if (typeof module !== 'undefined') {
  module.exports = { normalizeVersion, isSupportedVersion, createStageMessage, dummyy };
}
