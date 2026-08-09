import * as RustSdkCryptoJs from '@matrix-org/matrix-sdk-crypto-wasm';
import { hydrate, type HydrationContext } from './hydrate';

// Wasm key objects hide their material behind `toBase64()`; `String()` gives `[object Object]`.
export const keyToBase64 = (key: unknown): string => {
  const encode = (key as { toBase64?: () => string } | null)?.toBase64;
  return typeof encode === 'function' ? encode.call(key) : String(key);
};

// `CollectStrategy` exposes no getters, only `eq()`, so the variant has to be recovered by
// comparison. Names are the ones `matrix_crypto::rooms::collect_strategy` parses.
const COLLECT_STRATEGIES: ReadonlyArray<[string, () => unknown]> = [
  ['identityBasedStrategy', () => RustSdkCryptoJs.CollectStrategy.identityBasedStrategy()],
  ['onlyTrustedDevices', () => RustSdkCryptoJs.CollectStrategy.onlyTrustedDevices()],
  [
    'errorOnVerifiedUserProblem',
    () => RustSdkCryptoJs.CollectStrategy.errorOnUnverifiedUserProblem(),
  ],
  ['allDevices', () => RustSdkCryptoJs.CollectStrategy.allDevices()],
];

export const collectStrategyName = (strategy: unknown): string => {
  const candidate = strategy as { eq?: (other: unknown) => boolean } | null;
  if (typeof candidate?.eq !== 'function') return 'allDevices';
  for (const [name, build] of COLLECT_STRATEGIES) {
    try {
      if (candidate.eq(build())) return name;
    } catch {
      // Not a variant this wasm build exposes.
    }
  }
  return 'allDevices';
};

// Wasm accessors live on the prototype, so JSON would carry only the internal pointer, and a
// dropped `sharingStrategy` silently means "share room keys with every device".
const num = (value: unknown) => (typeof value === 'bigint' ? Number(value) : value);

export const encodeEncryptionSettings = (settings: unknown): Record<string, unknown> | null => {
  if (settings === null || typeof settings !== 'object') return null;
  const s = settings as Record<string, unknown>;
  return {
    algorithm: s.algorithm,
    historyVisibility: s.historyVisibility,
    rotationPeriod: num(s.rotationPeriod),
    rotationPeriodMessages: num(s.rotationPeriodMessages),
    sharingStrategy: collectStrategyName(s.sharingStrategy),
  };
};

export const encodeDecryptionSettings = (settings: unknown): Record<string, unknown> => {
  const trust = (settings as Record<string, unknown> | null)?.sender_device_trust_requirement;
  return { senderDeviceTrustRequirement: typeof trust === 'number' ? trust : 0 };
};

const hasOwnPrototype = (name: string): boolean => {
  const candidate = (RustSdkCryptoJs as Record<string, unknown>)[name];
  return typeof candidate === 'function' && 'prototype' in candidate;
};

// JSON has no `undefined`, so absent wasm values arrive as `null` and slip past js-sdk's
// `=== undefined` guards. Rewrite in place: an own property still shadows the wasm getter.
const nullsToUndefined = (record: Record<string, unknown>): void => {
  for (const [key, value] of Object.entries(record)) {
    if (value !== null) continue;
    Object.defineProperty(record, key, {
      value: undefined,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
};

// Every payload carries a `className` because js-sdk dispatches on `instanceof`.
export const graftWasmPrototypes = <T>(value: T, ctx: HydrationContext): T => {
  if (Array.isArray(value)) {
    value.forEach((item) => graftWasmPrototypes(item, ctx));
    return value;
  }
  if (value === null || typeof value !== 'object') return value;

  const record = value as Record<string, unknown>;
  for (const nested of Object.values(record)) {
    if (nested !== null && typeof nested === 'object') graftWasmPrototypes(nested, ctx);
  }

  const className = record.className;
  if (typeof className === 'string') {
    if (!hasOwnPrototype(className)) {
      throw new Error(
        `Rust crypto engine returned unknown wasm className "${className}"; ` +
          'the engine and matrix-sdk-crypto-wasm are out of sync'
      );
    }
    const wasmClass = (RustSdkCryptoJs as Record<string, unknown>)[className] as {
      prototype: object;
    };
    Object.setPrototypeOf(value, wasmClass.prototype);
    nullsToUndefined(record);
    hydrate(className, record, ctx);
  }
  return value;
};

export { RustSdkCryptoJs };
