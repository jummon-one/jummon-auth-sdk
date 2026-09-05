import type { PlatformRiskSignals } from "@jummon/auth/core";

/**
 * #85 risk-signal-collector RN adapter
 * (`engineering-team/initiatives/risk-signal-collector/README.md`). Same
 * "constructor injection, no hard dependency" rule as every other adapter
 * in this package: RN has no universal first-party API for language tag or
 * coarse device class (unlike the browser's `navigator.language`), so the
 * app supplies whatever it already has (`expo-localization`,
 * `react-native-localize`, `react-native-device-info`, or its own
 * `Dimensions`-based heuristic) as small, structurally-typed callbacks.
 * Every field is OPTIONAL and every callback is defensively wrapped — a
 * missing dep or a throwing callback degrades that one field to `null`,
 * never a crash, matching `PlatformRiskSignals`'s own "coarse, best-effort"
 * contract.
 *
 * Timezone has a built-in fallback (`Intl.DateTimeFormat().resolvedOptions().timeZone`)
 * since modern Hermes (RN >=0.70 with the ICU build most current Expo/RN
 * apps ship) supports `Intl` directly — the same call the browser adapter
 * makes — so most apps get `tz` for free with no extra native dependency.
 */
export interface RiskSignalsNativeDeps {
  /** Coarse IANA timezone. Defaults to `Intl.DateTimeFormat().resolvedOptions().timeZone` if omitted — only supply this if your RN runtime lacks a working `Intl` (older Hermes without ICU). */
  getTimezone?(): string | null | undefined;
  /** Primary language tag, e.g. from `expo-localization`'s `getLocales()[0]?.languageTag` or `react-native-localize`'s `getLocales()[0]?.languageTag`. No built-in fallback — RN has no first-party API for this. */
  getLanguage?(): string | null | undefined;
  /** Coarse device class — e.g. derived from `react-native-device-info`'s `isTablet()` or your own `Dimensions`-based heuristic. No built-in fallback. */
  getDeviceClass?(): "mobile" | "tablet" | "desktop" | null | undefined;
}

function safeCall<T>(fn: (() => T | null | undefined) | undefined): T | null {
  if (!fn) {
    return null;
  }
  try {
    return fn() ?? null;
  } catch {
    return null;
  }
}

export function createReactNativeRiskSignals(deps: RiskSignalsNativeDeps = {}): PlatformRiskSignals {
  return {
    getTimezone(): string | null {
      const supplied = safeCall(deps.getTimezone);
      if (supplied) {
        return supplied;
      }
      try {
        return typeof Intl !== "undefined" ? Intl.DateTimeFormat().resolvedOptions().timeZone || null : null;
      } catch {
        return null;
      }
    },
    getLanguage(): string | null {
      return safeCall(deps.getLanguage);
    },
    getDeviceClass(): "mobile" | "tablet" | "desktop" | null {
      return safeCall(deps.getDeviceClass);
    },
  };
}
