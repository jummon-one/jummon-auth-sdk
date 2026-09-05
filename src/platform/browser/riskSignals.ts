import type { PlatformRiskSignals } from "../../core/platform/types";

/**
 * Browser `PlatformRiskSignals` (#85,
 * `engineering-team/initiatives/risk-signal-collector/README.md`) — three
 * coarse, allowlisted lookups, nothing else. No canvas/WebGL/audio/font
 * fingerprinting, no full `navigator.userAgent` string, no
 * `navigator.geolocation` call anywhere in this file — see
 * `PlatformRiskSignals`'s own doc comment for why that's structural, not a
 * discipline this file has to maintain by hand.
 */

/**
 * Minimal shape of the UA-Client-Hints `NavigatorUAData` this file reads —
 * `navigator.userAgentData` isn't in every TS `lib.dom` version yet, so this
 * is declared locally rather than relying on ambient DOM types. Chromium
 * only; Safari/Firefox fall through to the viewport-width heuristic below.
 */
interface NavigatorUAData {
  mobile: boolean;
}

const MOBILE_MAX_WIDTH = 767;
const TABLET_MAX_WIDTH = 1024;

export const browserRiskSignals: PlatformRiskSignals = {
  getTimezone(): string | null {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    } catch {
      return null;
    }
  },

  getLanguage(): string | null {
    if (typeof navigator === "undefined") {
      return null;
    }
    return navigator.language || navigator.languages?.[0] || null;
  },

  /**
   * UA-Client-Hints' coarse `mobile` boolean where available (Chromium) —
   * a single boolean, not a fingerprint-grade UA string — refined into
   * mobile-vs-tablet only via viewport width (Client Hints doesn't
   * distinguish the two on its own). Falls back to a pure viewport-width
   * heuristic everywhere else. Never parses `navigator.userAgent`.
   */
  getDeviceClass(): "mobile" | "tablet" | "desktop" | null {
    if (typeof navigator === "undefined") {
      return null;
    }
    const uaData = (navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData;
    const width = typeof window !== "undefined" ? window.innerWidth : null;

    if (uaData && typeof uaData.mobile === "boolean") {
      if (!uaData.mobile) {
        return "desktop";
      }
      if (width !== null && width > MOBILE_MAX_WIDTH) {
        return "tablet";
      }
      return "mobile";
    }

    if (width === null) {
      return null;
    }
    if (width <= MOBILE_MAX_WIDTH) {
      return "mobile";
    }
    if (width <= TABLET_MAX_WIDTH) {
      return "tablet";
    }
    return "desktop";
  },
};
