import { describe, expect, it } from "vitest";
import { createReactNativeRiskSignals, type RiskSignalsNativeDeps } from "./riskSignals";

describe("createReactNativeRiskSignals", () => {
  it("with no deps: falls back to Intl for timezone, returns null for lang/device_class (no first-party RN API)", () => {
    const signals = createReactNativeRiskSignals();

    expect(typeof signals.getTimezone()).toBe("string"); // Intl is available in the vitest/node runtime
    expect(signals.getLanguage()).toBeNull();
    expect(signals.getDeviceClass()).toBeNull();
  });

  it("uses supplied deps when provided, over the Intl fallback", () => {
    const deps: RiskSignalsNativeDeps = {
      getTimezone: () => "America/Sao_Paulo",
      getLanguage: () => "pt-BR",
      getDeviceClass: () => "mobile",
    };
    const signals = createReactNativeRiskSignals(deps);

    expect(signals.getTimezone()).toBe("America/Sao_Paulo");
    expect(signals.getLanguage()).toBe("pt-BR");
    expect(signals.getDeviceClass()).toBe("mobile");
  });

  it("falls back to Intl when the supplied getTimezone returns null/undefined", () => {
    const signals = createReactNativeRiskSignals({ getTimezone: () => null });
    expect(typeof signals.getTimezone()).toBe("string");
  });

  it("degrades to null (never throws) when a supplied callback throws", () => {
    const deps: RiskSignalsNativeDeps = {
      getTimezone: () => {
        throw new Error("native module not linked");
      },
      getLanguage: () => {
        throw new Error("native module not linked");
      },
      getDeviceClass: () => {
        throw new Error("native module not linked");
      },
    };
    const signals = createReactNativeRiskSignals(deps);

    // getTimezone still falls back to Intl rather than propagating the throw.
    expect(typeof signals.getTimezone()).toBe("string");
    expect(signals.getLanguage()).toBeNull();
    expect(signals.getDeviceClass()).toBeNull();
  });

  it("never returns anything but the allowlisted device_class values or null", () => {
    const signals = createReactNativeRiskSignals({ getDeviceClass: () => "tablet" });
    const result = signals.getDeviceClass();
    expect(["mobile", "tablet", "desktop", null]).toContain(result);
  });
});
