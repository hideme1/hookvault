import React, { useState, useEffect } from "react";
import type { Endpoint } from "../types";
import { api } from "../api/client";

interface TestWebhookDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  endpoints: Endpoint[];
  onEventSent: (endpointId: string) => void;
}

const PRESETS = {
  stripe: {
    name: "Stripe: payment_intent.succeeded",
    payload: JSON.stringify(
      {
        id: "evt_3N8x7b2eZvKYlo2C1gB1q",
        object: "event",
        api_version: "2024-11-20",
        created: Math.floor(Date.now() / 1000),
        type: "payment_intent.succeeded",
        data: {
          object: {
            id: "pi_3N8x7b2eZvKYlo2C1gB1q",
            object: "payment_intent",
            amount: 4999,
            currency: "usd",
            status: "succeeded",
            customer: "cus_NWbtp7hRuw1f29",
          },
        },
      },
      null,
      2
    ),
  },
  shopify: {
    name: "Shopify: orders/create",
    payload: JSON.stringify(
      {
        id: 820982911946154500,
        email: "buyer@example.com",
        closed_at: null,
        created_at: new Date().toISOString(),
        currency: "USD",
        total_price: "129.00",
        subtotal_price: "119.00",
        financial_status: "paid",
        line_items: [
          {
            id: 866550311764,
            title: "Security Engineering Handbook",
            price: "129.00",
            quantity: 1,
          },
        ],
      },
      null,
      2
    ),
  },
  github: {
    name: "GitHub: ping",
    payload: JSON.stringify(
      {
        zen: "Approachable is better than simple.",
        hook_id: 1099489,
        hook: {
          type: "Repository",
          id: 1099489,
          active: true,
          events: ["push", "pull_request"],
        },
        repository: {
          id: 1296269,
          name: "hookvault",
          full_name: "acme/hookvault",
          private: true,
        },
      },
      null,
      2
    ),
  },
  minimal: {
    name: "Custom Minimal",
    payload: JSON.stringify(
      {
        event: "test.notification",
        timestamp: new Date().toISOString(),
        data: {
          message: "HookVault local demo event",
          verified: true,
        },
      },
      null,
      2
    ),
  },
};

export const TestWebhookDrawer: React.FC<TestWebhookDrawerProps> = ({
  isOpen,
  onClose,
  endpoints,
  onEventSent,
}) => {
  const [selectedEndpointId, setSelectedEndpointId] = useState<string>("");
  const [selectedPreset, setSelectedPreset] = useState<keyof typeof PRESETS>("stripe");
  const [payload, setPayload] = useState(PRESETS.stripe.payload);
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [signatureHeader, setSignatureHeader] = useState("");

  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<{
    status: number;
    body: string;
    durationMs: number;
  } | null>(null);

  useEffect(() => {
    if (endpoints.length > 0 && !selectedEndpointId) {
      setSelectedEndpointId(endpoints[0].id);
    }
  }, [endpoints, selectedEndpointId]);

  if (!isOpen) return null;

  const currentEndpoint = endpoints.find((e) => e.id === selectedEndpointId);

  const handlePresetChange = (presetKey: keyof typeof PRESETS) => {
    setSelectedPreset(presetKey);
    setPayload(PRESETS[presetKey].payload);
  };

  const handleGenerateIdempotencyKey = () => {
    const uuid = "idemp_" + Math.random().toString(36).substring(2, 10);
    setIdempotencyKey(uuid);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentEndpoint) return;

    setSending(true);
    setResult(null);

    const headers: Record<string, string> = {};
    if (idempotencyKey.trim()) {
      headers["Idempotency-Key"] = idempotencyKey.trim();
    }
    if (signatureHeader.trim()) {
      headers["x-hookvault-signature"] = signatureHeader.trim();
    }

    const start = performance.now();
    try {
      const res = await api.ingest.sendTest(
        currentEndpoint.publicSlug,
        payload,
        headers
      );
      const durationMs = Math.round(performance.now() - start);
      setResult({
        status: res.status,
        body: res.body,
        durationMs,
      });
      onEventSent(currentEndpoint.id);
    } catch (err: any) {
      const durationMs = Math.round(performance.now() - start);
      setResult({
        status: 500,
        body: err.message || "Failed to deliver request",
        durationMs,
      });
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="absolute inset-0 bg-black/70 backdrop-blur-none transition-opacity"
      ></div>

      {/* Drawer Container */}
      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-lg bg-[#141414] border-l border-[#262626] flex flex-col shadow-2xl">
          {/* Header */}
          <div className="p-4 border-b border-[#262626] flex items-center justify-between bg-[#0A0A0A]">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
              <h2 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
                SEND TEST WEBHOOK
              </h2>
            </div>
            <button
              onClick={onClose}
              className="font-mono text-xs text-muted hover:text-[#FAFAFA] px-2 py-1"
            >
              ESC / ✕
            </button>
          </div>

          {/* Form Body */}
          <form onSubmit={handleSend} className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Endpoint Selector */}
            <div>
              <label className="block text-[11px] font-mono text-muted uppercase tracking-wider mb-1">
                Target Ingestion Endpoint
              </label>
              {endpoints.length === 0 ? (
                <div className="p-3 border border-[#262626] bg-[#0A0A0A] font-mono text-xs text-[#C1121F]">
                  No endpoints exist yet. Please create an endpoint first.
                </div>
              ) : (
                <select
                  value={selectedEndpointId}
                  onChange={(e) => setSelectedEndpointId(e.target.value)}
                  className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] focus:outline-none focus:border-[#FAFAFA]"
                >
                  {endpoints.map((ep) => (
                    <option key={ep.id} value={ep.id}>
                      {ep.name} (/in/{ep.publicSlug})
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Ingestion URL Preview */}
            {currentEndpoint && (
              <div className="p-2.5 bg-[#0A0A0A] border border-[#262626] font-mono text-[11px] space-y-1">
                <div className="text-muted uppercase text-[10px]">Ingest URL (POST):</div>
                <div className="text-[#FAFAFA] truncate select-all">
                  {window.location.origin}/in/{currentEndpoint.publicSlug}
                </div>
                <div className="text-muted text-[10px] truncate">
                  Relays to: <span className="text-[#FAFAFA]">{currentEndpoint.targetUrl}</span>
                </div>
              </div>
            )}

            {/* Payload Presets */}
            <div>
              <label className="block text-[11px] font-mono text-muted uppercase tracking-wider mb-1">
                Payload Template Preset
              </label>
              <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
                {Object.entries(PRESETS).map(([key, item]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handlePresetChange(key as keyof typeof PRESETS)}
                    className={`py-1.5 px-2 text-left border transition-colors truncate ${
                      selectedPreset === key
                        ? "border-[#FAFAFA] bg-[#262626] text-[#FAFAFA] font-semibold"
                        : "border-[#262626] bg-[#0A0A0A] text-muted hover:text-[#FAFAFA]"
                    }`}
                  >
                    {item.name.split(":")[0]}
                  </button>
                ))}
              </div>
            </div>

            {/* Idempotency Key */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-mono text-muted uppercase tracking-wider">
                  Idempotency-Key (Optional)
                </label>
                <button
                  type="button"
                  onClick={handleGenerateIdempotencyKey}
                  className="text-[10px] font-mono text-muted hover:text-[#FAFAFA] underline"
                >
                  Generate Key
                </button>
              </div>
              <input
                type="text"
                value={idempotencyKey}
                onChange={(e) => setIdempotencyKey(e.target.value)}
                placeholder="e.g. idemp_8f17a9bc"
                className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-1.5 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA]"
              />
            </div>

            {/* HMAC Signature (Optional) */}
            <div>
              <label className="block text-[11px] font-mono text-muted uppercase tracking-wider mb-1">
                x-hookvault-signature (Optional)
              </label>
              <input
                type="text"
                value={signatureHeader}
                onChange={(e) => setSignatureHeader(e.target.value)}
                placeholder="Leave blank for unverified test, or provide HMAC hex"
                className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-1.5 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA]"
              />
            </div>

            {/* JSON Payload Editor */}
            <div>
              <label className="block text-[11px] font-mono text-muted uppercase tracking-wider mb-1">
                JSON Body Payload
              </label>
              <textarea
                rows={10}
                required
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="w-full bg-[#0A0A0A] border border-[#262626] p-3 text-xs font-mono text-[#FAFAFA] focus:outline-none focus:border-[#FAFAFA] resize-none"
              ></textarea>
            </div>

            {/* Execution Result Box */}
            {result && (
              <div
                className={`p-3 border font-mono text-xs space-y-1 ${
                  result.status >= 200 && result.status < 300
                    ? "border-[#10B981] bg-[#10B981]/10 text-[#FAFAFA]"
                    : "border-[#C1121F] bg-[#C1121F]/10 text-[#FAFAFA]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold">
                    HTTP {result.status} ({result.durationMs}ms)
                  </span>
                  <span className="text-[11px] uppercase">
                    {result.status >= 200 && result.status < 300
                      ? "Ingested & Relayed"
                      : "Rejected / Error"}
                  </span>
                </div>
                <div className="text-[11px] text-muted break-all max-h-24 overflow-y-auto">
                  {result.body}
                </div>
              </div>
            )}

            {/* Submit Action */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={sending || !currentEndpoint}
                className="w-full py-2.5 bg-[#FAFAFA] text-[#0A0A0A] hover:bg-[#E5E5E5] disabled:opacity-50 text-xs font-mono font-bold tracking-wider uppercase transition-colors"
              >
                {sending ? "TRANSMITTING..." : "FIRE TEST WEBHOOK NOW"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
