import React, { useState, useEffect, useRef } from "react";
import type { Endpoint, WebhookEvent } from "../types";
import { api } from "../api/client";

interface EventInspectorProps {
  endpoints: Endpoint[];
  selectedEndpointId?: string;
  onSelectEndpointId: (id?: string) => void;
  onOpenTestDrawer: () => void;
}

export const EventInspector: React.FC<EventInspectorProps> = ({
  endpoints,
  selectedEndpointId,
  onSelectEndpointId,
  onOpenTestDrawer,
}) => {
  const [events, setEvents] = useState<WebhookEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<WebhookEvent | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [replaySuccess, setReplaySuccess] = useState<string | null>(null);
  const [autoPoll, setAutoPoll] = useState(true);
  const [copiedPayload, setCopiedPayload] = useState(false);

  // Poll timer
  const pollTimerRef = useRef<number | null>(null);

  const fetchEvents = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await api.events.list(selectedEndpointId);
      setEvents(data);
      if (!selectedEventId && data.length > 0) {
        setSelectedEventId(data[0].id);
      }
    } catch (err) {
      console.error("Failed to fetch events", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const fetchEventDetail = async (id: string) => {
    try {
      const eventData = await api.events.get(id);
      setSelectedEvent(eventData);
    } catch (err) {
      console.error("Failed to fetch event detail", err);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [selectedEndpointId]);

  useEffect(() => {
    if (selectedEventId) {
      fetchEventDetail(selectedEventId);
    } else {
      setSelectedEvent(null);
    }
  }, [selectedEventId]);

  // 5s Auto-polling
  useEffect(() => {
    if (!autoPoll) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      return;
    }

    pollTimerRef.current = window.setInterval(() => {
      fetchEvents(true);
      if (selectedEventId) {
        fetchEventDetail(selectedEventId);
      }
    }, 5000);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [autoPoll, selectedEndpointId, selectedEventId]);

  const handleReplay = async () => {
    if (!selectedEvent) return;
    setReplaying(true);
    setReplaySuccess(null);

    try {
      const delivery = await api.events.replay(selectedEvent.id);
      setReplaySuccess(`Replay #${delivery.attemptNumber} executed with HTTP ${delivery.statusCode || delivery.errorCode}`);
      // Refresh event detail to get new delivery attempt
      await fetchEventDetail(selectedEvent.id);
      await fetchEvents(true);
    } catch (err: any) {
      alert(err.message || "Replay failed");
    } finally {
      setReplaying(false);
      setTimeout(() => setReplaySuccess(null), 4000);
    }
  };

  const handleCopyPayload = () => {
    if (!selectedEvent?.bodyText) return;
    navigator.clipboard.writeText(selectedEvent.bodyText);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  // Parse headers safely
  let parsedHeaders: Record<string, string> = {};
  if (selectedEvent?.headersJson) {
    try {
      parsedHeaders = JSON.parse(selectedEvent.headersJson);
    } catch {}
  }

  // Format body pretty
  let formattedBody = selectedEvent?.bodyText || "";
  if (selectedEvent?.bodyText) {
    try {
      formattedBody = JSON.stringify(JSON.parse(selectedEvent.bodyText), null, 2);
    } catch {}
  }

  const endpointMap = new Map(endpoints.map((e) => [e.id, e]));

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col md:flex-row overflow-hidden bg-[#0A0A0A]">
      {/* ─── LEFT PANE: Event Stream List ───────────────────────────────────── */}
      <div className="w-full md:w-[380px] lg:w-[420px] flex-shrink-0 border-r border-[#262626] flex flex-col h-full bg-[#0A0A0A]">
        {/* Controls Bar */}
        <div className="p-3 border-b border-[#262626] bg-[#141414] space-y-2.5">
          {/* Endpoint Filter */}
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-mono text-muted uppercase">FILTER:</label>
            <select
              value={selectedEndpointId || ""}
              onChange={(e) => onSelectEndpointId(e.target.value || undefined)}
              className="flex-1 bg-[#0A0A0A] border border-[#262626] px-2 py-1 text-xs font-mono text-[#FAFAFA] focus:outline-none focus:border-[#FAFAFA]"
            >
              <option value="">All Endpoints ({endpoints.length})</option>
              {endpoints.map((ep) => (
                <option key={ep.id} value={ep.id}>
                  {ep.name}
                </option>
              ))}
            </select>
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-2">
              <button
                onClick={() => fetchEvents(false)}
                className="px-2.5 py-1 bg-[#0A0A0A] hover:bg-[#1A1A1A] border border-[#262626] text-[#FAFAFA] text-[11px] font-semibold flex items-center gap-1.5 transition-colors"
                title="Manual Refresh"
              >
                <span>↻</span>
                <span>REFRESH</span>
              </button>

              <label className="flex items-center gap-1.5 cursor-pointer text-muted hover:text-[#FAFAFA] select-none text-[11px]">
                <input
                  type="checkbox"
                  checked={autoPoll}
                  onChange={(e) => setAutoPoll(e.target.checked)}
                  className="rounded-none accent-[#FAFAFA] cursor-pointer"
                />
                <span className="flex items-center gap-1">
                  {autoPoll && <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse"></span>}
                  <span>5S POLL</span>
                </span>
              </label>
            </div>

            <span className="text-muted text-[11px]">
              {events.length} {events.length === 1 ? "EVENT" : "EVENTS"}
            </span>
          </div>
        </div>

        {/* Scrollable Event List */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#262626]">
          {loading && events.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-muted">
              Loading webhook stream...
            </div>
          ) : events.length === 0 ? (
            <div className="p-8 text-center font-mono space-y-3">
              <p className="text-xs text-[#FAFAFA]">No webhook events received yet</p>
              <p className="text-[11px] text-muted">
                Fire your first test webhook payload straight to your ingest URL.
              </p>
              <button
                onClick={onOpenTestDrawer}
                className="px-3 py-1.5 bg-[#FAFAFA] text-[#0A0A0A] text-xs font-bold font-mono uppercase"
              >
                Send Test Webhook
              </button>
            </div>
          ) : (
            events.map((ev) => {
              const isSelected = selectedEventId === ev.id;
              const ep = endpointMap.get(ev.endpointId);
              const is2xx =
                ev.latestStatusCode && ev.latestStatusCode >= 200 && ev.latestStatusCode < 300;

              return (
                <div
                  key={ev.id}
                  onClick={() => setSelectedEventId(ev.id)}
                  className={`p-3 cursor-pointer transition-colors font-mono text-xs ${
                    isSelected
                      ? "bg-[#141414] border-l-2 border-[#FAFAFA]"
                      : "hover:bg-[#111111] border-l-2 border-transparent"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="px-1.5 py-0.5 bg-[#262626] text-[#FAFAFA] font-bold text-[10px]">
                        {ev.method}
                      </span>
                      <span className="text-[11px] text-[#FAFAFA] font-medium truncate max-w-[150px]">
                        {ep ? ep.name : ev.endpointId.slice(0, 8)}
                      </span>
                    </div>

                    {/* Delivery Status Badge */}
                    {ev.latestStatusCode !== undefined && ev.latestStatusCode !== null ? (
                      <span
                        className={`text-[10px] px-1.5 py-0.2 border ${
                          is2xx
                            ? "border-[#10B981]/30 bg-[#10B981]/10 text-[#10B981]"
                            : "border-[#C1121F]/30 bg-[#C1121F]/10 text-[#C1121F]"
                        }`}
                      >
                        {ev.latestStatusCode}
                      </span>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.2 border border-[#262626] text-muted">
                        PENDING
                      </span>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-muted">
                    <span>{new Date(ev.receivedAt).toLocaleTimeString()}</span>

                    {/* HMAC Badge */}
                    {ev.signatureValid === true && (
                      <span className="text-[10px] text-[#10B981] flex items-center gap-1 font-semibold">
                        <span className="w-1 h-1 rounded-full bg-[#10B981]"></span>
                        HMAC VALID
                      </span>
                    )}
                    {ev.signatureValid === false && (
                      <span className="text-[10px] text-[#C1121F] flex items-center gap-1 font-semibold">
                        <span className="w-1 h-1 rounded-full bg-[#C1121F]"></span>
                        HMAC INVALID
                      </span>
                    )}
                    {ev.signatureValid === null && (
                      <span className="text-[10px] text-[#555555]">NO SIG</span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ─── RIGHT PANE: Event Inspector Details & Replay ────────────────────── */}
      <div className="flex-1 flex flex-col h-full bg-[#0A0A0A] overflow-y-auto">
        {!selectedEvent ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center font-mono">
            <div className="w-10 h-10 border border-[#262626] flex items-center justify-center text-muted mb-3">
              ⚡
            </div>
            <p className="text-xs text-[#FAFAFA] font-medium">Select an incoming event</p>
            <p className="text-xs text-muted max-w-sm mt-1">
              Click an event from the left stream to inspect request headers, cryptographic signatures, payload, and execute 1-click safe replays.
            </p>
          </div>
        ) : (
          <div className="p-6 space-y-6">
            {/* Header Card with Replay Button */}
            <div className="p-4 bg-[#141414] border border-[#262626] flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1 font-mono">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-white text-black font-bold text-xs">
                    {selectedEvent.method}
                  </span>
                  <span className="text-xs text-[#FAFAFA] font-bold">
                    {endpointMap.get(selectedEvent.endpointId)?.name || "Endpoint"}
                  </span>
                  <span className="text-[11px] text-muted">
                    ({selectedEvent.id})
                  </span>
                </div>
                <div className="text-[11px] text-muted">
                  Received at {new Date(selectedEvent.receivedAt).toLocaleString()}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleReplay}
                  disabled={replaying}
                  className="px-4 py-2 bg-[#FAFAFA] hover:bg-[#E5E5E5] text-[#0A0A0A] font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 disabled:opacity-50 transition-colors shadow-sm"
                >
                  <span>⚡</span>
                  <span>{replaying ? "REPLAYING..." : "1-CLICK REPLAY"}</span>
                </button>
              </div>
            </div>

            {/* Replay feedback banner */}
            {replaySuccess && (
              <div className="p-3 border border-[#10B981] bg-[#10B981]/10 text-xs font-mono text-[#FAFAFA] flex items-center gap-2 animate-fade-in">
                <span className="text-[#10B981] font-bold">✓</span>
                <span>{replaySuccess}</span>
              </div>
            )}

            {/* Section 1: Delivery Attempts History */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
                  DELIVERY ATTEMPTS LOG ({selectedEvent.deliveryAttempts?.length || 0})
                </h3>
              </div>

              {selectedEvent.deliveryAttempts && selectedEvent.deliveryAttempts.length > 0 ? (
                <div className="border border-[#262626] bg-[#141414] overflow-x-auto font-mono text-xs">
                  <table className="w-full text-left">
                    <thead className="bg-[#0A0A0A] border-b border-[#262626] text-muted text-[11px] uppercase">
                      <tr>
                        <th className="py-2.5 px-3">#</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Latency</th>
                        <th className="py-2.5 px-3">Error / Note</th>
                        <th className="py-2.5 px-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#262626]">
                      {selectedEvent.deliveryAttempts.map((attempt) => {
                        const is2xx =
                          attempt.statusCode &&
                          attempt.statusCode >= 200 &&
                          attempt.statusCode < 300;

                        return (
                          <tr key={attempt.id} className="hover:bg-[#1A1A1A]">
                            <td className="py-2 px-3 text-muted">
                              #{attempt.attemptNumber}
                            </td>
                            <td className="py-2 px-3">
                              {attempt.statusCode ? (
                                <span
                                  className={`px-1.5 py-0.5 text-[11px] border font-bold ${
                                    is2xx
                                      ? "border-[#10B981]/30 bg-[#10B981]/10 text-[#10B981]"
                                      : "border-[#C1121F]/30 bg-[#C1121F]/10 text-[#C1121F]"
                                  }`}
                                >
                                  {attempt.statusCode}
                                </span>
                              ) : (
                                <span className="px-1.5 py-0.5 text-[11px] border border-[#C1121F]/30 bg-[#C1121F]/10 text-[#C1121F] font-bold">
                                  {attempt.errorCode || "NETWORK_FAIL"}
                                </span>
                              )}
                            </td>
                            <td className="py-2 px-3 text-[#FAFAFA]">
                              {attempt.durationMs !== null ? `${attempt.durationMs}ms` : "-"}
                            </td>
                            <td className="py-2 px-3 text-muted max-w-[200px] truncate">
                              {attempt.responseSnippet || attempt.errorCode || "-"}
                            </td>
                            <td className="py-2 px-3 text-muted text-[11px]">
                              {new Date(attempt.createdAt).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 bg-[#141414] border border-[#262626] font-mono text-xs text-muted text-center">
                  No delivery attempts recorded for this event.
                </div>
              )}
            </div>

            {/* Section 2: Request Headers Table */}
            <div className="space-y-2">
              <h3 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
                INCOMING REQUEST HEADERS
              </h3>
              <div className="border border-[#262626] bg-[#141414] overflow-x-auto font-mono text-xs max-h-48 overflow-y-auto">
                <table className="w-full text-left">
                  <thead className="bg-[#0A0A0A] border-b border-[#262626] text-muted text-[11px] uppercase sticky top-0">
                    <tr>
                      <th className="py-2 px-3 w-1/3">Header</th>
                      <th className="py-2 px-3">Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#262626]">
                    {Object.entries(parsedHeaders).map(([key, value]) => (
                      <tr key={key} className="hover:bg-[#1A1A1A]">
                        <td className="py-1.5 px-3 text-muted">{key}</td>
                        <td className="py-1.5 px-3 text-[#FAFAFA] break-all select-all">
                          {value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Section 3: Payload Viewer */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
                  RAW PAYLOAD BODY
                </h3>
                <button
                  onClick={handleCopyPayload}
                  disabled={!selectedEvent.bodyText}
                  className="px-2 py-1 text-[11px] font-mono border border-[#262626] hover:border-[#555555] text-muted hover:text-[#FAFAFA] transition-colors"
                >
                  {copiedPayload ? "COPIED" : "COPY PAYLOAD"}
                </button>
              </div>

              <div className="border border-[#262626] bg-[#141414] p-4 max-h-96 overflow-auto">
                <pre className="font-mono text-xs text-[#FAFAFA] whitespace-pre-wrap break-all">
                  {formattedBody || "<empty body>"}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
