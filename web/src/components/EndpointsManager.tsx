import React, { useState } from "react";
import type { Endpoint } from "../types";
import { api, RequestError } from "../api/client";

interface EndpointsManagerProps {
  endpoints: Endpoint[];
  onRefresh: () => void;
  onSelectEndpoint: (id: string) => void;
}

export const EndpointsManager: React.FC<EndpointsManagerProps> = ({
  endpoints,
  onRefresh,
  onSelectEndpoint,
}) => {
  const [showModal, setShowModal] = useState(false);
  const [newEndpointName, setNewEndpointName] = useState("");
  const [newEndpointTargetUrl, setNewEndpointTargetUrl] = useState("https://");
  const [submitting, setSubmitting] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const [copiedSlug, setCopiedSlug] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteConfirmation, setDeleteConfirmation] = useState<Endpoint | null>(null);

  const handleCopyIngestUrl = (publicSlug: string) => {
    const fullUrl = `${window.location.origin}/in/${publicSlug}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedSlug(publicSlug);
    setTimeout(() => {
      setCopiedSlug(null);
    }, 2000);
  };

  const handleCreateEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);
    setSubmitting(true);

    try {
      await api.endpoints.create({
        name: newEndpointName.trim(),
        targetUrl: newEndpointTargetUrl.trim(),
      });
      setShowModal(false);
      setNewEndpointName("");
      setNewEndpointTargetUrl("https://");
      onRefresh();
    } catch (err: any) {
      if (err instanceof RequestError) {
        setModalError(err.message);
      } else {
        setModalError(err.message || "Failed to create endpoint");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteEndpoint = async (id: string) => {
    setDeletingId(id);
    try {
      await api.endpoints.delete(id);
      setDeleteConfirmation(null);
      onRefresh();
    } catch (err: any) {
      alert(err.message || "Failed to delete endpoint");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Top Banner & Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#262626]">
        <div>
          <h1 className="text-sm font-mono font-bold text-[#FAFAFA] tracking-wider uppercase">
            WEBHOOK ENDPOINTS
          </h1>
          <p className="text-xs text-muted font-mono mt-0.5">
            Ingest webhooks through secure public slugs and safely relay to verified HTTPS targets.
          </p>
        </div>
        <button
          onClick={() => {
            setShowModal(true);
            setModalError(null);
          }}
          className="px-4 py-2 bg-[#FAFAFA] text-[#0A0A0A] hover:bg-[#E5E5E5] font-mono text-xs font-bold tracking-wider uppercase transition-colors self-start sm:self-auto"
        >
          + NEW ENDPOINT
        </button>
      </div>

      {/* Endpoints Table / Cards */}
      {endpoints.length === 0 ? (
        <div className="bg-[#141414] border border-[#262626] p-12 text-center">
          <div className="w-8 h-8 mx-auto mb-3 border border-[#262626] flex items-center justify-center font-mono text-muted text-xs">
            0
          </div>
          <p className="text-xs font-mono text-[#FAFAFA] font-medium">No endpoints configured yet</p>
          <p className="text-xs font-mono text-muted mt-1 max-w-sm mx-auto">
            Create your first endpoint to generate a unique public ingestion slug and start inspecting incoming webhooks.
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-4 px-4 py-1.5 bg-[#FAFAFA] text-[#0A0A0A] font-mono text-xs font-bold uppercase"
          >
            Create Endpoint
          </button>
        </div>
      ) : (
        <div className="border border-[#262626] bg-[#141414] overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#0A0A0A] border-b border-[#262626] text-muted text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Endpoint</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Ingest URL</th>
                <th className="py-3 px-4">Target URL (Relay)</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {endpoints.map((ep) => {
                const isCopied = copiedSlug === ep.publicSlug;

                return (
                  <tr key={ep.id} className="hover:bg-[#1A1A1A] transition-colors">
                    {/* Name */}
                    <td className="py-3 px-4 font-semibold text-[#FAFAFA]">
                      <div>{ep.name}</div>
                      <div className="text-[10px] text-muted font-normal">
                        Created {new Date(ep.createdAt).toLocaleDateString()}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      {ep.isActive ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 border border-[#10B981]/30 bg-[#10B981]/10 text-[#10B981] text-[11px]">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></span>
                          ACTIVE
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 border border-[#262626] bg-[#0A0A0A] text-muted text-[11px]">
                          PAUSED
                        </span>
                      )}
                    </td>

                    {/* Ingest URL with 1-click copy */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <code className="text-[#FAFAFA] bg-[#0A0A0A] px-2 py-1 border border-[#262626] max-w-[220px] truncate select-all">
                          /in/{ep.publicSlug}
                        </code>
                        <button
                          onClick={() => handleCopyIngestUrl(ep.publicSlug)}
                          className={`px-2 py-1 text-[11px] font-mono border transition-colors ${
                            isCopied
                              ? "border-[#10B981] bg-[#10B981]/10 text-[#10B981]"
                              : "border-[#262626] bg-[#0A0A0A] text-muted hover:text-[#FAFAFA] hover:border-[#555555]"
                          }`}
                          title="Copy Full Ingest URL"
                        >
                          {isCopied ? "COPIED" : "COPY"}
                        </button>
                      </div>
                    </td>

                    {/* Target URL */}
                    <td className="py-3 px-4 text-muted max-w-[260px] truncate">
                      <span className="text-[#FAFAFA]">{ep.targetUrl}</span>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectEndpoint(ep.id)}
                          className="px-2.5 py-1 text-[11px] font-mono border border-[#262626] bg-[#0A0A0A] text-[#FAFAFA] hover:border-[#FAFAFA] transition-colors"
                        >
                          INSPECT
                        </button>
                        <button
                          onClick={() => setDeleteConfirmation(ep)}
                          className="px-2.5 py-1 text-[11px] font-mono border border-transparent text-muted hover:text-[#C1121F] hover:border-[#C1121F]/40 transition-colors"
                          title="Delete endpoint"
                        >
                          DELETE
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* New Endpoint Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[#141414] border border-[#262626] max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#262626] pb-3">
              <h2 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
                NEW WEBHOOK ENDPOINT
              </h2>
              <button
                onClick={() => setShowModal(false)}
                className="text-muted hover:text-[#FAFAFA] font-mono text-sm"
              >
                ✕
              </button>
            </div>

            {/* Security Notice */}
            <div className="p-3 bg-[#0A0A0A] border border-[#262626] text-[11px] font-mono text-muted space-y-1">
              <div className="text-[#FAFAFA] font-semibold">SSRF Protection Invariant:</div>
              <p>
                Outbound webhooks strictly require valid HTTPS endpoints. Target URLs pointing to loopback (127.0.0.1, ::1), RFC1918 private subnets, cloud metadata services, or non-HTTPS schemes are rejected by default.
              </p>
            </div>

            {/* Error Message */}
            {modalError && (
              <div className="p-3 border border-[#C1121F] bg-[#C1121F]/10 text-xs text-[#FAFAFA] font-mono flex items-start gap-2">
                <span className="text-[#C1121F] font-bold">!</span>
                <span className="flex-1">{modalError}</span>
              </div>
            )}

            <form onSubmit={handleCreateEndpoint} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-muted mb-1 uppercase tracking-wider">
                  Endpoint Name
                </label>
                <input
                  type="text"
                  required
                  value={newEndpointName}
                  onChange={(e) => setNewEndpointName(e.target.value)}
                  placeholder="e.g. Stripe Webhooks"
                  className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA]"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-muted mb-1 uppercase tracking-wider">
                  Target URL (HTTPS Only)
                </label>
                <input
                  type="url"
                  required
                  value={newEndpointTargetUrl}
                  onChange={(e) => setNewEndpointTargetUrl(e.target.value)}
                  placeholder="https://api.yourdomain.com/webhooks"
                  className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA]"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 border border-[#262626] hover:border-[#555555] text-muted hover:text-[#FAFAFA] font-mono text-xs uppercase"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-[#FAFAFA] text-[#0A0A0A] hover:bg-[#E5E5E5] disabled:opacity-50 font-mono text-xs font-bold uppercase"
                >
                  {submitting ? "VALIDATING..." : "CREATE ENDPOINT"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmation && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#141414] border border-[#C1121F]/50 max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h2 className="font-mono text-xs font-bold text-[#FAFAFA] tracking-wider uppercase">
              CONFIRM DELETION
            </h2>
            <p className="font-mono text-xs text-muted">
              Are you sure you want to delete endpoint{" "}
              <strong className="text-[#FAFAFA] font-semibold">"{deleteConfirmation.name}"</strong>?
              This will permanently delete the endpoint, its signing secrets, and all associated incoming events and delivery logs.
            </p>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setDeleteConfirmation(null)}
                className="px-4 py-2 border border-[#262626] hover:border-[#555555] text-muted hover:text-[#FAFAFA] font-mono text-xs uppercase"
              >
                CANCEL
              </button>
              <button
                type="button"
                disabled={deletingId !== null}
                onClick={() => handleDeleteEndpoint(deleteConfirmation.id)}
                className="px-4 py-2 bg-[#C1121F] hover:bg-[#9E0C18] text-[#FAFAFA] font-mono text-xs font-bold uppercase"
              >
                {deletingId ? "DELETING..." : "DELETE ENDPOINT"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
