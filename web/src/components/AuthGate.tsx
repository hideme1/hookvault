import React, { useState } from "react";
import { api, RequestError } from "../api/client";
import type { User, Session } from "../types";

interface AuthGateProps {
  onAuthenticated: (user: User, session: Session) => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ onAuthenticated }) => {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "signin") {
        const res = await api.auth.signIn(email, password);
        onAuthenticated(res.user, res.session);
      } else {
        if (!name.trim()) {
          setError("Name is required");
          setLoading(false);
          return;
        }
        const res = await api.auth.signUp(name.trim(), email, password);
        onAuthenticated(res.user, res.session);
      }
    } catch (err: any) {
      if (err instanceof RequestError) {
        setError(err.message);
      } else {
        setError(err.message || "Authentication failed. Check your credentials.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] flex flex-col items-center justify-center p-4">
      {/* Brand Header */}
      <div className="w-full max-w-md mb-8 text-center">
        <div className="inline-flex items-center gap-2 mb-3">
          <div className="w-6 h-6 bg-white flex items-center justify-center font-mono font-bold text-black text-xs">
            HV
          </div>
          <span className="font-mono text-sm tracking-widest text-[#FAFAFA] font-semibold">
            HOOKVAULT
          </span>
          <span className="text-[10px] uppercase font-mono tracking-wider px-1.5 py-0.5 border border-[#262626] text-muted">
            SECURITY-FIRST
          </span>
        </div>
        <p className="text-xs text-muted font-mono">
          Anti-SSRF Webhook Ingestion & Replay Engine
        </p>
      </div>

      {/* Auth Card */}
      <div className="w-full max-w-md bg-[#141414] border border-[#262626] rounded-none p-6 shadow-2xl">
        {/* Tab Controls */}
        <div className="grid grid-cols-2 gap-px bg-[#262626] p-px mb-6 font-mono text-xs">
          <button
            type="button"
            onClick={() => {
              setMode("signin");
              setError(null);
            }}
            className={`py-2 text-center transition-colors ${
              mode === "signin"
                ? "bg-[#141414] text-[#FAFAFA] font-semibold"
                : "bg-[#0A0A0A] text-muted hover:text-[#FAFAFA]"
            }`}
          >
            SIGN IN
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("signup");
              setError(null);
            }}
            className={`py-2 text-center transition-colors ${
              mode === "signup"
                ? "bg-[#141414] text-[#FAFAFA] font-semibold"
                : "bg-[#0A0A0A] text-muted hover:text-[#FAFAFA]"
            }`}
          >
            CREATE ACCOUNT
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-5 p-3 border border-[#C1121F] bg-[#C1121F]/10 text-xs text-[#FAFAFA] font-mono flex items-start gap-2">
            <span className="text-[#C1121F] font-bold">!</span>
            <span className="flex-1">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === "signup" && (
            <div>
              <label className="block text-xs font-mono text-muted mb-1 uppercase tracking-wider">
                Full Name
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA] transition-colors"
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-muted mb-1 uppercase tracking-wider">
              Email Address
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@domain.com"
              className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA] transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-muted mb-1 uppercase tracking-wider">
              Password
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full bg-[#0A0A0A] border border-[#262626] px-3 py-2 text-xs font-mono text-[#FAFAFA] placeholder-[#555555] focus:outline-none focus:border-[#FAFAFA] transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-2.5 px-4 bg-[#FAFAFA] text-[#0A0A0A] hover:bg-[#E5E5E5] disabled:opacity-50 text-xs font-mono font-bold tracking-wider uppercase transition-colors"
          >
            {loading ? "AUTHENTICATING..." : mode === "signin" ? "SIGN IN" : "REGISTER TENANT"}
          </button>
        </form>

        <div className="mt-6 pt-4 border-t border-[#262626] text-center">
          <p className="text-[11px] font-mono text-muted">
            Strict tenant isolation enforced at database query layer.
          </p>
        </div>
      </div>
    </div>
  );
};
