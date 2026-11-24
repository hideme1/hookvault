import React from "react";
import type { User } from "../types";

interface NavbarProps {
  user: User;
  onSignOut: () => void;
  onOpenTestDrawer: () => void;
  activeTab: "inspector" | "endpoints";
  setActiveTab: (tab: "inspector" | "endpoints") => void;
  endpointCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  onSignOut,
  onOpenTestDrawer,
  activeTab,
  setActiveTab,
  endpointCount,
}) => {
  return (
    <header className="h-14 border-b border-[#262626] bg-[#0A0A0A] px-4 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Tabs */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 bg-white flex items-center justify-center font-mono font-bold text-black text-[10px]">
            HV
          </div>
          <span className="font-mono text-xs tracking-widest text-[#FAFAFA] font-bold">
            HOOKVAULT
          </span>
        </div>

        <nav className="flex items-center gap-1 font-mono text-xs">
          <button
            onClick={() => setActiveTab("inspector")}
            className={`px-3 py-1.5 border transition-colors ${
              activeTab === "inspector"
                ? "border-[#FAFAFA] bg-[#141414] text-[#FAFAFA] font-semibold"
                : "border-transparent text-muted hover:text-[#FAFAFA]"
            }`}
          >
            EVENTS INSPECTOR
          </button>
          <button
            onClick={() => setActiveTab("endpoints")}
            className={`px-3 py-1.5 border transition-colors flex items-center gap-1.5 ${
              activeTab === "endpoints"
                ? "border-[#FAFAFA] bg-[#141414] text-[#FAFAFA] font-semibold"
                : "border-transparent text-muted hover:text-[#FAFAFA]"
            }`}
          >
            <span>ENDPOINTS</span>
            <span className="px-1 text-[10px] bg-[#262626] text-[#FAFAFA]">
              {endpointCount}
            </span>
          </button>
        </nav>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-3">
        {/* Send Test Webhook Quick Button */}
        <button
          onClick={onOpenTestDrawer}
          className="px-3 py-1.5 bg-[#141414] hover:bg-[#1A1A1A] border border-[#262626] hover:border-[#FAFAFA] text-[#FAFAFA] font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors"
        >
          <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
          <span>SEND TEST WEBHOOK</span>
        </button>

        <div className="h-4 w-px bg-[#262626]"></div>

        {/* User Identity */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-muted hidden sm:inline">{user.email}</span>
          <button
            onClick={onSignOut}
            className="px-2 py-1 text-muted hover:text-[#C1121F] border border-transparent hover:border-[#C1121F]/40 transition-colors"
            title="Sign Out"
          >
            SIGN OUT
          </button>
        </div>
      </div>
    </header>
  );
};
