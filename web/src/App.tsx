import { useState, useEffect } from "react";
import type { User, Session, Endpoint } from "./types";
import { api } from "./api/client";
import { AuthGate } from "./components/AuthGate";
import { Navbar } from "./components/Navbar";
import { EndpointsManager } from "./components/EndpointsManager";
import { EventInspector } from "./components/EventInspector";
import { TestWebhookDrawer } from "./components/TestWebhookDrawer";

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [, setSession] = useState<Session | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  const [activeTab, setActiveTab] = useState<"inspector" | "endpoints">("inspector");
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | undefined>(undefined);
  const [isTestDrawerOpen, setIsTestDrawerOpen] = useState(false);

  // Check existing session on load
  const checkAuth = async () => {
    setAuthLoading(true);
    try {
      const data = await api.auth.getSession();
      if (data?.user && data?.session) {
        setUser(data.user);
        setSession(data.session);
        await loadEndpoints();
      } else {
        setUser(null);
        setSession(null);
      }
    } catch {
      setUser(null);
      setSession(null);
    } finally {
      setAuthLoading(false);
    }
  };

  const loadEndpoints = async () => {
    try {
      const list = await api.endpoints.list();
      setEndpoints(list);
    } catch (err) {
      console.error("Failed to load endpoints", err);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const handleAuthenticated = (authedUser: User, authedSession: Session) => {
    setUser(authedUser);
    setSession(authedSession);
    loadEndpoints();
  };

  const handleSignOut = async () => {
    try {
      await api.auth.signOut();
    } catch {}
    setUser(null);
    setSession(null);
    setEndpoints([]);
  };

  const handleSelectEndpointFromManager = (endpointId: string) => {
    setSelectedEndpointId(endpointId);
    setActiveTab("inspector");
  };

  const handleEventSentFromDrawer = (endpointId: string) => {
    setSelectedEndpointId(endpointId);
    setActiveTab("inspector");
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex items-center justify-center font-mono text-xs text-muted">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-[#FAFAFA] animate-ping"></div>
          <span>INITIALIZING HOOKVAULT...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <AuthGate onAuthenticated={handleAuthenticated} />;
  }

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#FAFAFA] flex flex-col font-sans">
      <Navbar
        user={user}
        onSignOut={handleSignOut}
        onOpenTestDrawer={() => setIsTestDrawerOpen(true)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        endpointCount={endpoints.length}
      />

      <main className="flex-1 flex flex-col overflow-hidden">
        {activeTab === "endpoints" ? (
          <EndpointsManager
            endpoints={endpoints}
            onRefresh={loadEndpoints}
            onSelectEndpoint={handleSelectEndpointFromManager}
          />
        ) : (
          <EventInspector
            endpoints={endpoints}
            selectedEndpointId={selectedEndpointId}
            onSelectEndpointId={setSelectedEndpointId}
            onOpenTestDrawer={() => setIsTestDrawerOpen(true)}
          />
        )}
      </main>

      {/* Built-in Send Test Webhook Drawer */}
      <TestWebhookDrawer
        isOpen={isTestDrawerOpen}
        onClose={() => setIsTestDrawerOpen(false)}
        endpoints={endpoints}
        onEventSent={handleEventSentFromDrawer}
      />
    </div>
  );
}
