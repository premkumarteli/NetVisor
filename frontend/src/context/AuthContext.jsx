import { useEffect, useState } from "react";
import { authService } from "../services/api";
import { isAdminRole } from "../utils/roles";
import { AuthContext } from "./auth-context";
import { ensureRealtimeConnection, disconnectRealtime } from "../socket";

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = async () => {
    setLoading(true);
    try {
      const res = await authService.getCurrentUser();
      const authenticatedUser = res.data?.authenticated ? res.data : null;
      setUser(authenticatedUser);
      if (authenticatedUser) {
        ensureRealtimeConnection(true);
      } else {
        disconnectRealtime();
      }
    } catch {
      setUser(null);
      disconnectRealtime();
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await authService.logout();
    } finally {
      setUser(null);
      disconnectRealtime();
    }
  };

  useEffect(() => {
    refreshUser();

    const handleAuthExpired = () => {
      setUser(null);
      disconnectRealtime();
    };

    window.addEventListener("netvisor:auth-expired", handleAuthExpired);
    return () => window.removeEventListener("netvisor:auth-expired", handleAuthExpired);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAdmin: isAdminRole(user?.role),
        refreshUser,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
