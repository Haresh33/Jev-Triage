import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./theme.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("missing #root element");

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } });

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <div className="app-root">
        <App />
      </div>
    </QueryClientProvider>
  </StrictMode>,
);
