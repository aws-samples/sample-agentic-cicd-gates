import "@cloudscape-design/global-styles/index.css";
import { applyMode, Mode } from "@cloudscape-design/global-styles";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ensureSignedIn } from "./auth";

applyMode(Mode.Dark); // dark by default; suits a wall display

const root = ReactDOM.createRoot(document.getElementById("root")!);

// The SPA renders nothing from the account until sign-in has produced an
// access token; the API refuses every request without one regardless.
ensureSignedIn().then(
  () => root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  ),
  (err: unknown) => root.render(
    <main className="presenter" role="alert">
      <h1>Sign-in did not complete</h1>
      <p>{err instanceof Error ? err.message : String(err)}</p>
      <p><a href="/">Try again</a></p>
    </main>,
  ),
);
