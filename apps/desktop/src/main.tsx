import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App, { StartupProblem } from "./App";
import { bridge } from "./bridge";
import "./styles.css";

// Before anything else asks the app for anything: whether it could start
// on this computer's files at all.
void bridge.startupProblem().catch(() => null).then((problem) => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      {problem ? <StartupProblem problem={problem} /> : <App />}
    </StrictMode>,
  );
});
