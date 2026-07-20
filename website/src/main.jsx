import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import { installDomTranslations } from "./i18n";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

installDomTranslations();
