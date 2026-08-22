import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("Sentinel Local", () => {
  it("renders the security map without inventing devices outside Tauri", async () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Home security map" })).toBeInTheDocument();
    expect((await screen.findAllByText("Local only")).length).toBeGreaterThan(0);
    expect(await screen.findByRole("heading", { name: "Network relationship unavailable" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Unknown device, unknown/i })).not.toBeInTheDocument();
  });

  it("navigates to live findings and states the safe release boundary", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Network relationship unavailable" });
    fireEvent.click(screen.getByRole("button", { name: /Threats/i }));
    expect(screen.getByRole("heading", { name: "Threat management", level: 2 })).toBeInTheDocument();
    expect(screen.getByText(/Protected remediation boundary/i)).toBeInTheDocument();
  });

  it("persists dark mode from settings", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Network relationship unavailable" });
    fireEvent.click(screen.getByRole("button", { name: /Settings/i }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Dark mode" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(window.localStorage.getItem("sentinel-theme")).toBe("dark");
  });
});
