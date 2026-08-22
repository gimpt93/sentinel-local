import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("Sentinel Local", () => {
  it("renders the approved security map and local-only status", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Home security map" })).toBeInTheDocument();
    expect(screen.getAllByText("Local only").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Unknown device, unknown/i })).toBeInTheDocument();
  });

  it("navigates to threat management and labels remediation as simulated", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /Threats/i }));
    expect(screen.getByRole("heading", { name: "Threat management", level: 2 })).toBeInTheDocument();
    expect(screen.getByText(/simulated in this prototype/i)).toBeInTheDocument();
  });
});
