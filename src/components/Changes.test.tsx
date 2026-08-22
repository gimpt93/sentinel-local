import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { DeviceProfile, ThreatFinding } from "../types";
import { DeviceInspector } from "./DeviceInspector";
import { MembersView, ThreatsView } from "./Views";

const device: DeviceProfile = { id: "neighbor-test", name: "Living room device", type: "unknown", ip: "192.168.1.25", mac: "AA-BB-CC-DD-EE-FF", trust: "unknown", access: "Router managed", firstSeen: "Today", lastSeen: "Now", discoverySource: "Windows ARP neighbor table", riskReasons: ["Not labeled"] };

describe("Sentinel Local 0.3 changes", () => {
  it("expands device evidence from the overview inspector", () => {
    render(<DeviceInspector device={device} onClose={vi.fn()} onIdentify={vi.fn()} onRestrict={vi.fn()} onRouter={vi.fn()}/>);
    fireEvent.click(screen.getByRole("button", { name: /Expand more details/i }));
    expect(screen.getByRole("heading", { name: "Extended device details" })).toBeInTheDocument();
    expect(screen.getByText("neighbor-test")).toBeInTheDocument();
  });

  it("edits a member name and requested device category", () => {
    const save = vi.fn();
    render(<MembersView devices={[device]} onSave={save}/>);
    fireEvent.click(screen.getByRole("button", { name: "Edit device" }));
    fireEvent.change(screen.getByLabelText("Device name"), { target: { value: "Living Room TV" } });
    fireEvent.change(screen.getByLabelText("Device type"), { target: { value: "tv" } });
    fireEvent.click(screen.getByRole("button", { name: "Save device" }));
    expect(save).toHaveBeenCalledWith("neighbor-test", "Living Room TV", "trusted", "tv");
  });

  it("requires explicit confirmation before quarantine", async () => {
    const finding: ThreatFinding = { id: "clam-test", engine: "ClamAV", classification: "Test detection", confidence: "Engine detection", location: "sample.bin", sha256: "abc", detectedAt: new Date().toISOString(), severity: "high", availableActions: ["Quarantine"] };
    const action = vi.fn().mockResolvedValue(undefined);
    render(<ThreatsView findings={[finding]} onRefresh={vi.fn()} onAction={action}/>);
    fireEvent.click(screen.getByRole("button", { name: "Quarantine" }));
    fireEvent.click(screen.getByRole("button", { name: "Move to quarantine" }));
    expect(action).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: /understand the impact/i }));
    fireEvent.click(screen.getByRole("button", { name: "Move to quarantine" }));
    expect(action).toHaveBeenCalledWith(finding, "quarantine");
  });
});
