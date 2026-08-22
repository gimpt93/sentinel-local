import { CircleHelp, Laptop, Monitor, Router, Smartphone } from "lucide-react";
import type { DeviceProfile } from "../types";

export function DeviceIcon({ type, size = 28 }: { type: DeviceProfile["type"]; size?: number }) {
  const Icon = type === "router" ? Router : type === "phone" ? Smartphone : type === "laptop" ? Laptop : type === "unknown" ? CircleHelp : Monitor;
  return <Icon size={size} aria-hidden="true" />;
}
