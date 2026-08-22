import { Cast, CircleHelp, Laptop, Monitor, Router, Smartphone, Tv } from "lucide-react";
import type { DeviceProfile } from "../types";

export function DeviceIcon({ type, size = 28 }: { type: DeviceProfile["type"]; size?: number }) {
  const Icon = type === "router" ? Router : type === "cellphone" ? Smartphone : type === "laptop" ? Laptop : type === "tv" ? Tv : type === "streaming" ? Cast : type === "unknown" ? CircleHelp : Monitor;
  return <Icon size={size} aria-hidden="true" />;
}
