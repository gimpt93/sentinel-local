import { CheckCircle2, ChevronUp } from "lucide-react";
import type { ToolStatus } from "../types";

export function ProtectionDrawer({ tools, onOpen }: { tools: ToolStatus[]; onOpen: (id: string) => void }) {
  return <section className="protection-drawer"><h2>Protection details <ChevronUp size={16}/></h2><div className="protection-list">{tools.map(tool => <button key={tool.id} onClick={() => onOpen(tool.id)}><span className="tool-icon"><CheckCircle2 size={21}/></span><span><strong>{tool.name}</strong><small>{tool.capability}</small><small>{tool.installed ? tool.state : "Detect and guide"}</small></span><em className={tool.installed ? "good-text" : "muted-text"}>{tool.installed ? "Detected" : "Optional"}</em></button>)}</div></section>;
}
