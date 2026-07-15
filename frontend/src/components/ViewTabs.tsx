// Tab bar switching the center pane between the investigation views (M8).

import { useAppStore, type ViewMode } from "../store/useAppStore";

const TABS: { mode: ViewMode; label: string }[] = [
  { mode: "graph", label: "Graph" },
  { mode: "tree", label: "Process Tree" },
  { mode: "attack", label: "Attack Path" },
];

export default function ViewTabs() {
  const viewMode = useAppStore((s) => s.viewMode);
  const setViewMode = useAppStore((s) => s.setViewMode);
  const attackCount = useAppStore((s) => s.attackPaths?.length ?? 0);

  return (
    <div className="view-tabs">
      {TABS.map((t) => (
        <button
          key={t.mode}
          className={`view-tab ${viewMode === t.mode ? "active" : ""}`}
          onClick={() => setViewMode(t.mode)}
        >
          {t.label}
          {t.mode === "attack" && attackCount > 0 && (
            <span className="tab-badge">{attackCount}</span>
          )}
        </button>
      ))}
    </div>
  );
}
