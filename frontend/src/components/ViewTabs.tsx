// Tab bar switching the center pane between the investigation views (M8).

import { useAppStore, type ViewMode } from "../store/useAppStore";
import { AttackPathIcon, GraphIcon, TreeIcon } from "./Icons";

const TABS: { mode: ViewMode; label: string; icon: typeof GraphIcon }[] = [
  { mode: "graph", label: "Graph Canvas", icon: GraphIcon },
  { mode: "tree", label: "Process Tree", icon: TreeIcon },
  { mode: "attack", label: "Attack Path", icon: AttackPathIcon },
];

export default function ViewTabs() {
  const viewMode = useAppStore((s) => s.viewMode);
  const setViewMode = useAppStore((s) => s.setViewMode);
  const attackCount = useAppStore((s) => s.attackPaths?.length ?? 0);

  return (
    <div className="view-tabs">
      {TABS.map((t) => {
        const Icon = t.icon;
        return (
          <button
            key={t.mode}
            className={`view-tab ${viewMode === t.mode ? "active" : ""}`}
            onClick={() => setViewMode(t.mode)}
          >
            <Icon className="tab-icon" />
            <span className="tab-label">{t.label}</span>
            {t.mode === "attack" && attackCount > 0 && (
              <span className="tab-badge">{attackCount}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
