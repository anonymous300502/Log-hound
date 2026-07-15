import { useEffect, useRef, useState } from "react";
import Toolbar from "./components/Toolbar";
import SearchPanel from "./components/SearchPanel";
import GraphView from "./components/GraphView";
import ProcessTreeView from "./components/ProcessTreeView";
import AttackPathView from "./components/AttackPathView";
import DetailPanel from "./components/DetailPanel";
import TimeScrubber from "./components/TimeScrubber";
import ViewTabs from "./components/ViewTabs";
import { useAppStore } from "./store/useAppStore";

export default function App() {
  const [layoutName, setLayoutName] = useState("cose");
  const [fitSignal, setFitSignal] = useState(0);
  const viewMode = useAppStore((s) => s.viewMode);
  const loadOverview = useAppStore((s) => s.loadOverview);

  // Populate the canvas with a top-risk overview on first load so the app opens
  // onto something meaningful instead of a blank graph.
  const bootstrapped = useRef(false);
  useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;
    void loadOverview();
  }, [loadOverview]);

  return (
    <div className="app">
      <Toolbar
        layoutName={layoutName}
        onLayout={setLayoutName}
        onFit={() => setFitSignal((n) => n + 1)}
      />
      <div className="main">
        <SearchPanel />
        <div className="center">
          <ViewTabs />
          <div className="center-view">
            {/* Keep the Cytoscape graph mounted (preserves layout); overlay the
                React Flow views when active. */}
            <div style={{ display: viewMode === "graph" ? "block" : "none", height: "100%" }}>
              <GraphView layoutName={layoutName} fitSignal={fitSignal} />
            </div>
            {viewMode === "tree" && <ProcessTreeView />}
            {viewMode === "attack" && <AttackPathView />}
          </div>
        </div>
        <DetailPanel />
      </div>
      <TimeScrubber />
    </div>
  );
}
