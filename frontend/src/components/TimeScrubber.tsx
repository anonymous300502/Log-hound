// Bottom rail: the time-rewind scrubber (PLAN.md §11, the headline feature).
// It spans the temporal extent of the loaded graph, draws an event histogram for
// context, and exposes two handles [from, to]. Moving them re-queries the graph
// with the window applied, so the canvas shows the environment as it was then.

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { useDebounce } from "../lib/useDebounce";
import { fmtTime } from "../lib/format";

export default function TimeScrubber() {
  const nodes = useAppStore((s) => s.nodes);
  const window = useAppStore((s) => s.window);
  const setWindow = useAppStore((s) => s.setWindow);
  const dataRange = useAppStore((s) => s.dataRange);
  const setDataRange = useAppStore((s) => s.setDataRange);

  // Establish baseline data range. Once computed from full graph, keep it stable
  // so that applying a temporal window filter doesn't collapse the track slider.
  useEffect(() => {
    let lo = Number.POSITIVE_INFINITY;
    let hi = Number.NEGATIVE_INFINITY;
    for (const n of Object.values(nodes)) {
      if (n.first_seen < lo) lo = n.first_seen;
      if (n.last_seen > hi) hi = n.last_seen;
    }
    if (!Number.isFinite(lo) || !Number.isFinite(hi) || hi <= lo) return;
    const pad = Math.max(1000, Math.round((hi - lo) * 0.01));
    const calculated = { from: lo - pad, to: hi + pad };

    if (!dataRange) {
      setDataRange(calculated);
    } else if (window === null) {
      if (calculated.from < dataRange.from || calculated.to > dataRange.to) {
        setDataRange({
          from: Math.min(dataRange.from, calculated.from),
          to: Math.max(dataRange.to, calculated.to),
        });
      }
    }
  }, [nodes, dataRange, window, setDataRange]);

  const range = dataRange;

  // Local handle positions (committed to the store after debounce).
  const [from, setFrom] = useState<number | null>(null);
  const [to, setTo] = useState<number | null>(null);

  // Initialize handles when range appears or when reset to all time
  useEffect(() => {
    if (!range) {
      setFrom(null);
      setTo(null);
      return;
    }
    if (window === null) {
      setFrom(range.from);
      setTo(range.to);
    }
  }, [range, window]);

  const debFrom = useDebounce(from, 200);
  const debTo = useDebounce(to, 200);

  // Commit the window (unless the handles span the whole range → all time).
  useEffect(() => {
    if (!range || debFrom == null || debTo == null) return;
    const isAll = debFrom <= range.from && debTo >= range.to;
    if (isAll) {
      if (window !== null) void setWindow(null);
      return;
    }
    if (!window || Math.abs(window.from - debFrom) > 50 || Math.abs(window.to - debTo) > 50) {
      void setWindow({ from: debFrom, to: debTo });
    }
  }, [debFrom, debTo, range, window, setWindow]);

  const bucket = range ? Math.max(1000, Math.floor((range.to - range.from) / 60)) : 1000;
  const histogram = useQuery({
    queryKey: ["timeline", range?.from, range?.to, bucket],
    queryFn: () => api.timeline({ window: range!, bucket }),
    enabled: !!range,
  });

  if (!range) {
    return (
      <footer className="scrubber empty muted small">
        Time-rewind — pivot to an entity to enable temporal filtering.
      </footer>
    );
  }

  const span = range.to - range.from;
  const pct = (t: number) => ((t - range.from) / span) * 100;
  const maxCount = Math.max(1, ...(histogram.data?.map((b) => b.count) ?? [1]));

  const setPreset = (fraction: "first" | "second" | "all") => {
    if (!range) return;
    if (fraction === "all") {
      setFrom(range.from);
      setTo(range.to);
      void setWindow(null);
    } else if (fraction === "first") {
      const mid = range.from + Math.floor((range.to - range.from) / 2);
      setFrom(range.from);
      setTo(mid);
    } else if (fraction === "second") {
      const mid = range.from + Math.floor((range.to - range.from) / 2);
      setFrom(mid);
      setTo(range.to);
    }
  };

  return (
    <footer className="scrubber">
      <div className="scrubber-head">
        <span className="field-label">Time rewind</span>
        <span className="scrubber-window muted small">
          {from != null && to != null ? `${fmtTime(from)} → ${fmtTime(to)}` : "—"}
        </span>
        <div className="scrubber-presets">
          <button className="btn tiny" onClick={() => setPreset("first")}>
            1st Half
          </button>
          <button className="btn tiny" onClick={() => setPreset("second")}>
            2nd Half
          </button>
          <button className="btn tiny" onClick={() => setPreset("all")} disabled={!window}>
            All time
          </button>
        </div>
      </div>

      <div className="track-wrap">
        {/* Histogram of event counts across the span. */}
        <div className="histogram">
          {histogram.data?.map((b) => (
            <div
              key={b.bucket}
              className="hist-bar"
              style={{
                left: `${pct(b.bucket)}%`,
                width: `${100 / 62}%`,
                height: `${(b.count / maxCount) * 100}%`,
              }}
              title={`${fmtTime(b.bucket)} · ${b.count} events`}
            />
          ))}
        </div>

        {/* Selected band. */}
        {from != null && to != null && (
          <div
            className="sel-band"
            style={{ left: `${pct(from)}%`, width: `${pct(to) - pct(from)}%` }}
          />
        )}

        {/* Dual range handles (overlaid). */}
        <input
          type="range"
          className="range from"
          min={range.from}
          max={range.to}
          step={Math.max(1, Math.floor(span / 500))}
          value={from ?? range.from}
          onChange={(e) => {
            const v = Math.min(Number(e.target.value), (to ?? range.to) - 1);
            setFrom(v);
          }}
        />
        <input
          type="range"
          className="range to"
          min={range.from}
          max={range.to}
          step={Math.max(1, Math.floor(span / 500))}
          value={to ?? range.to}
          onChange={(e) => {
            const v = Math.max(Number(e.target.value), (from ?? range.from) + 1);
            setTo(v);
          }}
        />
      </div>
    </footer>
  );
}
