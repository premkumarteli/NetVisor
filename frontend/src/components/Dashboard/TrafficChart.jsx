import { useRef, useMemo, useCallback } from 'react';
import EmptyState from '../V2/EmptyState';
import { useImmersion } from '../../immersion/engine/useImmersion';

const VIEWBOX_W = 680;
const VIEWBOX_H = 160;
const PAD = { top: 16, right: 12, bottom: 8, left: 8 };

function catmullRomSpline(pts) {
  if (pts.length < 2) return '';
  let d = `M ${pts[0][0]} ${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i > 0 ? i - 1 : i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i < pts.length - 2 ? i + 2 : i + 1];
    const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
    const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
    const cp2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C ${cp1x.toFixed(2)} ${cp1y.toFixed(2)}, ${cp2x.toFixed(2)} ${cp2y.toFixed(2)}, ${p2[0].toFixed(2)} ${p2[1].toFixed(2)}`;
  }
  return d;
}

const TrafficChart = ({ data, resolution = 'hour', height = 260 }) => {
  const { palette } = useImmersion();
  const svgRef = useRef(null);
  const tooltipRef = useRef(null);

  const accent = palette?.accent || '#f97316';   // fall back to orange matching dashboard theme
  const surface = palette?.surface || '#1a1f2e';
  const grid = palette?.grid || '#2a3147';
  const textMuted = palette?.textMuted || '#6b7280';

  // Format helper for bytes and rates
  const formatBytes = useCallback((bytes, isRate = false) => {
    const absBytes = Math.abs(bytes);
    let formatted = '0 B';
    if (absBytes >= 1024 * 1024 * 1024) {
      formatted = `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    } else if (absBytes >= 1024 * 1024) {
      formatted = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else if (absBytes >= 1024) {
      formatted = `${(bytes / 1024).toFixed(1)} KB`;
    } else {
      formatted = `${Math.round(bytes)} B`;
    }
    return isRate && resolution === 'second' ? `${formatted}/s` : formatted;
  }, [resolution]);

  // Memoize values processing to comply with hooks dependency rules
  const { formattedLabels, chartValues, n } = useMemo(() => {
    const labels = Array.isArray(data?.labels) ? data.labels : [];
    const rawValues = Array.isArray(data?.values) ? data.values : [];
    const values = rawValues.map((v) => {
      const num = Number(v);
      return Number.isFinite(num) ? num : 0;
    });

    let cleanLabels = labels.map((lbl) => {
      if (!lbl) return '';
      let cleanLbl = lbl;
      if (typeof lbl === 'string' && !lbl.includes('T') && !lbl.includes('Z')) {
        cleanLbl = lbl.replace(' ', 'T') + 'Z';
      }
      const d = new Date(cleanLbl);
      if (Number.isNaN(d.getTime())) return lbl;
      
      if (resolution === 'second') {
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        const ss = String(d.getSeconds()).padStart(2, '0');
        return `${hh}:${mm}:${ss}`;
      } else {
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
      }
    });

    let visibleLabels = cleanLabels.slice(0, values.length);
    let chartValues = [...values];

    if (chartValues.length === 1 && visibleLabels.length > 0) {
      const cur = visibleLabels[0];
      let prior = 'Start';
      const parts = cur.split(':');
      if (parts.length >= 2) {
        const hh = (parseInt(parts[0], 10) - 1 + 24) % 24;
        prior = `${String(hh).padStart(2, '0')}:${parts[1]}`;
      }
      visibleLabels = [prior, cur];
      chartValues = [0, chartValues[0]];
    }

    return { formattedLabels: visibleLabels, chartValues, n: chartValues.length };
  }, [data, resolution]);

  // Hook definitions placed top-level before early returns
  const handleMouseMove = useCallback((e) => {
    if (!svgRef.current || !tooltipRef.current || n === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = VIEWBOX_W / rect.width;
    const mx = (e.clientX - rect.left) * scaleX;
    const idx = Math.round(((mx - PAD.left) / (VIEWBOX_W - PAD.left - PAD.right)) * (n - 1));
    const clamped = Math.max(0, Math.min(n - 1, idx));
    const tipEl = tooltipRef.current;
    const tipX = e.clientX - rect.left;
    tipEl.style.left = `${tipX > rect.width * 0.7 ? tipX - 130 : tipX + 12}px`;
    tipEl.style.top = `${e.clientY - rect.top - 48}px`;
    tipEl.style.display = 'block';
    
    const timeLabel = formattedLabels[clamped];
    const valueLabel = formatBytes(chartValues[clamped], true);
    
    tipEl.innerHTML = `<span style="color:${textMuted};font-size:11px">${timeLabel}</span><br/><strong style="font-size:14px">${valueLabel}</strong>`;
  }, [n, chartValues, formattedLabels, textMuted, formatBytes]);

  const handleMouseLeave = useCallback(() => {
    if (tooltipRef.current) tooltipRef.current.style.display = 'none';
  }, []);

  if (n === 0) {
    return (
      <div style={{ height }}>
        <EmptyState
          icon="ri-line-chart-line"
          title="No traffic data yet"
          description="The chart will populate once the live flow window has enough samples."
        />
      </div>
    );
  }

  const rawMin = Math.min(...chartValues);
  const rawMax = Math.max(...chartValues);
  const vPad = (rawMax - rawMin) * 0.18 || 5;
  const vMin = Math.max(0, rawMin - vPad);
  const vMax = rawMax + vPad;

  const toX = (i) => PAD.left + (i / (n - 1)) * (VIEWBOX_W - PAD.left - PAD.right);
  const toY = (v) => PAD.top + (1 - (v - vMin) / (vMax - vMin)) * (VIEWBOX_H - PAD.top - PAD.bottom);

  const pts = chartValues.map((v, i) => [toX(i), toY(v)]);
  const linePath = catmullRomSpline(pts);
  const bottom = VIEWBOX_H - PAD.bottom;
  const fillPath = `${linePath} L ${pts[pts.length - 1][0].toFixed(2)} ${bottom} L ${pts[0][0].toFixed(2)} ${bottom} Z`;

  // Y-axis grid ticks
  const gridTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
    y: PAD.top + (1 - f) * (VIEWBOX_H - PAD.top - PAD.bottom),
    label: formatBytes(vMin + f * (vMax - vMin), true),
  }));

  // X-axis labels: show 5 evenly spaced
  const xAxisIdxs = n <= 5
    ? chartValues.map((_, i) => i)
    : [0, Math.floor(n * 0.25), Math.floor(n * 0.5), Math.floor(n * 0.75), n - 1];

  // Node markers: sparse → show all; dense → every ~8 plus last
  const isSparse = n <= 6;
  const nodeStep = Math.max(1, Math.floor(n / 8));
  const nodePts = pts.filter((_, i) => isSparse || i % nodeStep === 0 || i === n - 1);

  // Hex/RGB/RGBA to rgba helper
  function hexAlpha(colorStr, a) {
    if (!colorStr) return `rgba(249,115,22,${a})`;
    const trimmed = colorStr.trim();

    const rgbMatch = trimmed.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$/i);
    if (rgbMatch) {
      const r = rgbMatch[1];
      const g = rgbMatch[2];
      const b = rgbMatch[3];
      return `rgba(${r}, ${g}, ${b}, ${a})`;
    }

    if (trimmed.startsWith('#')) {
      const h = trimmed.replace('#', '');
      const norm = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
      const v = parseInt(norm, 16);
      if (isFinite(v)) {
        return `rgba(${(v >> 16) & 255}, ${(v >> 8) & 255}, ${v & 255}, ${a})`;
      }
    }

    return trimmed;
  }

  const gradId = `tg-${accent.replace('#', '')}`;

  return (
    <div style={{ position: 'relative', height }}>
      {/* SVG chart */}
      <div style={{ position: 'relative' }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
          width="100%"
          height={height - 24}
          preserveAspectRatio="none"
          style={{ display: 'block', overflow: 'visible', cursor: 'crosshair' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={accent} stopOpacity="0.22" />
              <stop offset="100%" stopColor={accent} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {gridTicks.map(({ y, label }) => (
            <g key={y}>
              <line x1={PAD.left} x2={VIEWBOX_W - PAD.right} y1={y} y2={y}
                stroke={grid} strokeWidth="0.5" strokeDasharray="3,4" />
              <text x={PAD.left} y={y - 3} fontSize="10" fill={textMuted}
                style={{ fontFamily: 'monospace' }}>{label}</text>
            </g>
          ))}

          {/* Fill */}
          <path d={fillPath} fill={`url(#${gradId})`} />

          {/* Line */}
          <path d={linePath} fill="none" stroke={accent} strokeWidth="2"
            strokeLinecap="round" strokeLinejoin="round" />

          {/* Nodes */}
          {nodePts.map(([x, y], i) => {
            const isLast = !isSparse && i === nodePts.length - 1;
            return (
              <g key={i}>
                {isLast && (
                  <circle cx={x} cy={y} r="9" fill={hexAlpha(accent, 0.12)} />
                )}
                <circle cx={x} cy={y} r={isLast ? 5 : 3}
                  fill={surface} stroke={accent}
                  strokeWidth={isLast ? 2 : 1.5} />
                {isLast && (
                  <circle cx={x} cy={y} r="2.5" fill={accent} />
                )}
              </g>
            );
          })}
        </svg>

        {/* X-axis labels */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, padding: `0 ${PAD.right}px` }}>
          {xAxisIdxs.map((idx) => (
            <span key={idx} style={{ fontSize: 11, color: textMuted, fontFamily: 'monospace' }}>
              {formattedLabels[idx]}
            </span>
          ))}
        </div>

        {/* Tooltip */}
        <div
          ref={tooltipRef}
          style={{
            position: 'absolute',
            display: 'none',
            background: surface,
            border: `1px solid ${hexAlpha(accent, 0.4)}`,
            borderRadius: 6,
            padding: '6px 10px',
            pointerEvents: 'none',
            zIndex: 20,
            minWidth: 110,
          }}
        />
      </div>
    </div>
  );
};

export default TrafficChart;