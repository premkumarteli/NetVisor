import { useRef, useMemo, useCallback, useState } from 'react';
import EmptyState from '../V2/EmptyState';
import { useImmersion } from '../../immersion/engine/useImmersion';

const VIEWBOX_W = 680;
const VIEWBOX_H = 160;
const PAD = { top: 18, right: 16, bottom: 10, left: 10 };

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
  const [hoveredPoint, setHoveredPoint] = useState(null);

  const accent = palette?.accent || '#54c8e8';
  const surface = palette?.surface || '#0c1524';
  const grid = palette?.grid || 'rgba(255, 255, 255, 0.08)';
  const textMuted = palette?.textMuted || '#94a3b8';

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

  const stats = useMemo(() => {
    if (!chartValues.length) return { peak: 0, avg: 0, current: 0 };
    const peak = Math.max(...chartValues);
    const avg = chartValues.reduce((a, b) => a + b, 0) / chartValues.length;
    const current = chartValues[chartValues.length - 1] || 0;
    return { peak, avg, current };
  }, [chartValues]);

  const rawMin = Math.min(...(chartValues.length ? chartValues : [0]));
  const rawMax = Math.max(...(chartValues.length ? chartValues : [0]));
  const vPad = (rawMax - rawMin) * 0.18 || 5;
  const vMin = Math.max(0, rawMin - vPad);
  const vMax = rawMax + vPad;

  const toX = useCallback((i) => PAD.left + (i / Math.max(1, n - 1)) * (VIEWBOX_W - PAD.left - PAD.right), [n]);
  const toY = useCallback((v) => PAD.top + (1 - (v - vMin) / Math.max(1, vMax - vMin)) * (VIEWBOX_H - PAD.top - PAD.bottom), [vMin, vMax]);

  const handleMouseMove = useCallback((e) => {
    if (!svgRef.current || !tooltipRef.current || n === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = VIEWBOX_W / rect.width;
    const mx = (e.clientX - rect.left) * scaleX;
    const idx = Math.round(((mx - PAD.left) / (VIEWBOX_W - PAD.left - PAD.right)) * (n - 1));
    const clamped = Math.max(0, Math.min(n - 1, idx));

    const cx = toX(clamped);
    const cy = toY(chartValues[clamped]);
    setHoveredPoint({ x: cx, y: cy, index: clamped });

    const tipEl = tooltipRef.current;
    const tipX = e.clientX - rect.left;
    tipEl.style.left = `${tipX > rect.width * 0.7 ? tipX - 140 : tipX + 14}px`;
    tipEl.style.top = `${e.clientY - rect.top - 52}px`;
    tipEl.style.display = 'block';
    
    const timeLabel = formattedLabels[clamped] || 'Active Point';
    const valueLabel = formatBytes(chartValues[clamped], true);
    
    tipEl.innerHTML = `<div style="color:${textMuted};font-size:11px;font-family:monospace">${timeLabel}</div><div style="font-size:14px;font-weight:700;color:#fff;margin-top:2px">${valueLabel}</div>`;
  }, [n, chartValues, formattedLabels, textMuted, formatBytes, toX, toY]);

  const handleMouseLeave = useCallback(() => {
    setHoveredPoint(null);
    if (tooltipRef.current) tooltipRef.current.style.display = 'none';
  }, []);

  if (n === 0) {
    return (
      <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <EmptyState
          icon="ri-line-chart-line"
          title="No traffic samples yet"
          description="The live throughput chart will plot bandwidth data as packets flow through the gateway."
        />
      </div>
    );
  }

  const pts = chartValues.map((v, i) => [toX(i), toY(v)]);
  const linePath = catmullRomSpline(pts);
  const bottom = VIEWBOX_H - PAD.bottom;
  const fillPath = `${linePath} L ${pts[pts.length - 1][0].toFixed(2)} ${bottom} L ${pts[0][0].toFixed(2)} ${bottom} Z`;

  const gridTicks = [0, 0.33, 0.66, 1].map((f) => ({
    y: PAD.top + (1 - f) * (VIEWBOX_H - PAD.top - PAD.bottom),
    label: formatBytes(vMin + f * (vMax - vMin), true),
  }));

  const xAxisIdxs = n <= 5
    ? chartValues.map((_, i) => i)
    : [0, Math.floor(n * 0.25), Math.floor(n * 0.5), Math.floor(n * 0.75), n - 1];

  const isSparse = n <= 6;
  const nodeStep = Math.max(1, Math.floor(n / 8));
  const nodePts = pts.filter((_, i) => isSparse || i % nodeStep === 0 || i === n - 1);

  function hexAlpha(colorStr, a) {
    if (!colorStr) return `rgba(84,200,232,${a})`;
    const trimmed = colorStr.trim();
    const rgbMatch = trimmed.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$/i);
    if (rgbMatch) {
      return `rgba(${rgbMatch[1]}, ${rgbMatch[2]}, ${rgbMatch[3]}, ${a})`;
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

  const gradId = `tg-${accent.replace(/[^a-zA-Z0-9]/g, '')}`;

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      {/* Live Graph Metrics Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'flex-end',
        gap: '1.25rem',
        padding: '0 0.5rem 0.6rem 0.5rem',
        fontSize: '0.76rem',
        color: textMuted,
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        marginBottom: '0.5rem',
      }}>
        <div>
          <span>Peak: </span>
          <strong style={{ color: '#fff', fontFamily: 'monospace' }}>{formatBytes(stats.peak, true)}</strong>
        </div>
        <div>
          <span>Average: </span>
          <strong style={{ color: '#fff', fontFamily: 'monospace' }}>{formatBytes(stats.avg, true)}</strong>
        </div>
        <div>
          <span>Current: </span>
          <strong style={{ color: accent, fontFamily: 'monospace' }}>{formatBytes(stats.current, true)}</strong>
        </div>
      </div>

      {/* SVG Chart */}
      <div style={{ position: 'relative' }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
          width="100%"
          height={height - 50}
          preserveAspectRatio="none"
          style={{ display: 'block', overflow: 'visible', cursor: 'crosshair' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={accent} stopOpacity="0.28" />
              <stop offset="60%" stopColor={accent} stopOpacity="0.08" />
              <stop offset="100%" stopColor={accent} stopOpacity="0" />
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Grid lines */}
          {gridTicks.map(({ y, label }) => (
            <g key={y}>
              <line x1={PAD.left} x2={VIEWBOX_W - PAD.right} y1={y} y2={y}
                stroke={grid} strokeWidth="0.75" strokeDasharray="4,5" />
              <text x={PAD.left} y={y - 4} fontSize="9" fill={textMuted}
                style={{ fontFamily: 'monospace' }}>{label}</text>
            </g>
          ))}

          {/* Area Fill */}
          <path d={fillPath} fill={`url(#${gradId})`} />

          {/* Line Stroke */}
          <path d={linePath} fill="none" stroke={accent} strokeWidth="2.2"
            strokeLinecap="round" strokeLinejoin="round" />

          {/* Node Markers */}
          {nodePts.map(([x, y], i) => {
            const isLast = !isSparse && i === nodePts.length - 1;
            return (
              <g key={i}>
                {isLast && (
                  <circle cx={x} cy={y} r="9" fill={hexAlpha(accent, 0.16)} />
                )}
                <circle cx={x} cy={y} r={isLast ? 4.5 : 2.5}
                  fill={surface} stroke={accent}
                  strokeWidth={isLast ? 2 : 1.5} />
                {isLast && (
                  <circle cx={x} cy={y} r="2" fill={accent} />
                )}
              </g>
            );
          })}

          {/* Interactive Scrub Line */}
          {hoveredPoint && (
            <g pointerEvents="none">
              <line
                x1={hoveredPoint.x}
                x2={hoveredPoint.x}
                y1={PAD.top}
                y2={VIEWBOX_H - PAD.bottom}
                stroke={accent}
                strokeWidth="1.2"
                strokeDasharray="2,2"
                opacity="0.85"
              />
              <circle
                cx={hoveredPoint.x}
                cy={hoveredPoint.y}
                r="6"
                fill={accent}
                filter="url(#glow)"
              />
              <circle
                cx={hoveredPoint.x}
                cy={hoveredPoint.y}
                r="3"
                fill="#ffffff"
              />
            </g>
          )}
        </svg>

        {/* X-axis labels */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, padding: `0 ${PAD.right}px` }}>
          {xAxisIdxs.map((idx) => (
            <span key={idx} style={{ fontSize: 10, color: textMuted, fontFamily: 'monospace' }}>
              {formattedLabels[idx]}
            </span>
          ))}
        </div>

        {/* Floating Tooltip */}
        <div
          ref={tooltipRef}
          style={{
            position: 'absolute',
            display: 'none',
            background: surface,
            border: `1px solid ${hexAlpha(accent, 0.4)}`,
            borderRadius: 8,
            padding: '7px 11px',
            pointerEvents: 'none',
            zIndex: 20,
            boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
            backdropFilter: 'blur(10px)',
          }}
        />
      </div>
    </div>
  );
};

export default TrafficChart;