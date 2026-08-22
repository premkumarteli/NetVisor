import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import EmptyState from '../V2/EmptyState';
import { useImmersion } from '../../immersion/engine/useImmersion';

ChartJS.register(ArcElement, Tooltip, Legend);

const withAlpha = (color, alpha) => {
  if (!color) return `rgba(148, 163, 184, ${alpha})`;
  if (color.startsWith('#')) {
    const hex = color.slice(1);
    const normalized = hex.length === 3 ? hex.split('').map((char) => char + char).join('') : hex;
    const value = Number.parseInt(normalized, 16);
    const red = (value >> 16) & 255;
    const green = (value >> 8) & 255;
    const blue = value & 255;
    return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
  }
  const rgbMatch = color.match(/rgba?\(([^)]+)\)/);
  if (rgbMatch) {
    const channels = rgbMatch[1].split(',').slice(0, 3).join(',');
    return `rgba(${channels}, ${alpha})`;
  }
  return color;
};

const ThreatDistributionChart = ({ distribution = {}, height = 180, legendPosition = 'right' }) => {
  const { palette } = useImmersion();
  const entries = Object.entries(distribution || {})
    .map(([label, value]) => [label, Number(value)])
    .filter(([, value]) => Number.isFinite(value) && value > 0);
  const labels = entries.map(([label]) => label);
  const values = entries.map(([, value]) => value);
  const total = values.reduce((sum, v) => sum + v, 0);

  if (labels.length === 0) {
    return (
      <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="nv-chart-shell__empty">
          <EmptyState
            icon="ri-pie-chart-line"
            title="No threat data available"
            description="The distribution chart will populate once the threat queue has classified events."
          />
        </div>
      </div>
    );
  }

  const surface = palette?.surface || '#0c1524';
  const text = palette?.text || '#ffffff';
  const textMuted = palette?.textMuted || '#94a3b8';
  const grid = palette?.grid || 'rgba(255,255,255,0.08)';

  const severityColors = {
    LOW: palette?.success || '#00ff9d',
    MEDIUM: palette?.warning || '#ffbf00',
    HIGH: '#ff8a00',
    CRITICAL: palette?.danger || '#ff2a2a',
  };

  const colors = labels.map((label) => severityColors[String(label).toUpperCase()] || palette?.accent || '#54c8e8');

  const data = {
    labels: labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors.map((color) => withAlpha(color, 0.35)),
        borderColor: colors,
        borderWidth: 1.5,
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '68%',
    layout: {
      padding: 6,
    },
    plugins: {
      legend: {
        position: legendPosition,
        labels: {
          color: textMuted,
          font: { size: 11, weight: '600' },
          usePointStyle: true,
          padding: 10,
        },
      },
      tooltip: {
        backgroundColor: surface,
        titleColor: text,
        bodyColor: textMuted,
        borderColor: grid,
        borderWidth: 1,
        padding: 10,
        displayColors: true,
        callbacks: {
          label: (context) => {
            const val = context.raw || 0;
            const pct = total > 0 ? Math.round((val / total) * 100) : 0;
            return ` ${context.label}: ${val} (${pct}%)`;
          },
        },
      },
    },
  };

  return (
    <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px`, position: 'relative', width: '100%' }}>
      <div className="nv-chart-shell__canvas" style={{ position: 'relative', height: `${height}px` }}>
        <Doughnut data={data} options={options} />
      </div>
    </div>
  );
};

export default ThreatDistributionChart;
