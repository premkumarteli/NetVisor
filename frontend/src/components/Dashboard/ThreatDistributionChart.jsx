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

  if (labels.length === 0) {
    return (
      <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
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

  const severityColors = {
    LOW: palette.success,
    MEDIUM: palette.warning,
    HIGH: '#ff8a00',
    CRITICAL: palette.danger || '#ff1744',
  };

  const colors = labels.map((label) => severityColors[String(label).toUpperCase()] || palette.accent);

  const data = {
    labels: labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors.map((color) => withAlpha(color, 0.34)),
        borderColor: colors,
        borderWidth: 1.5,
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '62%',
    layout: {
      padding: 8,
    },
    plugins: {
      legend: {
        position: legendPosition,
        labels: {
          color: palette.textMuted,
          font: { size: 10, weight: 'bold' },
          usePointStyle: true,
          padding: 12,
        },
      },
      tooltip: {
        backgroundColor: palette.surface,
        titleColor: palette.text,
        bodyColor: palette.textMuted,
        borderColor: palette.grid,
        borderWidth: 1,
        padding: 10,
        displayColors: true,
      }
    }
  };

  return (
    <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
      <div className="nv-chart-shell__canvas">
        <Doughnut data={data} options={options} />
      </div>
    </div>
  );
};

export default ThreatDistributionChart;
