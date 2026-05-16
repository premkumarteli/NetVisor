import { Bar, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import EmptyState from '../V2/EmptyState';
import { useImmersion } from '../../immersion/engine/useImmersion';

ChartJS.register(
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const withFallbackAlpha = (color, alpha) => {
  if (!color) return `rgba(6, 182, 212, ${alpha})`;
  if (color.startsWith('#')) {
    const hex = color.slice(1);
    const normalized = hex.length === 3 ? hex.split('').map((char) => char + char).join('') : hex;
    const value = Number.parseInt(normalized, 16);
    if (!Number.isFinite(value)) return color;
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

const TrafficChart = ({ data, height = 240 }) => {
  const { palette } = useImmersion();
  const labels = Array.isArray(data?.labels) ? data.labels : [];
  const rawValues = Array.isArray(data?.values) ? data.values : [];
  const values = rawValues.map((value) => {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : 0;
  });

  if (labels.length === 0 || values.length === 0) {
    return (
      <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
        <div className="nv-chart-shell__empty">
          <EmptyState
            icon="ri-line-chart-line"
            title="No traffic data yet"
            description="The chart will populate once the live flow window has enough samples."
          />
        </div>
      </div>
    );
  }

  const visibleLabels = labels.slice(0, values.length);
  const nonZeroCount = values.filter((value) => value > 0).length;
  const useSparseBars = values.length < 4 || nonZeroCount < 3;

  const chartData = {
    labels: visibleLabels,
    datasets: [
      {
        label: 'Traffic (MB)',
        data: values,
        maxBarThickness: 32,
        borderColor: palette.accent,
        backgroundColor: (context) => {
          const ctx = context.chart.ctx;
          const gradient = ctx.createLinearGradient(0, 0, 0, 400);
          gradient.addColorStop(0, palette.accentGlow || 'rgba(6, 182, 212, 0.5)');
          gradient.addColorStop(1, useSparseBars ? withFallbackAlpha(palette.accent, 0.14) : 'rgba(0, 0, 0, 0)');
          return gradient;
        },
        fill: !useSparseBars,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: useSparseBars ? 0 : (values.length <= 8 ? 3 : 2),
        pointHoverRadius: 4,
        pointBackgroundColor: palette.accent,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    interaction: {
      intersect: false,
      mode: 'index',
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: palette.grid },
        ticks: { color: palette.textMuted, maxTicksLimit: 5 },
      },
      x: {
        grid: { display: false },
        ticks: { color: palette.textMuted, maxTicksLimit: 8 },
      },
    },
  };

  return (
    <div className="nv-chart-shell" style={{ '--nv-chart-height': `${height}px` }}>
      <div className="nv-chart-shell__canvas">
        {useSparseBars ? <Bar data={chartData} options={options} /> : <Line data={chartData} options={options} />}
      </div>
    </div>
  );
};

export default TrafficChart;
