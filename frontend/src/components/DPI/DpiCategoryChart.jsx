import { useMemo } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { useImmersion } from '../../immersion/engine/useImmersion';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const DpiCategoryChart = ({ events = [], height = 200 }) => {
  const { palette } = useImmersion();

  const categoryData = useMemo(() => {
    const counts = {
      'Media & Video': 0,
      'Search Engines': 0,
      'Cloud & APIs': 0,
      'Social & Chat': 0,
      'Other Web': 0,
    };

    events.forEach((ev) => {
      const url = String(ev.page_url || ev.domain || ev.base_domain || '').toLowerCase();
      const cat = String(ev.content_category || '').toLowerCase();

      if (url.includes('youtube') || url.includes('video') || url.includes('vimeo') || url.includes('netflix') || cat === 'streaming') {
        counts['Media & Video'] += 1;
      } else if (Boolean(ev.search_query) || url.includes('google.com/search') || url.includes('bing.com') || url.includes('duckduckgo')) {
        counts['Search Engines'] += 1;
      } else if (url.includes('aws') || url.includes('azure') || url.includes('api.') || url.includes('googleapis') || url.includes('cloudflare')) {
        counts['Cloud & APIs'] += 1;
      } else if (url.includes('twitter') || url.includes('facebook') || url.includes('instagram') || url.includes('slack') || url.includes('discord')) {
        counts['Social & Chat'] += 1;
      } else {
        counts['Other Web'] += 1;
      }
    });

    return counts;
  }, [events]);

  const labels = Object.keys(categoryData);
  const values = Object.values(categoryData);

  const colors = [
    '#ef4444', // Media (Red)
    '#54c8e8', // Search (Cyan)
    '#8b5cf6', // Cloud (Purple)
    '#f59e0b', // Social (Amber)
    '#64748b', // Other (Slate)
  ];

  const surface = palette?.surface || '#0c1524';
  const text = palette?.text || '#ffffff';
  const textMuted = palette?.textMuted || '#94a3b8';
  const grid = palette?.grid || 'rgba(255,255,255,0.06)';

  const data = {
    labels,
    datasets: [
      {
        label: 'Sessions',
        data: values,
        backgroundColor: colors.map((c) => `${c}55`),
        borderColor: colors,
        borderWidth: 1.5,
        borderRadius: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: surface,
        titleColor: text,
        bodyColor: textMuted,
        borderColor: grid,
        borderWidth: 1,
        padding: 8,
      },
    },
    scales: {
      x: {
        grid: { color: grid },
        ticks: { color: textMuted, font: { size: 10 } },
      },
      y: {
        grid: { display: false },
        ticks: { color: text, font: { size: 11, weight: '600' } },
      },
    },
  };

  return (
    <div style={{ height: `${height}px`, width: '100%' }}>
      <Bar data={data} options={options} />
    </div>
  );
};

export default DpiCategoryChart;
