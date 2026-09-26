import React, { useMemo } from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip } from 'chart.js';

ChartJS.register(ArcElement, Tooltip);

const CATEGORY_COLORS = {
  'Malicious Domain': '#EF4444', // red
  'Suspicious Activity': '#F59E0B', // amber
  'VPN Usage': '#8B5CF6', // purple
  'Anomaly': '#3B82F6', // blue
  'Others': '#10B981', // teal/green
};

export const ThreatDistributionCard = ({ alerts = [], riskDistribution = {} }) => {
  const categories = useMemo(() => {
    const counts = {
      'Malicious Domain': 0,
      'Suspicious Activity': 0,
      'VPN Usage': 0,
      'Anomaly': 0,
      'Others': 0,
    };

    if (Array.isArray(alerts) && alerts.length > 0) {
      alerts.forEach((alert) => {
        const text = `${alert.title || ''} ${alert.message || ''} ${alert.rule_name || ''} ${alert.detection || ''}`.toLowerCase();
        if (text.includes('dns') || text.includes('domain') || text.includes('c2') || text.includes('beaconing')) {
          counts['Malicious Domain']++;
        } else if (text.includes('vpn') || text.includes('proxy') || text.includes('tor')) {
          counts['VPN Usage']++;
        } else if (text.includes('scan') || text.includes('flood') || text.includes('mining')) {
          counts['Suspicious Activity']++;
        } else if (text.includes('anomaly') || text.includes('heuristic') || text.includes('deviation')) {
          counts['Anomaly']++;
        } else {
          counts['Others']++;
        }
      });
    } else if (riskDistribution && Object.keys(riskDistribution).length > 0) {
      counts['Malicious Domain'] = Number(riskDistribution.CRITICAL || 0);
      counts['Suspicious Activity'] = Number(riskDistribution.HIGH || 0);
      counts['Anomaly'] = Number(riskDistribution.MEDIUM || 0);
      counts['Others'] = Number(riskDistribution.LOW || 0);
    }

    return Object.entries(counts);
  }, [alerts, riskDistribution]);

  const totalThreats = categories.reduce((sum, [, count]) => sum + count, 0);

  const chartData = useMemo(() => {
    const labels = categories.map(([cat]) => cat);
    const data = categories.map(([, count]) => (totalThreats === 0 ? 1 : count));
    const bgColors =
      totalThreats === 0
        ? ['#1E293B']
        : labels.map((cat) => CATEGORY_COLORS[cat] || '#94A3B8');

    return {
      labels,
      datasets: [
        {
          data: totalThreats === 0 ? [1] : data,
          backgroundColor: bgColors,
          borderWidth: 0,
          hoverOffset: 4,
        },
      ],
    };
  }, [categories, totalThreats]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '76%',
    plugins: {
      legend: { display: false },
      tooltip: {
        enabled: totalThreats > 0,
        backgroundColor: '#0F172A',
        titleColor: '#F8FAFC',
        bodyColor: '#94A3B8',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        padding: 8,
      },
    },
  };

  return (
    <div
      className="glass-card p-5 flex flex-col justify-between"
      style={{
        background: 'rgba(10, 14, 26, 0.72)',
        backdropFilter: 'blur(20px) saturate(150%)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <i className="ri-shield-flash-line text-[#9AA3B8] text-base"></i>
          <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
            Threat Distribution
          </h3>
        </div>
        <button type="button" className="text-[#5E6579] hover:text-white">
          <i className="ri-more-line"></i>
        </button>
      </div>

      <div className="flex items-center gap-5">
        {/* Donut Chart with Center Metric */}
        <div className="relative w-32 h-32 shrink-0">
          <Doughnut data={chartData} options={chartOptions} />
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-extrabold text-[#FFFFFF] tabular-nums tracking-tight">
              {totalThreats}
            </span>
            <span className="text-[9.5px] text-[#9AA3B8] font-medium">
              Threats
            </span>
          </div>
        </div>

        {/* Legend List (Exact to reference) */}
        <div className="flex-1 space-y-1.5 min-w-0">
          {categories.map(([category, count]) => {
            const color = CATEGORY_COLORS[category] || '#9AA3B8';
            return (
              <div key={category} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 truncate">
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-[#9AA3B8] text-[11.5px] truncate">{category}</span>
                </div>
                <span className="mono font-semibold text-[#FFFFFF] text-xs">
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ThreatDistributionCard;
