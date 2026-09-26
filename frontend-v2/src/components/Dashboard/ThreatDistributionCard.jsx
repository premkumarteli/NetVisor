import React, { useMemo } from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

const CATEGORY_COLORS = {
  'Malicious Domain': '#FB7185', // rose
  'Suspicious Activity': '#F59E0B', // amber
  'VPN Usage': '#A78BFA', // violet
  'Anomaly': '#60A5FA', // blue
  'Others': '#54C8E8', // teal
};

export const ThreatDistributionCard = ({ alerts = [], riskDistribution = {} }) => {
  // Aggregate threat counts by category
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
      // Fallback to risk distribution if raw alert items not loaded
      counts['Malicious Domain'] = Number(riskDistribution.CRITICAL || 0);
      counts['Suspicious Activity'] = Number(riskDistribution.HIGH || 0);
      counts['Anomaly'] = Number(riskDistribution.MEDIUM || 0);
      counts['Others'] = Number(riskDistribution.LOW || 0);
    }

    return Object.entries(counts).filter(([, count]) => count > 0);
  }, [alerts, riskDistribution]);

  const totalThreats = categories.reduce((sum, [, count]) => sum + count, 0);

  const chartData = useMemo(() => {
    const labels = categories.map(([cat]) => cat);
    const data = categories.map(([, count]) => count);
    const bgColors = labels.map((cat) => CATEGORY_COLORS[cat] || '#9AA3B8');

    return {
      labels,
      datasets: [
        {
          data,
          backgroundColor: bgColors.map((c) => `${c}B3`), // 70% opacity
          borderColor: bgColors,
          borderWidth: 1.5,
          hoverOffset: 6,
        },
      ],
    };
  }, [categories]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '72%',
    plugins: {
      legend: {
        display: false, // We render our own custom crisp legend
      },
      tooltip: {
        backgroundColor: '#111422',
        titleColor: '#F1F3F9',
        bodyColor: '#9AA3B8',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        padding: 10,
        boxPadding: 4,
        usePointStyle: true,
      },
    },
  };

  return (
    <div className="glass-card p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-[#9AA3B8]">
            Threat Breakdown
          </span>
          <h3 className="text-base font-bold text-[#F1F3F9] tracking-tight">
            Threat Distribution
          </h3>
        </div>
        <span className="text-xs font-bold mono text-[#FB7185] bg-rose-500/10 border border-rose-500/20 px-2 py-0.5 rounded-full">
          {totalThreats} total
        </span>
      </div>

      {totalThreats === 0 ? (
        <div className="py-10 flex flex-col items-center justify-center text-center">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-2">
            <i className="ri-shield-check-line text-lg"></i>
          </div>
          <p className="text-xs font-bold text-[#F1F3F9]">No Threats Detected</p>
          <p className="text-[11px] text-[#5E6579] mt-0.5">
            Network baseline is normal with 0 active anomalies.
          </p>
        </div>
      ) : (
        <div className="flex items-center gap-4">
          {/* Donut Chart with center metric */}
          <div className="relative w-36 h-36 shrink-0">
            <Doughnut data={chartData} options={chartOptions} />
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-extrabold text-[#F1F3F9] tabular-nums tracking-tight">
                {totalThreats}
              </span>
              <span className="text-[9px] uppercase tracking-wider text-[#9AA3B8] font-bold">
                Threats
              </span>
            </div>
          </div>

          {/* Custom Legend */}
          <div className="flex-1 space-y-1.5 min-w-0">
            {categories.map(([category, count]) => {
              const color = CATEGORY_COLORS[category] || '#9AA3B8';
              const percent = Math.round((count / totalThreats) * 100);
              return (
                <div key={category} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 truncate">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: color }}
                    />
                    <span className="text-[#9AA3B8] truncate">{category}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="mono font-bold text-[#F1F3F9]">{count}</span>
                    <span className="text-[10px] text-[#5E6579] w-7 text-right">{percent}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatDistributionCard;
