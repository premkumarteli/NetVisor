import os
import csv
from datetime import datetime, timezone

class ResultWriter:
    """Exports time-series performance data as CSV and generates formatted markdown reports with ASCII sparkline charts."""
    
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        os.makedirs(target_dir, exist_ok=True)

    def write_time_series_csv(self, history: list):
        csv_path = os.path.join(self.target_dir, "performance_time_series.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "CPU_Percent", "RAM_MB", "Queue_Depth"])
            for h in history:
                writer.writerow([
                    h["timestamp"],
                    h["cpu_pct"],
                    h["ram_mb"],
                    h["queue_depth"]
                ])
        print(f"Time-series CSV exported to: {csv_path}")

    def generate_report(self, duration: int, stats: dict, history: list):
        # Extract resource vectors
        cpus = [h["cpu_pct"] for h in history] if history else [0.0]
        rams = [h["ram_mb"] for h in history] if history else [0.0]
        queues = [h["queue_depth"] for h in history] if history else [0]
        
        avg_cpu = sum(cpus) / len(cpus) if cpus else 0.0
        avg_ram = sum(rams) / len(rams) if rams else 0.0
        max_queue = max(queues) if queues else 0
        
        # Build ASCII charts
        cpu_chart = self._make_ascii_chart(cpus, "Server CPU Load Over Time (%)")
        ram_chart = self._make_ascii_chart(rams, "Server Memory Footprint Over Time (MB)")
        queue_chart = self._make_ascii_chart(queues, "Database Ingestion Queue Lag Over Time (Batches)")
        
        report_path = os.path.join(self.target_dir, "performance_results.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# NetVisor Ingestion Performance Results\n\n")
            f.write(f"Generated at: {datetime.now(timezone.utc).isoformat()}\n\n")
            
            f.write("## Test Parameters\n")
            f.write("- **Target Ingestion Rate**: 10,000 flows/second\n")
            f.write(f"- **Target Duration**: {duration} seconds\n\n")
            
            f.write("## Measurement Summary\n\n")
            f.write("| Metric | Achieved Value | SLO Status |\n")
            f.write("|---|---|---|\n")
            f.write(f"| **Throughput** | {stats['throughput']:,.2f} flows/sec | {'✅ PASS' if stats['throughput'] >= 9900 else '❌ FAIL'} |\n")
            f.write(f"| **P95 Latency** | {stats['p95_ms']:.2f} ms | {'✅ PASS' if stats['p95_ms'] <= 50.0 else '❌ FAIL'} |\n")
            f.write(f"| **Server CPU** | {avg_cpu:.1f}% | {'✅ PASS' if avg_cpu <= 80 else '❌ FAIL'} |\n")
            f.write(f"| **Server Memory** | {avg_ram:.1f} MB | {'✅ PASS' if avg_ram <= 4000 else '❌ FAIL'} |\n")
            f.write(f"| **Max Queue Lag** | {max_queue} batches | {'✅ PASS' if max_queue <= 50 else '❌ FAIL'} |\n\n")
            
            f.write("## Latency Percentiles\n")
            f.write(f"- **P50 (Median)**: {stats['p50_ms']:.2f} ms\n")
            f.write(f"- **P95**: {stats['p95_ms']:.2f} ms\n")
            f.write(f"- **P99**: {stats['p99_ms']:.2f} ms\n\n")
            
            f.write("## Resource Utilization Line Charts\n\n")
            f.write(cpu_chart + "\n")
            f.write(ram_chart + "\n")
            f.write(queue_chart + "\n")
            
        print(f"Markdown performance report generated at: {report_path}")

    def _make_ascii_chart(self, data: list, title: str, width: int = 50, height: int = 8) -> str:
        if not data:
            return "*(No data sampled)*"
            
        vals = [float(x) for x in data]
        vmin, vmax = min(vals), max(vals)
        if vmax == vmin:
            vmax += 1.0
            
        # Draw raster line plot
        chart = []
        for row in range(height - 1, -1, -1):
            threshold = vmin + (vmax - vmin) * (row / max(1, height - 1))
            line_chars = []
            for i in range(width):
                idx = int(i * len(vals) / width)
                val = vals[min(idx, len(vals) - 1)]
                # If value is close to or above current threshold, draw point
                if val >= threshold:
                    line_chars.append("*")
                else:
                    line_chars.append(" ")
            chart.append("".join(line_chars))
            
        chart_str = "\n".join(chart)
        return f"### {title}\n*Range: {vmin:.1f} to {vmax:.1f}*\n```\n{chart_str}\n```\n"
