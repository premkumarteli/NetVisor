/**
 * Client-side Export Utilities for NetVisor SOC Investigations
 * Allows instant CSV and JSON exports for reporting and compliance audits.
 */

export const exportToJson = (filename = 'netvisor-export', data = []) => {
  const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
    JSON.stringify(data, null, 2)
  )}`;
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', jsonString);
  downloadAnchor.setAttribute('download', `${filename}-${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
};

export const exportToCsv = (filename = 'netvisor-export', columns = [], rows = []) => {
  if (!rows || rows.length === 0) {
    return;
  }

  const headers = columns.map((col) => `"${(col.label || col.key).replace(/"/g, '""')}"`).join(',');
  const rowStrings = rows.map((row) => {
    return columns
      .map((col) => {
        let val = row[col.key];
        if (typeof val === 'object' && val !== null) {
          val = JSON.stringify(val);
        } else if (val === undefined || val === null) {
          val = '';
        }
        return `"${String(val).replace(/"/g, '""')}"`;
      })
      .join(',');
  });

  const csvContent = `data:text/csv;charset=utf-8,${encodeURIComponent(
    [headers, ...rowStrings].join('\r\n')
  )}`;

  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', csvContent);
  downloadAnchor.setAttribute('download', `${filename}-${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
};
