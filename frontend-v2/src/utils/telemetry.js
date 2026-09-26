export const formatConfidence = (value) => {
  const score = Number(value) || 0;
  if (score >= 0.8) {
    return `High (${score.toFixed(2)})`;
  }
  if (score >= 0.55) {
    return `Medium (${score.toFixed(2)})`;
  }
  return `Low (${score.toFixed(2)})`;
};

export const confidenceTone = (value) => {
  const score = Number(value) || 0;
  if (score >= 0.8) {
    return 'success';
  }
  if (score >= 0.55) {
    return 'warning';
  }
  return 'danger';
};
