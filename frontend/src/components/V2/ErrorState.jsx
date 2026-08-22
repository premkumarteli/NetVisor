const ErrorState = ({
  title = 'Failed to load telemetry',
  message = 'An unexpected error occurred while communicating with the NetVisor gateway or agent service.',
  onRetry,
  compact = false,
  className = '',
}) => {
  if (compact) {
    return (
      <div className={`nv-error-compact ${className}`.trim()}>
        <i className="ri-error-warning-line"></i>
        <span>{message}</span>
        {onRetry ? (
          <button type="button" className="nv-button nv-button--ghost nv-button--xs" onClick={onRetry}>
            <i className="ri-refresh-line"></i> Retry
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <div className={`nv-empty nv-empty--error ${className}`.trim()} role="alert">
      <div className="nv-empty__icon" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
        <i className="ri-alert-line"></i>
      </div>
      <div className="nv-stack" style={{ gap: '0.5rem', textAlign: 'center' }}>
        <h3 className="nv-empty__title" style={{ color: '#fca5a5' }}>{title}</h3>
        <p className="nv-empty__description">{message}</p>
      </div>
      {onRetry ? (
        <button type="button" className="nv-button nv-button--secondary" onClick={onRetry} style={{ marginTop: '0.5rem' }}>
          <i className="ri-refresh-line"></i> Try Again
        </button>
      ) : null}
    </div>
  );
};

export default ErrorState;
