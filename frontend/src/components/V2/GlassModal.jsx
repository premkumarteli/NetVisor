import { useEffect } from 'react';
import { playHoverSound, playSuccessSound } from '../../utils/sound';

const GlassModal = ({
  open,
  title,
  description,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  onConfirm,
  onCancel,
  variant = 'confirm', // 'confirm' | 'alert' | 'danger'
  children
}) => {
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onCancel?.();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onCancel]);

  if (!open) return null;

  const handleConfirmClick = () => {
    playSuccessSound();
    onConfirm?.();
  };

  const handleCancelClick = () => {
    onCancel?.();
  };

  return (
    <>
      <div 
        className="nv-modal-backdrop animate-fade-in" 
        onClick={handleCancelClick}
        aria-hidden="true" 
      />
      <div 
        className={`nv-modal animate-scale-in nv-modal--${variant}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <button 
          type="button" 
          className="nv-button nv-button--ghost nv-modal__close" 
          onClick={handleCancelClick}
          onMouseEnter={playHoverSound}
          aria-label="Close modal"
        >
          <i className="ri-close-line"></i>
        </button>

        <div className="nv-modal__header">
          <div className="nv-modal__icon-wrap">
            {variant === 'danger' ? (
              <i className="ri-error-warning-line text-danger"></i>
            ) : variant === 'alert' ? (
              <i className="ri-information-line text-accent"></i>
            ) : (
              <i className="ri-checkbox-circle-line text-success"></i>
            )}
          </div>
          <h3 id="modal-title">{title}</h3>
          {description ? <p className="nv-modal__description">{description}</p> : null}
        </div>

        <div className="nv-modal__body">
          {children}
        </div>

        <div className="nv-modal__footer">
          {variant !== 'alert' ? (
            <button 
              type="button" 
              className="nv-button nv-button--secondary" 
              onClick={handleCancelClick}
              onMouseEnter={playHoverSound}
            >
              {cancelText}
            </button>
          ) : null}
          <button 
            type="button" 
            className={`nv-button ${variant === 'danger' ? 'nv-button--danger' : 'nv-button--primary'}`}
            onClick={handleConfirmClick}
            onMouseEnter={playHoverSound}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </>
  );
};

export default GlassModal;
