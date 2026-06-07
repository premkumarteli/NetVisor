import { playHoverSound } from '../../utils/sound';

const Switch = ({ checked, onChange, disabled = false, label }) => {
  const handleToggle = () => {
    if (disabled) return;
    onChange?.(!checked);
  };

  return (
    <label 
      className={`nv-switch-container ${disabled ? 'is-disabled' : ''}`.trim()}
      onMouseEnter={playHoverSound}
    >
      <div 
        className={`nv-switch ${checked ? 'is-checked' : ''}`.trim()}
        onClick={handleToggle}
        role="checkbox"
        aria-checked={checked}
        tabIndex={disabled ? -1 : 0}
        onKeyDown={(e) => {
          if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            handleToggle();
          }
        }}
      >
        <span className="nv-switch__track" />
        <span className="nv-switch__thumb" />
      </div>
      {label ? <span className="nv-switch__label">{label}</span> : null}
    </label>
  );
};

export default Switch;
