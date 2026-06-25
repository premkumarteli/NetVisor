CREATE TABLE IF NOT EXISTS user_refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    family_id VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    revoked TINYINT NOT NULL DEFAULT 0,
    revoked_reason VARCHAR(50) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    UNIQUE KEY uq_token_hash (token_hash),
    INDEX idx_user_refresh_tokens_family (family_id),
    INDEX idx_user_refresh_tokens_user (user_id)
);
