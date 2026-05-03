ALTER TABLE email_mfa_codes
    ADD COLUMN IF NOT EXISTS purpose VARCHAR(20) NOT NULL DEFAULT 'login';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_email_mfa_codes_purpose'
    ) THEN
        ALTER TABLE email_mfa_codes
            ADD CONSTRAINT chk_email_mfa_codes_purpose
            CHECK (purpose IN ('login', 'setup'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_email_mfa_codes_user_purpose
    ON email_mfa_codes(user_id, purpose);
