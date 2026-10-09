-- Account lockout: track failed login attempts per account and a soft
-- lockout window. This complements the per-IP rate limiter with a
-- per-account throttle so a distributed brute force (many IPs, same
-- account) is bounded.
--
-- failed_login_count: consecutive failed logins. Zeroed on a successful
--     login.
-- locked_until: when non-NULL, login is refused until this timestamp.

ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;
