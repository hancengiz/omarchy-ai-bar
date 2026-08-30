CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO auth_kv (key, value) VALUES (
  'kirocli:odic:token',
  '{"access_token":"fixture-kiro-access-token-canary"}'
);
INSERT INTO state (key, value) VALUES (
  'api.codewhisperer.profile',
  '{"arn":"arn:aws:codewhisperer:us-east-1:123456789012:profile/fixture"}'
);
