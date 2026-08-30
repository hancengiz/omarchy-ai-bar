#!/bin/sh
set -eu

if [ "${AWS_PROFILE+x}" = "x" ]; then
  echo "AWS_PROFILE leaked into profile subprocess" >&2
  exit 8
fi

if [ "${AWS_TEST_EXPIRED:-}" = "1" ]; then
  echo "The SSO session associated with this profile has expired; run aws sso login." >&2
  exit 1
fi

if [ "${AWS_ACCESS_KEY_ID:-}" != "AKIA_SOURCE_FIXTURE" ] || \
   [ "${AWS_SECRET_ACCESS_KEY:-}" != "source-secret-fixture" ] || \
   [ "${AWS_SESSION_TOKEN:-}" != "source-session-fixture" ]; then
  echo "profile source environment was not preserved" >&2
  exit 9
fi

case "$*" in
  "configure export-credentials --profile work --format process")
    printf '%s\n' '{"Version":1,"AccessKeyId":"AKIA_PROFILE_FIXTURE","SecretAccessKey":"profile-secret-fixture","SessionToken":"profile-session-fixture"}'
    ;;
  "configure get region --profile work")
    printf '%s\n' 'ap-southeast-2'
    ;;
  *)
    echo "unexpected fixture arguments" >&2
    exit 10
    ;;
esac
