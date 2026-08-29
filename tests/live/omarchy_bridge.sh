#!/usr/bin/bash -p

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  /usr/bin/printf '%s\n' 'omarchy_bridge: this wrapper may not be sourced' >&2
  return 2
fi

if [[ $- != *p* ]]; then
  /usr/bin/printf '%s\n' \
    'omarchy_bridge: invoke this executable directly so its privileged Bash startup boundary is active' >&2
  /usr/bin/kill -KILL "$$"
fi

set +x
set +v
set +a
set +f
set +k
set +m
set +C

unsafe_environment_name=""
while IFS= read -r -d '' environment_entry; do
  environment_name=${environment_entry%%=*}
  case $environment_name in
    BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_COMPAT|FUNCNEST|BASH_FUNC_*%%|LD_*|GLIBC_TUNABLES|\
      QT_PLUGIN_PATH|QT_QPA_PLATFORM_PLUGIN_PATH|QML_*|QML2_IMPORT_PATH|\
      TAR_OPTIONS|RIPGREP_CONFIG_PATH)
      unsafe_environment_name=$environment_name
      break
      ;;
  esac
done </proc/$$/environ

set -euo pipefail

if [[ -n $unsafe_environment_name || -n ${BASH_ENV:-} || -n ${ENV:-} ||
  -n $(builtin compgen -A function) || -n $(builtin alias -p) ]]; then
  builtin printf '%s\n' \
    'omarchy_bridge: refusing a caller environment with startup, loader, or code-path controls' >&2
  exit 2
fi
unset BASH_ENV ENV BASH_COMPAT FUNCNEST CDPATH GLOBIGNORE POSIXLY_CORRECT \
  LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH GLIBC_TUNABLES \
  QT_PLUGIN_PATH QT_QPA_PLATFORM_PLUGIN_PATH \
  QML_IMPORT_PATH QML2_IMPORT_PATH QML_PLUGIN_PATH QML_DISK_CACHE_PATH \
  QML_FORCE_DISK_CACHE QML_DISABLE_DISK_CACHE \
  TAR_OPTIONS RIPGREP_CONFIG_PATH \
  unsafe_environment_name environment_entry environment_name
export -n SHELLOPTS BASHOPTS 2>/dev/null || true
IFS=$' \t\n'
PATH=/usr/share/omarchy/bin:/usr/bin
export PATH
hash -r

script_dir=$(cd -P -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec "$script_dir/../../scripts/live-smoke-omarchy.sh" "$@"
