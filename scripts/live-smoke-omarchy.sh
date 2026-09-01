#!/usr/bin/bash -p

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  /usr/bin/printf '%s\n' 'live-smoke: this harness may not be sourced' >&2
  return 2
fi

if [[ $- != *p* ]]; then
  /usr/bin/printf '%s\n' \
    'live-smoke: invoke this executable directly so its privileged Bash startup boundary is active' >&2
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
    'live-smoke: refusing a caller environment with startup, loader, or code-path controls' >&2
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

# Destructive-by-design live integration harness for the exact Omarchy release
# on which the QML bridge was developed. It never edits packaged Omarchy files,
# never symlinks the development plugin, and on a clean teardown retains only
# its mode-0700 evidence directory. The transient shell runs in private user, mount, and network
# namespaces built by Bubblewrap. The exact packaged code stays at its canonical
# path, while a read-only bind of a safe default removes the packaged-default
# loading race before the first QML engine tick. Agent and weather widgets are
# disabled, agent credentials stay isolated, and direct network access is
# unavailable. Notification, clipboard, theme, and stay-awake state are bound
# read-write only inside that private namespace so desktop events are not
# discarded; none of their contents are copied into evidence. The private
# mounts disappear only after the transient cgroup is empty. Every acknowledged
# live mutation is identity-pinned and reversed by cleanup(). An ambiguously
# acknowledged headless create is never claimed or deleted. The 96-bit suffix
# is encoded only with Unicode White_Space after lowercase `fallback`, so the
# exact audited monitor manager trims and ignores the connector. Even if a
# parser stripped the suffix, Hyprland would not mistake the lowercase bytes
# for its reserved literal FALLBACK. Residuals retain recovery evidence.

readonly plugin_id="local.omarchy-ai-bar"
readonly other_panel_id="omarchy.audio"
readonly expected_omarchy_version="4.0.1-1"
readonly expected_hyprland_version="0.56.2"
readonly expected_hyprland_commit="efb50993780079460b0cbed1363e2166a2de1d9f"
readonly expected_hyprland_sha256="11781a4ea72fcf193f6f803d031c3c8494537a14f18583fe937609345277812c"
readonly expected_hyprctl_sha256="776f8483421a14889388cae185aa158bccf21a0ca5c284371d6b8df37f4a190b"
readonly expected_quickshell_version="Quickshell 0.3.1"
readonly expected_empty_quickshell_registry=$'No running instances for "/usr/share/omarchy/shell/shell.qml"\nUse --all to list all instances.'
readonly expected_hyprmoncfgd_version="hyprmoncfgd version 1.16.1"
readonly expected_hyprmoncfgd_sha256="a601087b50530a77d172fbbc84aab635408f96cddf9e3c4a5a08ad4a75174483"
readonly expected_aquamarine_path="/usr/lib/libaquamarine.so.0.14.0"
readonly expected_aquamarine_sha256="996c0383167204db62b727e3d59aeae9de18ab74394280a3599ad3c221b97fbc"
readonly expected_hyprutils_path="/usr/lib/libhyprutils.so.0.14.1"
readonly expected_hyprutils_sha256="804ec61be1370f7615867fb699f10fd98acdd7f9704755927ab5db55ee23a29c"
readonly expected_socat_sha256="c823e6f60c4657758fb4cbe0dee62e3563ad61ae734adcdb8e7e840c4867b7bb"
readonly expected_iproute2_version="iproute2 7.2.0-1"
readonly expected_ss_sha256="b5956b0c54b348bb4d69d80fd096c861785b4aaf03b722d226de5821135ded8b"
readonly expected_bash_sha256="575e03ac834b739349a4484de481abcd06a6f7193cefc795260a32a1943f20a5"
readonly expected_source_sha256="4084764b088f546e5298dd4c4d217a6b5ada9f7216eb01c71a6146b13b684fa6"
readonly expected_release_binary_sha256="82b1e6aca338c734e57f726cea20bb7f38c6f2a99dd6b0d13bc657f65691339b"
readonly expected_plugin_manifest_sha256="ac2afe4143810f25bec48ffaecfb20288de1aaaa2670312d102b5e93b8e2d4ec"
readonly expected_snapshot_fixture_sha256="ba574bf4837828b9b90659acfdb0f0b0309ca2df836c7d2bd100c7bf7462ee66"
readonly stream_id="a11ce000000000000000000000000001"

if (( $# != 0 )); then
  echo "usage: $0" >&2
  exit 2
fi

umask 077

die() {
  echo "live-smoke: $*" >&2
  exit 1
}

die_with_status() {
  local status=$1
  shift
  [[ $status =~ ^[1-9][0-9]*$ && $status -le 255 ]] || status=1
  echo "live-smoke: $*" >&2
  exit "$status"
}

note() {
  printf 'live-smoke: %s\n' "$*"
}

require_command() {
  local resolved=""
  resolved=$(type -P "$1" 2>/dev/null) || die "required command is unavailable: $1"
  [[ $resolved == /usr/bin/* || $resolved == /usr/share/omarchy/bin/* ]] ||
    die "required command is outside the trusted packaged PATH: $1"
}

encode_headless_nonce() {
  local nonce=$1 encoded="fallback" digit rune="" index
  [[ $nonce =~ ^[0-9a-f]{24}$ ]] || return 1
  for (( index = 0; index < 24; index++ )); do
    digit=${nonce:index:1}
    case $digit in
      0) rune=$'\u00a0' ;;
      1) rune=$'\u1680' ;;
      2) rune=$'\u2000' ;;
      3) rune=$'\u2001' ;;
      4) rune=$'\u2002' ;;
      5) rune=$'\u2003' ;;
      6) rune=$'\u2004' ;;
      7) rune=$'\u2005' ;;
      8) rune=$'\u2006' ;;
      9) rune=$'\u2007' ;;
      a) rune=$'\u2008' ;;
      b) rune=$'\u2009' ;;
      c) rune=$'\u200a' ;;
      d) rune=$'\u202f' ;;
      e) rune=$'\u205f' ;;
      f) rune=$'\u3000' ;;
      *) return 1 ;;
    esac
    encoded+=$rune
  done
  printf '%s' "$encoded"
}

headless_name_matches_nonce() {
  [[ ${headless_nonce:-} =~ ^[0-9a-f]{24}$ && -n ${headless_name:-} ]] || return 1
  printf '%s' "$headless_name" | jq -Rse --arg nonce "$headless_nonce" '
    {
      "0": 160, "1": 5760,
      "2": 8192, "3": 8193, "4": 8194, "5": 8195,
      "6": 8196, "7": 8197, "8": 8198, "9": 8199,
      "a": 8200, "b": 8201, "c": 8202,
      "d": 8239, "e": 8287, "f": 12288
    } as $map
    | ($nonce | split("")) as $digits
    | explode == (("fallback" | explode) +
        [range(0; 24) as $index | $map[$digits[$index]]])
  ' >/dev/null
}

systemctl_user_query() {
  if (( ${cleanup_active:-0} )); then
    timeout --kill-after=0.1s 0.3s systemctl --user "$@"
  else
    timeout --kill-after=0.1s 0.8s systemctl --user "$@"
  fi
}

hyprctl_bounded() {
  if (( ${cleanup_active:-0} )); then
    timeout --kill-after=0.1s 0.3s hyprctl "$@"
  else
    timeout --kill-after=0.2s 2s hyprctl "$@"
  fi
}

lua_long_string_literal() {
  local value=$1 equals="" terminator="" attempt
  [[ -n $value && $value != $'\n'* && $value != $'\r'* ]] || return 1
  for (( attempt = 0; attempt < 32; attempt++ )); do
    terminator="]${equals}]"
    if [[ $value != *"$terminator"* ]]; then
      printf '[%s[%s]%s]' "$equals" "$value" "$equals"
      return 0
    fi
    equals+="="
  done
  return 1
}

dispatch_monitor_safely() {
  local monitor=$1 literal=""
  if [[ $monitor == eDP-1 ]]; then
    :
  elif [[ $monitor == "${headless_name:-}" ]] && headless_name_matches_nonce; then
    :
  else
    return 1
  fi
  literal=$(lua_long_string_literal "$monitor") || return 1
  hyprctl_bounded eval \
    "hl.dispatch(hl.dsp.focus({ monitor = $literal }))" >/dev/null
}

dispatch_cursor_safely() {
  local x=$1 y=$2
  [[ $x =~ ^-?[0-9]+$ && $y =~ ^-?[0-9]+$ ]] || return 1
  (( x >= -2147483648 && x <= 2147483647 &&
    y >= -2147483648 && y <= 2147483647 )) || return 1
  hyprctl_bounded eval \
    "hl.dispatch(hl.dsp.cursor.move({ x = $x, y = $y }))" >/dev/null
}

compositor_identity_matches() {
  local instances="" current_pid="" current_start="" current_owner=""
  local current_executable="" current_executable_identity="" current_executable_hash=""
  local current_aquamarine_identity="" current_hyprutils_identity="" version=""
  local current_mount_namespace="" harness_mount_namespace=""
  instances=$(hyprctl_bounded -j instances 2>/dev/null) || return 1
  current_pid=$(jq -er --arg signature "$HYPRLAND_INSTANCE_SIGNATURE" \
    --arg socket "$WAYLAND_DISPLAY" '
      [.[] | select(.instance == $signature and .wl_socket == $socket)]
      | if length == 1 and (.[0].pid | type) == "number"
          and .[0].pid > 0 and .[0].pid == (.[0].pid | floor)
        then .[0].pid else empty end
    ' <<<"$instances") || return 1
  [[ $current_pid == "$hyprland_compositor_pid_before" &&
    -r /proc/$current_pid/stat && -L /proc/$current_pid/exe &&
    -r /proc/$current_pid/maps ]] || return 1
  current_start=$(awk '{print $22}' "/proc/$current_pid/stat" 2>/dev/null) || return 1
  current_owner=$(stat -c '%u' -- "/proc/$current_pid" 2>/dev/null) || return 1
  current_mount_namespace=$(readlink -- "/proc/$current_pid/ns/mnt" 2>/dev/null) || return 1
  harness_mount_namespace=$(readlink -- "/proc/$$/ns/mnt" 2>/dev/null) || return 1
  current_executable=$(readlink -- "/proc/$current_pid/exe" 2>/dev/null) || return 1
  current_executable_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$current_pid/exe" 2>/dev/null) || return 1
  current_executable_hash=$(sha256_packaged_file /usr/bin/Hyprland) || return 1
  current_aquamarine_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "$expected_aquamarine_path" 2>/dev/null) || return 1
  current_hyprutils_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "$expected_hyprutils_path" 2>/dev/null) || return 1
  [[ $current_start == "$hyprland_compositor_start_before" &&
    $current_owner == "$UID" && $current_executable == /usr/bin/Hyprland &&
    $current_mount_namespace == "$hyprland_mount_namespace_before" &&
    $harness_mount_namespace == "$harness_mount_namespace_before" &&
    $current_mount_namespace == "$harness_mount_namespace" &&
    $current_executable_identity == "$hyprland_executable_identity_before" &&
    $current_executable_hash == "$expected_hyprland_sha256" &&
    $current_aquamarine_identity == "$aquamarine_identity_before" &&
    $current_hyprutils_identity == "$hyprutils_identity_before" &&
    $(sha256_packaged_file "$expected_aquamarine_path") == "$expected_aquamarine_sha256" &&
    $(sha256_packaged_file "$expected_hyprutils_path") == "$expected_hyprutils_sha256" &&
    $(command -v hyprctl) == /usr/bin/hyprctl &&
    $(sha256_packaged_file /usr/bin/hyprctl) == "$expected_hyprctl_sha256" ]] || return 1
  version=$(hyprctl_bounded -j version 2>/dev/null) || return 1
  jq -e --arg version "$expected_hyprland_version" \
    --arg commit "$expected_hyprland_commit" '
      .version == $version and .commit == $commit and .dirty == false
      and .buildAquamarine == "0.14.0" and .systemAquamarine == "0.14.0"
      and .abiHash == ($commit + "_aq_0.14_hu_0.14_hg_0.5_hc_0.1_hlg_0.6")
    ' <<<"$version" >/dev/null || return 1
  awk -v expected_path="$expected_aquamarine_path" \
    -v expected_inode="$aquamarine_inode_before" '
      /libaquamarine/ {
        seen++
        if (NF != 6 || $6 != expected_path || $5 != expected_inode || $0 ~ /\(deleted\)$/)
          bad = 1
      }
      END { exit(seen == 5 && !bad ? 0 : 1) }
    ' "/proc/$current_pid/maps" || return 1
  awk -v expected_path="$expected_hyprutils_path" \
    -v expected_inode="$hyprutils_inode_before" '
      /libhyprutils/ {
        seen++
        if (NF != 6 || $6 != expected_path || $5 != expected_inode || $0 ~ /\(deleted\)$/)
          bad = 1
      }
      END { exit(seen == 5 && !bad ? 0 : 1) }
    ' "/proc/$current_pid/maps"
}

hyprland_config_errors_match() {
  local current=""
  current=$(hyprctl_bounded configerrors 2>&1) || return 1
  [[ $current == "$hyprland_config_errors_before" ]]
}

hyprland_persistent_config_matches_baseline() {
  file_envelope_matches "$monitor_manager_config_file" \
    "$monitor_manager_config_hash_before" "$monitor_manager_config_stat_before" \
    "$monitor_manager_config_acl_before" "$monitor_manager_config_xattr_before" \
    hyprmoncfg-monitors.lua.before-reload || return 1
  file_envelope_matches "$hyprland_lua_file" \
    "$hyprland_lua_hash_before" "$hyprland_lua_stat_before" \
    "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
    hyprland.lua.before-reload || return 1
  tree_digest_noatime \
    "$monitor_profiles_root" "$evidence_dir/hyprmoncfg-profiles.before-reload.sha256" ||
    return 1
  cmp -s -- "$monitor_profiles_digest_before" \
    "$evidence_dir/hyprmoncfg-profiles.before-reload.sha256"
}

reload_hyprland_until_clean() {
  local attempt
  for (( attempt = 0; attempt < 8; attempt++ )); do
    if live_lock_is_held && session_is_safe_for_live_mutation &&
      compositor_identity_matches && hyprland_persistent_config_matches_baseline &&
      hyprctl_bounded reload >/dev/null 2>&1 &&
      compositor_identity_matches && hyprland_persistent_config_matches_baseline &&
      hyprland_config_errors_match; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

restore_cursor_from_file() {
  local source=$1 label=$2 attempt x="" y="" current="" max_attempts=30
  (( ${cleanup_active:-0} )) && max_attempts=5
  [[ -f $source && ! -L $source && $label =~ ^[a-z0-9.-]+$ ]] || return 1
  read -r x y < <(jq -er '[.x, .y] | @tsv' "$source") || return 1
  [[ $x =~ ^-?[0-9]+$ && $y =~ ^-?[0-9]+$ ]] || return 1
  current="$evidence_dir/cursor.$label.current.json"
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    if live_lock_is_held && session_is_safe_for_live_mutation &&
      compositor_identity_matches &&
      dispatch_cursor_safely "$x" "$y" >/dev/null 2>&1 &&
      (set -o pipefail; hyprctl_bounded cursorpos -j 2>/dev/null | jq -S .) >"$current" &&
      cmp -s -- "$source" "$current"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

compositor_lock_state() {
  local status
  if timeout --kill-after=0.1s 0.8s omarchy-hyprland-session-locked \
    >/dev/null 2>&1; then
    printf 'locked\n'
    return 0
  else
    status=$?
  fi
  if [[ $status == 1 ]]; then
    printf 'unlocked\n'
    return 0
  fi
  return 1
}

session_is_confirmed_unlocked() {
  [[ $(compositor_lock_state 2>/dev/null) == unlocked ]]
}

safe_absolute_path() {
  local path=$1
  [[ $path =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  [[ $path != *//* && $path != */./* && $path != */../* && $path != */. && $path != */.. ]]
}

reviewed_source_sha256() {
  local unexpected="" source="" source_hash="" manifest=""
  local output="" digest="" unused="" candidate
  local -a sources=()
  for candidate in \
    "$repo_root/build.rs" \
    "$repo_root/crates/app/build.rs" \
    "$repo_root/crates/domain/build.rs" \
    "$repo_root/crates/ipc/build.rs"; do
    [[ ! -e $candidate && ! -L $candidate ]] || return 1
  done
  for candidate in \
    "$repo_root/crates/app/src" \
    "$repo_root/crates/domain/src" \
    "$repo_root/crates/ipc/src"; do
    [[ -d $candidate && ! -L $candidate ]] || return 1
  done
  unexpected=$(
    cd -- "$repo_root" || exit 1
    find crates/app/src crates/domain/src crates/ipc/src -xdev \
      ! -type d ! \( -type f -name '*.rs' \) -print -quit
  ) || return 1
  [[ -z $unexpected ]] || return 1
  mapfile -d '' -t sources < <(
    cd -- "$repo_root" || exit 1
    {
      printf '%s\0' \
        Cargo.lock Cargo.toml rust-toolchain.toml \
        crates/app/Cargo.toml crates/domain/Cargo.toml crates/ipc/Cargo.toml \
        crates/app/tests/hyprland_event_witness.rs fixtures/domain/snapshot-v1.json
      find crates/app/src crates/domain/src crates/ipc/src -xdev \
        -type f -name '*.rs' -print0
    } | LC_ALL=C sort -z
  )
  (( ${#sources[@]} >= 8 )) || return 1
  for source in "${sources[@]}"; do
    [[ $source =~ ^[A-Za-z0-9._/-]+$ && $source != *//* &&
      $source != */../* && $source != ../* &&
      -f $repo_root/$source && ! -L $repo_root/$source ]] || return 1
    source_hash=$(sha256_file "$repo_root/$source") || return 1
    manifest+="$source_hash  $source"$'\n'
  done
  output=$(printf '%s' "$manifest" | sha256sum) || return 1
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1
  printf '%s\n' "$digest"
}

reviewed_source_boundary_matches() {
  [[ $(reviewed_source_sha256) == "$expected_source_sha256" ]]
}

file_identity() {
  stat -c '%d:%i:%u:%F' -- "$1"
}

fd_file_identity() {
  stat -L -c '%d:%i:%u:%F' -- "$1"
}

stable_regular_file_identity() {
  [[ -f $1 && ! -L $1 ]] || return 1
  stat -c '%d:%i:%u:%f' -- "$1"
}

fd_stable_regular_file_identity() {
  stat -L -c '%d:%i:%u:%f' -- "$1"
}

fd_access_mode() {
  local flags=""
  flags=$(awk '$1 == "flags:" { if (++count == 1) value = $2 }
    END { if (count == 1) print value }' "$1" 2>/dev/null) || return 1
  [[ $flags =~ ^0[0-7]+$ ]] || return 1
  printf '%d\n' "$((8#$flags & 3))"
}

lock_path_identity() {
  stat -c '%d:%i:%u' -- "$1"
}

lock_fd_identity() {
  stat -L -c '%d:%i:%u' -- "$1"
}

mountpoint_is_absent_in_host_namespace() {
  local path=$1 status
  if timeout --kill-after=0.1s 0.5s findmnt --kernel=mountinfo \
    --mountpoint "$path" >/dev/null 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ $status == 1 ]]
}

acquire_live_lock() {
  local fd_identity="" acquired_identity="" candidate_identity="" creation_token=""
  local current_contents="" candidate_fd="" return_status=0
  local status=0 interrupted=0 creation_fd_open=0 acquired=0
  [[ -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR &&
    $(file_identity "$XDG_RUNTIME_DIR") == "$runtime_root_identity" ]] || return 1

  creation_token=$(dd if=/dev/urandom bs=32 count=1 status=none | sha256sum | awk '{print $1}') ||
    return 1
  [[ $creation_token =~ ^[0-9a-f]{64}$ ]] || return 1
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  if [[ ! -e $live_lock_path && ! -L $live_lock_path ]]; then
    set -o noclobber
    if { exec {candidate_fd}>"$live_lock_path"; } 2>/dev/null; then
      creation_fd_open=1
    fi
    set +o noclobber
  fi

  if (( creation_fd_open )); then
    candidate_identity=$(lock_fd_identity "/proc/$$/fd/$candidate_fd") || status=1
    acquired_identity=$(lock_path_identity "$live_lock_path") || status=1
    if [[ $status == 0 && -n $candidate_identity &&
      $candidate_identity == "$acquired_identity" &&
      -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR &&
      $(file_identity "$XDG_RUNTIME_DIR") == "$runtime_root_identity" &&
      -f $live_lock_path && ! -L $live_lock_path &&
      $(stat -c '%u:%a' -- "$live_lock_path" 2>/dev/null) == "$UID:600" ]]; then
      # The descriptor was opened with O_EXCL in this shell. Publish its inode
      # before writing so even a partial token remains exactly attributable.
      live_lock_identity=$candidate_identity
      live_lock_created=1
      live_lock_fd=$candidate_fd
      if flock -n "$candidate_fd" && live_lock_is_held &&
        printf '%s\n' "$creation_token" >&"$candidate_fd"; then
        current_contents=$(<"$live_lock_path")
        if [[ $current_contents == "$creation_token" &&
          $(lock_path_identity "$live_lock_path") == "$candidate_identity" ]] &&
          live_lock_is_held; then
          acquired=1
        else
          status=1
        fi
      else
        status=1
      fi
    else
      status=1
    fi
  else
    if [[ ! -f $live_lock_path || -L $live_lock_path ||
      $(stat -c '%u:%a' -- "$live_lock_path" 2>/dev/null) != "$UID:600" ]]; then
      status=1
    elif ! exec {candidate_fd}<>"$live_lock_path"; then
      status=1
    else
      acquired_identity=$(lock_path_identity "$live_lock_path") || status=1
      fd_identity=$(lock_fd_identity "/proc/$$/fd/$candidate_fd") || status=1
      if [[ $status == 0 && $fd_identity == "$acquired_identity" ]]; then
        live_lock_identity=$acquired_identity
        live_lock_created=0
        live_lock_fd=$candidate_fd
        if flock -n "$candidate_fd" && live_lock_is_held; then
          acquired=1
        else
          status=1
        fi
      else
        status=1
      fi
    fi
  fi
  (( acquired )) || status=1
  trap '' HUP INT TERM
  return_status=$status
  (( interrupted == 0 )) || return_status=$interrupted

  if (( return_status != 0 && creation_fd_open )); then
    if ! rollback_created_live_lock_fd_candidate "$candidate_fd"; then
      # Another invocation may have acquired the just-created inode. In that
      # case deletion authority is deliberately discarded rather than retried
      # later without the exact held descriptor.
      if [[ $live_lock_fd =~ ^[0-9]+$ && -e /proc/$$/fd/$live_lock_fd ]]; then
        exec {live_lock_fd}>&- || true
      elif [[ $candidate_fd =~ ^[0-9]+$ && -e /proc/$$/fd/$candidate_fd ]]; then
        exec {candidate_fd}>&- || true
      fi
      live_lock_fd=""
      live_lock_identity=""
      live_lock_created=0
    fi
  elif (( return_status != 0 )); then
    if [[ $live_lock_fd =~ ^[0-9]+$ && -e /proc/$$/fd/$live_lock_fd ]]; then
      exec {live_lock_fd}>&- || true
    elif [[ $candidate_fd =~ ^[0-9]+$ && -e /proc/$$/fd/$candidate_fd ]]; then
      exec {candidate_fd}>&- || true
    fi
    live_lock_fd=""
    live_lock_identity=""
    live_lock_created=0
  fi
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  return "$return_status"
}

rollback_created_live_lock_fd_candidate() {
  local rollback_fd=$1 expected_identity=""
  [[ $rollback_fd =~ ^[0-9]+$ && -e /proc/$$/fd/$rollback_fd ]] || return 1
  expected_identity=$(lock_fd_identity "/proc/$$/fd/$rollback_fd") || return 1
  [[ -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR &&
    $(file_identity "$XDG_RUNTIME_DIR") == "$runtime_root_identity" &&
    -f $live_lock_path && ! -L $live_lock_path &&
    $(stat -c '%u:%a' -- "$live_lock_path" 2>/dev/null) == "$UID:600" &&
    $(lock_path_identity "$live_lock_path") == "$expected_identity" ]] || return 1
  flock -n "$rollback_fd" || return 1
  [[ -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR &&
    $(file_identity "$XDG_RUNTIME_DIR") == "$runtime_root_identity" &&
    -f $live_lock_path && ! -L $live_lock_path &&
    $(stat -c '%u:%a' -- "$live_lock_path" 2>/dev/null) == "$UID:600" &&
    $(lock_path_identity "$live_lock_path") == "$expected_identity" &&
    $(lock_fd_identity "/proc/$$/fd/$rollback_fd") == "$expected_identity" ]] || return 1
  rm -f -- "$live_lock_path" || return 1
  [[ ! -e $live_lock_path && ! -L $live_lock_path ]] || return 1
  [[ $(lock_fd_identity "/proc/$$/fd/$rollback_fd") == "$expected_identity" ]] || return 1
  flock -n "$rollback_fd" || return 1
  if [[ $live_lock_fd == "$rollback_fd" ]]; then
    exec {live_lock_fd}>&- || return 1
  else
    exec {rollback_fd}>&- || return 1
  fi
  live_lock_fd=""
  live_lock_identity=""
  live_lock_created=0
}

live_lock_is_held() {
  local fd_identity=""
  [[ $live_lock_fd =~ ^[0-9]+$ && -n $live_lock_identity &&
    -f $live_lock_path && ! -L $live_lock_path &&
    $(stat -c '%u:%a' -- "$live_lock_path" 2>/dev/null) == "$UID:600" &&
    $(lock_path_identity "$live_lock_path") == "$live_lock_identity" ]] || return 1
  fd_identity=$(lock_fd_identity "/proc/$$/fd/$live_lock_fd") || return 1
  [[ $fd_identity == "$live_lock_identity" ]] || return 1
  flock -n "$live_lock_fd"
}

unlink_live_lock_path_while_held() {
  local fd_identity=""
  live_lock_is_held || return 1
  rm -f -- "$live_lock_path" || return 1
  [[ ! -e $live_lock_path && ! -L $live_lock_path ]] || return 1
  fd_identity=$(lock_fd_identity "/proc/$$/fd/$live_lock_fd") || return 1
  [[ $fd_identity == "$live_lock_identity" ]] || return 1
  flock -n "$live_lock_fd"
}

sha256_file() {
  local output="" digest="" unused=""
  if ! output=$(set -o pipefail; dd if="$1" iflag=noatime,nofollow status=none | sha256sum); then
    return 1
  fi
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1
  printf '%s\n' "$digest"
}

sha256_packaged_file() {
  local path=$1 identity_before="" identity_after=""
  local atime="" mtime="" ctime="" now="" mount_options=""
  local output="" digest="" unused=""
  [[ -f $path && ! -L $path && $(stat -c '%u:%g' -- "$path" 2>/dev/null) == 0:0 ]] ||
    return 1
  mount_options=$(findmnt --kernel=mountinfo --target "$path" \
    --output OPTIONS --noheadings 2>/dev/null) || return 1
  [[ $mount_options != *$'\n'* &&
    $mount_options =~ (^|,)relatime(,|$) ]] || return 1
  identity_before=$(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' \
    -- "$path" 2>/dev/null) || return 1
  read -r atime mtime ctime < <(stat -c '%X %Y %Z' -- "$path" 2>/dev/null) || return 1
  printf -v now '%(%s)T' -1
  [[ $atime =~ ^[0-9]+$ && $mtime =~ ^[0-9]+$ && $ctime =~ ^[0-9]+$ &&
    $now =~ ^[0-9]+$ && $atime -gt $mtime && $atime -gt $ctime &&
    $now -ge $atime && $((now - atime)) -lt 86340 ]] || return 1

  # O_NOATIME is unavailable to an unprivileged reader of root-owned package
  # files. The relatime precondition above and exact atime sandwich prove that
  # this ordinary, no-follow read did not alter package metadata.
  if ! output=$(set -o pipefail; dd if="$path" iflag=nofollow status=none | sha256sum); then
    return 1
  fi
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1
  identity_after=$(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' \
    -- "$path" 2>/dev/null) || return 1
  [[ $identity_after == "$identity_before" ]] || return 1
  printf '%s\n' "$digest"
}

proc_executable_sha256() {
  local candidate_pid=$1 expected_start=$2 expected_identity=$3
  local start_before="" start_after="" identity_before="" identity_after=""
  local output="" digest="" unused=""
  [[ $candidate_pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ &&
    -n $expected_identity && -r /proc/$candidate_pid/stat &&
    -L /proc/$candidate_pid/exe ]] || return 1
  start_before=$(awk '{print $22}' "/proc/$candidate_pid/stat" 2>/dev/null) || return 1
  identity_before=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$candidate_pid/exe" 2>/dev/null) || return 1
  [[ $start_before == "$expected_start" &&
    $identity_before == "$expected_identity" ]] || return 1

  # /proc/<pid>/exe is intentionally followed only inside a PID-start-time and
  # full-inode-identity sandwich. Generic file hashing rejects symlinks.
  if ! output=$(set -o pipefail; \
    dd if="/proc/$candidate_pid/exe" iflag=noatime status=none | sha256sum); then
    return 1
  fi
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1

  start_after=$(awk '{print $22}' "/proc/$candidate_pid/stat" 2>/dev/null) || return 1
  identity_after=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$candidate_pid/exe" 2>/dev/null) || return 1
  [[ $start_after == "$expected_start" && $start_after == "$start_before" &&
    $identity_after == "$expected_identity" &&
    $identity_after == "$identity_before" ]] || return 1
  printf '%s\n' "$digest"
}

canonical_json_file_hash() {
  local output="" digest="" unused=""
  if ! output=$(
    set -o pipefail
    dd if="$1" iflag=noatime,nofollow status=none | jq -S -c . | sha256sum
  ); then
    return 1
  fi
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1
  printf '%s\n' "$digest"
}

shell_ipc_canonical_hash() {
  local output="" digest="" unused=""
  if ! output=$(
    set -o pipefail
    OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
      omarchy-shell shell listShellConfig 2>/dev/null | jq -S -c . | sha256sum
  ); then
    return 1
  fi
  read -r digest unused <<<"$output" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]] || return 1
  printf '%s\n' "$digest"
}

cleanup_bar_retry_allowed() {
  (( ! ${cleanup_active:-0} || ${cleanup_bar_restore_deadline:-0} == 0 ||
    SECONDS < cleanup_bar_restore_deadline ))
}

cleanup_monitor_retry_allowed() {
  (( ! ${cleanup_active:-0} || ${cleanup_monitor_deadline:-0} == 0 ||
    SECONDS < cleanup_monitor_deadline ))
}

cleanup_final_retry_allowed() {
  (( ! ${cleanup_active:-0} || ${cleanup_final_deadline:-0} == 0 ||
    SECONDS < cleanup_final_deadline ))
}

wait_for_effective_shell_config() {
  local expected=$1 attempt current="" max_attempts=50
  (( ${cleanup_active:-0} )) && max_attempts=6
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    cleanup_bar_retry_allowed || return 1
    current=$(shell_ipc_canonical_hash 2>/dev/null) || current=""
    [[ $current == "$expected" ]] && return 0
    sleep 0.1
  done
  return 1
}

tree_digest_noatime() {
  local root=$1 destination=$2 digest="" unused=""
  [[ -d $root && ! -L $root ]] || return 1
  if ! (
    set -o pipefail
    # The restored shell legitimately rereads plugin files, so access time is
    # excluded. O_NOATIME keeps this audit itself read-only; ctime remains in
    # the pax records to detect metadata replacement or mutation.
    /usr/bin/env -u TAR_OPTIONS /usr/bin/tar \
      --atime-preserve=system --one-file-system --sort=name --format=posix --numeric-owner \
      --acls --xattrs --xattrs-include='*' \
      --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime' \
      -cf - -C "$root" . | sha256sum
  ) >"$destination"; then
    return 1
  fi
  read -r digest unused <"$destination" || return 1
  [[ $digest =~ ^[0-9a-f]{64}$ && $unused == - ]]
}

run_isolated() {
  HOME=$isolated_home XDG_CONFIG_HOME=$isolated_config_home \
    XDG_CACHE_HOME=$isolated_cache_home XDG_DATA_HOME=$isolated_data_home \
    XDG_STATE_HOME=$isolated_state_home CODEX_HOME=$isolated_home/.codex \
    CLAUDE_CONFIG_DIR=$isolated_home/.claude \
    FIREWORKS_AUTH_PATH=$isolated_config_home/fireworks/auth.ini \
    FIREWORKS_API_KEY= FIREWORKS_ACCOUNT_ID= OPENAI_API_KEY= CODEX_API_KEY= \
    ANTHROPIC_API_KEY= ANTHROPIC_AUTH_TOKEN= "$@"
}

run_shell_config_mutation() {
  local status interrupted=0 mutation_started=0 requested_bar_position="" resulting_bar_position=""
  if (( $# == 4 )) && [[ $1 == omarchy && $2 == bar && $3 == position &&
    $4 =~ ^(top|bottom|left|right)$ ]]; then
    requested_bar_position=$4
  fi
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  if [[ -f $shell_config && ! -L $shell_config && $(stat -c '%u:%a' -- "$shell_config") == "$UID:600" ]] &&
    [[ -n $shell_hash_expected && $(sha256_file "$shell_config") == "$shell_hash_expected" ]]; then
    mutation_started=1
    run_isolated timeout --kill-after=1s 5s "$@"
    status=$?
  else
    status=1
  fi
  if (( mutation_started )) && [[ -f $shell_config && ! -L $shell_config && $(stat -c '%u:%a' -- "$shell_config") == "$UID:600" ]]; then
    shell_hash_expected=$(sha256_file "$shell_config")
    shell_canonical_hash_expected=$(canonical_json_file_hash "$shell_config")
    if [[ -n $requested_bar_position ]]; then
      resulting_bar_position=$(jq -er '.bar.position' "$shell_config" 2>/dev/null)
      if [[ $resulting_bar_position == "$requested_bar_position" ]]; then
        bar_position_last_expected=$resulting_bar_position
      fi
    fi
  elif (( mutation_started )); then
    status=1
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  if (( status == 0 )) && ! wait_for_effective_shell_config "$shell_canonical_hash_expected"; then
    return 1
  fi
  return "$status"
}

create_owned_directory() {
  local path=$1 mode=$2 identity_variable=$3 expected_parent_identity=$4
  local manifest_destination=${5:-} manifest_valid_variable=${6:-}
  local parent status interrupted=0 identity=""
  parent=$(dirname -- "$path") || return 1
  [[ -d $parent && ! -L $parent && $(file_identity "$parent") == "$expected_parent_identity" ]] ||
    return 1
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  mkdir -m "$mode" -- "$path"
  status=$?
  if [[ -d $parent && ! -L $parent && $(file_identity "$parent") == "$expected_parent_identity" &&
    -d $path && ! -L $path && $(stat -c '%u' -- "$path") == "$UID" ]] &&
    { (( status == 0 )) || (( interrupted != 0 )); }; then
    identity=$(file_identity "$path")
    printf -v "$identity_variable" '%s' "$identity"
    if [[ -n $manifest_destination && -n $manifest_valid_variable ]]; then
      if tree_manifest "$path" "$manifest_destination"; then
        printf -v "$manifest_valid_variable" '%s' 1
      else
        status=1
      fi
    fi
    if (( status != 0 )) || [[ $(stat -c '%a' -- "$path") != "$mode" ]]; then
      status=1
    fi
  else
    status=1
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

install_owned_file() {
  local source=$1 target=$2 mode=$3 identity_variable=$4 expected_parent_identity=$5
  local parent status interrupted=0 identity=""
  parent=$(dirname -- "$target") || return 1
  [[ -d $parent && ! -L $parent && $(file_identity "$parent") == "$expected_parent_identity" ]] ||
    return 1
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  install -m "$mode" -- "$source" "$target"
  status=$?
  if [[ -d $parent && ! -L $parent && $(file_identity "$parent") == "$expected_parent_identity" &&
    -f $target && ! -L $target && $(stat -c '%u' -- "$target") == "$UID" ]]; then
    identity=$(file_identity "$target")
    printf -v "$identity_variable" '%s' "$identity"
    if (( status != 0 )) || [[ $(stat -c '%a' -- "$target") != "$mode" ]]; then
      status=1
    fi
  else
    status=1
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

copy_plugin_tree() {
  local status interrupted=0 source_mode
  local source_manifest_after_copy="$evidence_dir/plugin-source.after-copy.manifest"
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  cp -a -- "$plugin_source/." "$plugin_target/"
  status=$?
  source_mode=$(stat -c '%a' -- "$plugin_source") || status=1
  chmod "$source_mode" -- "$plugin_target" || status=1
  plugin_target_manifest_valid=0
  if plugin_tree_matches_frozen_manifest "$plugin_target" "$plugin_target_manifest"; then
    plugin_target_manifest_valid=1
  else
    status=1
  fi
  if ! plugin_tree_matches_frozen_manifest \
    "$plugin_source" "$source_manifest_after_copy"; then
    status=1
  fi
  if (( status != 0 )) ||
    ! cmp -s -- "$plugin_source_manifest" "$source_manifest_after_copy" ||
    ! cmp -s -- "$source_manifest_after_copy" "$plugin_target_manifest"; then
    status=1
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

start_mock_server() {
  local status=0 interrupted=0 attempt current_pgid current_sid current_uid
  local candidate_socket_identity=""
  [[ -d $production_runtime && ! -L $production_runtime &&
    $(file_identity "$production_runtime") == "$production_runtime_identity" &&
    ! -e $display_socket && ! -L $display_socket &&
    -z $display_socket_identity ]] || return 1
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e

  mock_started=1
  setsid socat "UNIX-LISTEN:$display_socket,fork,mode=0600" \
    "EXEC:$mock_handler,nofork" 2>"$evidence_dir/mock-server.stderr" &
  mock_pid=$!
  mock_pgid=$mock_pid
  mock_pid_start=""
  for (( attempt = 0; attempt < 50; attempt++ )); do
    if [[ -z $mock_pid_start ]]; then
      mock_pid_start=$(awk '{print $22}' "/proc/$mock_pid/stat" 2>/dev/null)
    fi
    current_pgid=$(ps -o pgid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    current_sid=$(ps -o sid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    current_uid=$(ps -o uid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    if [[ -n $mock_pid_start && $current_pgid == "$mock_pgid" &&
      $current_sid == "$mock_pgid" && $current_uid == "$UID" ]]; then
      break
    fi
    kill -0 "$mock_pid" 2>/dev/null || break
    sleep 0.02
  done
  if [[ -z $mock_pid_start || $current_pgid != "$mock_pgid" ||
    $current_sid != "$mock_pgid" || $current_uid != "$UID" ]]; then
    status=1
  fi

  for (( attempt = 0; attempt < 50; attempt++ )); do
    if [[ -S $display_socket && ! -L $display_socket ]] &&
      [[ -d $production_runtime && ! -L $production_runtime &&
        $(file_identity "$production_runtime") == "$production_runtime_identity" ]] &&
      [[ $(stat -c '%u:%a' -- "$display_socket" 2>/dev/null) == "$UID:600" ]]; then
      candidate_socket_identity=$(file_identity "$display_socket" 2>/dev/null) ||
        candidate_socket_identity=""
      if [[ -n $candidate_socket_identity ]]; then
        break
      fi
    fi
    kill -0 "$mock_pid" 2>/dev/null || break
    sleep 0.1
  done
  if [[ -z $candidate_socket_identity ]]; then
    status=1
  fi
  for (( attempt = 0; attempt < 50 && ${#candidate_socket_identity} > 0; attempt++ )); do
    if mock_listener_owns_display_socket &&
      [[ $(file_identity "$display_socket" 2>/dev/null) == "$candidate_socket_identity" ]]; then
      display_socket_identity=$candidate_socket_identity
      break
    fi
    kill -0 "$mock_pid" 2>/dev/null || break
    sleep 0.02
  done
  if [[ $display_socket_identity != "$candidate_socket_identity" ]]; then
    status=1
  fi
  trap '' HUP INT TERM

  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

mock_leader_identity_matches() {
  local current_pgid current_sid current_uid current_start executable argument
  local -a arguments=()
  [[ $mock_pid =~ ^[1-9][0-9]*$ && $mock_pgid == "$mock_pid" &&
    $mock_pid_start =~ ^[1-9][0-9]*$ && -r /proc/$mock_pid/cmdline &&
    -L /proc/$mock_pid/exe ]] || return 1
  current_pgid=$(ps -o pgid= -p "$mock_pid" 2>/dev/null | tr -d ' ') || return 1
  current_sid=$(ps -o sid= -p "$mock_pid" 2>/dev/null | tr -d ' ') || return 1
  current_uid=$(ps -o uid= -p "$mock_pid" 2>/dev/null | tr -d ' ') || return 1
  current_start=$(awk '{print $22}' "/proc/$mock_pid/stat" 2>/dev/null) || return 1
  executable=$(readlink -f -- "/proc/$mock_pid/exe" 2>/dev/null) || return 1
  while IFS= read -r -d '' argument; do
    arguments+=("$argument")
  done </proc/"$mock_pid"/cmdline
  [[ $current_pgid == "$mock_pgid" && $current_sid == "$mock_pgid" &&
    $current_uid == "$UID" && $current_start == "$mock_pid_start" &&
    $executable == /usr/bin/socat1 && ${#arguments[@]} == 3 &&
    ${arguments[0]} == socat &&
    ${arguments[1]} == "UNIX-LISTEN:$display_socket,fork,mode=0600" &&
    ${arguments[2]} == "EXEC:$mock_handler,nofork" ]]
}

mock_listener_owns_display_socket() {
  local descriptor link inode found=0
  local -a socket_inodes=()
  [[ -d $production_runtime && ! -L $production_runtime &&
    $(file_identity "$production_runtime") == "$production_runtime_identity" ]] || return 1
  mock_leader_identity_matches || return 1
  mapfile -t socket_inodes < <(
    awk -v path="$display_socket" '$8 == path { print $7 }' /proc/net/unix
  )
  (( ${#socket_inodes[@]} == 1 )) || return 1
  inode=${socket_inodes[0]}
  [[ $inode =~ ^[1-9][0-9]*$ ]] || return 1
  for descriptor in /proc/"$mock_pid"/fd/*; do
    link=$(readlink -- "$descriptor" 2>/dev/null) || continue
    [[ $link == "socket:[$inode]" ]] && found=1
  done
  (( found == 1 )) || return 1
  mock_leader_identity_matches
}

mock_group_state() {
  local pid pgid sid uid extra current_pgid current_sid current_uid current_start
  local found=0 row_count=0 snapshot="$evidence_dir/.mock-process-table"
  [[ $mock_pid =~ ^[1-9][0-9]*$ && $mock_pgid =~ ^[1-9][0-9]*$ &&
    $mock_pid == "$mock_pgid" && $mock_pid_start =~ ^[1-9][0-9]*$ ]] || return 2

  if ! ps -eo pid=,pgid=,sid=,uid= >"$snapshot"; then
    return 2
  fi
  [[ -f $snapshot && ! -L $snapshot &&
    $(stat -c '%u:%a' -- "$snapshot" 2>/dev/null) == "$UID:600" ]] || return 2

  while read -r pid pgid sid uid extra; do
    [[ -z $extra && $pid =~ ^[1-9][0-9]*$ && $pgid =~ ^[0-9]+$ &&
      $sid =~ ^[0-9]+$ && $uid =~ ^[0-9]+$ ]] || return 2
    row_count=$((row_count + 1))
    [[ $pgid == "$mock_pgid" ]] || continue
    found=1
    [[ $sid == "$mock_pgid" && $uid == "$UID" ]] || return 2
  done <"$snapshot"
  (( row_count > 0 )) || return 2
  (( found )) || return 1

  if [[ -d /proc/$mock_pid ]]; then
    current_pgid=$(ps -o pgid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    current_sid=$(ps -o sid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    current_uid=$(ps -o uid= -p "$mock_pid" 2>/dev/null | tr -d ' ')
    current_start=$(awk '{print $22}' "/proc/$mock_pid/stat" 2>/dev/null)
    [[ $current_pgid == "$mock_pgid" && $current_sid == "$mock_pgid" &&
      $current_uid == "$UID" && $current_start == "$mock_pid_start" ]] || return 2
  fi
  return 0
}

reap_mock_leader_if_exited() {
  local state
  [[ $mock_pid =~ ^[1-9][0-9]*$ && -r /proc/$mock_pid/stat ]] || return 0
  state=$(awk '{print $3}' "/proc/$mock_pid/stat" 2>/dev/null)
  if [[ $state == Z ]]; then
    wait "$mock_pid" 2>/dev/null || true
  fi
}

transient_cgroup_is_quiet() {
  local control_group=$1 cgroup_root populated=""
  [[ -z $control_group ]] && return 0
  [[ $control_group == /user.slice/* && $control_group != *..* &&
    $control_group != *//* ]] || return 1
  cgroup_root="/sys/fs/cgroup$control_group"
  [[ -d $cgroup_root ]] || return 0
  [[ -r $cgroup_root/cgroup.events ]] || return 1
  populated=$(awk '$1 == "populated" { print $2 }' "$cgroup_root/cgroup.events") || return 1
  [[ $populated == 0 ]]
}

transient_unit_quiescent_sample() {
  local state="" key value load="" active="" main_pid="" control_group="" job=""
  local load_count=0 active_count=0 main_count=0 cgroup_count=0 job_count=0
  state=$(systemctl_user_query show -p LoadState -p ActiveState -p MainPID \
    -p ControlGroup -p Job -- "$transient_unit" 2>/dev/null) || return 1
  while IFS='=' read -r key value; do
    case $key in
      LoadState) load=$value; load_count=$((load_count + 1)) ;;
      ActiveState) active=$value; active_count=$((active_count + 1)) ;;
      MainPID) main_pid=$value; main_count=$((main_count + 1)) ;;
      ControlGroup) control_group=$value; cgroup_count=$((cgroup_count + 1)) ;;
      Job) job=$value; job_count=$((job_count + 1)) ;;
      *) return 1 ;;
    esac
  done <<<"$state"
  [[ $load_count == 1 && $active_count == 1 && $main_count == 1 &&
    $cgroup_count == 1 && $job_count == 1 ]] || return 1
  [[ $load == not-found || $load == loaded ]] || return 1
  [[ $active == inactive || $active == failed ]] || return 1
  [[ $main_pid == 0 && -z $job ]] || return 1
  if [[ -n $transient_control_group && -n $control_group &&
    $control_group != "$transient_control_group" ]]; then
    return 1
  fi
  transient_cgroup_is_quiet "$control_group" || return 1
  transient_cgroup_is_quiet "$transient_control_group"
}

transient_unit_quiescent() {
  if (( transient_submission_pending && ! transient_submission_absence_proven )); then
    return 1
  fi
  transient_unit_quiescent_sample
}

no_readable_transient_token_processes() {
  local process entry
  for process in /proc/[1-9][0-9]*; do
    [[ -d $process ]] || continue
    {
      while IFS= read -r -d '' entry; do
        [[ $entry == "OAB_LIVE_HARNESS_TOKEN=$transient_token" ]] && return 1
      done <"$process/environ"
    } 2>/dev/null || true
  done
  return 0
}

prove_transient_submission_stably_absent() {
  local attempt state="" key value load="" active="" main_pid="" control_group="" job=""
  local load_count active_count main_count cgroup_count job_count stable=0
  local -a temporary_pids=()
  (( transient_submission_pending )) || return 1
  no_readable_transient_token_processes || return 1
  mapfile -t temporary_pids < <(list_temporary_binary_pids)
  (( ${#temporary_pids[@]} == 0 )) || return 1
  for (( attempt = 0; attempt < 30; attempt++ )); do
    load="" active="" main_pid="" control_group="" job=""
    load_count=0 active_count=0 main_count=0 cgroup_count=0 job_count=0
    state=$(timeout --kill-after=0.1s 0.3s systemctl --user show \
      -p LoadState -p ActiveState -p MainPID -p ControlGroup -p Job -- \
      "$transient_unit" 2>/dev/null) || return 1
    while IFS='=' read -r key value; do
      case $key in
        LoadState) load=$value; load_count=$((load_count + 1)) ;;
        ActiveState) active=$value; active_count=$((active_count + 1)) ;;
        MainPID) main_pid=$value; main_count=$((main_count + 1)) ;;
        ControlGroup) control_group=$value; cgroup_count=$((cgroup_count + 1)) ;;
        Job) job=$value; job_count=$((job_count + 1)) ;;
        *) return 1 ;;
      esac
    done <<<"$state"
    if [[ $load_count == 1 && $active_count == 1 && $main_count == 1 &&
      $cgroup_count == 1 && $job_count == 1 &&
      $load == not-found && $active == inactive && $main_pid == 0 &&
      -z $control_group && -z $job ]] &&
      transient_cgroup_is_quiet "$transient_control_group"; then
      stable=$((stable + 1))
      if (( stable >= 20 )); then
        no_readable_transient_token_processes || return 1
        mapfile -t temporary_pids < <(list_temporary_binary_pids)
        (( ${#temporary_pids[@]} == 0 )) || return 1
        transient_submission_absence_proven=1
        return 0
      fi
    else
      stable=0
    fi
    sleep 0.1
  done
  return 1
}

transient_unit_is_owned() {
  local state="" key value id="" transient="" fragment="" exec_start="" environment=""
  local control_group="" invocation="" job=""
  local exec_payload="" exec_argv="" exec_tail="" expected_exec_argv=""
  local expected_fragment=""
  local id_count=0 transient_count=0 fragment_count=0 exec_count=0 environment_count=0
  local cgroup_count=0 invocation_count=0 job_count=0
  state=$(systemctl_user_query show -p Id -p Transient -p FragmentPath -p ExecStart \
    -p Environment -p ControlGroup -p InvocationID -p Job -- "$transient_unit" 2>/dev/null) ||
    return 1
  while IFS='=' read -r key value; do
    case $key in
      Id) id=$value; id_count=$((id_count + 1)) ;;
      Transient) transient=$value; transient_count=$((transient_count + 1)) ;;
      FragmentPath) fragment=$value; fragment_count=$((fragment_count + 1)) ;;
      ExecStart) exec_start=$value; exec_count=$((exec_count + 1)) ;;
      Environment) environment=$value; environment_count=$((environment_count + 1)) ;;
      ControlGroup) control_group=$value; cgroup_count=$((cgroup_count + 1)) ;;
      InvocationID) invocation=$value; invocation_count=$((invocation_count + 1)) ;;
      Job) job=$value; job_count=$((job_count + 1)) ;;
      *) return 1 ;;
    esac
  done <<<"$state"
  [[ $id_count == 1 && $transient_count == 1 && $fragment_count == 1 &&
    $exec_count == 1 && $environment_count == 1 && $cgroup_count == 1 &&
    $invocation_count == 1 && $job_count == 1 && ${#job} -le 256 ]] || return 1
  expected_exec_argv="/usr/bin/bwrap --die-with-parent --unshare-user --uid $UID --gid $(id -g) --unshare-net --ro-bind / / --dev-bind /dev /dev --proc /proc --tmpfs /tmp --bind $XDG_RUNTIME_DIR $XDG_RUNTIME_DIR --ro-bind $temporary_binary $temporary_binary --ro-bind $evidence_dir $evidence_dir --bind $isolated_home $isolated_home --bind $real_state_root $state_bridge --ro-bind $safe_shell_default /usr/share/omarchy/config/omarchy/shell.json -- $namespace_wrapper"
  expected_fragment="$XDG_RUNTIME_DIR/systemd/transient/$transient_unit"
  [[ $exec_start == '{ path=/usr/bin/bwrap ; argv[]='* ]] || return 1
  exec_payload=${exec_start#'{ path=/usr/bin/bwrap ; argv[]='}
  [[ $exec_payload == *' ; ignore_errors='* ]] || return 1
  exec_argv=${exec_payload%%' ; ignore_errors='*}
  exec_tail=${exec_payload#*' ; ignore_errors='}
  [[ $exec_argv == "$expected_exec_argv" &&
    $exec_tail == 'no ; start_time=['*' ; stop_time=['*' ; pid='*' ; code='*' ; status='*' }' &&
    $exec_tail != *'argv[]='* && $exec_tail != *'path='* ]] || return 1
  [[ $id == "$transient_unit" && $transient == yes && $fragment == "$expected_fragment" &&
    " $environment " == *" OMARCHY_AI_BAR_EXECUTABLE=$temporary_binary "* &&
    " $environment " == *" OMARCHY_AI_BAR_DISPLAY_SOCKET=$display_socket "* &&
    " $environment " == *" OAB_LIVE_HARNESS_TOKEN=$transient_token "* &&
    " $environment " == *" OAB_SAFE_SHELL_DEFAULT=$safe_shell_default "* &&
    " $environment " == *" OAB_REAL_STATE_ROOT=$real_state_root "* &&
    " $environment " == *" OAB_STATE_BRIDGE=$state_bridge "* &&
    " $environment " == *" OAB_OUTER_UID=$UID "* &&
    " $environment " == *" OMARCHY_PATH=/usr/share/omarchy "* &&
    " $environment " == *" PATH=/usr/share/omarchy/bin:/usr/bin "* &&
    " $environment " == *" HOME=$isolated_home "* &&
    " $environment " == *" XDG_CONFIG_HOME=$isolated_config_home "* &&
    " $environment " == *" XDG_CACHE_HOME=$isolated_cache_home "* &&
    " $environment " == *" XDG_DATA_HOME=$isolated_data_home "* &&
    " $environment " == *" XDG_STATE_HOME=$isolated_state_home "* &&
    " $environment " == *" CODEX_HOME=$isolated_home/.codex "* &&
    " $environment " == *" CLAUDE_CONFIG_DIR=$isolated_home/.claude "* &&
    " $environment " == *" FIREWORKS_AUTH_PATH=$isolated_config_home/fireworks/auth.ini "* &&
    " $environment " == *" FIREWORKS_API_KEY= "* &&
    " $environment " == *" FIREWORKS_ACCOUNT_ID= "* &&
    " $environment " == *" OPENAI_API_KEY= "* &&
    " $environment " == *" CODEX_API_KEY= "* &&
    " $environment " == *" ANTHROPIC_API_KEY= "* &&
    " $environment " == *" ANTHROPIC_AUTH_TOKEN= "* &&
    " $environment " == *" LD_PRELOAD= "* &&
    " $environment " == *" LD_AUDIT= "* &&
    " $environment " == *" LD_LIBRARY_PATH= "* &&
    " $environment " == *" GLIBC_TUNABLES= "* &&
    " $environment " == *" QT_PLUGIN_PATH= "* &&
    " $environment " == *" QT_QPA_PLATFORM_PLUGIN_PATH= "* &&
    " $environment " == *" QML_IMPORT_PATH= "* &&
    " $environment " == *" QML2_IMPORT_PATH= "* &&
    " $environment " == *" QML_PLUGIN_PATH= "* &&
    " $environment " == *" QML_DISK_CACHE_PATH= "* &&
    " $environment " == *" QML_FORCE_DISK_CACHE= "* &&
    " $environment " == *" QML_DISABLE_DISK_CACHE=1 "* &&
    " $environment " == *" BASH_ENV= "* &&
    " $environment " == *" ENV= "* &&
    " $environment " == *" BASH_COMPAT= "* &&
    " $environment " == *" FUNCNEST= "* &&
    " $environment " == *" TAR_OPTIONS= "* &&
    " $environment " == *" RIPGREP_CONFIG_PATH= "* ]] || return 1
  if [[ -n $control_group ]]; then
    [[ $control_group == */"$transient_unit" && $control_group != *..* &&
      $control_group != *//* ]] || return 1
  else
    (( transient_submission_pending )) || return 1
  fi
  if [[ -n $transient_control_group && $control_group != "$transient_control_group" ]]; then
    return 1
  fi
  if [[ -n $transient_invocation ]]; then
    [[ $invocation == "$transient_invocation" ]] || return 1
  elif (( transient_submission_pending )) && [[ -z $invocation ]]; then
    :
  else
    [[ $invocation =~ ^[0-9a-f]{32}$ ]] || return 1
  fi
}

stop_owned_transient_until_quiet() {
  local attempt max_attempts=30
  (( ${cleanup_active:-0} )) && max_attempts=5
  if (( transient_submission_pending )) && prove_transient_submission_stably_absent; then
    return 0
  fi
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    transient_unit_quiescent && return 0
    if transient_unit_is_owned; then
      systemctl_user_query --no-block stop "$transient_unit" \
        >>"$evidence_dir/transient-stop.cleanup.log" 2>&1 || true
    fi
    sleep 0.1
  done
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    transient_unit_quiescent && return 0
    if transient_unit_is_owned; then
      systemctl_user_query kill --kill-whom=all --signal=KILL "$transient_unit" \
        >>"$evidence_dir/transient-stop.cleanup.log" 2>&1 || true
    fi
    sleep 0.1
  done
  if (( transient_submission_pending )); then
    prove_transient_submission_stably_absent
    return
  fi
  transient_unit_quiescent
}

reprove_transient_quiescence() {
  local attempt stable=0
  (( ! transient_stop_unresolved )) || return 1
  if (( transient_submission_pending && ! transient_submission_absence_proven )); then
    return 1
  fi
  for (( attempt = 0; attempt < 4; attempt++ )); do
    if transient_unit_quiescent_sample && no_readable_transient_token_processes; then
      stable=$((stable + 1))
      (( stable >= 3 )) && return 0
    else
      stable=0
    fi
    sleep 0.1
  done
  return 1
}

tree_manifest() {
  local root=$1 destination=$2 relative digest unused metadata escaped listing status=0
  : >"$destination"
  listing=$(mktemp --tmpdir="$(dirname -- "$destination")" .tree-objects.XXXXXXXX) || return 1
  if ! (
    cd -- "$root" && find . -xdev -print0 | sort -z
  ) >"$listing"; then
    rm -f -- "$listing"
    return 1
  fi
  (
    cd -- "$root"
    while IFS= read -r -d '' relative; do
      printf -v escaped '%q' "$relative"
      if [[ -L $relative ]]; then
        return 1
      elif [[ -d $relative ]]; then
        metadata=$(stat -c '%a:%u:%g' -- "$relative") || return 1
        printf 'd %s %s\n' "$metadata" "$escaped"
      elif [[ -f $relative ]]; then
        metadata=$(stat -c '%a:%u:%g:%s' -- "$relative") || return 1
        digest=$(sha256_file "$relative") || return 1
        printf 'f %s %s %s\n' "$metadata" "$digest" "$escaped"
      else
        return 1
      fi
    done <"$listing"
  ) >"$destination"
  status=$?
  rm -f -- "$listing" || status=1
  return "$status"
}

plugin_tree_matches_frozen_manifest() {
  local root=$1 destination=$2 unexpected="" manifest_sha256=""
  local -a names=()
  [[ -d $root && ! -L $root ]] || return 1
  unexpected=$(find "$root" -xdev -mindepth 1 ! -type f -print -quit) || return 1
  [[ -z $unexpected ]] || return 1
  mapfile -d '' -t names < <(
    cd -- "$root" || exit 1
    find . -xdev -mindepth 1 -maxdepth 1 -type f -printf '%P\0' | LC_ALL=C sort -z
  )
  [[ ${#names[@]} == 13 && ${names[0]} == AppSettings.qml &&
    ${names[1]} == BarWidget.qml && ${names[2]} == InlineChart.qml &&
    ${names[3]} == Panel.qml && ${names[4]} == Protocol.js &&
    ${names[5]} == ProviderCatalog.qml && ${names[6]} == ProviderDetail.qml &&
    ${names[7]} == QuotaMetric.qml && ${names[8]} == Service.qml &&
    ${names[9]} == SettingsHome.qml && ${names[10]} == UsageExtraSection.qml &&
    ${names[11]} == UsageView.qml && ${names[12]} == manifest.json ]] || return 1
  tree_manifest "$root" "$destination" || return 1
  manifest_sha256=$(sha256_file "$destination") || return 1
  [[ $manifest_sha256 == "$expected_plugin_manifest_sha256" ]]
}

verify_real_user_state() {
  local label=$1 acl xattr digest current_stat
  [[ $label =~ ^[a-z0-9-]+$ ]] || return 1
  [[ -f $real_shell_config && ! -L $real_shell_config &&
    $(sha256_file "$real_shell_config") == "$real_shell_hash_before" ]] || return 1
  current_stat=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' \
    -- "$real_shell_config") || return 1
  [[ $current_stat == "$real_shell_stat_before" ]] || return 1
  acl="$evidence_dir/shell.real.$label.acl"
  xattr="$evidence_dir/shell.real.$label.xattr"
  digest="$evidence_dir/plugins.real.$label.sha256"
  getfacl -cp --absolute-names "$real_shell_config" >"$acl" 2>/dev/null || return 1
  getfattr -d -m- --absolute-names "$real_shell_config" >"$xattr" 2>/dev/null || return 1
  cmp -s -- "$real_shell_acl_before" "$acl" || return 1
  cmp -s -- "$real_shell_xattr_before" "$xattr" || return 1
  [[ ! -e $real_plugin_target && ! -L $real_plugin_target &&
    -d $real_plugin_root && ! -L $real_plugin_root &&
    $(file_identity "$real_plugin_root") == "$real_plugin_root_identity" ]] || return 1
  tree_digest_noatime "$real_plugin_root" "$digest" || return 1
  cmp -s -- "$real_plugin_digest_before" "$digest"
}

file_envelope_matches() {
  local path=$1 expected_hash=$2 expected_stat=$3 acl_before=$4 xattr_before=$5 label=$6
  local acl_after xattr_after current_stat
  [[ $label =~ ^[a-z0-9.-]+$ && -f $path && ! -L $path ]] || return 1
  [[ $(sha256_file "$path") == "$expected_hash" ]] || return 1
  current_stat=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' -- "$path") || return 1
  [[ $current_stat == "$expected_stat" ]] || return 1
  acl_after="$evidence_dir/$label.acl"
  xattr_after="$evidence_dir/$label.xattr"
  getfacl -cp --absolute-names "$path" >"$acl_after" 2>/dev/null || return 1
  getfattr -d -m- --absolute-names "$path" >"$xattr_after" 2>/dev/null || return 1
  cmp -s -- "$acl_before" "$acl_after" && cmp -s -- "$xattr_before" "$xattr_after"
}

normalized_monitor_state() {
  jq -S '
    [ .[] ] | sort_by(.name)
  '
}

normalized_workspace_state() {
  jq -S '
    [ .[] | {
        id, name, monitor, monitorID, windows, hasfullscreen, ispersistent,
        lastwindow, tiledLayout
      } ] | sort_by(.id, .name)
  '
}

normalized_client_state() {
  jq -S '
    [ .[]
      | del(.title, .class, .initialTitle, .initialClass, .xdgDescription, .xdgTag)
    ] | sort_by(.address)
  '
}

capture_normalized_monitor_state() {
  local destination=$1
  (set -o pipefail; hyprctl_bounded monitors all -j | normalized_monitor_state) >"$destination"
}

capture_normalized_workspace_state() {
  local destination=$1
  (set -o pipefail; hyprctl_bounded workspaces -j | normalized_workspace_state) >"$destination"
}

capture_normalized_client_state() {
  local destination=$1
  (set -o pipefail; hyprctl_bounded clients -j | normalized_client_state) >"$destination"
}

capture_quiescent_shell_layers() {
  local destination=$1 expected_pid=$2
  [[ $expected_pid =~ ^[1-9][0-9]*$ ]] || return 1
  (set -o pipefail; hyprctl_bounded layers -j | jq -Se --argjson pid "$expected_pid" '
    [ to_entries[] as $monitor
      | $monitor.value.levels | to_entries[] as $level
      | $level.value[]
      | {
          monitor: $monitor.key,
          level: ($level.key | tonumber),
          namespace, pid, x, y, w, h, alpha
        }
    ] as $layers
    | if ($layers | length) == 2
        and all($layers[]; .pid == $pid)
        and ([$layers[] | select(.namespace == "omarchy-background")] | length) == 1
        and ([$layers[] | select(.namespace == "omarchy-bar")] | length) == 1
        and all($layers[]; .namespace == "omarchy-background" or .namespace == "omarchy-bar")
      then [$layers[] | del(.pid)] | sort_by(.monitor, .level, .namespace)
      else error("shell layer UI is not quiescent") end
  ' ) >"$destination"
}

monitor_watcher_scope_count() {
  set -o pipefail
  systemctl_user_query list-units --all --type=scope --output=json 2>/dev/null |
    jq '[.[] | select(.description == "omarchy-hyprland-monitor-watch" and .active == "active")] | length'
}

monitor_manager_identity_matches() {
  local invocation main_pid control_group start executable owner
  local executable_identity="" package_identity=""
  invocation=$(systemctl_user_query show -p InvocationID --value "$monitor_manager_unit" 2>/dev/null) || return 1
  main_pid=$(systemctl_user_query show -p MainPID --value "$monitor_manager_unit" 2>/dev/null) || return 1
  control_group=$(systemctl_user_query show -p ControlGroup --value "$monitor_manager_unit" 2>/dev/null) || return 1
  [[ $invocation == "$monitor_manager_invocation_before" &&
    $main_pid == "$monitor_manager_pid_before" &&
    $control_group == "$monitor_manager_cgroup_before" &&
    $main_pid =~ ^[1-9][0-9]*$ && -r /proc/$main_pid/stat && -L /proc/$main_pid/exe ]] || return 1
  start=$(awk '{print $22}' "/proc/$main_pid/stat" 2>/dev/null) || return 1
  executable=$(readlink -f -- "/proc/$main_pid/exe" 2>/dev/null) || return 1
  executable_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$main_pid/exe" 2>/dev/null) || return 1
  package_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- /usr/bin/hyprmoncfgd 2>/dev/null) || return 1
  owner=$(stat -c '%u' -- "/proc/$main_pid" 2>/dev/null) || return 1
  [[ $start == "$monitor_manager_pid_start_before" &&
    $executable == /usr/bin/hyprmoncfgd && $owner == "$UID" &&
    $executable_identity == "$monitor_manager_executable_identity_before" &&
    $package_identity == "$monitor_manager_executable_identity_before" &&
    $(sha256_packaged_file /usr/bin/hyprmoncfgd) == "$expected_hyprmoncfgd_sha256" ]]
}

monitor_manager_running_exact() {
  local active="" substate="" freezer=""
  monitor_manager_identity_matches || return 1
  active=$(systemctl_user_query show -p ActiveState --value "$monitor_manager_unit" 2>/dev/null) ||
    return 1
  substate=$(systemctl_user_query show -p SubState --value "$monitor_manager_unit" 2>/dev/null) ||
    return 1
  freezer=$(systemctl_user_query show -p FreezerState --value "$monitor_manager_unit" 2>/dev/null) ||
    return 1
  [[ $active == active && $substate == running && $freezer == running ]]
}

monitor_manager_fingerprint() {
  systemctl_user_query show "$monitor_manager_unit" \
    -p Id -p LoadState -p UnitFileState -p FragmentPath -p ExecStart \
    -p Restart -p KillMode
}

hyprmoncfg_socket_is_owned_listener() {
  local listener_inode="" descriptor link
  local -a listener_inodes=()
  [[ -S $hyprmoncfg_socket && ! -L $hyprmoncfg_socket ]] || return 1
  [[ $(stat -c '%u:%a' -- "$hyprmoncfg_socket" 2>/dev/null) == "$UID:600" ]] || return 1
  mapfile -t listener_inodes < <(
    awk -v path="$hyprmoncfg_socket" \
      '$8 == path && $4 == "00010000" && $5 == "0001" && $6 == "01" { print $7 }' \
      /proc/net/unix
  )
  (( ${#listener_inodes[@]} == 1 )) || return 1
  listener_inode=${listener_inodes[0]}
  [[ $listener_inode =~ ^[1-9][0-9]*$ ]] || return 1
  for descriptor in /proc/"$monitor_manager_pid_before"/fd/*; do
    link=$(readlink -- "$descriptor" 2>/dev/null) || continue
    [[ $link == "socket:[$listener_inode]" ]] && return 0
  done
  return 1
}

hyprmoncfg_preview_is_clear() {
  local request_id="omarchy-ai-bar-live-status-$UID-$$" response=""
  hyprmoncfg_socket_is_owned_listener || return 1
  response=$(
    printf '%s\n' \
      "{\"type\":\"request\",\"protocol_version\":1,\"id\":\"$request_id\",\"method\":\"status\"}" |
      timeout --kill-after=0.1s 1s socat -T 0.5 - "UNIX-CONNECT:$hyprmoncfg_socket" \
        2>/dev/null
  ) || return 1
  (( ${#response} <= 1048576 )) || return 1
  [[ -n $response && $response != *$'\n'* ]] || return 1
  jq -e --arg id "$request_id" --arg version "${expected_hyprmoncfgd_version##* }" '
    (keys | sort) == [
      "id", "protocol_version", "result", "server_protocol_version", "type"
    ]
    and .type == "response" and .protocol_version == 1
    and .server_protocol_version == 1 and .id == $id
    and (.result | type) == "object" and .result.schema_version == 1
    and .result.version == $version
    and (.result.daemon | type) == "object"
    and .result.daemon.running == true
    and (.result.daemon.preview? == null)
  ' <<<"$response" >/dev/null
}

capture_hyprmoncfg_status() {
  local destination=$1 label=$2 request_id="" response=""
  [[ $label =~ ^[a-z0-9-]+$ && -n $destination ]] || return 1
  request_id="omarchy-ai-bar-live-$label-$UID-$$"
  hyprmoncfg_socket_is_owned_listener || return 1
  response=$(
    printf '%s\n' \
      "{\"type\":\"request\",\"protocol_version\":1,\"id\":\"$request_id\",\"method\":\"status\"}" |
      timeout --kill-after=0.1s 1s socat -T 0.5 - "UNIX-CONNECT:$hyprmoncfg_socket" \
        2>/dev/null
  ) || return 1
  (( ${#response} <= 1048576 )) || return 1
  [[ -n $response && $response != *$'\n'* ]] || return 1
  jq -Se --arg id "$request_id" --arg version "${expected_hyprmoncfgd_version##* }" '
    if (keys | sort) == [
        "id", "protocol_version", "result", "server_protocol_version", "type"
      ]
      and .type == "response" and .protocol_version == 1
      and .server_protocol_version == 1 and .id == $id
      and (.result | type) == "object"
      and (.result | keys | sort) == [
        "active_profile", "daemon", "monitors", "profiles",
        "recommended_profile", "schema_version", "version"
      ]
      and .result.schema_version == 1 and .result.version == $version
      and (.result.daemon | type) == "object"
      and .result.daemon.running == true
      and (.result.daemon.preview? == null)
      and (.result.monitors | type) == "array"
      and (.result.profiles | type) == "array"
      and (.result.active_profile == null or (.result.active_profile | type) == "object")
      and (.result.recommended_profile == null or
        (.result.recommended_profile | type) == "object")
    then .result else error("unexpected hyprmoncfg status envelope") end
  ' <<<"$response" >"$destination"
}

assert_headless_workspace_state() {
  local destination=$1 client_destination=$2 extra_id
  capture_normalized_workspace_state "$destination" || return 1
  capture_normalized_client_state "$client_destination" || return 1
  cmp -s -- "$clients_normalized_before" "$client_destination" || return 1
  jq -e --arg monitor "$headless_name" --slurpfile baseline "$workspaces_normalized_before" '
    ($baseline[0]) as $before
    | . as $current
    | ($current - $before) as $added
    | ($before - $current) as $missing
    | ($current | length) == ($before | length) + 1
      and ($missing | length) == 0
      and ($added | length) == 1
        and $added[0].monitor == $monitor
        and $added[0].windows == 0
        and $added[0].hasfullscreen == false
        and $added[0].ispersistent == false
  ' "$destination" >/dev/null || return 1
  extra_id=$(jq -er --slurpfile baseline "$workspaces_normalized_before" '
    (. - $baseline[0])
    | if length == 1 then .[0].id else empty end
  ' "$destination") || return 1
  [[ $extra_id =~ ^[1-9][0-9]*$ ]] || return 1
  headless_workspace_id=$extra_id
  jq -e --arg monitor "$headless_name" --argjson workspace "$headless_workspace_id" '
    any(.[]; .name == $monitor and .activeWorkspace.id == $workspace)
  ' "$monitors_configured" >/dev/null
}

manager_override_line() {
  set -o pipefail
  systemctl_user_query show-environment |
    sed -n '/^OMARCHY_AI_BAR_\(EXECUTABLE\|DISPLAY_SOCKET\)=/p'
}

manager_session_environment_matches() {
  local environment="" entry
  local omarchy_count=0 wayland_count=0 runtime_count=0 hyprland_count=0 home_count=0
  local config_count=0 cache_count=0 data_count=0 state_count=0
  environment=$(systemctl_user_query show-environment) || return 1
  while IFS= read -r entry; do
    case $entry in
      OMARCHY_PATH=*)
        omarchy_count=$((omarchy_count + 1))
        [[ $entry == OMARCHY_PATH=/usr/share/omarchy ]] || return 1
        ;;
      WAYLAND_DISPLAY=*)
        wayland_count=$((wayland_count + 1))
        [[ $entry == "WAYLAND_DISPLAY=$WAYLAND_DISPLAY" ]] || return 1
        ;;
      XDG_RUNTIME_DIR=*)
        runtime_count=$((runtime_count + 1))
        [[ $entry == "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" ]] || return 1
        ;;
      HYPRLAND_INSTANCE_SIGNATURE=*)
        hyprland_count=$((hyprland_count + 1))
        [[ $entry == "HYPRLAND_INSTANCE_SIGNATURE=$HYPRLAND_INSTANCE_SIGNATURE" ]] || return 1
        ;;
      HOME=*)
        home_count=$((home_count + 1))
        [[ $entry == "HOME=$HOME" ]] || return 1
        ;;
      XDG_CONFIG_HOME=*)
        config_count=$((config_count + 1))
        [[ $entry == "XDG_CONFIG_HOME=$real_xdg_config_home" ]] || return 1
        ;;
      XDG_CACHE_HOME=*)
        cache_count=$((cache_count + 1))
        [[ $entry == "XDG_CACHE_HOME=$real_xdg_cache_home" ]] || return 1
        ;;
      XDG_DATA_HOME=*)
        data_count=$((data_count + 1))
        [[ $entry == "XDG_DATA_HOME=$real_xdg_data_home" ]] || return 1
        ;;
      XDG_STATE_HOME=*)
        state_count=$((state_count + 1))
        [[ $entry == "XDG_STATE_HOME=$real_xdg_state_home" ]] || return 1
        ;;
      OMARCHY_AI_BAR_EXECUTABLE=*|OMARCHY_AI_BAR_DISPLAY_SOCKET=*|OAB_LIVE_HARNESS_TOKEN=*)
        return 1
        ;;
      BASH_ENV=*|ENV=*|SHELLOPTS=*|BASHOPTS=*|BASH_COMPAT=*|FUNCNEST=*|\
        BASH_FUNC_*%%=*|LD_*=*|GLIBC_TUNABLES=*|\
        QT_PLUGIN_PATH=*|QT_QPA_PLATFORM_PLUGIN_PATH=*|QML_*=*|QML2_IMPORT_PATH=*|\
        TAR_OPTIONS=*|RIPGREP_CONFIG_PATH=*)
        return 1
        ;;
    esac
  done <<<"$environment"
  [[ $omarchy_count == 1 && $wayland_count == 1 && $runtime_count == 1 &&
    $hyprland_count == 1 && $home_count == 1 && $config_count == 1 &&
    $cache_count == 1 && $data_count == 1 && $state_count == 1 ]]
}

process_has_no_effective_code_loading_environment() {
  local pid=$1 entry
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      LD_PRELOAD=|LD_AUDIT=|LD_LIBRARY_PATH=|GLIBC_TUNABLES=|\
        QT_PLUGIN_PATH=|QT_QPA_PLATFORM_PLUGIN_PATH=|QML_IMPORT_PATH=|QML2_IMPORT_PATH=|\
        QML_PLUGIN_PATH=|QML_DISK_CACHE_PATH=|QML_FORCE_DISK_CACHE=|\
        QML_DISABLE_DISK_CACHE=1|TAR_OPTIONS=|RIPGREP_CONFIG_PATH=)
        ;;
      BASH_ENV=*|ENV=*|SHELLOPTS=*|BASHOPTS=*|BASH_COMPAT=*|FUNCNEST=*|\
        BASH_FUNC_*%%=*|LD_*=*|GLIBC_TUNABLES=*|\
        QT_PLUGIN_PATH=*|QT_QPA_PLATFORM_PLUGIN_PATH=*|QML_*=*|QML2_IMPORT_PATH=*|\
        TAR_OPTIONS=*|RIPGREP_CONFIG_PATH=*)
        return 1
        ;;
    esac
  done </proc/"$pid"/environ
}

process_has_exact_transient_execution_environment() {
  local pid=$1 entry
  local preload_count=0 audit_count=0 library_count=0 tunables_count=0
  local qt_plugin_count=0 qt_platform_count=0 qml_count=0 qml2_count=0
  local qml_plugin_count=0 qml_cache_path_count=0 qml_force_count=0 qml_disable_count=0
  local tar_options_count=0 ripgrep_config_count=0 path_count=0
  process_has_no_effective_code_loading_environment "$pid" || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      LD_PRELOAD=) preload_count=$((preload_count + 1)) ;;
      LD_AUDIT=) audit_count=$((audit_count + 1)) ;;
      LD_LIBRARY_PATH=) library_count=$((library_count + 1)) ;;
      GLIBC_TUNABLES=) tunables_count=$((tunables_count + 1)) ;;
      QT_PLUGIN_PATH=) qt_plugin_count=$((qt_plugin_count + 1)) ;;
      QT_QPA_PLATFORM_PLUGIN_PATH=) qt_platform_count=$((qt_platform_count + 1)) ;;
      QML_IMPORT_PATH=) qml_count=$((qml_count + 1)) ;;
      QML2_IMPORT_PATH=) qml2_count=$((qml2_count + 1)) ;;
      QML_PLUGIN_PATH=) qml_plugin_count=$((qml_plugin_count + 1)) ;;
      QML_DISK_CACHE_PATH=) qml_cache_path_count=$((qml_cache_path_count + 1)) ;;
      QML_FORCE_DISK_CACHE=) qml_force_count=$((qml_force_count + 1)) ;;
      QML_DISABLE_DISK_CACHE=1) qml_disable_count=$((qml_disable_count + 1)) ;;
      TAR_OPTIONS=) tar_options_count=$((tar_options_count + 1)) ;;
      RIPGREP_CONFIG_PATH=) ripgrep_config_count=$((ripgrep_config_count + 1)) ;;
      PATH=*)
        path_count=$((path_count + 1))
        [[ $entry == PATH=/usr/share/omarchy/bin:/usr/bin ]] || return 1
        ;;
    esac
  done </proc/"$pid"/environ
  [[ $preload_count == 1 && $audit_count == 1 && $library_count == 1 &&
    $tunables_count == 1 && $qt_plugin_count == 1 && $qt_platform_count == 1 &&
    $qml_count == 1 && $qml2_count == 1 && $qml_plugin_count == 1 &&
    $qml_cache_path_count == 1 && $qml_force_count == 1 && $qml_disable_count == 1 &&
    $tar_options_count == 1 && $ripgrep_config_count == 1 && $path_count == 1 ]]
}

wait_for_shell() {
  local attempt max_attempts=25
  (( ${cleanup_active:-0} )) && max_attempts=8
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    if OMARCHY_SHELL_IPC_TIMEOUT=0.1s timeout --kill-after=0.1s 0.3s \
      omarchy-shell shell ping >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

bounded_shell_ipc() {
  OMARCHY_SHELL_IPC_TIMEOUT=0.3s timeout --kill-after=0.1s 0.8s omarchy-shell "$@"
}

shell_lock_state_is_clear() {
  local output=""
  output=$(bounded_shell_ipc lock status 2>/dev/null) || return 1
  jq -e '
    type == "object"
    and .locked == false
    and .requested == false
    and .pending == false
    and .sessionLocked == false
    and .secure == false
    and .authenticating == false
  ' <<<"$output" >/dev/null
}

session_is_safe_for_live_mutation() {
  session_is_confirmed_unlocked &&
    shell_lock_state_is_clear &&
    session_is_confirmed_unlocked
}

wait_for_session_safe_for_live_mutation() {
  local attempt
  for (( attempt = 0; attempt < 50; attempt++ )); do
    session_is_safe_for_live_mutation && return 0
    sleep 0.1
  done
  return 1
}

shell_lock_state_matches_compositor() {
  local before="" after="" output=""
  before=$(compositor_lock_state 2>/dev/null) || return 1
  output=$(bounded_shell_ipc lock status 2>/dev/null) || return 1
  after=$(compositor_lock_state 2>/dev/null) || return 1
  [[ $before == "$after" ]] || return 1
  if [[ $before == unlocked ]]; then
    jq -e '
      type == "object"
      and .locked == false
      and .requested == false
      and .pending == false
      and .sessionLocked == false
      and .secure == false
      and .authenticating == false
    ' <<<"$output" >/dev/null
  else
    jq -e '
      type == "object"
      and .locked == true
      and .requested == true
      and .sessionLocked == true
      and .secure == true
    ' <<<"$output" >/dev/null
  fi
}

wait_for_shell_lock_consistency() {
  local attempt max_attempts=100
  (( ${cleanup_active:-0} )) && max_attempts=5
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    shell_lock_state_matches_compositor && return 0
    sleep 0.1
  done
  return 1
}

isolated_plugin_policy_matches() {
  local plugins=""
  plugins=$(OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell listPlugins 2>/dev/null) || return 1
  jq -e --arg id "$plugin_id" '
    . as $plugins
    | any($plugins[]; .id == $id and (.kinds | index("service")) != null
        and (.kinds | index("bar-widget")) != null and .enabled == false)
      and any($plugins[]; .id == "omarchy.agents" and .enabled == false)
      and all([
        "omarchy.background", "omarchy.clipboard", "omarchy.emojis",
        "omarchy.idle", "omarchy.image-picker", "omarchy.notifications",
        "omarchy.reminders"
      ][]; . as $continuity_plugin
        | any($plugins[]; .id == $continuity_plugin and .enabled == true))
  ' <<<"$plugins" >/dev/null
}

wait_for_isolated_plugin_policy() {
  local attempt
  for (( attempt = 0; attempt < 50; attempt++ )); do
    isolated_plugin_policy_matches && return 0
    sleep 0.1
  done
  return 1
}

shell_pid() {
  hyprctl_bounded layers -j | jq -er '
    [ .[] | .levels | to_entries[] | .value[]
      | select(.namespace == "omarchy-bar") | .pid ]
    | unique
    | if length == 1 then .[0] else empty end
  '
}

quickshell_instance_is_exact() {
  local expected_pid=$1 registered_pid=""
  registered_pid=$(sole_packaged_quickshell_registry_pid) || return 1
  [[ $registered_pid == "$expected_pid" ]]
}

packaged_quickshell_registry_json() {
  local instances=""
  if (( ${cleanup_active:-0} )); then
    instances=$(timeout --kill-after=0.1s 0.5s quickshell list \
      -p /usr/share/omarchy/shell --any-display --json 2>/dev/null) || return 1
  else
    instances=$(timeout --kill-after=0.2s 2s quickshell list \
      -p /usr/share/omarchy/shell --any-display --json 2>/dev/null) || return 1
  fi
  # Quickshell 0.3.1 prints this exact successful text response instead of
  # JSON when the selected configuration has no instances. Normalize only the
  # frozen packaged-path sentinel; every other non-array response fails closed.
  if [[ $instances == "$expected_empty_quickshell_registry" ]]; then
    printf '[]\n'
    return 0
  fi
  jq -cse '
    if length == 1 and (.[0] | type) == "array" then .[0]
    else error("unexpected registry envelope")
    end
  ' <<<"$instances" 2>/dev/null
}

sole_packaged_quickshell_registry_pid() {
  local instances=""
  instances=$(packaged_quickshell_registry_json) || return 1
  jq -er '
    if length == 1
      and (. [0].pid | type) == "number"
      and .[0].pid >= 1 and .[0].pid <= 4194304
      and .[0].pid == (. [0].pid | floor)
      and .[0].config_path == "/usr/share/omarchy/shell/shell.qml"
      and (. [0].id | type == "string" and test("^[a-z0-9]+$"))
      and (. [0].shell_id | type == "string" and test("^[0-9a-f]{32}$"))
    then .[0].pid else empty end
  ' <<<"$instances"
}

quickshell_has_no_instances() {
  local instances=""
  instances=$(packaged_quickshell_registry_json) || return 1
  jq -e 'length == 0' <<<"$instances" >/dev/null
}

registry_is_exclusive_or_absent() {
  local expected_pid=$1
  [[ $expected_pid =~ ^[1-9][0-9]*$ ]] || return 1
  quickshell_has_no_instances || quickshell_instance_is_exact "$expected_pid"
}

wait_for_stable_no_quickshell_instances() {
  local attempt absence_streak=0 required=${1:-3}
  [[ $required =~ ^[1-9][0-9]*$ && $required -le 20 ]] || return 1
  for (( attempt = 0; attempt < 30; attempt++ )); do
    if quickshell_has_no_instances; then
      absence_streak=$((absence_streak + 1))
      (( absence_streak >= required )) && return 0
    else
      absence_streak=0
    fi
    sleep 0.1
  done
  return 1
}

packaged_shell_process_is_exact() {
  local pid=$1 expected_start=$2 start="" owner="" executable="" argument
  local -a arguments=()
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ &&
    -r /proc/$pid/stat && -r /proc/$pid/cmdline && -L /proc/$pid/exe ]] || return 1
  start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  owner=$(stat -c '%u' -- "/proc/$pid" 2>/dev/null) || return 1
  executable=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null) || return 1
  while IFS= read -r -d '' argument; do
    arguments+=("$argument")
  done </proc/"$pid"/cmdline
  [[ $start == "$expected_start" && $owner == "$UID" &&
    $executable == /usr/bin/quickshell && ${#arguments[@]} == 4 &&
    ${arguments[0]} == quickshell && ${arguments[1]} == -n &&
    ${arguments[2]} == -p && ${arguments[3]} == /usr/share/omarchy/shell ]]
}

process_task_is_same() {
  local pid=$1 expected_start=$2 start="" owner=""
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ &&
    -r /proc/$pid/stat ]] || return 1
  start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  owner=$(stat -c '%u' -- "/proc/$pid" 2>/dev/null) || return 1
  [[ $start == "$expected_start" && $owner == "$UID" ]]
}

process_task_is_absent_or_replaced() {
  local pid=$1 expected_start=$2 start=""
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -e /proc/$pid ]] || return 0
  [[ -r /proc/$pid/stat ]] || return 1
  start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  [[ $start =~ ^[1-9][0-9]*$ && $start != "$expected_start" ]]
}

original_shell_process_is_same() {
  packaged_shell_process_is_exact "$original_shell_pid" "$original_shell_pid_start"
}

packaged_shell_launcher_process_is_exact() {
  local pid=$1 expected_start=$2 start="" owner="" executable="" argument
  local -a arguments=()
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ &&
    -r /proc/$pid/stat && -r /proc/$pid/cmdline && -L /proc/$pid/exe ]] || return 1
  start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  owner=$(stat -c '%u' -- "/proc/$pid" 2>/dev/null) || return 1
  executable=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null) || return 1
  while IFS= read -r -d '' argument; do
    arguments+=("$argument")
  done </proc/"$pid"/cmdline
  [[ $start == "$expected_start" && $owner == "$UID" &&
    $executable == /usr/bin/bash && ${#arguments[@]} == 2 &&
    ${arguments[0]} == /bin/bash &&
    ${arguments[1]} == /usr/share/omarchy/bin/omarchy-launch-shell ]]
}

packaged_shell_launcher_process_is_running_exact() {
  local pid=$1 expected_start=$2 state=""
  packaged_shell_launcher_process_is_exact "$pid" "$expected_start" || return 1
  state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || return 1
  [[ $state != T && $state != t && $state != Z && $state != X && $state != x ]]
}

original_launcher_process_is_same() {
  packaged_shell_launcher_process_is_exact \
    "$original_launcher_pid" "$original_launcher_pid_start"
}

original_launcher_task_is_same() {
  process_task_is_same "$original_launcher_pid" "$original_launcher_pid_start"
}

original_launcher_task_is_stably_absent() {
  local attempt
  for (( attempt = 0; attempt < 3; attempt++ )); do
    process_task_is_absent_or_replaced \
      "$original_launcher_pid" "$original_launcher_pid_start" || return 1
    sleep 0.05
  done
}

resolve_exact_packaged_launcher_for_shell() {
  local shell=$1 launcher="" launcher_start="" parent_recheck=""
  [[ $shell =~ ^[1-9][0-9]*$ ]] || return 1
  launcher=$(ps -o ppid= -p "$shell" 2>/dev/null | tr -d ' ') || return 1
  [[ $launcher =~ ^[1-9][0-9]*$ ]] || return 1
  launcher_start=$(awk '{print $22}' "/proc/$launcher/stat" 2>/dev/null) || return 1
  packaged_shell_launcher_process_is_exact "$launcher" "$launcher_start" || return 1
  process_has_frontend_environment "$launcher" "$HOME" "$real_xdg_config_home" \
    "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" || return 1
  process_has_session_transport_environment "$launcher" || return 1
  parent_recheck=$(ps -o ppid= -p "$shell" 2>/dev/null | tr -d ' ') || return 1
  [[ $parent_recheck == "$launcher" ]] || return 1
  packaged_shell_launcher_process_is_exact "$launcher" "$launcher_start" || return 1
  printf '%s:%s\n' "$launcher" "$launcher_start"
}

normal_packaged_shell_process_is_exact() {
  local pid=$1 expected_start=$2
  packaged_shell_process_is_exact "$pid" "$expected_start" || return 1
  process_has_any_override "$pid" && return 1
  process_has_frontend_environment "$pid" "$HOME" "$real_xdg_config_home" \
    "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" || return 1
  process_has_session_transport_environment "$pid"
}

pin_replacement_under_original_launcher() {
  local candidate_pid="" candidate_start="" launcher_pair="" registry_recheck=""
  process_task_is_absent_or_replaced \
    "$original_shell_pid" "$original_shell_pid_start" || return 1
  original_launcher_process_is_same || return 1
  process_has_frontend_environment "$original_launcher_pid" "$HOME" \
    "$real_xdg_config_home" "$real_xdg_cache_home" "$real_xdg_data_home" \
    "$real_xdg_state_home" || return 1
  process_has_session_transport_environment "$original_launcher_pid" || return 1
  candidate_pid=$(sole_packaged_quickshell_registry_pid) || return 1
  [[ $candidate_pid =~ ^[1-9][0-9]*$ && $candidate_pid != "$original_shell_pid" ]] || return 1
  candidate_start=$(awk '{print $22}' "/proc/$candidate_pid/stat" 2>/dev/null) || return 1
  [[ $candidate_start =~ ^[1-9][0-9]*$ ]] || return 1
  normal_packaged_shell_process_is_exact "$candidate_pid" "$candidate_start" || return 1
  launcher_pair=$(resolve_exact_packaged_launcher_for_shell "$candidate_pid") || return 1
  [[ $launcher_pair == "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1

  registry_recheck=$(sole_packaged_quickshell_registry_pid) || return 1
  [[ $registry_recheck == "$candidate_pid" ]] || return 1
  process_task_is_absent_or_replaced \
    "$original_shell_pid" "$original_shell_pid_start" || return 1
  original_launcher_process_is_same || return 1
  normal_packaged_shell_process_is_exact "$candidate_pid" "$candidate_start" || return 1
  [[ $(resolve_exact_packaged_launcher_for_shell "$candidate_pid") == \
    "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1
  [[ $(sole_packaged_quickshell_registry_pid) == "$candidate_pid" ]] || return 1
  printf '%s:%s\n' "$candidate_pid" "$candidate_start"
}

direct_exact_shell_child_of_original_launcher() {
  local children="" child="" child_start="" child_executable="" launcher_pair=""
  local -a child_pids=() candidates=()
  original_launcher_process_is_same || return 1
  process_has_frontend_environment "$original_launcher_pid" "$HOME" \
    "$real_xdg_config_home" "$real_xdg_cache_home" "$real_xdg_data_home" \
    "$real_xdg_state_home" || return 1
  process_has_session_transport_environment "$original_launcher_pid" || return 1
  [[ -r /proc/$original_launcher_pid/task/$original_launcher_pid/children ]] || return 1
  children=$(<"/proc/$original_launcher_pid/task/$original_launcher_pid/children")
  read -r -a child_pids <<<"$children"
  for child in "${child_pids[@]}"; do
    [[ $child =~ ^[1-9][0-9]*$ && -L /proc/$child/exe ]] || return 1
    child_executable=$(readlink -f -- "/proc/$child/exe" 2>/dev/null) || return 1
    [[ $child_executable == /usr/bin/quickshell ]] || continue
    child_start=$(awk '{print $22}' "/proc/$child/stat" 2>/dev/null) || return 1
    [[ $child_start =~ ^[1-9][0-9]*$ ]] || return 1
    normal_packaged_shell_process_is_exact "$child" "$child_start" || return 1
    launcher_pair=$(resolve_exact_packaged_launcher_for_shell "$child") || return 1
    [[ $launcher_pair == "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1
    candidates+=("$child:$child_start")
  done
  (( ${#candidates[@]} == 1 )) || return 1
  original_launcher_process_is_same || return 1
  printf '%s\n' "${candidates[0]}"
}

original_launcher_is_stopped_exact() {
  local state=""
  original_launcher_process_is_same || return 1
  state=$(awk '{print $3}' "/proc/$original_launcher_pid/stat" 2>/dev/null) || return 1
  [[ $state == T || $state == t ]]
}

original_launcher_is_running_exact() {
  local state=""
  original_launcher_process_is_same || return 1
  state=$(awk '{print $3}' "/proc/$original_launcher_pid/stat" 2>/dev/null) || return 1
  [[ $state != T && $state != t && $state != Z && $state != X && $state != x ]]
}

stopped_original_launcher_child_state() {
  local children="" children_recheck="" child="" child_start="" launcher_pair=""
  local -a child_pids=()
  original_launcher_is_stopped_exact || return 1
  [[ -r /proc/$original_launcher_pid/task/$original_launcher_pid/children ]] || return 1
  children=$(<"/proc/$original_launcher_pid/task/$original_launcher_pid/children")
  read -r -a child_pids <<<"$children"
  if (( ${#child_pids[@]} == 0 )); then
    quickshell_has_no_instances || return 1
    original_launcher_is_stopped_exact || return 1
    children_recheck=$(<"/proc/$original_launcher_pid/task/$original_launcher_pid/children")
    [[ -z $children_recheck ]] || return 1
    printf 'none\n'
    return 0
  fi
  (( ${#child_pids[@]} == 1 )) || return 1
  child=${child_pids[0]}
  [[ $child =~ ^[1-9][0-9]*$ ]] || return 1
  child_start=$(awk '{print $22}' "/proc/$child/stat" 2>/dev/null) || return 1
  [[ $child_start =~ ^[1-9][0-9]*$ ]] || return 1
  normal_packaged_shell_process_is_exact "$child" "$child_start" || return 1
  launcher_pair=$(resolve_exact_packaged_launcher_for_shell "$child") || return 1
  [[ $launcher_pair == "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1
  registry_is_exclusive_or_absent "$child" || return 1
  original_launcher_is_stopped_exact || return 1
  children_recheck=$(<"/proc/$original_launcher_pid/task/$original_launcher_pid/children")
  read -r -a child_pids <<<"$children_recheck"
  (( ${#child_pids[@]} == 1 )) && [[ ${child_pids[0]} == "$child" ]] || return 1
  normal_packaged_shell_process_is_exact "$child" "$child_start" || return 1
  printf '%s:%s\n' "$child" "$child_start"
}

continue_original_launcher_after_failed_stop_proof() {
  local attempt stable=0
  (( original_launcher_stop_pending )) || return 0
  for (( attempt = 0; attempt < 10; attempt++ )); do
    if original_launcher_task_is_stably_absent; then
      original_launcher_stop_pending=0
      return 0
    fi
    if original_launcher_task_is_same; then
      original_launcher_task_is_same || continue
      kill -CONT -- "$original_launcher_pid" 2>/dev/null || true
    fi
    if original_launcher_is_running_exact; then
      stable=$((stable + 1))
      if (( stable >= 2 )); then
        original_launcher_stop_pending=0
        return 0
      fi
    else
      stable=0
    fi
    sleep 0.05
  done
  return 1
}

pin_direct_replacement_under_original_launcher() {
  local candidate_pair="" candidate_recheck="" candidate_pid="" candidate_start=""
  process_task_is_absent_or_replaced \
    "$original_shell_pid" "$original_shell_pid_start" || return 1
  candidate_pair=$(direct_exact_shell_child_of_original_launcher) || return 1
  IFS=: read -r candidate_pid candidate_start <<<"$candidate_pair"
  [[ $candidate_pid =~ ^[1-9][0-9]*$ && $candidate_pid != "$original_shell_pid" &&
    $candidate_start =~ ^[1-9][0-9]*$ ]] || return 1
  registry_is_exclusive_or_absent "$candidate_pid" || return 1
  candidate_recheck=$(direct_exact_shell_child_of_original_launcher) || return 1
  [[ $candidate_recheck == "$candidate_pair" ]] || return 1
  normal_packaged_shell_process_is_exact "$candidate_pid" "$candidate_start" || return 1
  registry_is_exclusive_or_absent "$candidate_pid" || return 1
  printf '%s\n' "$candidate_pair"
}

wait_for_recovery_supervision_exit() {
  local recovery_pid=$1 recovery_start=$2 attempt absence_streak=0
  [[ $recovery_pid =~ ^[1-9][0-9]*$ && $recovery_start =~ ^[1-9][0-9]*$ ]] || return 1
  for (( attempt = 0; attempt < 60; attempt++ )); do
    if process_task_is_absent_or_replaced "$original_shell_pid" "$original_shell_pid_start" &&
      process_task_is_absent_or_replaced "$original_launcher_pid" "$original_launcher_pid_start" &&
      process_task_is_absent_or_replaced "$recovery_pid" "$recovery_start" &&
      quickshell_has_no_instances; then
      absence_streak=$((absence_streak + 1))
      (( absence_streak >= 20 )) && return 0
    else
      absence_streak=0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_original_shell_process_exit() {
  local attempt absent_streak=0
  for (( attempt = 0; attempt < 40; attempt++ )); do
    if process_task_is_absent_or_replaced "$original_shell_pid" "$original_shell_pid_start" &&
      process_task_is_absent_or_replaced "$original_launcher_pid" "$original_launcher_pid_start"; then
      absent_streak=$((absent_streak + 1))
      (( absent_streak >= 5 )) && return 0
    else
      absent_streak=0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_original_shell_exit_and_stable_absence() {
  local attempt absent_streak=0
  for (( attempt = 0; attempt < 60; attempt++ )); do
    if process_task_is_absent_or_replaced "$original_shell_pid" "$original_shell_pid_start" &&
      process_task_is_absent_or_replaced "$original_launcher_pid" "$original_launcher_pid_start" &&
      { (( ! recovery_term_committed )) ||
        process_task_is_absent_or_replaced \
          "$term_tainted_shell_pid" "$term_tainted_shell_pid_start"; } &&
      quickshell_has_no_instances; then
      absent_streak=$((absent_streak + 1))
      (( absent_streak >= 20 )) && return 0
    else
      absent_streak=0
    fi
    sleep 0.1
  done
  return 1
}

process_has_override() {
  local pid=$1 expected=${2:-$temporary_binary} entry
  local override_count=0 socket_count=0 token_count=0
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      OMARCHY_AI_BAR_EXECUTABLE=*)
        override_count=$((override_count + 1))
        [[ $entry == "OMARCHY_AI_BAR_EXECUTABLE=$expected" ]] || return 1
        ;;
      OMARCHY_AI_BAR_DISPLAY_SOCKET=*)
        socket_count=$((socket_count + 1))
        [[ $entry == "OMARCHY_AI_BAR_DISPLAY_SOCKET=$display_socket" ]] || return 1
        ;;
      OAB_LIVE_HARNESS_TOKEN=*)
        token_count=$((token_count + 1))
        [[ $entry == "OAB_LIVE_HARNESS_TOKEN=$transient_token" ]] || return 1
        ;;
    esac
  done </proc/"$pid"/environ
  [[ $override_count == 1 && $socket_count == 1 && $token_count == 1 ]] &&
    process_in_transient_cgroup "$pid" &&
    process_has_exact_transient_execution_environment "$pid"
}

process_has_any_override() {
  local pid=$1
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ $entry == OMARCHY_AI_BAR_EXECUTABLE=* ||
      $entry == OMARCHY_AI_BAR_DISPLAY_SOCKET=* ||
      $entry == OAB_LIVE_HARNESS_TOKEN=* ]] && return 0
  done </proc/"$pid"/environ
  return 1
}

process_has_frontend_environment() {
  local pid=$1 expected_home=$2 expected_config=$3 expected_cache=$4 expected_data=$5
  local expected_state=$6 entry
  local home_count=0 config_count=0 cache_count=0 data_count=0 state_count=0
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      HOME=*)
        home_count=$((home_count + 1))
        [[ $entry == "HOME=$expected_home" ]] || return 1
        ;;
      XDG_CONFIG_HOME=*)
        config_count=$((config_count + 1))
        [[ $entry == "XDG_CONFIG_HOME=$expected_config" ]] || return 1
        ;;
      XDG_CACHE_HOME=*)
        cache_count=$((cache_count + 1))
        [[ $entry == "XDG_CACHE_HOME=$expected_cache" ]] || return 1
        ;;
      XDG_DATA_HOME=*)
        data_count=$((data_count + 1))
        [[ $entry == "XDG_DATA_HOME=$expected_data" ]] || return 1
        ;;
      XDG_STATE_HOME=*)
        state_count=$((state_count + 1))
        [[ $entry == "XDG_STATE_HOME=$expected_state" ]] || return 1
        ;;
    esac
  done </proc/"$pid"/environ
  [[ $home_count == 1 && $config_count == 1 && $cache_count == 1 &&
    $data_count == 1 && $state_count == 1 ]] &&
    process_has_no_effective_code_loading_environment "$pid"
}

process_has_session_transport_environment() {
  local pid=$1 expected_omarchy=${2:-/usr/share/omarchy} entry
  local omarchy_count=0 wayland_count=0 runtime_count=0 hyprland_count=0
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      OMARCHY_PATH=*)
        omarchy_count=$((omarchy_count + 1))
        [[ $entry == "OMARCHY_PATH=$expected_omarchy" ]] || return 1
        ;;
      WAYLAND_DISPLAY=*)
        wayland_count=$((wayland_count + 1))
        [[ $entry == "WAYLAND_DISPLAY=$WAYLAND_DISPLAY" ]] || return 1
        ;;
      XDG_RUNTIME_DIR=*)
        runtime_count=$((runtime_count + 1))
        [[ $entry == "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" ]] || return 1
        ;;
      HYPRLAND_INSTANCE_SIGNATURE=*)
        hyprland_count=$((hyprland_count + 1))
        [[ $entry == "HYPRLAND_INSTANCE_SIGNATURE=$HYPRLAND_INSTANCE_SIGNATURE" ]] || return 1
        ;;
    esac
  done </proc/"$pid"/environ
  [[ $omarchy_count == 1 && $wayland_count == 1 && $runtime_count == 1 &&
    $hyprland_count == 1 ]]
}

process_has_agent_isolation() {
  local pid=$1 entry
  local codex_count=0 claude_count=0 fireworks_auth_count=0 fireworks_key_count=0
  local fireworks_account_count=0 openai_count=0 codex_key_count=0
  local anthropic_key_count=0 anthropic_token_count=0
  [[ -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    case $entry in
      CODEX_HOME=*)
        codex_count=$((codex_count + 1))
        [[ $entry == "CODEX_HOME=$isolated_home/.codex" ]] || return 1
        ;;
      CLAUDE_CONFIG_DIR=*)
        claude_count=$((claude_count + 1))
        [[ $entry == "CLAUDE_CONFIG_DIR=$isolated_home/.claude" ]] || return 1
        ;;
      FIREWORKS_AUTH_PATH=*)
        fireworks_auth_count=$((fireworks_auth_count + 1))
        [[ $entry == "FIREWORKS_AUTH_PATH=$isolated_config_home/fireworks/auth.ini" ]] || return 1
        ;;
      FIREWORKS_API_KEY=*)
        fireworks_key_count=$((fireworks_key_count + 1))
        [[ $entry == FIREWORKS_API_KEY= ]] || return 1
        ;;
      FIREWORKS_ACCOUNT_ID=*)
        fireworks_account_count=$((fireworks_account_count + 1))
        [[ $entry == FIREWORKS_ACCOUNT_ID= ]] || return 1
        ;;
      OPENAI_API_KEY=*)
        openai_count=$((openai_count + 1))
        [[ $entry == OPENAI_API_KEY= ]] || return 1
        ;;
      CODEX_API_KEY=*)
        codex_key_count=$((codex_key_count + 1))
        [[ $entry == CODEX_API_KEY= ]] || return 1
        ;;
      ANTHROPIC_API_KEY=*)
        anthropic_key_count=$((anthropic_key_count + 1))
        [[ $entry == ANTHROPIC_API_KEY= ]] || return 1
        ;;
      ANTHROPIC_AUTH_TOKEN=*)
        anthropic_token_count=$((anthropic_token_count + 1))
        [[ $entry == ANTHROPIC_AUTH_TOKEN= ]] || return 1
        ;;
    esac
  done </proc/"$pid"/environ
  [[ $codex_count == 1 && $claude_count == 1 && $fireworks_auth_count == 1 &&
    $fireworks_key_count == 1 && $fireworks_account_count == 1 && $openai_count == 1 &&
    $codex_key_count == 1 && $anthropic_key_count == 1 && $anthropic_token_count == 1 ]]
}

state_bridge_host_is_owned() {
  local first_entry=""
  [[ -d $isolated_local_home && ! -L $isolated_local_home &&
    $(file_identity "$isolated_local_home") == "$isolated_local_home_identity" &&
    -d $isolated_state_home && ! -L $isolated_state_home &&
    $(file_identity "$isolated_state_home") == "$isolated_state_home_identity" &&
    -d $state_bridge && ! -L $state_bridge &&
    $(file_identity "$state_bridge") == "$state_bridge_identity" &&
    $(stat -c '%u:%a' -- "$state_bridge") == "$UID:700" ]] || return 1
  first_entry=$(find "$state_bridge" -mindepth 1 -maxdepth 1 -print -quit) || return 1
  [[ -z $first_entry ]]
}

state_bridge_target_is_pinned() {
  [[ -d $real_state_parent && ! -L $real_state_parent &&
    $(file_identity "$real_state_parent") == "$real_state_parent_identity" &&
    -d $real_state_root && ! -L $real_state_root &&
    $(file_identity "$real_state_root") == "$real_state_root_identity" ]]
}

state_namespace_scaffold_is_valid() {
  [[ -f $safe_shell_default && ! -L $safe_shell_default &&
    $(file_identity "$safe_shell_default") == "$safe_shell_default_identity" &&
    $(stat -c '%u:%a' -- "$safe_shell_default") == "$UID:400" &&
    $(canonical_json_file_hash "$safe_shell_default") == "$safe_shell_default_hash" &&
    -f $namespace_wrapper && ! -L $namespace_wrapper && -x $namespace_wrapper &&
    $(file_identity "$namespace_wrapper") == "$namespace_wrapper_identity" &&
    $(stat -c '%u:%a' -- "$namespace_wrapper") == "$UID:700" ]] || return 1
  state_bridge_host_is_owned && state_bridge_target_is_pinned &&
    mountpoint_is_absent_in_host_namespace "$state_bridge"
}

namespace_mount_mode_matches() {
  local pid=$1 target=$2 expected_type=$3 expected_mode=$4 mount_json=""
  [[ $pid =~ ^[1-9][0-9]*$ && -d /proc/$pid && -n $target && -n $expected_type &&
    $expected_mode =~ ^(ro|rw)$ ]] || return 1
  mount_json=$(timeout --kill-after=0.1s 0.8s findmnt --kernel=mountinfo --task "$pid" \
    --direction backward --first-only --json --output TARGET,FSTYPE,VFS-OPTIONS \
    --mountpoint "$target" 2>/dev/null) || return 1
  jq -e --arg target "$target" --arg type "$expected_type" --arg mode "$expected_mode" '
    .filesystems | length == 1
    and .[0].target == $target
    and .[0].fstype == $type
    and ((.[0]["vfs-options"] // "") | split(",") | index($mode)) != null
  ' <<<"$mount_json" >/dev/null
}

shell_namespace_is_valid() {
  local pid=$1 proc_root="" user_namespace="" mount_namespace="" net_namespace=""
  local interfaces=""
  [[ $pid =~ ^[1-9][0-9]*$ && -d /proc/$pid && -r /proc/$pid/net/dev ]] || return 1
  process_in_transient_cgroup "$pid" || return 1
  state_namespace_scaffold_is_valid || return 1
  proc_root="/proc/$pid/root"
  [[ -f $proc_root/usr/share/omarchy/config/omarchy/shell.json &&
    ! -L $proc_root/usr/share/omarchy/config/omarchy/shell.json &&
    $(file_identity "$proc_root/usr/share/omarchy/config/omarchy/shell.json") == "$safe_shell_default_identity" &&
    $(canonical_json_file_hash "$proc_root/usr/share/omarchy/config/omarchy/shell.json") == "$safe_shell_default_hash" &&
    -f $proc_root$temporary_binary && ! -L $proc_root$temporary_binary &&
    $(file_identity "$proc_root$temporary_binary") == "$temporary_binary_identity" &&
    $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$proc_root$temporary_binary") == \
      "$temporary_binary_full_identity" &&
    $(sha256_file "$proc_root$temporary_binary") == "$temporary_binary_sha256" &&
    -d $proc_root$state_bridge && ! -L $proc_root$state_bridge &&
    $(file_identity "$proc_root$state_bridge") == "$real_state_root_identity" ]] || return 1
  namespace_mount_mode_matches "$pid" / "$(stat -f -c '%T' -- /)" ro || return 1
  namespace_mount_mode_matches "$pid" /usr/share/omarchy/config/omarchy/shell.json \
    "$(stat -f -c '%T' -- "$safe_shell_default")" ro || return 1
  namespace_mount_mode_matches "$pid" "$state_bridge" \
    "$(stat -f -c '%T' -- "$real_state_root")" rw || return 1
  namespace_mount_mode_matches "$pid" "$isolated_home" \
    "$(stat -f -c '%T' -- "$isolated_home")" rw || return 1
  namespace_mount_mode_matches "$pid" "$evidence_dir" \
    "$(stat -f -c '%T' -- "$evidence_dir")" ro || return 1
  namespace_mount_mode_matches "$pid" "$XDG_RUNTIME_DIR" \
    "$(stat -f -c '%T' -- "$XDG_RUNTIME_DIR")" rw || return 1
  namespace_mount_mode_matches "$pid" "$temporary_binary" \
    "$(stat -f -c '%T' -- "$temporary_binary")" ro || return 1
  namespace_mount_mode_matches "$pid" /tmp tmpfs rw || return 1
  user_namespace=$(readlink -- "/proc/$pid/ns/user") || return 1
  mount_namespace=$(readlink -- "/proc/$pid/ns/mnt") || return 1
  net_namespace=$(readlink -- "/proc/$pid/ns/net") || return 1
  [[ $user_namespace != "$(readlink -- /proc/self/ns/user)" &&
    $mount_namespace != "$(readlink -- /proc/self/ns/mnt)" &&
    $net_namespace != "$(readlink -- /proc/self/ns/net)" ]] || return 1
  interfaces=$(awk -F: 'NR > 2 { name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name); print name }' \
    "/proc/$pid/net/dev") || return 1
  [[ $interfaces == lo ]] || return 1
  ! awk 'NR > 1 && NF > 0 { found=1 } END { exit(found ? 0 : 1) }' \
    "/proc/$pid/net/route" >/dev/null
}

notification_owner_is_shell() {
  local expected_pid=$1 owner=""
  owner=$(
    set -o pipefail
    timeout --kill-after=0.1s 0.5s busctl --user status org.freedesktop.Notifications \
      2>/dev/null | sed -n 's/^PID=//p'
  ) || return 1
  [[ $owner == "$expected_pid" ]]
}

clipboard_watchers_owned_by_shell() {
  local expected_shell=$1 expected_home=$2 expected_config=$3 expected_cache=$4
  local expected_data=$5 expected_state=$6 expected_omarchy=${7:-/usr/share/omarchy}
  local process pid parent uid argument
  local text_seen=0 image_seen=0 watcher_count=0
  local -a arguments=()

  for process in /proc/[1-9][0-9]*; do
    [[ -r $process/cmdline ]] || continue
    pid=${process##*/}
    arguments=()
    while IFS= read -r -d '' argument; do
      arguments+=("$argument")
    done <"$process/cmdline"
    (( ${#arguments[@]} == 6 )) || continue
    [[ ${arguments[0]} == wl-paste && ${arguments[1]} == --type &&
      ${arguments[3]} == --watch &&
      ${arguments[4]} == "$expected_omarchy/shell/plugins/clipboard/capture.sh" &&
      ${arguments[2]} == "${arguments[5]}" ]] || continue
    [[ ${arguments[2]} == text || ${arguments[2]} == image/png ]] || continue
    parent=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ') || return 1
    uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ') || return 1
    [[ $parent == "$expected_shell" && $uid == "$UID" ]] || return 1
    process_has_frontend_environment "$pid" "$expected_home" "$expected_config" \
      "$expected_cache" "$expected_data" "$expected_state" || return 1
    watcher_count=$((watcher_count + 1))
    if [[ ${arguments[2]} == text ]]; then
      text_seen=$((text_seen + 1))
    else
      image_seen=$((image_seen + 1))
    fi
  done
  [[ $watcher_count == 2 && $text_seen == 1 && $image_seen == 1 ]]
}

idle_continuity_matches() {
  local expected_path=$1 output=""
  output=$(OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell idle status 2>/dev/null) || return 1
  jq -e --arg path "$expected_path" '
    .stayAwake == true and .stayAwakeStateLoaded == true and .enabled == false
    and .idle == false and .inIdleCycle == false
    and .screensaverStarted == false and .screensaverWindows == 0
    and .processes == {lock: false, screensaver: false, wake: false}
    and .timers == {
      lock: false, screensaver: false, screensaverLaunchGrace: false
    }
    and .stayAwakeStatePath == $path
  ' <<<"$output" >/dev/null
}

wait_for_shell_continuity() {
  local shell=$1 home=$2 config=$3 cache=$4 data=$5 state=$6 marker=$7
  local expected_omarchy=${8:-/usr/share/omarchy} attempt max_attempts=50
  (( ${cleanup_active:-0} )) && max_attempts=6
  for (( attempt = 0; attempt < max_attempts; attempt++ )); do
    if notification_owner_is_shell "$shell" &&
      clipboard_watchers_owned_by_shell "$shell" "$home" "$config" "$cache" "$data" "$state" \
        "$expected_omarchy" &&
      idle_continuity_matches "$marker"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

process_in_transient_cgroup() {
  local pid=$1 hierarchy controllers path match_count=0
  [[ -n $transient_control_group && -r /proc/$pid/cgroup ]] || return 1
  while IFS=: read -r hierarchy controllers path; do
    if [[ $hierarchy == 0 && -z $controllers ]]; then
      match_count=$((match_count + 1))
      [[ $path == "$transient_control_group" ]] || return 1
    fi
  done </proc/"$pid"/cgroup
  [[ $match_count == 1 ]]
}

is_temporary_binary_pid() {
  local pid=$1 executable="" start="" executable_identity=""
  local executable_full_identity="" executable_sha256=""
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat && -r /proc/$pid/cmdline &&
    -L /proc/$pid/exe ]] || return 1
  [[ $(stat -c '%u' -- "/proc/$pid") == "$UID" ]] || return 1
  start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  executable=$(readlink -f -- "/proc/$pid/exe") || return 1
  [[ $executable == "$temporary_binary" && -f $temporary_binary &&
    ! -L $temporary_binary &&
    $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
    $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
      "$temporary_binary_full_identity" &&
    $(sha256_file "$temporary_binary") == "$temporary_binary_sha256" ]] || return 1
  executable_identity=$(fd_file_identity "/proc/$pid/exe") || return 1
  executable_full_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$pid/exe") || return 1
  executable_sha256=$(proc_executable_sha256 \
    "$pid" "$start" "$temporary_binary_full_identity") || return 1
  [[ $executable == "$temporary_binary" &&
    $executable_identity == "$temporary_binary_identity" &&
    $executable_full_identity == "$temporary_binary_full_identity" &&
    $executable_sha256 == "$temporary_binary_sha256" ]]
}

is_temporary_bridge_pid() {
  local pid=$1 argument
  local -a arguments=()

  is_temporary_binary_pid "$pid" || return 1
  while IFS= read -r -d '' argument; do
    arguments+=("$argument")
  done </proc/"$pid"/cmdline
  (( ${#arguments[@]} == 5 )) || return 1
  [[ ${arguments[0]} == "$temporary_binary" &&
    ${arguments[1]} == bridge &&
    ${arguments[2]} == stdio &&
    ${arguments[3]} == --socket &&
    ${arguments[4]} == "$display_socket" ]]
}

is_exact_bridge_pid() {
  is_temporary_bridge_pid "$1" && process_has_override "$1"
}

list_exact_bridge_pids() {
  local process pid
  for process in /proc/[1-9][0-9]*; do
    [[ -d $process ]] || continue
    pid=${process##*/}
    is_exact_bridge_pid "$pid" && printf '%s\n' "$pid"
  done
}

list_temporary_binary_pids() {
  local process pid
  for process in /proc/[1-9][0-9]*; do
    [[ -d $process ]] || continue
    pid=${process##*/}
    is_temporary_binary_pid "$pid" && printf '%s\n' "$pid"
  done
}

wait_for_one_bridge() {
  local rejected_pid=${1:-} attempt
  local -a pids=()
  for (( attempt = 0; attempt < 120; attempt++ )); do
    mapfile -t pids < <(list_exact_bridge_pids)
    if (( ${#pids[@]} == 1 )) && [[ -z $rejected_pid || ${pids[0]} != "$rejected_pid" ]]; then
      printf '%s\n' "${pids[0]}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

mock_event_count() {
  local event=$1 action=${2:-}
  if [[ ! -s $mock_log ]]; then
    printf '0\n'
    return 0
  fi
  if [[ -n $action ]]; then
    timeout --kill-after=0.1s 0.8s flock -s -w 0.3 "$mock_log" \
      jq -s --arg event "$event" --arg action "$action" \
      '[.[] | select(.event == $event and .action == $action)] | length' "$mock_log"
  else
    timeout --kill-after=0.1s 0.8s flock -s -w 0.3 "$mock_log" \
      jq -s --arg event "$event" \
      '[.[] | select(.event == $event)] | length' "$mock_log"
  fi
}

wait_for_mock_count() {
  local event=$1 action=$2 minimum=$3 attempt count
  for (( attempt = 0; attempt < 120; attempt++ )); do
    if ! count=$(mock_event_count "$event" "$action"); then
      sleep 0.1
      continue
    fi
    [[ $count =~ ^[0-9]+$ ]] || return 1
    if (( count >= minimum )); then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

finalize_mock_evidence() {
  local complete=$1
  [[ $complete == 0 || $complete == 1 ]] || return 1
  [[ -f $mock_log && ! -L $mock_log &&
    $(stat -c '%u:%a' -- "$mock_log" 2>/dev/null) == "$UID:600" ]] || return 1
  jq -s -e --argjson complete "$complete" '
    . as $events
    | {
        connected: ([$events[] | select(.event == "connected")] | length),
        hello: ([$events[] | select(.event == "hello")] | length),
        snapshot_ack: ([$events[] | select(.event == "snapshot_ack")] | length),
        open_panel: ([$events[] | select(.event == "action" and .action == "open_panel")] | length),
        close_panel: ([$events[] | select(.event == "action" and .action == "close_panel")] | length),
        refresh_all: ([$events[] | select(.event == "action" and .action == "refresh_all")] | length),
        disconnected: ([$events[] | select(.event == "disconnected")] | length)
      } as $counts
    | if all($events[];
        type == "object"
        and (if .event == "connected" then
               (keys | sort) == ["event", "handler_pid"]
               and (.handler_pid | type == "number" and . > 0 and . == floor)
             elif .event == "hello" or .event == "disconnected" then
               (keys | sort) == ["event"]
             elif .event == "snapshot_ack" then
               (keys | sort) == ["event", "sequence"] and .sequence == 1
             elif .event == "action" then
               (keys | sort) == ["action", "event", "request_id"]
               and (.action | IN("open_panel", "close_panel", "refresh_all"))
               and (.request_id | type == "number" and . > 0
                 and . <= 9007199254740991 and . == floor)
             else false end))
        and ($counts.disconnected <= $counts.connected)
        and ($complete == 0 or
          ($counts.hello >= 4 and $counts.snapshot_ack >= 3
           and $counts.open_panel >= 10 and $counts.close_panel >= 10
           and $counts.refresh_all >= 1))
      then $counts
      else error("mock evidence is incomplete or malformed") end
  ' "$mock_log" >"$evidence_dir/mock-server.summary.json"
}

wait_for_geometry() {
  local expected_count=$1 destination=$2 attempt geometry
  for (( attempt = 0; attempt < 120; attempt++ )); do
    cleanup_bar_retry_allowed || return 1
    if geometry=$(bounded_shell_ipc shell debugBarGeometry 2>/dev/null) &&
      jq -e --arg id "$plugin_id" --argjson count "$expected_count" '
        [ .[] | select(
          .id == $id and .visible == true and .itemVisible == true and
          .width > 0 and .height > 0 and .itemWidth > 0 and .itemHeight > 0
        ) ] | length == $count
      ' <<<"$geometry" >/dev/null; then
      jq -S . <<<"$geometry" >"$destination"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_bar_position() {
  local edge=$1 attempt config
  for (( attempt = 0; attempt < 80; attempt++ )); do
    cleanup_bar_retry_allowed || return 1
    if config=$(bounded_shell_ipc shell listShellConfig 2>/dev/null) &&
      jq -e --arg edge "$edge" '.bar.position == $edge' <<<"$config" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_panel_layers() {
  local target=$1 other=$2 destination=$3 attempt layers expected_pid=""
  expected_pid=$(shell_pid) || return 1
  for (( attempt = 0; attempt < 80; attempt++ )); do
    layers=$(hyprctl_bounded layers -j) || {
      sleep 0.1
      continue
    }
    if jq -e --arg target "$target" --arg other "$other" \
      --argjson expected_pid "$expected_pid" '
      def named($monitor; $namespace):
        [ .[$monitor].levels | to_entries[] | .value[]
          | select(.namespace == $namespace) ];
      (named($target; "omarchy-keyboard-panel")) as $target_panel
      | (named($target; "omarchy-keyboard-panel-dismiss")) as $target_dismiss
      | (named($other; "omarchy-keyboard-panel")) as $other_panel
      | (named($other; "omarchy-keyboard-panel-dismiss")) as $other_dismiss
      | ($target_panel | length) == 1
      and $target_panel[0].pid == $expected_pid
      and ($target_dismiss | length) == 0
      and ($other_panel | length) == 0
      and ($other_dismiss | length) == 1
      and $other_dismiss[0].pid == $expected_pid
    ' <<<"$layers" >/dev/null; then
      jq -S . <<<"$layers" >"$destination"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_all_panels_closed() {
  local expected_monitors=$1 layers_destination=$2 geometry_destination=$3
  local attempt layers="" geometry=""
  [[ $expected_monitors =~ ^[1-9][0-9]*$ ]] || return 1
  for (( attempt = 0; attempt < 80; attempt++ )); do
    layers=$(hyprctl_bounded layers -j 2>/dev/null) || {
      sleep 0.1
      continue
    }
    geometry=$(bounded_shell_ipc omarchy-ai-bar debugPanelGeometry 2>/dev/null) || {
      sleep 0.1
      continue
    }
    if jq -e '
      [ .[]?.levels | to_entries[] | .value[]
        | select(.namespace == "omarchy-keyboard-panel"
          or .namespace == "omarchy-keyboard-panel-dismiss") ]
      | length == 0
    ' <<<"$layers" >/dev/null &&
      jq -e --argjson expected "$expected_monitors" '
        length == $expected
        and ([.[].monitor] | unique | length) == $expected
        and all(.[]; .open == false and .ownsPopout == false
          and .foreignPopoutActive == false)
      ' <<<"$geometry" >/dev/null; then
      jq -S . <<<"$layers" >"$layers_destination"
      jq -S . <<<"$geometry" >"$geometry_destination"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_panel_geometry() {
  local target=$1 edge=$2 destination=$3 attempt geometry
  for (( attempt = 0; attempt < 80; attempt++ )); do
    if geometry=$(bounded_shell_ipc omarchy-ai-bar debugPanelGeometry 2>/dev/null) &&
      jq -e --arg target "$target" --arg edge "$edge" '
        def clamp($value; $low; $high): [$low, $value, $high] | sort | .[1];
        def rounded: if . >= 0 then (. + 0.5 | floor) else (. - 0.5 | ceil) end;
        ([.[] | select(.monitor == $target)]) as $matches
        | ($matches | length) == 1
        and ([.[] | select(.monitor != $target and .open == true)] | length) == 0
        and ($matches[0] | .open == true and .ownsPopout == true
          and .foreignPopoutActive == false and .barPosition == $edge)
        and ($matches[0] | .anchorWidth > 0 and .anchorHeight > 0
          and .cardWidth > 0 and .cardHeight > 0
          and .screenWidth > 0 and .screenHeight > 0)
        and ($matches[0] |
          (if $edge == "bottom" then
             clamp(.anchorX + .anchorWidth / 2 - .cardWidth / 2;
               .margin; .screenWidth - .cardWidth - .margin) | rounded
           elif $edge == "left" then
             clamp(.barWidth + .gap; .margin; .screenWidth - .cardWidth - .margin) | rounded
           elif $edge == "right" then
             clamp(.screenWidth - .barWidth - .cardWidth - .gap;
               .margin; .screenWidth - .cardWidth - .margin) | rounded
           else
             clamp(.anchorX + .anchorWidth / 2 - .cardWidth / 2;
               .margin; .screenWidth - .cardWidth - .margin) | rounded
           end) == .cardX
          and
          (if $edge == "bottom" then
             clamp(.screenHeight - .barHeight - .cardHeight - .gap;
               .margin; .screenHeight - .cardHeight - .margin) | rounded
           elif $edge == "left" or $edge == "right" then
             clamp(.anchorY + .anchorHeight / 2 - .cardHeight / 2;
               .margin; .screenHeight - .cardHeight - .margin) | rounded
           else
             clamp(.barHeight + .gap; .margin; .screenHeight - .cardHeight - .margin) | rounded
           end) == .cardY)
      ' <<<"$geometry" >/dev/null; then
      jq -S . <<<"$geometry" >"$destination"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_foreign_panel_ownership() {
  local target=$1 destination=$2 attempt geometry
  for (( attempt = 0; attempt < 80; attempt++ )); do
    if geometry=$(bounded_shell_ipc omarchy-ai-bar debugPanelGeometry 2>/dev/null) &&
      jq -e --arg target "$target" '
        ([.[] | select(.monitor == $target)]) as $matches
        | ($matches | length) == 1
        and all(.[]; .open == false and .ownsPopout == false)
        and ($matches[0].foreignPopoutActive == true)
      ' <<<"$geometry" >/dev/null; then
      jq -S . <<<"$geometry" >"$destination"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

focus_monitor() {
  local monitor=$1 attempt
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches || return 1
  dispatch_monitor_safely "$monitor"
  for (( attempt = 0; attempt < 50; attempt++ )); do
    if hyprctl_bounded monitors -j | jq -e --arg monitor "$monitor" \
      'any(.[]; .name == $monitor and .focused == true)' >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

focus_monitor_once_cleanup() {
  local monitor=$1
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches || return 1
  dispatch_monitor_safely "$monitor" >/dev/null 2>&1 || return 1
  hyprctl_bounded monitors -j 2>/dev/null | jq -e --arg monitor "$monitor" \
    'any(.[]; .name == $monitor and .focused == true)' >/dev/null
}

focus_monitor_cleanup() {
  local monitor=$1 attempt
  for (( attempt = 0; attempt < 5; attempt++ )); do
    focus_monitor_once_cleanup "$monitor" && return 0
    sleep 0.05
  done
  return 1
}

move_cursor_to_monitor_center() {
  local monitor=$1 coordinates x y
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches || return 1
  coordinates=$(hyprctl_bounded monitors -j | jq -er --arg monitor "$monitor" '
    .[] | select(.name == $monitor)
    | [(.x + ((.width / .scale) / 2) | floor),
       (.y + ((.height / .scale) / 2) | floor)]
    | @tsv
  ')
  read -r x y <<<"$coordinates"
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches || return 1
  dispatch_cursor_safely "$x" "$y"
}

dispatch_workspace_safely() {
  local workspace=$1
  [[ $workspace =~ ^[1-9][0-9]*$ ]] || return 1
  (( workspace <= 2147483647 )) || return 1
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches || return 1
  hyprctl_bounded eval \
    "hl.dispatch(hl.dsp.focus({ workspace = \"$workspace\" }))" >/dev/null 2>&1
}

headless_event_log_is_exact() {
  [[ -n $headless_event_log && -n $headless_event_log_identity &&
    -f $headless_event_log && ! -L $headless_event_log &&
    $(stable_regular_file_identity "$headless_event_log") == \
      "$headless_event_log_identity" &&
    $(stat -c '%u:%a' -- "$headless_event_log" 2>/dev/null) == "$UID:600" ]]
}

headless_event_handshake_is_exact() {
  [[ -n $headless_ready_pipe && -n $headless_ready_pipe_identity &&
    -n $headless_authorization_pipe && -n $headless_authorization_pipe_identity &&
    $headless_ready_parent_fd =~ ^[1-9][0-9]*$ &&
    $headless_authorization_parent_fd =~ ^[1-9][0-9]*$ &&
    $headless_ready_parent_fd != "$headless_authorization_parent_fd" &&
    -p $headless_ready_pipe && ! -L $headless_ready_pipe &&
    -p $headless_authorization_pipe && ! -L $headless_authorization_pipe &&
    $(file_identity "$headless_ready_pipe") == "$headless_ready_pipe_identity" &&
    $(file_identity "$headless_authorization_pipe") == "$headless_authorization_pipe_identity" &&
    $(stat -c '%u:%a' -- "$headless_ready_pipe") == "$UID:600" &&
    $(stat -c '%u:%a' -- "$headless_authorization_pipe") == "$UID:600" &&
    $(fd_file_identity "/proc/$$/fd/$headless_ready_parent_fd" 2>/dev/null) == "$headless_ready_pipe_identity" &&
    $(fd_access_mode "/proc/$$/fdinfo/$headless_ready_parent_fd") == 0 &&
    $(fd_file_identity "/proc/$$/fd/$headless_authorization_parent_fd" 2>/dev/null) == "$headless_authorization_pipe_identity" &&
    $(fd_access_mode "/proc/$$/fdinfo/$headless_authorization_parent_fd") == 1 ]]
}

close_owned_descriptor() {
  local variable=$1 expected_identity=$2 expected_access=$3 descriptor=""
  descriptor=${!variable:-}
  [[ $descriptor =~ ^[1-9][0-9]*$ && $expected_access =~ ^[012]$ &&
    $(fd_file_identity "/proc/$$/fd/$descriptor" 2>/dev/null) == "$expected_identity" &&
    $(fd_access_mode "/proc/$$/fdinfo/$descriptor") == "$expected_access" ]] || return 1
  exec {descriptor}>&- || return 1
  printf -v "$variable" '%s' ""
}

prepare_headless_event_handshake() {
  local ready_placeholder_fd="" authorization_placeholder_fd="" creation_status=0
  headless_ready_pipe="$temporary_runtime/event-witness-ready.pipe"
  headless_authorization_pipe="$temporary_runtime/event-witness-authorization.pipe"
  safe_absolute_path "$headless_ready_pipe" &&
    safe_absolute_path "$headless_authorization_pipe" || return 1
  [[ ! -e $headless_ready_pipe && ! -L $headless_ready_pipe &&
    ! -e $headless_authorization_pipe && ! -L $headless_authorization_pipe ]] || return 1

  headless_ready_pipe_created=1
  if mkfifo -m 0600 -- "$headless_ready_pipe"; then
    creation_status=0
  else
    creation_status=$?
  fi
  if [[ -d $temporary_runtime && ! -L $temporary_runtime &&
    $(file_identity "$temporary_runtime") == "$temporary_runtime_identity" &&
    -p $headless_ready_pipe && ! -L $headless_ready_pipe &&
    $(stat -c '%u:%a' -- "$headless_ready_pipe") == "$UID:600" ]]; then
    headless_ready_pipe_identity=$(file_identity "$headless_ready_pipe") || return 1
  fi
  (( creation_status == 0 )) && [[ -n $headless_ready_pipe_identity ]] || return 1
  (( ${interrupted:-0} == 0 )) || return "$interrupted"

  headless_authorization_pipe_created=1
  if mkfifo -m 0600 -- "$headless_authorization_pipe"; then
    creation_status=0
  else
    creation_status=$?
  fi
  if [[ -d $temporary_runtime && ! -L $temporary_runtime &&
    $(file_identity "$temporary_runtime") == "$temporary_runtime_identity" &&
    -p $headless_authorization_pipe && ! -L $headless_authorization_pipe &&
    $(stat -c '%u:%a' -- "$headless_authorization_pipe") == "$UID:600" ]]; then
    headless_authorization_pipe_identity=$(file_identity "$headless_authorization_pipe") || return 1
  fi
  (( creation_status == 0 )) && [[ -n $headless_authorization_pipe_identity ]] || return 1
  (( ${interrupted:-0} == 0 )) || return "$interrupted"

  exec {ready_placeholder_fd}<>"$headless_ready_pipe" || return 1
  if ! exec {headless_ready_child_fd}>"$headless_ready_pipe"; then
    exec {ready_placeholder_fd}>&- || true
    return 1
  fi
  if ! exec {headless_ready_parent_fd}<"$headless_ready_pipe"; then
    exec {ready_placeholder_fd}>&- || true
    return 1
  fi
  exec {ready_placeholder_fd}>&- || return 1

  exec {authorization_placeholder_fd}<>"$headless_authorization_pipe" || return 1
  if ! exec {headless_authorization_child_fd}<"$headless_authorization_pipe"; then
    exec {authorization_placeholder_fd}>&- || true
    return 1
  fi
  if ! exec {headless_authorization_parent_fd}>"$headless_authorization_pipe"; then
    exec {authorization_placeholder_fd}>&- || true
    return 1
  fi
  exec {authorization_placeholder_fd}>&- || return 1

  headless_ready_child_fd_number=$headless_ready_child_fd
  headless_authorization_child_fd_number=$headless_authorization_child_fd
  [[ $headless_ready_child_fd_number =~ ^[1-9][0-9]*$ &&
    $headless_authorization_child_fd_number =~ ^[1-9][0-9]*$ &&
    $headless_ready_child_fd_number != "$headless_authorization_child_fd_number" &&
    $(fd_file_identity "/proc/$$/fd/$headless_ready_child_fd_number") == "$headless_ready_pipe_identity" &&
    $(fd_access_mode "/proc/$$/fdinfo/$headless_ready_child_fd_number") == 1 &&
    $(fd_file_identity "/proc/$$/fd/$headless_authorization_child_fd_number") == "$headless_authorization_pipe_identity" &&
    $(fd_access_mode "/proc/$$/fdinfo/$headless_authorization_child_fd_number") == 0 ]] || return 1
  headless_event_handshake_is_exact
}

release_headless_event_handshake() {
  local status=0
  (( ! headless_event_handshake_released )) || return 0
  if [[ -n $headless_ready_child_fd ]]; then
    close_owned_descriptor headless_ready_child_fd \
      "$headless_ready_pipe_identity" 1 || status=1
  fi
  if [[ -n $headless_authorization_child_fd ]]; then
    close_owned_descriptor headless_authorization_child_fd \
      "$headless_authorization_pipe_identity" 0 || status=1
  fi
  if [[ -n $headless_ready_parent_fd ]]; then
    close_owned_descriptor headless_ready_parent_fd \
      "$headless_ready_pipe_identity" 0 || status=1
  fi
  if [[ -n $headless_authorization_parent_fd ]]; then
    close_owned_descriptor headless_authorization_parent_fd \
      "$headless_authorization_pipe_identity" 1 || status=1
  fi
  if (( headless_ready_pipe_created )); then
    if [[ -z $headless_ready_pipe_identity &&
      ! -e $headless_ready_pipe && ! -L $headless_ready_pipe ]]; then
      headless_ready_pipe_created=0
    elif [[ -p $headless_ready_pipe && ! -L $headless_ready_pipe &&
      $(file_identity "$headless_ready_pipe") == "$headless_ready_pipe_identity" ]]; then
      if rm -f -- "$headless_ready_pipe" &&
        [[ ! -e $headless_ready_pipe && ! -L $headless_ready_pipe ]]; then
        headless_ready_pipe_created=0
      else
        status=1
      fi
    else
      status=1
    fi
  fi
  if (( headless_authorization_pipe_created )); then
    if [[ -z $headless_authorization_pipe_identity &&
      ! -e $headless_authorization_pipe && ! -L $headless_authorization_pipe ]]; then
      headless_authorization_pipe_created=0
    elif [[ -p $headless_authorization_pipe && ! -L $headless_authorization_pipe &&
      $(file_identity "$headless_authorization_pipe") == "$headless_authorization_pipe_identity" ]]; then
      if rm -f -- "$headless_authorization_pipe" &&
        [[ ! -e $headless_authorization_pipe && ! -L $headless_authorization_pipe ]]; then
        headless_authorization_pipe_created=0
      else
        status=1
      fi
    else
      status=1
    fi
  fi
  if (( status == 0 )); then
    headless_event_handshake_released=1
  fi
  return "$status"
}

headless_event_watcher_candidate_is_owned() {
  local candidate_pid=$1 candidate_start=$2
  local start="" owner="" parent="" executable="" executable_identity=""
  local executable_full_identity="" executable_sha256=""
  local pgid="" sid="" environment_bytes="" core_limits="" argument descriptor
  local descriptor_identity="" descriptor_access=""
  local inherited_live_lock_count=0 ready_pipe_descriptor_count=0
  local authorization_pipe_descriptor_count=0
  local -a arguments=()
  [[ $candidate_pid =~ ^[1-9][0-9]*$ && $candidate_start =~ ^[1-9][0-9]*$ &&
    -r /proc/$candidate_pid/stat && -r /proc/$candidate_pid/cmdline &&
    -r /proc/$candidate_pid/environ && -r /proc/$candidate_pid/limits &&
    -L /proc/$candidate_pid/exe && -f $temporary_binary &&
    ! -L $temporary_binary &&
    $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
    $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == "$temporary_binary_full_identity" &&
    $(sha256_file "$temporary_binary") == "$temporary_binary_sha256" ]] || return 1
  headless_event_handshake_is_exact || return 1
  start=$(awk '{print $22}' "/proc/$candidate_pid/stat" 2>/dev/null) || return 1
  owner=$(stat -c '%u' -- "/proc/$candidate_pid" 2>/dev/null) || return 1
  parent=$(ps -o ppid= -p "$candidate_pid" 2>/dev/null | tr -d ' ') || return 1
  executable=$(readlink -f -- "/proc/$candidate_pid/exe" 2>/dev/null) || return 1
  executable_identity=$(fd_file_identity "/proc/$candidate_pid/exe" 2>/dev/null) || return 1
  executable_full_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
    -- "/proc/$candidate_pid/exe" 2>/dev/null) || return 1
  executable_sha256=$(proc_executable_sha256 \
    "$candidate_pid" "$candidate_start" "$temporary_binary_full_identity") || return 1
  environment_bytes=$(wc -c <"/proc/$candidate_pid/environ" 2>/dev/null) || return 1
  core_limits=$(awk '
    $1 == "Max" && $2 == "core" && $3 == "file" && $4 == "size" {
      count++
      value = $5 ":" $6 ":" $7
    }
    END { if (count == 1) print value }
  ' "/proc/$candidate_pid/limits" 2>/dev/null) || return 1
  pgid=$(ps -o pgid= -p "$candidate_pid" 2>/dev/null | tr -d ' ') || return 1
  sid=$(ps -o sid= -p "$candidate_pid" 2>/dev/null | tr -d ' ') || return 1
  while IFS= read -r -d '' argument; do
    arguments+=("$argument")
  done <"/proc/$candidate_pid/cmdline"
  for descriptor in /proc/"$candidate_pid"/fd/*; do
    if [[ $(lock_fd_identity "$descriptor" 2>/dev/null) == "$live_lock_identity" ]]; then
      inherited_live_lock_count=$((inherited_live_lock_count + 1))
    fi
    descriptor_identity=$(fd_file_identity "$descriptor" 2>/dev/null) || continue
    if [[ $descriptor_identity == "$headless_ready_pipe_identity" ]]; then
      descriptor_access=$(fd_access_mode \
        "/proc/$candidate_pid/fdinfo/${descriptor##*/}") || return 1
      [[ $descriptor_access == 1 ]] || return 1
      ready_pipe_descriptor_count=$((ready_pipe_descriptor_count + 1))
    elif [[ $descriptor_identity == "$headless_authorization_pipe_identity" ]]; then
      descriptor_access=$(fd_access_mode \
        "/proc/$candidate_pid/fdinfo/${descriptor##*/}") || return 1
      [[ $descriptor_access == 0 ]] || return 1
      authorization_pipe_descriptor_count=$((authorization_pipe_descriptor_count + 1))
    fi
  done
  [[ $start == "$candidate_start" && $owner == "$UID" && $parent == "$$" &&
    $executable == "$temporary_binary" &&
    $executable_identity == "$temporary_binary_identity" &&
    $executable_full_identity == "$temporary_binary_full_identity" &&
    $executable_sha256 == "$temporary_binary_sha256" &&
    $environment_bytes == 0 && $core_limits == 0:0:bytes &&
    $inherited_live_lock_count == 0 && $ready_pipe_descriptor_count == 1 &&
    $authorization_pipe_descriptor_count == 1 &&
    ! -e /proc/$candidate_pid/fd/$headless_ready_child_fd_number &&
    ! -e /proc/$candidate_pid/fd/$headless_authorization_child_fd_number &&
    $pgid == "$candidate_pid" && $sid == "$candidate_pid" &&
    ${#arguments[@]} == 13 && ${arguments[0]} == "$temporary_binary" &&
    ${arguments[1]} == bridge && ${arguments[2]} == hyprland-events &&
    ${arguments[3]} == --socket && ${arguments[4]} == "$headless_event_socket" &&
    ${arguments[5]} == --monitor-name-base64 &&
    ${arguments[6]} == "$headless_name_base64" &&
    ${arguments[7]} == --parent-pid && ${arguments[8]} == "$$" &&
    ${arguments[9]} == --ready-fd &&
    ${arguments[10]} == "$headless_ready_child_fd_number" &&
    ${arguments[11]} == --authorization-fd &&
    ${arguments[12]} == "$headless_authorization_child_fd_number" ]]
}

headless_event_socket_is_compositor_listener() {
  local descriptor link listener_inode="" compositor_fd_count=0
  local -a listener_inodes=()
  [[ -S $headless_event_socket && ! -L $headless_event_socket &&
    $(file_identity "$headless_event_socket") == "$headless_event_socket_identity" ]] || return 1
  compositor_identity_matches || return 1
  mapfile -t listener_inodes < <(
    awk -v path="$headless_event_socket" '
      $4 == "00010000" && $5 == "0001" && $6 == "01" &&
          $7 ~ /^[1-9][0-9]*$/ && $8 == path { print $7 }
    ' /proc/net/unix
  )
  (( ${#listener_inodes[@]} == 1 )) || return 1
  listener_inode=${listener_inodes[0]}
  for descriptor in /proc/"$hyprland_compositor_pid_before"/fd/*; do
    link=$(readlink -- "$descriptor" 2>/dev/null) || continue
    [[ $link == "socket:[$listener_inode]" ]] &&
      compositor_fd_count=$((compositor_fd_count + 1))
  done
  (( compositor_fd_count >= 1 ))
}

headless_event_socket_peer_is_exact() {
  local client_inode=$1 connections="" server_inode="" descriptor link
  local compositor_fd_count=0
  [[ $client_inode =~ ^[1-9][0-9]*$ && $(command -v ss) == /usr/bin/ss &&
    -f /usr/bin/ss && ! -L /usr/bin/ss &&
    $(sha256_packaged_file /usr/bin/ss) == "$expected_ss_sha256" ]] || return 1
  connections=$(timeout --kill-after=0.1s 0.5s /usr/bin/ss -xnH 2>/dev/null) || return 1
  server_inode=$(awk -v client="$client_inode" '
    $1 == "u_str" && $2 == "ESTAB" && $5 == "*" && $6 == client &&
        $7 == "*" && $8 ~ /^[1-9][0-9]*$/ {
      count++
      peer = $8
    }
    END { if (count == 1) print peer }
  ' <<<"$connections") || return 1
  [[ $server_inode =~ ^[1-9][0-9]*$ ]] || return 1
  awk -v path="$headless_event_socket" -v server="$server_inode" \
    -v client="$client_inode" '
      $1 == "u_str" && $2 == "ESTAB" && $5 == path && $6 == server &&
          $7 == "*" && $8 == client { count++ }
      END { exit(count == 1 ? 0 : 1) }
    ' <<<"$connections" || return 1
  headless_event_socket_is_compositor_listener || return 1
  for descriptor in /proc/"$hyprland_compositor_pid_before"/fd/*; do
    link=$(readlink -- "$descriptor" 2>/dev/null) || continue
    [[ $link == "socket:[$server_inode]" ]] &&
      compositor_fd_count=$((compositor_fd_count + 1))
  done
  (( compositor_fd_count >= 1 ))
}

headless_event_watcher_candidate_is_ready() {
  local candidate_pid=$1 candidate_start=$2 descriptor link socket_inode=""
  local connected_stream_inode="" connected_stream_count=0
  headless_event_watcher_candidate_is_owned "$candidate_pid" "$candidate_start" || return 1
  [[ -S $headless_event_socket && ! -L $headless_event_socket &&
    $(file_identity "$headless_event_socket") == "$headless_event_socket_identity" ]] || return 1
  headless_event_log_is_exact || return 1
  [[ -e /proc/$candidate_pid/fd/1 &&
    $(fd_stable_regular_file_identity "/proc/$candidate_pid/fd/1" 2>/dev/null) == \
      "$headless_event_log_identity" ]] || return 1
  for descriptor in /proc/"$candidate_pid"/fd/*; do
    link=$(readlink -- "$descriptor" 2>/dev/null) || continue
    if [[ $link =~ ^socket:\[([1-9][0-9]*)\]$ ]]; then
      socket_inode=${BASH_REMATCH[1]}
      if awk -v inode="$socket_inode" '
        $5 == "0001" && $6 == "03" && $7 == inode { found = 1 }
        END { exit(found ? 0 : 1) }
      ' /proc/net/unix; then
        connected_stream_count=$((connected_stream_count + 1))
        connected_stream_inode=$socket_inode
      fi
    fi
  done
  (( connected_stream_count == 1 )) || return 1
  headless_event_socket_peer_is_exact "$connected_stream_inode" || return 1
  headless_event_client_inode=$connected_stream_inode
}

headless_event_watcher_is_owned() {
  (( headless_event_watcher_started && headless_event_watcher_owned )) || return 1
  if (( headless_event_watcher_armed )); then
    process_task_is_same "$headless_event_watcher_pid" "$headless_event_watcher_start"
    return
  fi
  headless_event_watcher_candidate_is_owned \
    "$headless_event_watcher_pid" "$headless_event_watcher_start"
}

headless_event_watcher_pinned_is_exact() {
  local before="" after="" state="" parent="" pgid="" sid="" start=""
  local owner="" task_uid=""
  (( headless_event_watcher_started && headless_event_watcher_owned &&
    headless_event_watcher_ready && headless_event_watcher_armed )) || return 1
  [[ $headless_event_client_inode =~ ^[1-9][0-9]*$ &&
    -z $headless_ready_child_fd && -z $headless_ready_parent_fd &&
    -z $headless_authorization_child_fd &&
    -z $headless_authorization_parent_fd &&
    $headless_event_handshake_released == 1 &&
    ! -e $headless_ready_pipe && ! -L $headless_ready_pipe &&
    ! -e $headless_authorization_pipe && ! -L $headless_authorization_pipe ]] || return 1
  before=$(awk '{print $3 ":" $4 ":" $5 ":" $6 ":" $22}' \
    "/proc/$headless_event_watcher_pid/stat" 2>/dev/null) || return 1
  IFS=: read -r state parent pgid sid start <<<"$before"
  owner=$(stat -c '%u' -- "/proc/$headless_event_watcher_pid" 2>/dev/null) || return 1
  task_uid=$(awk '/^Uid:/ { if (NF == 5) print $2 ":" $3 ":" $4 ":" $5 }' \
    "/proc/$headless_event_watcher_pid/status" 2>/dev/null) || return 1
  [[ $state != Z && $state != X && $state != x &&
    $start == "$headless_event_watcher_start" && $owner == "$UID" &&
    $parent == "$$" && $pgid == "$headless_event_watcher_pid" &&
    $sid == "$headless_event_watcher_pid" &&
    $task_uid == "$UID:$UID:$UID:$UID" ]] || return 1
  headless_event_log_is_exact || return 1
  after=$(awk '{print $3 ":" $4 ":" $5 ":" $6 ":" $22}' \
    "/proc/$headless_event_watcher_pid/stat" 2>/dev/null) || return 1
  [[ $after == "$before" ]]
}

headless_event_watcher_armed_is_exact() {
  headless_event_watcher_pinned_is_exact || return 1
  headless_event_socket_peer_is_exact "$headless_event_client_inode" || return 1
  headless_event_watcher_pinned_is_exact
}

headless_event_watcher_is_exact() {
  (( headless_event_watcher_ready )) || return 1
  if (( headless_event_watcher_armed )); then
    # The full peer attribution is frozen at the R/A/D boundary. The exact
    # hashed Rust witness has no reconnect, fork, or exec path; after D it is
    # non-dumpable and continuity is proven by the immutable task/log pin.
    headless_event_watcher_pinned_is_exact
    return
  fi
  headless_event_watcher_candidate_is_ready \
    "$headless_event_watcher_pid" "$headless_event_watcher_start"
}

start_headless_event_watcher() {
  local attempt candidate_start="" status=1 interrupted=0 pre_ready=0
  local handshake_byte="" read_status=0
  (( ! headless_event_watcher_started && ! headless_event_watcher_owned &&
    ! headless_event_watcher_ready && ! headless_event_watcher_armed )) || return 1
  live_lock_is_held || return 1
  headless_event_socket_is_compositor_listener || return 1
  headless_event_log="$evidence_dir/hyprland-monitor-events.filtered.log"
  [[ ! -e $headless_event_log && ! -L $headless_event_log ]] || return 1
  : >"$headless_event_log" || return 1
  chmod 0600 -- "$headless_event_log" || return 1
  headless_event_log_identity=$(stable_regular_file_identity "$headless_event_log") || return 1
  headless_event_log_is_exact || return 1

  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  if prepare_headless_event_handshake && (( interrupted == 0 )); then
    (
      # Only the one-way child endpoints cross exec. The witness is outside
      # the transient shell cgroup and must never retain the singleton lock.
      exec {headless_ready_parent_fd}>&-
      exec {headless_authorization_parent_fd}>&-
      exec {live_lock_fd}>&-
      ulimit -c 0 || exit 1
      exec setsid /usr/bin/env -i "$temporary_binary" bridge hyprland-events \
        --socket "$headless_event_socket" \
        --monitor-name-base64 "$headless_name_base64" --parent-pid "$$" \
        --ready-fd "$headless_ready_child_fd_number" \
        --authorization-fd "$headless_authorization_child_fd_number"
    ) >"$headless_event_log" 2>"$evidence_dir/hyprland-monitor-events.stderr" &
    headless_event_watcher_pid=$!
    headless_event_watcher_started=1

    if ! close_owned_descriptor headless_ready_child_fd \
      "$headless_ready_pipe_identity" 1; then
      status=1
    elif ! close_owned_descriptor headless_authorization_child_fd \
      "$headless_authorization_pipe_identity" 0; then
      status=1
    else
      status=0
    fi

    for (( attempt = 0; attempt < 50; attempt++ )); do
      (( interrupted == 0 )) || break
      if (( ! headless_event_watcher_owned )); then
        candidate_start=$(awk '{print $22}' \
          "/proc/$headless_event_watcher_pid/stat" 2>/dev/null)
        if headless_event_watcher_candidate_is_owned \
          "$headless_event_watcher_pid" "$candidate_start"; then
          headless_event_watcher_start=$candidate_start
          headless_event_watcher_owned=1
        fi
      fi
      if (( headless_event_watcher_owned )) &&
        headless_event_watcher_candidate_is_ready \
          "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
        pre_ready=1
        break
      fi
      if (( headless_event_watcher_owned )); then
        process_task_is_same \
          "$headless_event_watcher_pid" "$headless_event_watcher_start" || break
      else
        kill -0 "$headless_event_watcher_pid" 2>/dev/null || break
      fi
      sleep 0.02
    done

    if (( status == 0 && pre_ready && interrupted == 0 )); then
      handshake_byte=""
      IFS= read -r -N 1 -t 1 handshake_byte <&"$headless_ready_parent_fd"
      read_status=$?
      [[ $read_status == 0 && $handshake_byte == R ]] || status=1
    else
      status=1
    fi
    if (( status == 0 )); then
      (( interrupted == 0 )) || status=1
    fi
    if (( status == 0 )); then
      headless_event_watcher_candidate_is_ready \
        "$headless_event_watcher_pid" "$headless_event_watcher_start" || status=1
    fi
    if (( status == 0 )); then
      (( interrupted == 0 )) || status=1
    fi
    if (( status == 0 )); then
      # From this point cleanup relies only on the already-pinned direct task:
      # the exact child may become deliberately unreadable through procfs.
      headless_event_authorization_committed=1
      printf 'A' >&"$headless_authorization_parent_fd" || status=1
    fi
    if (( status == 0 )); then
      close_owned_descriptor headless_authorization_parent_fd \
        "$headless_authorization_pipe_identity" 1 || status=1
    fi
    if (( status == 0 )); then
      handshake_byte=""
      IFS= read -r -N 1 -t 1 handshake_byte <&"$headless_ready_parent_fd"
      read_status=$?
      if [[ $read_status == 0 && $handshake_byte == D ]]; then
        headless_event_watcher_armed=1
      else
        status=1
      fi
    fi
    if (( status == 0 )); then
      handshake_byte=""
      IFS= read -r -N 1 -t 1 handshake_byte <&"$headless_ready_parent_fd"
      read_status=$?
      [[ $read_status == 1 && -z $handshake_byte ]] || status=1
    fi
    if (( status == 0 )); then
      release_headless_event_handshake || status=1
    fi
    if (( status == 0 )); then
      headless_event_watcher_ready=1
      headless_event_watcher_armed_is_exact || status=1
    fi
    if (( status == 0 )); then
      printf 'pid=%s\nstart=%s\nclient_inode=%s\n' \
        "$headless_event_watcher_pid" "$headless_event_watcher_start" \
        "$headless_event_client_inode" \
        >"$evidence_dir/headless-event-watcher.identity" || status=1
      [[ -f $evidence_dir/headless-event-watcher.identity &&
        ! -L $evidence_dir/headless-event-watcher.identity &&
        $(stat -c '%u:%a' -- "$evidence_dir/headless-event-watcher.identity" 2>/dev/null) == \
          "$UID:600" ]] || status=1
    fi
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

headless_event_sequence_state() {
  headless_event_log_is_exact || return 1
  awk -v added="monitoradded>>$headless_name" \
    -v removed="monitorremoved>>$headless_name" '
      $0 == added {
        if (state != 0) bad = 1
        state = 1
        next
      }
      $0 == removed {
        if (state != 1) bad = 1
        state = 2
        next
      }
      { bad = 1 }
      END {
        if (bad) print "invalid"
        else print state + 0
      }
    ' "$headless_event_log"
}

headless_event_generation_is_current() {
  headless_event_watcher_pinned_is_exact || return 1
  [[ $(headless_event_sequence_state) == 1 ]] || return 1
  headless_event_watcher_pinned_is_exact
}

record_headless_event_watcher_status() {
  local label=$1 state="indeterminate" task="indeterminate"
  [[ $label =~ ^[a-z0-9-]+$ && -d $evidence_dir && ! -L $evidence_dir ]] || return 1
  state=$(headless_event_sequence_state 2>/dev/null) || state=indeterminate
  if process_task_is_same \
    "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
    task=same
  elif process_task_is_absent_or_replaced \
    "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
    task=absent-or-replaced
  fi
  printf 'pid=%s\nstart=%s\ntask=%s\nsequence=%s\n' \
    "$headless_event_watcher_pid" "$headless_event_watcher_start" "$task" "$state" \
    >"$evidence_dir/headless-event-watcher.$label.status"
}

wait_for_headless_event_generation() {
  local attempt state=""
  for (( attempt = 0; attempt < 50; attempt++ )); do
    state=$(headless_event_sequence_state 2>/dev/null) || state=indeterminate
    case $state in
      1)
        headless_event_generation_is_current && return 0
        ;;
      invalid|2)
        record_headless_event_watcher_status creation-invalid >/dev/null 2>&1 || true
        return 1
        ;;
    esac
    if process_task_is_absent_or_replaced \
      "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
      record_headless_event_watcher_status creation-task-lost >/dev/null 2>&1 || true
      return 1
    fi
    sleep 0.02
  done
  record_headless_event_watcher_status creation-timeout >/dev/null 2>&1 || true
  return 1
}

wait_for_headless_removal_event() {
  local attempt state=""
  for (( attempt = 0; attempt < 50; attempt++ )); do
    state=$(headless_event_sequence_state 2>/dev/null) || state=indeterminate
    case $state in
      2)
        if headless_event_watcher_pinned_is_exact &&
          [[ $(headless_event_sequence_state) == 2 ]] &&
          headless_event_watcher_pinned_is_exact; then
          return 0
        fi
        ;;
      invalid|0)
        record_headless_event_watcher_status removal-invalid >/dev/null 2>&1 || true
        return 1
        ;;
    esac
    if process_task_is_absent_or_replaced \
      "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
      record_headless_event_watcher_status removal-task-lost >/dev/null 2>&1 || true
      return 1
    fi
    sleep 0.02
  done
  record_headless_event_watcher_status removal-timeout >/dev/null 2>&1 || true
  return 1
}

stop_headless_event_watcher() {
  local attempt candidate_start="" state="" parent=""
  (( headless_event_watcher_started )) || return 0
  if (( ! headless_event_watcher_owned )); then
    # Fork publication is deliberately separate from signal authority. Retry
    # the complete exact child proof during cleanup: a slow exec or transient
    # /proc/ps failure must not strand the naturally blocking witness.
    for (( attempt = 0; attempt < 250; attempt++ )); do
      candidate_start=$(awk '{print $22}' \
        "/proc/$headless_event_watcher_pid/stat" 2>/dev/null)
      if headless_event_watcher_candidate_is_owned \
        "$headless_event_watcher_pid" "$candidate_start"; then
        headless_event_watcher_start=$candidate_start
        headless_event_watcher_owned=1
        break
      fi
      if ! kill -0 "$headless_event_watcher_pid" 2>/dev/null; then
        wait "$headless_event_watcher_pid" 2>/dev/null || true
        headless_event_watcher_ready=0
        return 0
      fi
      state=$(ps -o stat= -p "$headless_event_watcher_pid" 2>/dev/null | tr -d ' ')
      parent=$(ps -o ppid= -p "$headless_event_watcher_pid" 2>/dev/null | tr -d ' ')
      if [[ $state == Z* && $parent == "$$" ]]; then
        wait "$headless_event_watcher_pid" 2>/dev/null || true
        headless_event_watcher_ready=0
        return 0
      fi
      sleep 0.02
    done
  fi
  if (( headless_event_watcher_owned )) &&
    [[ $headless_event_watcher_start =~ ^[1-9][0-9]*$ ]] &&
    process_task_is_same "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
    kill -TERM "$headless_event_watcher_pid" 2>/dev/null || true
  elif (( headless_event_watcher_owned )) &&
    process_task_is_absent_or_replaced \
      "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
    wait "$headless_event_watcher_pid" 2>/dev/null || true
    headless_event_watcher_ready=0
    return 0
  else
    # Parent-death termination is armed by the exact Rust mode, and the lock
    # FD was closed before exec. Without a published PID/start proof, retain
    # evidence and refuse to signal a potentially reused PID.
    return 1
  fi
  for (( attempt = 0; attempt < 50; attempt++ )); do
    process_task_is_absent_or_replaced \
      "$headless_event_watcher_pid" "$headless_event_watcher_start" && break
    sleep 0.02
  done
  if process_task_is_same "$headless_event_watcher_pid" "$headless_event_watcher_start"; then
    kill -KILL "$headless_event_watcher_pid" 2>/dev/null || true
  fi
  wait "$headless_event_watcher_pid" 2>/dev/null || true
  headless_event_watcher_ready=0
  process_task_is_absent_or_replaced \
    "$headless_event_watcher_pid" "$headless_event_watcher_start"
}

create_owned_headless_output() {
  local status interrupted=0 attempt identity=""
  live_lock_is_held || return 1
  session_is_safe_for_live_mutation || return 1
  compositor_identity_matches || return 1
  headless_event_socket_is_compositor_listener || return 1
  headless_name_matches_nonce || return 1
  headless_event_watcher_is_exact || return 1
  [[ $(headless_event_sequence_state) == 0 ]] || return 1
  hyprctl_bounded monitors all -j 2>/dev/null | jq -e --arg name "$headless_name" \
    'all(.[]; .name != $name)' >/dev/null || return 1
  trap 'interrupted=129' HUP
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  set +e
  # The nonce-bearing connector trims to lowercase fallback in the exact audited
  # hyprmoncfg build but is not Hyprland's byte-exact FALLBACK sentinel. Never
  # claim removal authority unless Hyprland acknowledges this exact request.
  hyprctl_bounded output create headless "$headless_name" >"$evidence_dir/headless-create.log"
  status=$?
  if (( status != 0 || interrupted != 0 )) ||
    [[ $(stat -c '%s' -- "$evidence_dir/headless-create.log" 2>/dev/null) != 3 ]] ||
    [[ $(<"$evidence_dir/headless-create.log") != ok ]]; then
    status=1
  else
    headless_creation_proven=1
    for (( attempt = 0; attempt < 15; attempt++ )); do
      (( interrupted == 0 || attempt == 0 )) || break
      if adopt_proven_headless_output; then
        identity=$headless_output_identity
        break
      fi
      (( interrupted == 0 )) || break
      sleep 0.1
    done
    if [[ -n $identity ]] && wait_for_headless_event_generation; then
      headless_output_identity=$identity
      status=0
    else
      status=1
    fi
  fi
  trap '' HUP INT TERM
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  set -e
  if (( interrupted != 0 )); then
    return "$interrupted"
  fi
  return "$status"
}

configure_owned_headless_output_once() {
  local x=$1 y=$2 status output_literal=""
  [[ $x =~ ^-?[0-9]+$ && $y =~ ^-?[0-9]+$ ]] || return 1
  output_literal=$(lua_long_string_literal "$headless_name") || return 1
  live_lock_is_held || return 1
  session_is_safe_for_live_mutation || return 1
  compositor_identity_matches || return 1
  headless_event_socket_is_compositor_listener || return 1
  headless_name_matches_nonce || return 1
  headless_event_generation_is_current || return 1
  headless_output_is_owned || return 1

  # The command can reach Hyprland even if this shell is interrupted before it
  # observes the reply, so cleanup must reload from the pinned baseline once
  # this boundary is crossed.
  headless_rule_mutated=1
  hyprctl_bounded eval \
    "hl.monitor({ output = $output_literal, mode = \"1920x1080@60\", position = \"${x}x${y}\", scale = \"1.5\" })" \
    >"$evidence_dir/headless-configure.log"
  status=$?
  (( status == 0 )) || return 1
  [[ $(stat -c '%s' -- "$evidence_dir/headless-configure.log" 2>/dev/null) == 3 &&
    $(<"$evidence_dir/headless-configure.log") == ok ]] || return 1
  live_lock_is_held && session_is_safe_for_live_mutation &&
    compositor_identity_matches && headless_event_generation_is_current &&
    headless_output_is_owned
}

adopt_proven_headless_output() {
  local identity=""
  (( headless_creation_proven )) || return 1
  [[ -z $headless_output_identity && -f $monitors_before ]] || return 1
  identity=$(hyprctl_bounded monitors all -j 2>/dev/null | jq -cer \
    --arg name "$headless_name" --slurpfile baseline "$monitors_before" '
      def identities:
        map({id, name, description, make, model, serial}) | sort_by(.name);
      ($baseline[0] | identities) as $before
      | ([.[] | select(.name != $name)] | identities) as $existing
      | ([.[] | select(.name == $name)
          | {id, name, description, make, model, serial}]) as $created
      | if length == ($baseline[0] | length) + 1
          and $existing == $before and ($created | length) == 1
          and ($created[0].id | type) == "number" and $created[0].id >= 0
          and $created[0].id == ($created[0].id | floor)
        then $created[0] else empty end
    ') || return 1
  [[ -n $identity ]] || return 1
  headless_output_identity=$identity
}

headless_output_is_owned() {
  [[ -n $headless_output_identity ]] || adopt_proven_headless_output || return 1
  hyprctl_bounded monitors all -j 2>/dev/null | jq -e \
    --arg name "$headless_name" --argjson identity "$headless_output_identity" '
      [ .[] | select(.name == $name)
        | {id, name, description, make, model, serial} ] == [$identity]
    ' >/dev/null
}

headless_presence_state() {
  local monitors=""
  monitors=$(hyprctl_bounded monitors all -j 2>/dev/null) || return 2
  jq -e '
    type == "array"
    and all(.[]; type == "object" and (.name | type) == "string")
  ' <<<"$monitors" >/dev/null || return 2
  if jq -e --arg name "$headless_name" 'any(.[]; .name == $name)' \
    <<<"$monitors" >/dev/null; then
    return 0
  fi
  return 1
}

headless_output_removal_state_is_exact() {
  local workspaces_current="$evidence_dir/workspaces.removal-attempt.json"
  local clients_current="$evidence_dir/clients.removal-attempt.json"
  (( ${cleanup_active:-0} )) || return 1
  [[ -f $workspaces_normalized_before && ! -L $workspaces_normalized_before &&
    -f $clients_normalized_before && ! -L $clients_normalized_before &&
    -n $headless_output_identity ]] || return 1
  headless_event_generation_is_current && headless_output_is_owned || return 1
  capture_normalized_workspace_state "$workspaces_current" || return 1
  capture_normalized_client_state "$clients_current" || return 1
  cmp -s -- "$clients_normalized_before" "$clients_current" || return 1
  jq -e --arg monitor "$headless_name" \
    --arg workspace_id "${headless_workspace_id:-}" \
    --argjson output_identity "$headless_output_identity" \
    --slurpfile baseline "$workspaces_normalized_before" '
      ($baseline[0]) as $before
      | . as $current
      | ($current - $before) as $added
      | ($before - $current) as $missing
      | ($missing | length) == 0
      and (
        $current == $before
        or (
          ($added | length) == 1
          and $added[0].monitor == $monitor
          and $added[0].monitorID == $output_identity.id
          and $added[0].windows == 0
          and $added[0].hasfullscreen == false
          and $added[0].ispersistent == false
          and $added[0].lastwindow == "0x0"
          and ($workspace_id == ""
            or ($added[0].id | tostring) == $workspace_id)
        )
      )
    ' "$workspaces_current" >/dev/null || return 1
  headless_event_generation_is_current && headless_output_is_owned
}

remove_owned_headless_output_once() {
  (( ${cleanup_active:-0} )) || return 1
  live_lock_is_held || return 1
  session_is_safe_for_live_mutation || return 1
  compositor_identity_matches || return 1
  headless_event_socket_is_compositor_listener || return 1
  headless_name_matches_nonce || return 1
  headless_event_generation_is_current || return 1
  headless_output_is_owned || return 1
  headless_output_removal_state_is_exact || return 1
  live_lock_is_held || return 1
  session_is_safe_for_live_mutation || return 1
  compositor_identity_matches || return 1
  headless_event_socket_is_compositor_listener || return 1
  headless_name_matches_nonce || return 1
  headless_event_generation_is_current || return 1
  headless_output_is_owned || return 1
  hyprctl_bounded output remove "$headless_name" >/dev/null 2>&1
}

assert_bar_layer_edge() {
  local layers_file=$1 monitor=$2 edge=$3
  jq -e --arg monitor "$monitor" --arg edge "$edge" \
    --slurpfile monitors "$monitors_configured" '
      def close($a; $b): (($a - $b) | fabs) <= 1;
      ($monitors[0][] | select(.name == $monitor)) as $m
      | ([ .[$monitor].levels | to_entries[] | .value[]
           | select(.namespace == "omarchy-bar") ]) as $bars
      | ($m.width / $m.scale | floor) as $mw
      | ($m.height / $m.scale | floor) as $mh
      | ($bars | length) == 1
        and ($bars[0].w > 0 and $bars[0].h > 0)
        and (if $edge == "top" then
               close($bars[0].x; $m.x) and close($bars[0].y; $m.y)
               and close($bars[0].w; $mw)
             elif $edge == "bottom" then
               close($bars[0].x; $m.x) and close($bars[0].w; $mw)
               and close($bars[0].y + $bars[0].h; $m.y + $mh)
             elif $edge == "left" then
               close($bars[0].x; $m.x) and close($bars[0].y; $m.y)
               and close($bars[0].h; $mh)
             else
               close($bars[0].y; $m.y) and close($bars[0].h; $mh)
               and close($bars[0].x + $bars[0].w; $m.x + $mw)
             end)
    ' "$layers_file" >/dev/null
}

script_dir=""
repo_root=""
release_binary=""
release_binary_full_identity=""
release_binary_sha256=""
snapshot_fixture=""
snapshot_fixture_full_identity=""
plugin_source=""
plugin_target=""
plugin_root=""
plugin_root_identity=""
real_plugin_root=""
real_plugin_target=""
real_plugin_root_identity=""
real_plugin_digest_before=""
shell_config=""
real_shell_config=""
real_shell_hash_before=""
real_shell_canonical_hash_before=""
real_shell_stat_before=""
real_shell_atime_before_capture=""
real_shell_acl_before=""
real_shell_xattr_before=""
real_xdg_config_home=""
real_xdg_cache_home=""
real_xdg_data_home=""
real_xdg_state_home=""
real_state_parent=""
real_state_parent_identity=""
real_state_root=""
real_state_root_identity=""
real_stay_awake_marker=""
real_stay_awake_hash_before=""
real_stay_awake_stat_before=""
real_stay_awake_acl_before=""
real_stay_awake_xattr_before=""
isolated_home=""
isolated_home_identity=""
isolated_local_home=""
isolated_local_home_identity=""
isolated_config_home=""
isolated_cache_home=""
isolated_data_home=""
isolated_state_home=""
isolated_state_home_identity=""
state_bridge=""
state_bridge_identity=""
safe_shell_default=""
safe_shell_default_identity=""
safe_shell_default_hash=""
namespace_wrapper=""
namespace_wrapper_identity=""
evidence_dir=""
evidence_dir_identity=""
temporary_runtime=""
temporary_runtime_identity=""
temporary_binary=""
temporary_binary_identity=""
temporary_binary_full_identity=""
temporary_binary_sha256=""
production_runtime=""
production_runtime_identity=""
real_production_runtime=""
real_display_socket=""
runtime_root_identity=""
live_lock_path=""
live_lock_identity=""
live_lock_fd=""
live_lock_created=0
display_socket=""
display_socket_identity=""
mock_pid=""
mock_pgid=""
mock_pid_start=""
mock_handler=""
mock_log=""
snapshot_wire=""
snapshot_frame=""
server_hello=""
transient_unit=""
transient_token=""
transient_invocation=""
transient_control_group=""
transient_submission_absence_proven=0
transient_submission_pending=0
headless_name=""
headless_nonce=""
headless_name_base64=""
headless_output_identity=""
headless_creation_proven=0
headless_rule_mutated=0
headless_event_socket=""
headless_event_socket_identity=""
headless_event_log=""
headless_event_log_identity=""
headless_ready_pipe=""
headless_ready_pipe_identity=""
headless_ready_pipe_created=0
headless_authorization_pipe=""
headless_authorization_pipe_identity=""
headless_authorization_pipe_created=0
headless_ready_child_fd=""
headless_ready_child_fd_number=""
headless_ready_parent_fd=""
headless_authorization_child_fd=""
headless_authorization_child_fd_number=""
headless_authorization_parent_fd=""
headless_event_handshake_released=0
headless_event_watcher_pid=""
headless_event_watcher_start=""
headless_event_watcher_started=0
headless_event_watcher_owned=0
headless_event_watcher_ready=0
headless_event_watcher_armed=0
headless_event_authorization_committed=0
headless_event_client_inode=""
headless_workspace_id=""
hyprland_config_errors_before=""
hyprland_compositor_pid_before=""
hyprland_compositor_start_before=""
hyprland_mount_namespace_before=""
harness_mount_namespace_before=""
hyprland_executable_identity_before=""
aquamarine_identity_before=""
aquamarine_inode_before=""
hyprutils_identity_before=""
hyprutils_inode_before=""
workspaces_normalized_before=""
clients_normalized_before=""
active_workspace_id_before=""
monitor_manager_unit="hyprmoncfgd.service"
hyprmoncfg_socket=""
monitor_manager_invocation_before=""
monitor_manager_pid_before=""
monitor_manager_pid_start_before=""
monitor_manager_executable_identity_before=""
monitor_manager_cgroup_before=""
monitor_manager_fingerprint_before=""
monitor_status_before=""
monitor_manager_config_file=""
hyprland_lua_file=""
monitor_profiles_root=""
monitor_profiles_digest_before=""
monitor_manager_config_hash_before=""
hyprland_lua_hash_before=""
monitor_manager_config_stat_before=""
monitor_manager_config_acl_before=""
monitor_manager_config_xattr_before=""
hyprland_lua_stat_before=""
hyprland_lua_acl_before=""
hyprland_lua_xattr_before=""
plugin_target_identity=""
plugin_source_manifest=""
plugin_target_manifest=""
shell_backup=""
shell_hash_before=""
shell_hash_expected=""
shell_stat_before=""
shell_identity_before=""
shell_canonical_before=""
shell_canonical_hash_expected=""
bar_position_before=""
bar_position_last_expected=""
plugin_entry_index_expected=""
plugin_entry_json_expected=""
plugin_list_before=""
plugin_list_hash_before=""
plugin_list_enabled_hash=""
monitors_before=""
monitors_configured=""
monitors_normalized_before=""
monitors_hash_before=""
cursor_before=""
focused_monitor_before=""
session_monitors_normalized_before=""
session_monitors_hash_before=""
session_monitors_raw=""
session_workspaces_normalized_before=""
session_clients_normalized_before=""
session_cursor_before=""
session_layers_normalized_before=""
manager_override_before=""
original_shell_pid=""
original_shell_pid_start=""
original_launcher_pid=""
original_launcher_pid_start=""
original_launcher_stop_pending=0
original_shell_stop_requested=0
recovery_term_committed=0
original_launcher_term_committed=0
term_tainted_shell_pid=""
term_tainted_shell_pid_start=""
adopted_normal_shell_pid=""
adopted_normal_launcher_pid=""
adopted_normal_launcher_start=""
shell_replaced=0
transient_started=0
state_bridge_created=0
plugin_copied=0
plugin_target_manifest_valid=0
config_mutated=0
plugin_entry_recorded=0
output_created=0
isolated_bar_baseline_restored=0
mock_started=0
temporary_runtime_created=0
production_runtime_created=0
cleanup_failed=0
cleanup_active=0
cleanup_bar_restore_deadline=0
cleanup_monitor_deadline=0
cleanup_final_deadline=0
transient_stop_unresolved=0

cleanup_problem() {
  cleanup_failed=1
  printf 'live-smoke: cleanup warning: %s\n' "$*" >&2
}

restore_isolated_bar_for_cleanup() {
  local pid current_position attempt candidate
  (( output_created && transient_started )) || return 1
  transient_unit_is_owned || return 1
  pid=$(shell_pid 2>/dev/null) || return 1
  quickshell_instance_is_exact "$pid" || return 1
  process_has_override "$pid" || return 1
  [[ -f $shell_config && ! -L $shell_config &&
    $(stat -c '%u:%a' -- "$shell_config") == "$UID:600" &&
    $(sha256_file "$shell_config") == "$shell_hash_expected" ]] || return 1
  OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell hide "$plugin_id" >/dev/null 2>&1 || true
  OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell hide "$other_panel_id" >/dev/null 2>&1 || true
  current_position=$(jq -er '.bar.position' "$shell_config" 2>/dev/null) || return 1
  if [[ $current_position != "$bar_position_before" ]]; then
    run_isolated timeout --kill-after=1s 5s omarchy bar position "$bar_position_before" \
      >"$evidence_dir/bar-position-restore.cleanup.log" 2>&1 || return 1
    shell_hash_expected=$(sha256_file "$shell_config") || return 1
    shell_canonical_hash_expected=$(canonical_json_file_hash "$shell_config") || return 1
  fi
  wait_for_effective_shell_config "$shell_canonical_hash_expected" || return 1
  wait_for_bar_position "$bar_position_before" || return 1
  wait_for_geometry 2 "$evidence_dir/geometry.restored-edge.cleanup.json" || return 1
  focus_monitor_cleanup "$focused_monitor_before" >/dev/null 2>&1 || return 1
  dispatch_workspace_safely "$active_workspace_id_before" || return 1
  for (( attempt = 0; attempt < 50; attempt++ )); do
    cleanup_bar_retry_allowed || return 1
    candidate="$evidence_dir/clients.restored-edge.cleanup.json"
    if capture_normalized_client_state "$candidate" &&
      cmp -s -- "$clients_normalized_before" "$candidate"; then
      isolated_bar_baseline_restored=1
      return 0
    fi
    sleep 0.1
  done
  return 1
}

terminate_exact_original_shell_for_recovery() {
  local attempt recovery_pair="" recovery_pid="" recovery_start="" launcher_pair=""
  local stopped_child_state="" stopped_child_recheck=""
  local launcher_present=0 launcher_kill_committed=0 recovery_deadline=$((SECONDS + 4))
  session_is_confirmed_unlocked || return 1
  live_lock_is_held || return 1

  # A failed clean stop can leave the pinned launcher in its one-second
  # supervisor backoff. Give a replacement a short real deadline to register;
  # an already pinned original child remains valid even while unregistered.
  for (( attempt = 0; attempt < 40 && SECONDS < recovery_deadline; attempt++ )); do
    launcher_present=0
    if original_launcher_task_is_same; then
      if ! original_launcher_process_is_same; then
        sleep 0.1
        continue
      fi
      launcher_present=1
      if original_shell_process_is_same &&
        registry_is_exclusive_or_absent "$original_shell_pid"; then
        recovery_pid=$original_shell_pid
        recovery_start=$original_shell_pid_start
        break
      fi
      recovery_pair=$(pin_replacement_under_original_launcher 2>/dev/null) || recovery_pair=""
      if [[ $recovery_pair == *:* ]]; then
        IFS=: read -r recovery_pid recovery_start <<<"$recovery_pair"
        break
      fi
      recovery_pair=$(pin_direct_replacement_under_original_launcher 2>/dev/null) || recovery_pair=""
      if [[ $recovery_pair == *:* ]]; then
        IFS=: read -r recovery_pid recovery_start <<<"$recovery_pair"
        break
      fi
    elif original_launcher_task_is_stably_absent; then
      if original_shell_process_is_same &&
        registry_is_exclusive_or_absent "$original_shell_pid"; then
        recovery_pid=$original_shell_pid
        recovery_start=$original_shell_pid_start
        break
      elif quickshell_has_no_instances; then
        return 0
      else
        return 1
      fi
    else
      sleep 0.1
      continue
    fi
    sleep 0.1
  done
  [[ $recovery_pid =~ ^[1-9][0-9]*$ && $recovery_start =~ ^[1-9][0-9]*$ ]] || return 1
  normal_packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
  registry_is_exclusive_or_absent "$recovery_pid" || return 1

  if (( launcher_present )); then
    original_launcher_is_running_exact || return 1
    process_has_frontend_environment "$original_launcher_pid" "$HOME" \
      "$real_xdg_config_home" "$real_xdg_cache_home" "$real_xdg_data_home" \
      "$real_xdg_state_home" || return 1
    process_has_session_transport_environment "$original_launcher_pid" || return 1
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    launcher_pair=$(resolve_exact_packaged_launcher_for_shell "$recovery_pid") || return 1
    [[ $launcher_pair == "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1
    normal_packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
    registry_is_exclusive_or_absent "$recovery_pid" || return 1
    [[ $(resolve_exact_packaged_launcher_for_shell "$recovery_pid") == \
      "$original_launcher_pid:$original_launcher_pid_start" ]] || return 1
    original_launcher_is_running_exact || return 1
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    original_launcher_is_running_exact || return 1
    kill -TERM -- "$original_launcher_pid" 2>/dev/null || return 1
    # TERM permanently changes the launcher's control flow: its trap sets
    # terminating=1 before asking the child to exit. The tree may remain fully
    # responsive while that unwind is pending, so publish the taint before any
    # later proof can fail and cleanup can consider adoption.
    recovery_term_committed=1
    original_launcher_term_committed=1
    term_tainted_shell_pid=$recovery_pid
    term_tainted_shell_pid_start=$recovery_start
  else
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    normal_packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
    registry_is_exclusive_or_absent "$recovery_pid" || return 1
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    normal_packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
    kill -TERM -- "$recovery_pid" 2>/dev/null || return 1
    recovery_term_committed=1
    term_tainted_shell_pid=$recovery_pid
    term_tainted_shell_pid_start=$recovery_start
  fi

  for (( attempt = 0; attempt < 25; attempt++ )); do
    if ! original_launcher_process_is_same &&
      ! packaged_shell_process_is_exact "$recovery_pid" "$recovery_start"; then
      break
    fi
    sleep 0.1
  done

  if original_launcher_task_is_same; then
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    original_launcher_is_running_exact || return 1
    original_launcher_is_running_exact || return 1
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    original_launcher_is_running_exact || return 1
    kill -STOP -- "$original_launcher_pid" 2>/dev/null || return 1
    original_launcher_stop_pending=1
    for (( attempt = 0; attempt < 10; attempt++ )); do
      original_launcher_is_stopped_exact && break
      sleep 0.05
    done
    if ! original_launcher_is_stopped_exact; then
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    fi
    stopped_child_state=$(stopped_original_launcher_child_state 2>/dev/null) || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    stopped_child_recheck=$(stopped_original_launcher_child_state 2>/dev/null) || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    if [[ $stopped_child_recheck != "$stopped_child_state" ]]; then
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    fi
    if [[ $stopped_child_state == none ]]; then
      if packaged_shell_process_is_exact "$recovery_pid" "$recovery_start"; then
        continue_original_launcher_after_failed_stop_proof || true
        return 1
      fi
    elif [[ $stopped_child_state == *:* ]]; then
      IFS=: read -r recovery_pid recovery_start <<<"$stopped_child_state"
      [[ $recovery_pid =~ ^[1-9][0-9]*$ && $recovery_start =~ ^[1-9][0-9]*$ ]] || {
        continue_original_launcher_after_failed_stop_proof || true
        return 1
      }
    else
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    fi
    session_is_confirmed_unlocked || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    live_lock_is_held || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    original_launcher_is_stopped_exact || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    [[ $(stopped_original_launcher_child_state 2>/dev/null) == "$stopped_child_state" ]] || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    session_is_confirmed_unlocked || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    live_lock_is_held || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    original_launcher_is_stopped_exact || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    if [[ $stopped_child_state != none ]]; then
      if packaged_shell_process_is_exact "$recovery_pid" "$recovery_start"; then
        session_is_confirmed_unlocked || {
          continue_original_launcher_after_failed_stop_proof || true
          return 1
        }
        packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || {
          continue_original_launcher_after_failed_stop_proof || true
          return 1
        }
        if ! kill -KILL -- "$recovery_pid" 2>/dev/null &&
          ! process_task_is_absent_or_replaced "$recovery_pid" "$recovery_start"; then
          continue_original_launcher_after_failed_stop_proof || true
          return 1
        fi
      elif ! process_task_is_absent_or_replaced "$recovery_pid" "$recovery_start"; then
        continue_original_launcher_after_failed_stop_proof || true
        return 1
      fi
    fi
    original_launcher_is_stopped_exact || {
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    }
    if ! kill -KILL -- "$original_launcher_pid" 2>/dev/null; then
      continue_original_launcher_after_failed_stop_proof || true
      return 1
    fi
    launcher_kill_committed=1
  elif ! original_launcher_task_is_stably_absent; then
    return 1
  fi
  if (( ! launcher_kill_committed )) &&
    packaged_shell_process_is_exact "$recovery_pid" "$recovery_start"; then
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    registry_is_exclusive_or_absent "$recovery_pid" || return 1
    normal_packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
    session_is_confirmed_unlocked || return 1
    live_lock_is_held || return 1
    packaged_shell_process_is_exact "$recovery_pid" "$recovery_start" || return 1
    kill -KILL -- "$recovery_pid" 2>/dev/null || return 1
  fi
  if wait_for_recovery_supervision_exit "$recovery_pid" "$recovery_start"; then
    (( launcher_kill_committed )) && original_launcher_stop_pending=0
    return 0
  fi
  if (( launcher_kill_committed )) && original_launcher_task_is_stably_absent; then
    original_launcher_stop_pending=0
  fi
  return 1
}

settle_original_shell_after_failed_replacement() {
  if (( ! original_shell_stop_requested && ! recovery_term_committed )); then
    wait_for_exact_normal_shell && return 1
  fi
  wait_for_original_shell_exit_and_stable_absence && return 0
  terminate_exact_original_shell_for_recovery || true
  continue_original_launcher_after_failed_stop_proof || true
  # A successfully delivered TERM is irreversible even if a later STOP/KILL
  # proof failed. Never adopt a still-responsive member of that doomed tree;
  # only authoritative all-instance absence may authorize a fresh restart.
  if (( recovery_term_committed )); then
    wait_for_original_shell_exit_and_stable_absence && return 0
    return 2
  fi
  wait_for_exact_normal_shell && return 1
  wait_for_original_shell_exit_and_stable_absence && return 0
  return 2
}

normal_shell_candidate_excludes_stale_original() {
  local candidate_pid=$1 candidate_start=$2 candidate_launcher_pid=$3
  local candidate_launcher_start=$4
  if (( original_shell_stop_requested )) &&
    { [[ $candidate_pid == "$original_shell_pid" &&
        $candidate_start == "$original_shell_pid_start" ]] ||
      [[ $candidate_launcher_pid == "$original_launcher_pid" &&
        $candidate_launcher_start == "$original_launcher_pid_start" ]]; }; then
    return 1
  fi
  if (( original_launcher_term_committed )) &&
    [[ $candidate_launcher_pid == "$original_launcher_pid" &&
      $candidate_launcher_start == "$original_launcher_pid_start" ]]; then
    return 1
  fi
  if (( recovery_term_committed )) &&
    [[ $candidate_pid == "$term_tainted_shell_pid" &&
      $candidate_start == "$term_tainted_shell_pid_start" ]]; then
    return 1
  fi
  if [[ $candidate_pid == "$original_shell_pid" ]]; then
    [[ $candidate_launcher_pid == "$original_launcher_pid" ]] &&
      original_shell_process_is_same && original_launcher_is_running_exact
  else
    process_task_is_absent_or_replaced \
      "$original_shell_pid" "$original_shell_pid_start" || return 1
    if original_launcher_task_is_same; then
      [[ $candidate_launcher_pid == "$original_launcher_pid" ]] &&
        original_launcher_is_running_exact
    elif original_launcher_task_is_stably_absent; then
      return 0
    else
      return 1
    fi
  fi
}

wait_for_exact_normal_shell() {
  local attempt candidate_pid="" candidate_start="" current_pid="" launcher_pair=""
  local candidate_launcher_pid="" candidate_launcher_start=""
  for (( attempt = 0; attempt < 10; attempt++ )); do
    if bounded_shell_ipc shell ping >/dev/null 2>&1; then
      candidate_pid=$(shell_pid 2>/dev/null) || candidate_pid=""
      candidate_start=""
      if [[ $candidate_pid =~ ^[1-9][0-9]*$ ]]; then
        candidate_start=$(awk '{print $22}' "/proc/$candidate_pid/stat" 2>/dev/null) ||
          candidate_start=""
      fi
      if [[ $candidate_pid =~ ^[1-9][0-9]*$ ]] &&
        [[ $candidate_start =~ ^[1-9][0-9]*$ ]] &&
        quickshell_instance_is_exact "$candidate_pid" &&
        normal_packaged_shell_process_is_exact "$candidate_pid" "$candidate_start" &&
        ! process_has_any_override "$candidate_pid" &&
        process_has_frontend_environment "$candidate_pid" "$HOME" \
          "$real_xdg_config_home" "$real_xdg_cache_home" "$real_xdg_data_home" \
          "$real_xdg_state_home" &&
        process_has_session_transport_environment "$candidate_pid" &&
        launcher_pair=$(resolve_exact_packaged_launcher_for_shell "$candidate_pid"); then
        IFS=: read -r candidate_launcher_pid candidate_launcher_start <<<"$launcher_pair"
        if [[ $candidate_launcher_pid =~ ^[1-9][0-9]*$ &&
          $candidate_launcher_start =~ ^[1-9][0-9]*$ ]] &&
          packaged_shell_launcher_process_is_running_exact \
            "$candidate_launcher_pid" "$candidate_launcher_start" &&
          normal_shell_candidate_excludes_stale_original \
            "$candidate_pid" "$candidate_start" \
            "$candidate_launcher_pid" "$candidate_launcher_start"; then
          break
        fi
      fi
    fi
    candidate_pid=""
    candidate_start=""
    candidate_launcher_pid=""
    candidate_launcher_start=""
    sleep 0.1
  done
  [[ $candidate_pid =~ ^[1-9][0-9]*$ ]] || return 1
  wait_for_shell_lock_consistency || return 1
  wait_for_effective_shell_config "$real_shell_canonical_hash_before" || return 1
  wait_for_shell_continuity "$candidate_pid" "$HOME" "$real_xdg_config_home" \
    "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" \
    "$real_stay_awake_marker" || return 1
  current_pid=$(shell_pid 2>/dev/null) || return 1
  [[ $current_pid == "$candidate_pid" ]] || return 1
  normal_shell_candidate_excludes_stale_original \
    "$candidate_pid" "$candidate_start" \
    "$candidate_launcher_pid" "$candidate_launcher_start" || return 1
  normal_packaged_shell_process_is_exact "$candidate_pid" "$candidate_start" || return 1
  quickshell_instance_is_exact "$candidate_pid" || return 1
  ! process_has_any_override "$candidate_pid" || return 1
  process_has_frontend_environment "$candidate_pid" "$HOME" \
    "$real_xdg_config_home" "$real_xdg_cache_home" "$real_xdg_data_home" \
    "$real_xdg_state_home" || return 1
  process_has_session_transport_environment "$candidate_pid" || return 1
  [[ $(resolve_exact_packaged_launcher_for_shell "$candidate_pid") == \
    "$candidate_launcher_pid:$candidate_launcher_start" ]] || return 1
  packaged_shell_launcher_process_is_running_exact \
    "$candidate_launcher_pid" "$candidate_launcher_start" || return 1
  adopted_normal_shell_pid=$candidate_pid
  adopted_normal_launcher_pid=$candidate_launcher_pid
  adopted_normal_launcher_start=$candidate_launcher_start
}

cleanup() {
  local status=$?
  trap '' HUP INT TERM
  trap - EXIT
  local pid current current_manifest final_manager mock_state=1
  local body_status=$status
  local transient_quiet=1
  local support_stack_teardown_safe=1
  local final_plugin_list="" final_plugin_hash="" final_monitors="" final_monitor_hash=""
  local final_workspaces="" final_clients=""
  local final_layers=""
  local final_cursor=""
  local temporary_binary_removal_safe=1
  local workspace_cleanup_before="" clients_cleanup_before="" workspace_cleanup_after=""
  local clients_cleanup_after="" monitor_cleanup_after="" candidate_workspace_id="" workspace_interim=""
  local clients_interim="" workspace_interim_valid=0
  local workspace_switch_succeeded=0 workspace_restore_succeeded=0
  local original_settle_state=2 normal_shell_available=0 restart_normal_shell=0
  local headless_state=2 headless_absence_streak=0
  local restart_status=0
  local all_quickshell_absent=0
  local headless_absence_proven=0 reload_proven=0 monitor_topology_proven=0
  local topology_capture_ok=1
  local headless_workspace_proven=0 headless_removal_authorized=0
  local headless_removal_witness_proven=0
  local headless_watcher_stopped=1
  local final_layer_match=0
  local -a bridge_pids=()
  set +e

  cleanup_active=1
  cleanup_final_deadline=$((SECONDS + 120))
  note "cleanup started"
  if [[ -n $live_lock_identity ]]; then
    live_lock_is_held || cleanup_problem "per-user live-smoke lock changed during the run"
  fi

  if (( output_created )); then
    cleanup_bar_restore_deadline=$((SECONDS + 8))
    restore_isolated_bar_for_cleanup ||
      cleanup_problem "isolated baseline bar edge/client layout did not settle before output cleanup"
    cleanup_bar_restore_deadline=0
  fi

  if (( output_created )); then
    cleanup_monitor_deadline=$((SECONDS + 30))
    if headless_name_matches_nonce && compositor_identity_matches; then
      for (( current = 0; current < 20; current++ )); do
        cleanup_monitor_retry_allowed || break
        headless_presence_state
        headless_state=$?
        (( headless_state != 2 )) && break
        sleep 0.05
      done
      if (( headless_state == 0 )); then
        if ! headless_output_is_owned; then
          cleanup_problem "refused to operate on a replaced headless output"
        else
        if [[ -n $focused_monitor_before && $active_workspace_id_before =~ ^[1-9][0-9]*$ ]]; then
          focus_monitor_cleanup "$focused_monitor_before" >/dev/null 2>&1 ||
            cleanup_problem "could not focus the original output before headless removal"
          dispatch_workspace_safely "$active_workspace_id_before" ||
            cleanup_problem "could not activate the original workspace before headless removal"
          for (( current = 0; current < 50; current++ )); do
            cleanup_monitor_retry_allowed || break
            if hyprctl_bounded monitors all -j | jq -e --arg monitor "$focused_monitor_before" \
              --argjson workspace "$active_workspace_id_before" '
                any(.[]; .name == $monitor and .focused == true
                  and .activeWorkspace.id == $workspace)
              ' >/dev/null 2>&1; then
              break
            fi
            sleep 0.1
          done
          hyprctl_bounded monitors all -j | jq -e --arg monitor "$focused_monitor_before" \
            --argjson workspace "$active_workspace_id_before" '
              any(.[]; .name == $monitor and .focused == true
                and .activeWorkspace.id == $workspace)
            ' >/dev/null 2>&1 ||
            cleanup_problem "original output/workspace did not settle before headless removal"
        fi

        if [[ -f $workspaces_normalized_before && -f $clients_normalized_before ]]; then
          workspace_cleanup_before="$evidence_dir/workspaces.before-output-removal.json"
          clients_cleanup_before="$evidence_dir/clients.before-output-removal.json"
          headless_workspace_proven=0
          for (( current = 0; current < 20; current++ )); do
            cleanup_monitor_retry_allowed || break
            if capture_normalized_workspace_state "$workspace_cleanup_before" &&
              capture_normalized_client_state "$clients_cleanup_before" &&
              cmp -s -- "$clients_normalized_before" "$clients_cleanup_before"; then
              candidate_workspace_id=$(jq -er --arg monitor "$headless_name" \
                --slurpfile baseline "$workspaces_normalized_before" '
                  if . == $baseline[0] then "none"
                  else
                    (. - $baseline[0]) as $added
                    | ($baseline[0] - .) as $missing
                    | if ($missing | length) == 0 and ($added | length) == 1
                      and $added[0].monitor == $monitor and $added[0].windows == 0
                      and $added[0].hasfullscreen == false and $added[0].ispersistent == false
                      then ($added[0].id | tostring) else empty end
                  end
                ' "$workspace_cleanup_before" 2>/dev/null)
              if [[ $candidate_workspace_id == none && -z $headless_workspace_id ]]; then
                headless_workspace_proven=1
                break
              elif [[ $candidate_workspace_id =~ ^[1-9][0-9]*$ ]] &&
                [[ -z $headless_workspace_id || $candidate_workspace_id == "$headless_workspace_id" ]]; then
                headless_workspace_id=$candidate_workspace_id
                headless_workspace_proven=1
                break
              fi
            fi
            sleep 0.1
          done
          (( headless_workspace_proven )) ||
            cleanup_problem "could not prove unchanged clients and an optional empty owned workspace before output removal"
        fi

        if (( headless_workspace_proven )); then
          headless_removal_authorized=1
          for (( current = 0; current < 10; current++ )); do
            cleanup_monitor_retry_allowed || break
            headless_presence_state
            headless_state=$?
            if (( headless_state == 1 )); then
              break
            elif (( headless_state == 0 )); then
              # Ownership and generation remain mandatory inside the removal
              # helper. A single bounded procfs/hyprctl sample is not evidence
              # that either changed, so retain authority and retry safely.
              remove_owned_headless_output_once || true
            fi
            sleep 0.1
          done
        fi
        fi
      elif (( headless_state == 2 )); then
        cleanup_problem "headless output presence was initially indeterminate during cleanup"
      fi
      headless_absence_streak=0
      for (( current = 0; current < 50; current++ )); do
        cleanup_monitor_retry_allowed || break
        headless_presence_state
        headless_state=$?
        if (( headless_state == 1 )); then
          headless_absence_streak=$((headless_absence_streak + 1))
          (( headless_absence_streak >= 3 )) && break
        elif (( headless_state == 0 )); then
          headless_absence_streak=0
          if (( ! headless_removal_authorized )); then
            cleanup_problem "headless output removal lacked stable output/workspace ownership"
            break
          fi
          remove_owned_headless_output_once || true
        else
          headless_absence_streak=0
        fi
        sleep 0.1
      done
      if (( headless_absence_streak >= 3 )); then
        headless_absence_proven=1
        if (( headless_creation_proven )); then
          if wait_for_headless_removal_event; then
            headless_removal_witness_proven=1
          else
            cleanup_problem "Hyprland monitor-generation witness did not record one exact removal"
          fi
        fi
      else
        cleanup_problem "owned headless output absence was not authoritatively stable after removal"
        if hyprctl_bounded monitors all -j \
          >"$evidence_dir/monitors.filtered-output-unresolved.json" 2>/dev/null &&
          jq -e --arg name "$headless_name" 'any(.[]; .name == $name)' \
            "$evidence_dir/monitors.filtered-output-unresolved.json" >/dev/null 2>&1; then
          printf '%s\n' \
            "The exact audited monitor manager remains running and ignores this connector." \
            "The harness did not prove removal authority or stable absence for its encoded connector." \
            "Connector name (base64): $headless_name_base64" \
            "Inspect the retained monitor evidence before any manual recovery." \
            "If the connector identity is still the harness-created headless output, remove it with:" \
            "  name=\$(printf '%s' '$headless_name_base64' | base64 -d)" \
            '  hyprctl output remove "$name"' \
            >"$evidence_dir/FILTERED-OUTPUT-RECOVERY-REQUIRED.txt"
        fi
      fi
      if (( ! headless_rule_mutated )); then
        reload_proven=1
      elif reload_hyprland_until_clean; then
        reload_proven=1
      else
        cleanup_problem "could not clear the transient monitor rule cleanly"
      fi
      if [[ -n $focused_monitor_before && $active_workspace_id_before =~ ^[1-9][0-9]*$ ]]; then
        focus_monitor_cleanup "$focused_monitor_before" >/dev/null 2>&1 ||
          cleanup_problem "could not refocus the original output after headless removal"
        dispatch_workspace_safely "$active_workspace_id_before" ||
          cleanup_problem "could not reactivate the original workspace after headless removal"
      fi

      if [[ $headless_workspace_id =~ ^[1-9][0-9]*$ ]] &&
        (( headless_absence_proven && headless_removal_witness_proven )) &&
        compositor_identity_matches; then
        workspace_interim="$evidence_dir/workspaces.after-output-removal.interim.json"
        clients_interim="$evidence_dir/clients.after-output-removal.interim.json"
        workspace_interim_valid=0
        for (( current = 0; current < 20; current++ )); do
          cleanup_monitor_retry_allowed || break
          if capture_normalized_workspace_state "$workspace_interim"; then
            workspace_interim_valid=1
            break
          fi
          sleep 0.1
        done
        if (( ! workspace_interim_valid )); then
          cleanup_problem "workspace presence remained indeterminate after headless removal"
        elif jq -e --argjson id "$headless_workspace_id" '
          any(.[]; .id == $id)
        ' "$workspace_interim" >/dev/null 2>&1; then
          if jq -e --argjson id "$headless_workspace_id" '
            any(.[]; .id == $id and .windows == 0 and .hasfullscreen == false
              and .ispersistent == false)
          ' "$workspace_interim" >/dev/null 2>&1 &&
            capture_normalized_client_state "$clients_interim" &&
            jq -e --argjson id "$headless_workspace_id" \
              'all(.[]; .workspace.id != $id)' "$clients_interim" >/dev/null 2>&1; then
            workspace_switch_succeeded=0
            for (( current = 0; current < 10; current++ )); do
              cleanup_monitor_retry_allowed || break
              if focus_monitor_once_cleanup "$focused_monitor_before" >/dev/null 2>&1 &&
                dispatch_workspace_safely "$headless_workspace_id"; then
                workspace_switch_succeeded=1
                break
              fi
              sleep 0.1
            done
            (( workspace_switch_succeeded )) ||
              cleanup_problem "could not activate the empty owned workspace for removal"

            workspace_restore_succeeded=0
            for (( current = 0; current < 30; current++ )); do
              cleanup_monitor_retry_allowed || break
              if focus_monitor_once_cleanup "$focused_monitor_before" >/dev/null 2>&1 &&
                dispatch_workspace_safely "$active_workspace_id_before" &&
                hyprctl_bounded monitors all -j | jq -e --arg monitor "$focused_monitor_before" \
                  --argjson workspace "$active_workspace_id_before" '
                    any(.[]; .name == $monitor and .focused == true
                      and .activeWorkspace.id == $workspace)
                  ' >/dev/null 2>&1 &&
                hyprctl_bounded workspaces -j | jq -e --argjson id "$headless_workspace_id" \
                  'all(.[]; .id != $id)' >/dev/null 2>&1; then
                workspace_restore_succeeded=1
                break
              fi
              sleep 0.1
            done
            (( workspace_restore_succeeded )) ||
              cleanup_problem "original workspace was not restored after owned workspace removal"
            hyprctl_bounded monitors all -j | jq -e --arg monitor "$focused_monitor_before" \
              --argjson workspace "$active_workspace_id_before" '
                any(.[]; .name == $monitor and .focused == true
                  and .activeWorkspace.id == $workspace)
              ' >/dev/null 2>&1 ||
              cleanup_problem "original output/workspace was not active after owned workspace cleanup"
            hyprctl_bounded workspaces -j | jq -e --argjson id "$headless_workspace_id" \
              'all(.[]; .id != $id)' >/dev/null 2>&1 ||
              cleanup_problem "owned headless workspace remained after the bounded removal sequence"
          else
            cleanup_problem "owned workspace survived with non-empty or changed state"
          fi
        fi
      elif [[ $headless_workspace_id =~ ^[1-9][0-9]*$ ]]; then
        cleanup_problem "retained the candidate headless workspace because output absence/generation authority was incomplete"
      fi

      if [[ -f $workspaces_normalized_before && -f $clients_normalized_before ]]; then
        monitor_cleanup_after="$evidence_dir/monitors.after-output-cleanup.json"
        workspace_cleanup_after="$evidence_dir/workspaces.after-output-cleanup.json"
        clients_cleanup_after="$evidence_dir/clients.after-output-cleanup.json"
        topology_capture_ok=0
        for (( current = 0; current < 20; current++ )); do
          cleanup_monitor_retry_allowed || break
          if capture_normalized_monitor_state "$monitor_cleanup_after" &&
            capture_normalized_workspace_state "$workspace_cleanup_after" &&
            capture_normalized_client_state "$clients_cleanup_after"; then
            topology_capture_ok=1
            break
          fi
          sleep 0.1
        done
        if (( ! topology_capture_ok )); then
          cleanup_problem "desktop topology was indeterminate after filtered-output cleanup"
        elif [[ $(sha256_file "$monitor_cleanup_after") == "$monitors_hash_before" ]] &&
          cmp -s -- "$workspaces_normalized_before" "$workspace_cleanup_after" &&
          cmp -s -- "$clients_normalized_before" "$clients_cleanup_after"; then
          monitor_topology_proven=1
        else
          cleanup_problem "monitor/workspace/client structure was not restored after filtered-output cleanup"
        fi
      fi
    else
      cleanup_problem "refused output cleanup after nonce or compositor identity changed"
    fi
    (( headless_absence_proven && reload_proven && monitor_topology_proven )) ||
      cleanup_problem "filtered headless output cleanup did not restore every topology invariant"
    cleanup_monitor_deadline=0
  fi

  if (( output_created )) && [[ -n $focused_monitor_before ]]; then
    focus_monitor_cleanup "$focused_monitor_before" >/dev/null 2>&1 ||
      cleanup_problem "could not restore focused monitor"
  fi
  if (( output_created )) && [[ -f $cursor_before ]]; then
    restore_cursor_from_file "$cursor_before" pre-headless ||
      cleanup_problem "could not restore cursor position"
  fi

  if (( output_created )); then
    # Let a queued removal (or an ambiguously acknowledged filtered create)
    # cross the daemon's debounce and poll boundaries before auditing state.
    sleep 7
    compositor_identity_matches ||
      cleanup_problem "running compositor identity changed after filtered-output cleanup"
    monitor_manager_running_exact ||
      cleanup_problem "hyprmoncfgd identity/state changed after filtered-output cleanup"
    [[ $(monitor_watcher_scope_count) == 0 ]] ||
      cleanup_problem "fallback monitor watcher appeared after filtered-output cleanup"
    hyprmoncfg_preview_is_clear ||
      cleanup_problem "hyprmoncfgd gained a display preview after filtered-output cleanup"
    if ! capture_hyprmoncfg_status \
      "$evidence_dir/hyprmoncfg-status.after-output-cleanup-settle.json" \
      after-output-cleanup-settle ||
      ! cmp -s -- "$monitor_status_before" \
        "$evidence_dir/hyprmoncfg-status.after-output-cleanup-settle.json"; then
      cleanup_problem "hyprmoncfg status changed after the filtered-output cleanup settle window"
    fi
    monitor_manager_fingerprint \
      >"$evidence_dir/hyprmoncfgd-unit.after-output-cleanup-settle.txt" 2>/dev/null
    cmp -s -- "$monitor_manager_fingerprint_before" \
      "$evidence_dir/hyprmoncfgd-unit.after-output-cleanup-settle.txt" ||
      cleanup_problem "hyprmoncfgd unit definition changed after filtered-output cleanup"
    file_envelope_matches "$monitor_manager_config_file" "$monitor_manager_config_hash_before" \
      "$monitor_manager_config_stat_before" "$monitor_manager_config_acl_before" \
      "$monitor_manager_config_xattr_before" hyprmoncfg-monitors.lua.after-output-cleanup-settle ||
      cleanup_problem "hyprmoncfg monitor profile changed after filtered-output cleanup"
    file_envelope_matches "$hyprland_lua_file" "$hyprland_lua_hash_before" \
      "$hyprland_lua_stat_before" "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
      hyprland.lua.after-output-cleanup-settle ||
      cleanup_problem "root Hyprland Lua config changed after filtered-output cleanup"
    if ! tree_digest_noatime \
      "$monitor_profiles_root" \
      "$evidence_dir/hyprmoncfg-profiles.after-output-cleanup-settle.sha256" ||
      ! cmp -s -- "$monitor_profiles_digest_before" \
        "$evidence_dir/hyprmoncfg-profiles.after-output-cleanup-settle.sha256"; then
      cleanup_problem "hyprmoncfg profile tree changed after filtered-output cleanup"
    fi
    hyprland_config_errors_match ||
      cleanup_problem "Hyprland configuration errors changed after filtered-output cleanup"
  fi
  if (( headless_event_watcher_started )); then
    if ! stop_headless_event_watcher; then
      headless_watcher_stopped=0
      support_stack_teardown_safe=0
      temporary_binary_removal_safe=0
      cleanup_problem "Hyprland monitor-generation witness did not terminate cleanly; retaining its support stack and named lock"
    fi
  fi
  if (( headless_watcher_stopped && ! headless_event_handshake_released )); then
    release_headless_event_handshake || {
      support_stack_teardown_safe=0
      temporary_binary_removal_safe=0
      cleanup_problem "private event-witness handshake endpoints could not be released exactly"
    }
  fi

  if (( transient_started )); then
    transient_quiet=0
    if stop_owned_transient_until_quiet; then
      transient_quiet=1
      transient_stop_unresolved=0
    else
      transient_stop_unresolved=1
    fi
    (( transient_quiet )) ||
      cleanup_problem "transient service identity/quiescence remained unresolved after stop and KILL retries"
  fi

  if (( transient_started && transient_quiet )); then
    if wait_for_stable_no_quickshell_instances 3; then
      all_quickshell_absent=1
    else
      transient_quiet=0
      cleanup_problem "packaged-shell absence was not stable after transient cgroup shutdown"
    fi
  fi

  if (( transient_started && transient_quiet )); then
    if ! reprove_transient_quiescence; then
      transient_quiet=0
      all_quickshell_absent=0
      transient_stop_unresolved=1
      cleanup_problem "transient submission did not remain quiescent at state-bridge teardown"
    fi
  fi

  if (( transient_started && ! transient_quiet )); then
    support_stack_teardown_safe=0
    temporary_binary_removal_safe=0
    cleanup_problem "isolated mock/socket/binary stack retained because transient quiescence is unresolved"
  fi

  if (( state_bridge_created )); then
    if [[ -e $state_bridge || -L $state_bridge ]]; then
      if (( transient_started && ! transient_quiet )); then
        cleanup_problem "state mountpoint could still be visible to the isolated shell cgroup"
      elif ! state_bridge_host_is_owned; then
        cleanup_problem "isolated-state mountpoint changed or is not empty after namespace teardown"
      fi
    elif [[ -n $state_bridge_identity ]]; then
      cleanup_problem "isolated-state mountpoint disappeared before cleanup"
    fi
    mountpoint_is_absent_in_host_namespace "$state_bridge" ||
      cleanup_problem "isolated-state mount absence was not proven in the host namespace"
  fi

  if [[ -n $real_shell_hash_before ]] &&
    ! verify_real_user_state cleanup-after-isolated-shell; then
    cleanup_problem "real shell/plugin state changed while the isolated shell was active"
  fi
  if [[ -n $real_stay_awake_hash_before ]] &&
    ! file_envelope_matches "$real_stay_awake_marker" "$real_stay_awake_hash_before" \
      "$real_stay_awake_stat_before" "$real_stay_awake_acl_before" \
      "$real_stay_awake_xattr_before" stay-awake.after-isolated-shell; then
    cleanup_problem "stay-awake marker envelope changed while the isolated shell was active"
  fi

  if (( shell_replaced )); then
    if (( ! transient_started )); then
      settle_original_shell_after_failed_replacement
      original_settle_state=$?
      if (( original_settle_state == 1 )); then
        normal_shell_available=1
      elif (( original_settle_state == 0 )); then
        restart_normal_shell=1
      else
        cleanup_problem "original shell was neither stably healthy nor absent after replacement failure"
      fi
    elif (( ! transient_quiet )); then
      cleanup_problem "normal shell launch withheld because the override cgroup is still live"
    elif (( ! all_quickshell_absent )); then
      cleanup_problem "normal shell launch withheld because an unexpected cross-display instance exists"
    else
      restart_normal_shell=1
    fi

    if (( restart_normal_shell )); then
      if ! manager_session_environment_matches; then
        cleanup_problem "normal shell restart withheld because user-manager session context changed"
      elif (( transient_started )) && ! reprove_transient_quiescence; then
        transient_quiet=0
        transient_stop_unresolved=1
        cleanup_problem "normal shell restart withheld because transient quiescence was not adjacent"
      elif ! wait_for_stable_no_quickshell_instances 3 || ! quickshell_has_no_instances; then
        cleanup_problem "normal shell restart withheld because packaged-shell absence was not adjacent"
      else
        timeout --kill-after=2s 55s omarchy restart shell \
          >"$evidence_dir/normal-shell-restart.cleanup.log" 2>&1
        restart_status=$?
        printf '%s\n' "$restart_status" >"$evidence_dir/normal-shell-restart.cleanup.status"
        if wait_for_exact_normal_shell; then
          normal_shell_available=1
          if (( restart_status != 0 )); then
            cleanup_problem "normal Omarchy shell was adopted exactly, but its restart command exited $restart_status"
          fi
        else
          cleanup_problem "could not restore and exactly adopt the normal Omarchy shell (restart status $restart_status)"
        fi
      fi
    fi

    if (( normal_shell_available )); then
      wait_for_shell_lock_consistency ||
        cleanup_problem "restored shell lock state did not match the compositor"
      wait_for_effective_shell_config "$real_shell_canonical_hash_before" ||
        cleanup_problem "restored Omarchy shell did not load the exact real shell.json"
      pid=$(shell_pid 2>/dev/null)
      if [[ ! $pid =~ ^[1-9][0-9]*$ ]]; then
        cleanup_problem "could not resolve the restored normal shell PID"
      elif [[ $pid != "$adopted_normal_shell_pid" ]]; then
        cleanup_problem "restored normal shell changed after exact adoption"
      elif ! quickshell_instance_is_exact "$pid"; then
        cleanup_problem "restored shell is not the only packaged-shell instance"
      elif process_has_any_override "$pid"; then
        cleanup_problem "restored shell retained an executable override"
      elif ! process_has_frontend_environment "$pid" "$HOME" "$real_xdg_config_home" \
        "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home"; then
        cleanup_problem "restored shell did not recover the canonical HOME/XDG environment"
      elif ! process_has_session_transport_environment "$pid"; then
        cleanup_problem "restored shell did not recover the canonical Omarchy session transport"
      elif [[ $(resolve_exact_packaged_launcher_for_shell "$pid" 2>/dev/null) != \
        "$adopted_normal_launcher_pid:$adopted_normal_launcher_start" ]]; then
        cleanup_problem "restored shell lost its exact packaged launcher"
      elif ! packaged_shell_launcher_process_is_running_exact \
        "$adopted_normal_launcher_pid" "$adopted_normal_launcher_start"; then
        cleanup_problem "restored shell launcher remained stopped after recovery"
      elif ! wait_for_shell_continuity "$pid" "$HOME" "$real_xdg_config_home" \
        "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" \
        "$real_stay_awake_marker"; then
        cleanup_problem "restored notification, clipboard, or stay-awake continuity failed"
      fi
      if [[ $pid =~ ^[1-9][0-9]*$ ]]; then
        focus_monitor_cleanup "$focused_monitor_before" >/dev/null 2>&1 ||
          cleanup_problem "could not restore the original focused monitor after shell restart"
        dispatch_workspace_safely "$active_workspace_id_before" ||
          cleanup_problem "could not restore the original active workspace after shell restart"
        if [[ -f $session_cursor_before ]]; then
          restore_cursor_from_file "$session_cursor_before" original-session ||
            cleanup_problem "could not restore the original cursor after shell restart"
        fi
      fi
    fi
  fi

  if (( transient_started )) && ! reprove_transient_quiescence; then
    transient_quiet=0
    transient_stop_unresolved=1
    support_stack_teardown_safe=0
    temporary_binary_removal_safe=0
    cleanup_problem "transient submission did not remain quiescent at support-stack teardown"
  fi

  mapfile -t bridge_pids < <(list_temporary_binary_pids)
  if (( ${#bridge_pids[@]} != 0 )); then
    cleanup_problem "temporary binary processes remained outside the quiescent transient cgroup"
    temporary_binary_removal_safe=0
    support_stack_teardown_safe=0
  fi

  if (( mock_started )); then
    if (( ! support_stack_teardown_safe )); then
      cleanup_problem "mock server retained with the unresolved isolated support stack"
      mock_state=2
    else
      reap_mock_leader_if_exited
      mock_group_state
      mock_state=$?
      if (( mock_state == 0 )); then
        kill -TERM -- "-$mock_pgid" 2>/dev/null ||
          cleanup_problem "could not send TERM to the owned mock-server process group"
        for (( current = 0; current < 30; current++ )); do
          reap_mock_leader_if_exited
          mock_group_state
          mock_state=$?
          (( mock_state == 1 )) && break
          (( mock_state == 2 )) && break
          sleep 0.1
        done
        if (( mock_state == 0 )); then
          if mock_group_state; then
            kill -KILL -- "-$mock_pgid" 2>/dev/null ||
              cleanup_problem "could not send KILL to the owned mock-server process group"
          fi
          for (( current = 0; current < 30; current++ )); do
            reap_mock_leader_if_exited
            mock_group_state
            mock_state=$?
            (( mock_state == 1 )) && break
            (( mock_state == 2 )) && break
            sleep 0.1
          done
        fi
        reap_mock_leader_if_exited
        mock_group_state
        mock_state=$?
      fi
    fi
    if (( mock_state == 0 )); then
      cleanup_problem "owned mock-server process group survived KILL"
      support_stack_teardown_safe=0
      temporary_binary_removal_safe=0
    elif (( mock_state == 2 )); then
      cleanup_problem "refused to signal a changed mock-server process group"
      support_stack_teardown_safe=0
      temporary_binary_removal_safe=0
    elif ! finalize_mock_evidence "$((body_status == 0))"; then
      cleanup_problem "final mock protocol evidence was incomplete or malformed"
    fi
  fi

  if (( support_stack_teardown_safe )) && [[ -e $display_socket || -L $display_socket ]]; then
    if [[ ! -L $display_socket && -S $display_socket && $(file_identity "$display_socket") == "$display_socket_identity" ]]; then
      rm -f -- "$display_socket" || cleanup_problem "could not remove the mock socket"
    else
      cleanup_problem "refused to remove an unattributed or replaced display socket"
    fi
  fi
  if (( support_stack_teardown_safe && production_runtime_created )) &&
    [[ -d $production_runtime && ! -L $production_runtime ]]; then
    if [[ $(file_identity "$production_runtime") == "$production_runtime_identity" ]]; then
      rmdir -- "$production_runtime" 2>/dev/null || cleanup_problem "production runtime directory is not empty"
    else
      cleanup_problem "production runtime directory identity changed"
    fi
  fi

  if (( support_stack_teardown_safe && temporary_binary_removal_safe )) &&
    [[ -e $temporary_binary || -L $temporary_binary ]]; then
    if [[ ! -L $temporary_binary && -f $temporary_binary && $(file_identity "$temporary_binary") == "$temporary_binary_identity" ]]; then
      rm -f -- "$temporary_binary" || cleanup_problem "could not remove temporary binary"
    else
      cleanup_problem "refused to remove a replaced temporary binary"
    fi
  fi
  if (( support_stack_teardown_safe && temporary_binary_removal_safe && temporary_runtime_created )) &&
    [[ -d $temporary_runtime && ! -L $temporary_runtime ]]; then
    if [[ $(file_identity "$temporary_runtime") == "$temporary_runtime_identity" ]]; then
      rmdir -- "$temporary_runtime" 2>/dev/null || cleanup_problem "temporary binary directory is not empty"
    else
      cleanup_problem "temporary binary directory identity changed"
    fi
  fi

  if [[ -n $real_shell_hash_before ]] &&
    ! verify_real_user_state cleanup-after-real-shell; then
    cleanup_problem "real shell/plugin state was not unchanged after normal shell restoration"
  fi
  if [[ -n $real_stay_awake_hash_before ]] &&
    ! file_envelope_matches "$real_stay_awake_marker" "$real_stay_awake_hash_before" \
      "$real_stay_awake_stat_before" "$real_stay_awake_acl_before" \
      "$real_stay_awake_xattr_before" stay-awake.after-real-shell; then
    cleanup_problem "stay-awake marker envelope was not restored"
  fi

  if [[ -f $shell_config && ! -L $shell_config ]]; then
    jq -S . "$shell_config" >"$evidence_dir/shell.isolated.after.json" 2>/dev/null ||
      cleanup_problem "isolated shell.json was not valid at cleanup"
  fi
  if [[ -n $state_bridge ]]; then
    state_bridge_host_is_owned ||
      cleanup_problem "retained evidence state mountpoint changed or is not empty"
    mountpoint_is_absent_in_host_namespace "$state_bridge" ||
      cleanup_problem "retained evidence state mount absence was not proven"
  fi
  if (( plugin_copied )); then
    current_manifest="$evidence_dir/plugin-target.after.manifest"
    if ! plugin_tree_matches_frozen_manifest \
      "$plugin_target" "$current_manifest" 2>/dev/null; then
      cleanup_problem "could not verify the retained isolated plugin tree"
    elif (( body_status == 0 )) && ! cmp -s -- "$plugin_source_manifest" "$current_manifest"; then
      cleanup_problem "retained isolated plugin tree changed during the live proof"
    fi
  fi

  if ! final_manager=$(manager_override_line 2>/dev/null); then
    cleanup_problem "could not query final user-manager override state"
  elif [[ $final_manager != "$manager_override_before" ]]; then
    cleanup_problem "user-manager override state changed"
  fi
  manager_session_environment_matches ||
    cleanup_problem "user-manager session environment changed during the live proof"

  if [[ -n $isolated_home ]]; then
    [[ -d $isolated_home && ! -L $isolated_home &&
      $(file_identity "$isolated_home") == "$isolated_home_identity" ]] ||
      cleanup_problem "retained isolated HOME identity changed"
  fi
  [[ ! -e $production_runtime && ! -L $production_runtime ]] ||
    cleanup_problem "private mock runtime still exists"
  [[ ! -e $real_production_runtime && ! -L $real_production_runtime ]] ||
    cleanup_problem "real production runtime appeared during the live proof"
  [[ ! -e $temporary_runtime && ! -L $temporary_runtime ]] || cleanup_problem "temporary binary runtime still exists"

  if [[ -f $plugin_list_before ]]; then
    if wait_for_shell; then
      wait_for_effective_shell_config "$real_shell_canonical_hash_before" ||
        cleanup_problem "final Omarchy shell effective configuration changed"
      OMARCHY_SHELL_IPC_TIMEOUT=0.5s timeout --kill-after=0.1s 1s \
        omarchy-shell shell rescanPlugins >/dev/null 2>&1 ||
        cleanup_problem "final Omarchy plugin rescan failed"
      final_plugin_list="$evidence_dir/plugin-list.after.json"
      for (( current = 0; current < 10; current++ )); do
        cleanup_final_retry_allowed || break
        if OMARCHY_SHELL_IPC_TIMEOUT=0.1s timeout --kill-after=0.1s 0.3s \
          omarchy-shell shell listPlugins 2>/dev/null | jq -S 'sort_by(.id)' >"$final_plugin_list"; then
          final_plugin_hash=$(sha256_file "$final_plugin_list")
          [[ $final_plugin_hash == "$plugin_list_hash_before" ]] && break
        fi
        sleep 0.1
      done
      [[ -s $final_plugin_list && $final_plugin_hash == "$plugin_list_hash_before" ]] ||
        cleanup_problem "plugin list was not restored"

      pid=$(shell_pid 2>/dev/null)
      if [[ ! $pid =~ ^[1-9][0-9]*$ ]]; then
        cleanup_problem "restored shell PID was unavailable for final verification"
      elif ! quickshell_instance_is_exact "$pid"; then
        cleanup_problem "restored shell instance identity changed during final verification"
      elif process_has_any_override "$pid"; then
        cleanup_problem "restored shell retained an executable override"
      elif ! process_has_frontend_environment "$pid" "$HOME" "$real_xdg_config_home" \
        "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home"; then
        cleanup_problem "restored shell retained an isolated HOME/XDG value"
      elif ! process_has_session_transport_environment "$pid"; then
        cleanup_problem "restored shell retained a noncanonical Omarchy session transport"
      elif ! wait_for_shell_continuity "$pid" "$HOME" "$real_xdg_config_home" \
        "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" \
        "$real_stay_awake_marker"; then
        cleanup_problem "restored shell continuity changed during final verification"
      fi

      if [[ $pid =~ ^[1-9][0-9]*$ && -f $session_layers_normalized_before ]]; then
        final_layers="$evidence_dir/session.layers.after.json"
        for (( current = 0; current < 10; current++ )); do
          cleanup_final_retry_allowed || break
          if capture_quiescent_shell_layers "$final_layers" "$pid" 2>/dev/null &&
            cmp -s -- "$session_layers_normalized_before" "$final_layers"; then
            final_layer_match=1
            break
          fi
          sleep 0.1
        done
        (( final_layer_match )) ||
          cleanup_problem "restored shell layer UI did not settle to the original geometry"
      fi
    else
      cleanup_problem "restored shell was unavailable for final plugin verification"
    fi
  fi

  if (( shell_replaced )) && [[ -f $session_monitors_normalized_before &&
    -f $session_workspaces_normalized_before && -f $session_clients_normalized_before ]]; then
    final_monitors="$evidence_dir/monitors.after.json"
    final_workspaces="$evidence_dir/workspaces.after.json"
    final_clients="$evidence_dir/clients.after.json"
    for (( current = 0; current < 10; current++ )); do
      cleanup_final_retry_allowed || break
      if capture_normalized_monitor_state "$final_monitors" 2>/dev/null &&
        capture_normalized_workspace_state "$final_workspaces" 2>/dev/null &&
        capture_normalized_client_state "$final_clients" 2>/dev/null; then
        final_monitor_hash=$(sha256_file "$final_monitors")
        if [[ $final_monitor_hash == "$session_monitors_hash_before" ]] &&
          cmp -s -- "$session_workspaces_normalized_before" "$final_workspaces" &&
          cmp -s -- "$session_clients_normalized_before" "$final_clients"; then
          break
        fi
      fi
      sleep 0.1
    done
    [[ -s $final_monitors && $final_monitor_hash == "$session_monitors_hash_before" ]] ||
      cleanup_problem "monitor state was not restored"
    [[ -s $final_workspaces ]] &&
      cmp -s -- "$session_workspaces_normalized_before" "$final_workspaces" ||
      cleanup_problem "original-session workspace state was not restored"
    [[ -s $final_clients ]] &&
      cmp -s -- "$session_clients_normalized_before" "$final_clients" ||
      cleanup_problem "original-session client state was not restored"
    if [[ $headless_workspace_id =~ ^[1-9][0-9]*$ ]]; then
      jq -e --argjson id "$headless_workspace_id" 'all(.[]; .id != $id)' \
        "$final_workspaces" >/dev/null 2>&1 ||
        cleanup_problem "owned headless workspace still exists"
    fi
  fi

  if (( shell_replaced )) && [[ -f $session_cursor_before ]]; then
    final_cursor="$evidence_dir/cursor.after.json"
    hyprctl_bounded cursorpos -j | jq -S . >"$final_cursor" 2>/dev/null ||
      cleanup_problem "could not capture final cursor position"
    if [[ -s $final_cursor ]] && ! cmp -s -- "$session_cursor_before" "$final_cursor"; then
      cleanup_problem "cursor position was not restored"
    fi
  fi

  if (( transient_started )); then
    if ! reprove_transient_quiescence; then
      transient_stop_unresolved=1
      cleanup_problem "transient submission was not quiescent at final verification"
    fi
    for (( current = 0; current < 10; current++ )); do
      [[ $(systemctl_user_query show -p LoadState --value "$transient_unit" 2>/dev/null) == not-found ]] && break
      sleep 0.1
    done
    [[ $(systemctl_user_query show -p LoadState --value "$transient_unit" 2>/dev/null) == not-found ]] ||
      cleanup_problem "transient override service was not collected"
  fi

  manager_session_environment_matches ||
    cleanup_problem "user-manager session environment changed at final teardown boundary"
  if ! final_manager=$(manager_override_line 2>/dev/null) ||
    [[ $final_manager != "$manager_override_before" ]]; then
    cleanup_problem "user-manager override state changed at final teardown boundary"
  fi

  if (( shell_replaced )); then
    if ! continue_original_launcher_after_failed_stop_proof; then
      cleanup_problem "the pinned packaged-shell launcher remained stopped after recovery"
    fi
    pid=$(shell_pid 2>/dev/null)
    if [[ ! $pid =~ ^[1-9][0-9]*$ ]] || ! quickshell_instance_is_exact "$pid" ||
      process_has_any_override "$pid" || ! process_has_session_transport_environment "$pid"; then
      cleanup_problem "normal packaged shell identity changed at final teardown boundary"
    elif [[ $pid != "$adopted_normal_shell_pid" ]] ||
      [[ $(resolve_exact_packaged_launcher_for_shell "$pid" 2>/dev/null) != \
        "$adopted_normal_launcher_pid:$adopted_normal_launcher_start" ]]; then
      cleanup_problem "normal packaged shell launcher changed at final teardown boundary"
    elif ! packaged_shell_launcher_process_is_running_exact \
      "$adopted_normal_launcher_pid" "$adopted_normal_launcher_start"; then
      cleanup_problem "normal packaged shell launcher was stopped at final teardown boundary"
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && $pid != "$original_shell_pid" ]] &&
      original_shell_process_is_same; then
      cleanup_problem "the pinned pre-replacement shell survived alongside its replacement"
    elif [[ $pid =~ ^[1-9][0-9]*$ && $pid != "$original_shell_pid" &&
      $adopted_normal_launcher_pid != "$original_launcher_pid" ]] &&
      original_launcher_process_is_same; then
      cleanup_problem "the pinned pre-replacement launcher survived alongside an unrelated replacement"
    elif [[ $pid == "$original_shell_pid" ]] &&
      { ! original_shell_process_is_same || ! original_launcher_process_is_same; }; then
      cleanup_problem "the adopted original shell lost its pinned launcher identity"
    fi
  fi

  compositor_identity_matches ||
    cleanup_problem "running compositor identity changed at the final teardown boundary"
  if [[ -n $monitor_manager_invocation_before ]]; then
    monitor_manager_running_exact ||
      cleanup_problem "hyprmoncfgd was not finally running with its original process identity"
    hyprmoncfg_socket_is_owned_listener ||
      cleanup_problem "hyprmoncfgd final private listener identity changed"
    hyprmoncfg_preview_is_clear ||
      cleanup_problem "hyprmoncfgd final strict status/preview state was not clear"
    if ! capture_hyprmoncfg_status \
      "$evidence_dir/hyprmoncfg-status.final.json" final ||
      ! cmp -s -- "$monitor_status_before" \
        "$evidence_dir/hyprmoncfg-status.final.json"; then
      cleanup_problem "hyprmoncfg final status differed from its baseline"
    fi
    [[ $(monitor_watcher_scope_count) == 0 ]] ||
      cleanup_problem "fallback monitor watcher was active at final verification"
    monitor_manager_fingerprint >"$evidence_dir/hyprmoncfgd-unit.final.txt" 2>/dev/null
    cmp -s -- "$monitor_manager_fingerprint_before" "$evidence_dir/hyprmoncfgd-unit.final.txt" ||
      cleanup_problem "hyprmoncfgd final unit definition changed"
    file_envelope_matches "$monitor_manager_config_file" "$monitor_manager_config_hash_before" \
      "$monitor_manager_config_stat_before" "$monitor_manager_config_acl_before" \
      "$monitor_manager_config_xattr_before" hyprmoncfg-monitors.lua.final ||
      cleanup_problem "hyprmoncfg monitor profile envelope changed during the live proof"
    file_envelope_matches "$hyprland_lua_file" "$hyprland_lua_hash_before" \
      "$hyprland_lua_stat_before" "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
      hyprland.lua.final ||
      cleanup_problem "root Hyprland Lua config envelope changed during the live proof"
    if ! tree_digest_noatime \
      "$monitor_profiles_root" "$evidence_dir/hyprmoncfg-profiles.final.sha256" ||
      ! cmp -s -- "$monitor_profiles_digest_before" \
        "$evidence_dir/hyprmoncfg-profiles.final.sha256"; then
      cleanup_problem "hyprmoncfg final profile tree changed"
    fi
  fi
  hyprland_config_errors_match ||
    cleanup_problem "Hyprland configuration errors changed at final verification"
  compositor_identity_matches ||
    cleanup_problem "running compositor identity changed during final desktop verification"
  if [[ -n $live_lock_identity ]]; then
    live_lock_is_held || cleanup_problem "per-user live-smoke lock was not retained through final verification"
    if (( live_lock_created )); then
      if (( support_stack_teardown_safe && transient_quiet )) &&
        { (( ! mock_started )) || (( mock_state == 1 )); }; then
        unlink_live_lock_path_while_held ||
          cleanup_problem "harness-created per-user live-smoke lock path could not be removed safely"
      else
        note "retaining the named live-smoke lock for unresolved inherited lock holders"
      fi
    fi
  fi

  if (( cleanup_failed )) && (( status == 0 )); then
    status=1
  fi
  if [[ -n $evidence_dir ]]; then
    printf '%s\n' "$body_status" >"$evidence_dir/harness-body-exit-status"
    printf '%s\n' "$status" >"$evidence_dir/harness-exit-status"
    printf '%s\n' "$cleanup_failed" >"$evidence_dir/cleanup-failed"
    note "evidence retained at $evidence_dir"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in \
  awk base64 basename bash busctl bwrap cat chmod cmp cp dd dirname env find findmnt flock getfacl \
  getfattr hyprctl hyprmoncfgd id install jq locale mkdir mkfifo mktemp omarchy \
  omarchy-hyprland-session-locked \
  omarchy-shell pacman ps quickshell readlink rg rm rmdir sed setsid sha256sum sleep socat sort ss stat \
  systemctl systemd-run tar timeout tr wc; do
  require_command "$command"
done

(( EUID != 0 )) || die "refusing to run as root"
[[ $(id -u) == "$UID" ]] || die "effective user identity is inconsistent"
(( BASH_VERSINFO[0] >= 5 )) || die "Bash 5 or newer is required"
[[ $(locale charmap) == UTF-8 ]] || die "a UTF-8 locale is required for the filtered connector nonce"
[[ $(readlink -f -- "/proc/$$/exe") == /usr/bin/bash &&
  -f /usr/bin/bash && ! -L /usr/bin/bash &&
  $(stat -c '%u:%g:%a' -- /usr/bin/bash) == 0:0:755 &&
  $(sha256_packaged_file /usr/bin/bash) == "$expected_bash_sha256" ]] ||
  die "the harness must run under the exact packaged /usr/bin/bash"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
release_binary="$repo_root/target/release/omarchy-ai-bar"
snapshot_fixture="$repo_root/fixtures/domain/snapshot-v1.json"
plugin_source="$repo_root/qml/omarchy-plugin"
real_plugin_root="$HOME/.config/omarchy/plugins"
real_plugin_target="$real_plugin_root/$plugin_id"
real_shell_config="$HOME/.config/omarchy/shell.json"
real_xdg_config_home=${XDG_CONFIG_HOME:-$HOME/.config}
real_xdg_cache_home=${XDG_CACHE_HOME:-$HOME/.cache}
real_xdg_data_home=${XDG_DATA_HOME:-$HOME/.local/share}
real_xdg_state_home=${XDG_STATE_HOME:-$HOME/.local/state}
real_state_parent=$real_xdg_state_home
real_state_root="$real_state_parent/omarchy"
real_stay_awake_marker="$real_state_root/indicators/stay-awake"
monitor_manager_config_file="$HOME/.config/hypr/hyprmoncfg-monitors.lua"
hyprland_lua_file="$HOME/.config/hypr/hyprland.lua"
monitor_profiles_root="$HOME/.config/hyprmoncfg/profiles"
hyprmoncfg_socket="$XDG_RUNTIME_DIR/hyprmoncfgd.sock"
headless_event_socket="$XDG_RUNTIME_DIR/hypr/${HYPRLAND_INSTANCE_SIGNATURE:-}/.socket2.sock"
real_production_runtime="$XDG_RUNTIME_DIR/omarchy-ai-bar"
real_display_socket="$real_production_runtime/display.sock"
live_lock_path="$XDG_RUNTIME_DIR/omarchy-ai-bar-live-smoke.lock"
transient_unit="omarchy-ai-bar-live-smoke-$UID-$$.service"

for path in "$HOME" "$repo_root" "$plugin_source" "$real_plugin_root" "$real_plugin_target" \
  "$real_shell_config" "$real_xdg_config_home" "$real_xdg_cache_home" \
  "$real_xdg_data_home" "$real_xdg_state_home" "$real_state_parent" "$real_state_root" \
  "$real_stay_awake_marker" \
  "$monitor_manager_config_file" "$hyprland_lua_file" "$monitor_profiles_root" \
  "$hyprmoncfg_socket" "$headless_event_socket" \
  "$real_production_runtime" "$real_display_socket" "$live_lock_path" \
  "$release_binary" "$snapshot_fixture"; do
  safe_absolute_path "$path" || die "unsafe path for live harness: $path"
done
reviewed_source_boundary_matches ||
  die "reviewed Rust source boundary changed"

[[ ${OMARCHY_PATH:-} == /usr/share/omarchy ]] ||
  die "this harness supports only the packaged /usr/share/omarchy session"
[[ ${XDG_RUNTIME_DIR:-} == "/run/user/$UID" ]] ||
  die "XDG_RUNTIME_DIR must be the canonical per-user runtime directory"
[[ $real_xdg_state_home == "$HOME/.local/state" ]] ||
  die "XDG_STATE_HOME must match Omarchy's HOME-relative state path"
[[ ${WAYLAND_DISPLAY:-} =~ ^wayland-[0-9]+$ ]] || die "no canonical Wayland display is active"
[[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} ]] || die "no Hyprland instance is selected"

[[ $(omarchy version) == "$expected_omarchy_version" ]] ||
  die "supported Omarchy version is exactly $expected_omarchy_version"
[[ -f /usr/bin/Hyprland && ! -L /usr/bin/Hyprland &&
  $(sha256_packaged_file /usr/bin/Hyprland) == "$expected_hyprland_sha256" ]] ||
  die "Hyprland executable is not the exact audited build"
hyprctl_bounded -j version | jq -e --arg version "$expected_hyprland_version" \
  --arg commit "$expected_hyprland_commit" '
  .version == $version and .commit == $commit and .dirty == false
' >/dev/null || die "supported Hyprland version is exactly $expected_hyprland_version clean"
[[ $(quickshell --version 2>&1) == "$expected_quickshell_version ("* ]] ||
  die "supported Quickshell version is exactly ${expected_quickshell_version#Quickshell }"
[[ $(hyprmoncfgd --version 2>&1) == "$expected_hyprmoncfgd_version" ]] ||
  die "supported hyprmoncfgd version is exactly 1.16.1"
[[ -f /usr/bin/hyprmoncfgd && ! -L /usr/bin/hyprmoncfgd &&
  $(sha256_packaged_file /usr/bin/hyprmoncfgd) == "$expected_hyprmoncfgd_sha256" ]] ||
  die "hyprmoncfgd executable is not the exact audited build"
[[ $(readlink -f -- /usr/lib/libaquamarine.so 2>/dev/null) == "$expected_aquamarine_path" &&
  -f $expected_aquamarine_path && ! -L $expected_aquamarine_path &&
  $(sha256_packaged_file "$expected_aquamarine_path") == "$expected_aquamarine_sha256" ]] ||
  die "Aquamarine is not the exact audited headless-output implementation"
[[ $(command -v hyprctl) == /usr/bin/hyprctl && -f /usr/bin/hyprctl &&
  ! -L /usr/bin/hyprctl && $(sha256_packaged_file /usr/bin/hyprctl) == "$expected_hyprctl_sha256" ]] ||
  die "hyprctl is not the exact audited IPC client"
[[ $(readlink -f -- /usr/lib/libhyprutils.so 2>/dev/null) == "$expected_hyprutils_path" &&
  -f $expected_hyprutils_path && ! -L $expected_hyprutils_path &&
  $(sha256_packaged_file "$expected_hyprutils_path") == "$expected_hyprutils_sha256" ]] ||
  die "Hyprutils is not the exact audited command-parser implementation"
hyprland_compositor_pid_before=$(hyprctl_bounded -j instances | jq -er \
  --arg signature "$HYPRLAND_INSTANCE_SIGNATURE" --arg socket "$WAYLAND_DISPLAY" '
    [.[] | select(.instance == $signature and .wl_socket == $socket)]
    | if length == 1 and (.[0].pid | type) == "number"
        and .[0].pid > 0 and .[0].pid == (.[0].pid | floor)
      then .[0].pid else empty end
  ') || die "could not pin the selected Hyprland instance PID"
hyprland_compositor_start_before=$(awk '{print $22}' \
  "/proc/$hyprland_compositor_pid_before/stat" 2>/dev/null) ||
  die "could not pin the selected Hyprland process start time"
[[ $hyprland_compositor_start_before =~ ^[1-9][0-9]*$ ]] ||
  die "selected Hyprland process start time is invalid"
hyprland_mount_namespace_before=$(readlink -- \
  "/proc/$hyprland_compositor_pid_before/ns/mnt") ||
  die "could not pin the selected Hyprland mount namespace"
harness_mount_namespace_before=$(readlink -- "/proc/$$/ns/mnt") ||
  die "could not pin the harness mount namespace"
[[ $hyprland_mount_namespace_before =~ ^mnt:\[[1-9][0-9]*\]$ &&
  $hyprland_mount_namespace_before == "$harness_mount_namespace_before" ]] ||
  die "selected Hyprland process is not in the canonical desktop mount namespace"
hyprland_executable_identity_before=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
  -- /usr/bin/Hyprland) || die "could not pin the Hyprland executable inode"
aquamarine_identity_before=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
  -- "$expected_aquamarine_path") || die "could not pin the Aquamarine library inode"
aquamarine_inode_before=$(stat -Lc '%i' -- "$expected_aquamarine_path") ||
  die "could not pin the Aquamarine mapping inode"
[[ $aquamarine_inode_before =~ ^[1-9][0-9]*$ ]] || die "Aquamarine inode is invalid"
hyprutils_identity_before=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
  -- "$expected_hyprutils_path") || die "could not pin the Hyprutils library inode"
hyprutils_inode_before=$(stat -Lc '%i' -- "$expected_hyprutils_path") ||
  die "could not pin the Hyprutils mapping inode"
[[ $hyprutils_inode_before =~ ^[1-9][0-9]*$ ]] || die "Hyprutils inode is invalid"
compositor_identity_matches ||
  die "the running compositor is not the exact audited Hyprland/Aquamarine build"

[[ -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR ]] || die "runtime directory is not a real directory"
[[ $(stat -c '%u:%a' -- "$XDG_RUNTIME_DIR") == "$UID:700" ]] ||
  die "runtime directory must be owned by this UID with mode 0700"
[[ -S $headless_event_socket && ! -L $headless_event_socket &&
  $(stat -c '%u' -- "$headless_event_socket") == "$UID" ]] ||
  die "selected Hyprland event socket is not a real user-owned socket"
headless_event_socket_identity=$(file_identity "$headless_event_socket")
headless_event_socket_is_compositor_listener ||
  die "selected Hyprland event socket is not owned by the pinned compositor"
[[ $(command -v bwrap) == /usr/bin/bwrap ]] ||
  die "Bubblewrap must resolve to the packaged /usr/bin/bwrap"
[[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap && -x /usr/bin/bwrap &&
  $(stat -c '%u:%g:%a' -- /usr/bin/bwrap) == 0:0:755 ]] ||
  die "the packaged Bubblewrap executable envelope is unexpected"
[[ $(command -v bash) == /usr/bin/bash && -f /usr/bin/bash && ! -L /usr/bin/bash &&
  -x /usr/bin/bash && $(stat -c '%u:%g:%a' -- /usr/bin/bash) == 0:0:755 ]] ||
  die "the packaged Bash interpreter envelope is unexpected"
[[ $(command -v socat) == /usr/bin/socat && -L /usr/bin/socat &&
  $(readlink -- /usr/bin/socat) == socat1 && -f /usr/bin/socat1 &&
  ! -L /usr/bin/socat1 && -x /usr/bin/socat1 &&
  $(stat -c '%u:%g:%a' -- /usr/bin/socat1) == 0:0:755 &&
  $(sha256_packaged_file /usr/bin/socat1) == "$expected_socat_sha256" ]] ||
  die "the packaged socat executable envelope is unexpected"
[[ $(pacman -Q iproute2) == "$expected_iproute2_version" &&
  $(command -v ss) == /usr/bin/ss && -f /usr/bin/ss && ! -L /usr/bin/ss &&
  -x /usr/bin/ss && $(stat -c '%u:%g:%a' -- /usr/bin/ss) == 0:0:755 &&
  $(sha256_packaged_file /usr/bin/ss) == "$expected_ss_sha256" ]] ||
  die "the packaged iproute2 socket-attribution envelope is unexpected"
runtime_root_identity=$(file_identity "$XDG_RUNTIME_DIR")
if acquire_live_lock; then
  :
else
  lock_status=$?
  die_with_status "$lock_status" \
    "could not acquire the private per-user live-smoke lock (another run may be active)"
fi
live_lock_is_held || die "live-smoke singleton lock was not retained"
[[ -d $real_plugin_root && ! -L $real_plugin_root &&
  $(stat -c '%u' -- "$real_plugin_root") == "$UID" ]] ||
  die "user plugin root must be a real user-owned directory"
[[ -d $real_state_parent && ! -L $real_state_parent &&
  $(stat -c '%u' -- "$real_state_parent") == "$UID" &&
  -d $real_state_root && ! -L $real_state_root &&
  $(stat -c '%u' -- "$real_state_root") == "$UID" ]] ||
  die "Omarchy continuity state must be rooted in real user-owned directories"
[[ -f $real_stay_awake_marker && ! -L $real_stay_awake_marker &&
  $(stat -c '%u' -- "$real_stay_awake_marker") == "$UID" ]] ||
  die "the existing stay-awake marker is required for the live proof"
[[ -f $real_shell_config && ! -L $real_shell_config &&
  $(stat -c '%u:%a' -- "$real_shell_config") == "$UID:600" ]] ||
  die "shell.json must be a user-owned mode-0600 regular file"
for monitor_file in "$monitor_manager_config_file" "$hyprland_lua_file"; do
  [[ -f $monitor_file && ! -L $monitor_file && $(stat -c '%u' -- "$monitor_file") == "$UID" ]] ||
    die "monitor configuration must be a user-owned regular file: $monitor_file"
done
[[ -d $monitor_profiles_root && ! -L $monitor_profiles_root &&
  $(stat -c '%u' -- "$monitor_profiles_root") == "$UID" ]] ||
  die "hyprmoncfg profiles must be a real user-owned directory"
if ! (set -o pipefail; dd if="$real_shell_config" iflag=noatime,nofollow status=none |
  jq -e '.version == 1 and (.bar | type == "object") and (.plugins | type == "array")' \
    >/dev/null); then
  die "shell.json is not the supported version-1 shape"
fi
if ! (set -o pipefail; dd if="$real_shell_config" iflag=noatime,nofollow status=none |
  jq -e --arg id "$plugin_id" \
    '([.. | objects | .id? | select(. == $id)] | length) == 0' >/dev/null); then
  die "$plugin_id is already referenced by real shell.json"
fi

[[ -d $plugin_source && ! -L $plugin_source && -f $plugin_source/manifest.json ]] ||
  die "development plugin source is missing"
jq -e --arg id "$plugin_id" '.schemaVersion == 1 and .id == $id' \
  "$plugin_source/manifest.json" >/dev/null || die "plugin manifest identity is unexpected"
plugin_source_symlink=$(find "$plugin_source" -xdev -type l -print -quit) ||
  die "could not inspect plugin source symlinks"
[[ -z $plugin_source_symlink ]] ||
  die "plugin source may not contain symlinks"
plugin_source_special=$(find "$plugin_source" -xdev ! -type f ! -type d -print -quit) ||
  die "could not inspect plugin source object types"
[[ -z $plugin_source_special ]] ||
  die "plugin source contains an unsupported filesystem object"
[[ ! -e $real_plugin_target && ! -L $real_plugin_target ]] ||
  die "plugin target already exists in the real user tree: $real_plugin_target"
[[ ! -e $real_production_runtime && ! -L $real_production_runtime ]] ||
  die "production runtime path already exists; stop the real daemon before running this harness"

bounded_shell_ipc shell ping >/dev/null || die "Omarchy shell is not ready"
session_is_safe_for_live_mutation ||
  die "compositor and shell lock state must both be stably clear before the live proof"
[[ $(bounded_shell_ipc shell listShellConfig | jq -r '.bar.position') =~ ^(top|bottom|left|right)$ ]] ||
  die "the built-in bar configuration is not ready"
initial_plugin_list=$(bounded_shell_ipc shell listPlugins) || die "initial plugin registry is unavailable"
jq -e --arg other "$other_panel_id" '
  any(.[]; .id == "omarchy.bar" and .active == true)
  and any(.[]; .id == $other and .enabled == true
    and (.kinds | index("bar-widget")) != null)
' <<<"$initial_plugin_list" >/dev/null ||
  die "the built-in bar and $other_panel_id ownership witness must already be enabled"
bounded_shell_ipc shell debugBarGeometry | jq -e --arg other "$other_panel_id" '
  any(.[]; .id == $other and .visible == true and .itemVisible == true
    and .width > 0 and .height > 0)
' >/dev/null || die "$other_panel_id is not a visible ownership witness"

[[ $(systemctl_user_query show -p Id --value "$monitor_manager_unit" 2>/dev/null) == "$monitor_manager_unit" &&
  $(systemctl_user_query show -p LoadState --value "$monitor_manager_unit" 2>/dev/null) == loaded &&
  $(systemctl_user_query show -p UnitFileState --value "$monitor_manager_unit" 2>/dev/null) == enabled &&
  $(systemctl_user_query show -p FragmentPath --value "$monitor_manager_unit" 2>/dev/null) == /usr/lib/systemd/user/hyprmoncfgd.service &&
  $(systemctl_user_query show -p ActiveState --value "$monitor_manager_unit" 2>/dev/null) == active &&
  $(systemctl_user_query show -p SubState --value "$monitor_manager_unit" 2>/dev/null) == running &&
  $(systemctl_user_query show -p FreezerState --value "$monitor_manager_unit" 2>/dev/null) == running ]] ||
  die "hyprmoncfgd must be the exact enabled, active packaged service"
systemctl_user_query show -p ExecStart --value "$monitor_manager_unit" |
  rg --no-config -F 'path=/usr/bin/hyprmoncfgd' >/dev/null ||
  die "hyprmoncfgd ExecStart is unexpected"
monitor_manager_invocation_before=$(systemctl_user_query show -p InvocationID --value "$monitor_manager_unit")
monitor_manager_pid_before=$(systemctl_user_query show -p MainPID --value "$monitor_manager_unit")
monitor_manager_cgroup_before=$(systemctl_user_query show -p ControlGroup --value "$monitor_manager_unit")
[[ $monitor_manager_invocation_before =~ ^[0-9a-f]{32}$ &&
  $monitor_manager_pid_before =~ ^[1-9][0-9]*$ &&
  $monitor_manager_cgroup_before == /user.slice/* ]] || die "hyprmoncfgd identity is incomplete"
monitor_manager_pid_start_before=$(awk '{print $22}' "/proc/$monitor_manager_pid_before/stat" 2>/dev/null)
monitor_manager_executable_identity_before=$(stat -Lc \
  '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- /usr/bin/hyprmoncfgd) ||
  die "could not pin the hyprmoncfgd executable inode"
monitor_manager_identity_matches || die "hyprmoncfgd process identity is not stable"
hyprmoncfg_socket_is_owned_listener ||
  die "hyprmoncfgd does not own the exact private status socket"
hyprmoncfg_preview_is_clear ||
  die "hyprmoncfgd has an active preview or did not return the strict status envelope"
[[ $(monitor_watcher_scope_count) == 0 ]] ||
  die "Omarchy's fallback monitor watcher must not be active while hyprmoncfgd owns monitoring"

manager_environment=$(systemctl_user_query show-environment)
manager_override_before=$(sed -n '/^OMARCHY_AI_BAR_\(EXECUTABLE\|DISPLAY_SOCKET\)=/p' \
  <<<"$manager_environment")
[[ -z $manager_override_before ]] ||
  die "an Omarchy AI Bar executable/socket override is already set in the user manager"
manager_session_environment_matches ||
  die "user manager session environment is not the exact packaged Omarchy context"

monitors_precheck_json=$(hyprctl_bounded monitors all -j)
hyprland_config_errors_before=$(hyprctl_bounded configerrors 2>&1)
[[ -z $hyprland_config_errors_before ]] ||
  die "Hyprland must have no configuration errors before the live monitor proof"
jq -e '
  length == 1 and .[0].name == "eDP-1" and .[0].disabled == false
  and .[0].scale == 1.25 and .[0].focused == true
' <<<"$monitors_precheck_json" >/dev/null ||
  die "expected exactly one focused eDP-1 output at scale 1.25 and no pre-existing headless output"
workspaces_precheck_json=$(hyprctl_bounded workspaces -j)
jq -e '
  length > 0
  and all(.[]; .id > 0 and .monitor == "eDP-1")
' <<<"$workspaces_precheck_json" >/dev/null ||
  die "every pre-existing regular workspace must be on eDP-1"
active_workspace_id_before=$(jq -er '.[] | select(.focused == true) | .activeWorkspace.id' \
  <<<"$monitors_precheck_json")
[[ $active_workspace_id_before =~ ^[1-9][0-9]*$ ]] || die "active workspace identity is invalid"
jq -e --argjson active "$active_workspace_id_before" '
  any(.[]; .id == $active)
' <<<"$workspaces_precheck_json" >/dev/null || die "active workspace is missing from workspace state"

original_shell_pid=$(shell_pid) || die "could not resolve the single Omarchy shell process"
quickshell_instance_is_exact "$original_shell_pid" ||
  die "the packaged shell must have exactly one same-UID instance across all displays"
[[ -r /proc/$original_shell_pid/environ ]] || die "cannot inspect the original shell environment"
original_launcher_pid=$(ps -o ppid= -p "$original_shell_pid" 2>/dev/null | tr -d ' ')
[[ $original_launcher_pid =~ ^[1-9][0-9]*$ ]] ||
  die "could not pin the original packaged-shell launcher"
original_launcher_pid_start=$(awk '{print $22}' "/proc/$original_launcher_pid/stat" 2>/dev/null)
[[ $original_launcher_pid_start =~ ^[1-9][0-9]*$ ]] ||
  die "could not pin the original shell launcher's start time"
original_launcher_is_running_exact || die "the original shell launcher identity/state is unexpected"
process_has_frontend_environment "$original_launcher_pid" "$HOME" "$real_xdg_config_home" \
  "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" ||
  die "the original shell launcher does not carry the canonical HOME/XDG environment"
process_has_session_transport_environment "$original_launcher_pid" ||
  die "the original shell launcher does not carry the canonical Omarchy session transport"
original_shell_pid_start=$(awk '{print $22}' "/proc/$original_shell_pid/stat" 2>/dev/null)
[[ $original_shell_pid_start =~ ^[1-9][0-9]*$ ]] ||
  die "could not pin the original shell process start time"
original_shell_process_is_same || die "the original shell process identity changed during capture"
if process_has_any_override "$original_shell_pid"; then
  die "the original shell unexpectedly carries the executable override"
fi
process_has_frontend_environment "$original_shell_pid" "$HOME" "$real_xdg_config_home" \
  "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" ||
  die "the original shell does not carry the canonical HOME/XDG environment"
process_has_session_transport_environment "$original_shell_pid" ||
  die "the original shell does not carry the canonical Omarchy session transport"
real_shell_canonical_hash_before=$(canonical_json_file_hash "$real_shell_config") ||
  die "could not hash the canonical real shell configuration"
wait_for_effective_shell_config "$real_shell_canonical_hash_before" ||
  die "the running shell has not loaded the exact real shell.json"
wait_for_shell_continuity "$original_shell_pid" "$HOME" "$real_xdg_config_home" \
  "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" \
  "$real_stay_awake_marker" ||
  die "the original notification, clipboard, or stay-awake service is not continuous"
real_state_parent_identity=$(file_identity "$real_state_parent")
real_state_root_identity=$(file_identity "$real_state_root")

reviewed_source_boundary_matches ||
  die "reviewed Rust source boundary changed before evidence setup"

evidence_dir=$(mktemp -d --tmpdir omarchy-ai-bar-live-smoke.XXXXXXXX)
chmod 0700 -- "$evidence_dir"
note "evidence directory: $evidence_dir"
evidence_dir_identity=$(file_identity "$evidence_dir")
production_runtime="$evidence_dir/mock-runtime"
display_socket="$production_runtime/display.sock"
safe_absolute_path "$production_runtime" || die "mock runtime path is unsafe"
safe_absolute_path "$display_socket" || die "mock socket path is unsafe"
(( ${#display_socket} <= 103 )) || die "mock socket path exceeds the Unix address limit"
transient_token=$(dd if=/dev/urandom bs=32 count=1 status=none | sha256sum | awk '{print $1}')
[[ $transient_token =~ ^[0-9a-f]{64}$ ]] || die "could not create a transient ownership token"
headless_nonce_full=$(dd if=/dev/urandom bs=32 count=1 status=none | sha256sum | awk '{print $1}')
[[ $headless_nonce_full =~ ^[0-9a-f]{64}$ ]] || die "could not create a headless-output nonce"
headless_nonce=${headless_nonce_full:0:24}
headless_name=$(encode_headless_nonce "$headless_nonce") ||
  die "could not encode the filtered headless-output nonce"
headless_name_matches_nonce ||
  die "synthetic output name is not the exact 96-bit Go-TrimSpace encoding"
[[ $headless_name != FALLBACK ]] || die "synthetic output collided with Hyprland's reserved sentinel"
headless_name_base64=$(printf '%s' "$headless_name" | base64 -w0)
[[ -n $headless_name_base64 && $headless_name_base64 != *$'\n'* ]] ||
  die "could not encode the filtered headless-output recovery name"
printf '%s\n' "$headless_nonce" >"$evidence_dir/headless-output.nonce"
printf '%s\n' "$headless_name_base64" >"$evidence_dir/headless-output.name.base64"

real_shell_atime_before_capture=$(stat -c '%X:%x' -- "$real_shell_config")
real_shell_hash_before=$(sha256_file "$real_shell_config")
real_shell_stat_before=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' \
  -- "$real_shell_config")
real_shell_acl_before="$evidence_dir/shell.real.before.acl"
real_shell_xattr_before="$evidence_dir/shell.real.before.xattr"
getfacl -cp --absolute-names "$real_shell_config" >"$real_shell_acl_before"
getfattr -d -m- --absolute-names "$real_shell_config" >"$real_shell_xattr_before" 2>/dev/null
real_shell_stat_after_capture=$(
  stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' -- "$real_shell_config"
)
[[ $(sha256_file "$real_shell_config") == "$real_shell_hash_before" &&
  $real_shell_stat_after_capture == "$real_shell_stat_before" &&
  $(stat -c '%X:%x' -- "$real_shell_config") == "$real_shell_atime_before_capture" ]] ||
  die "real shell.json changed during its read-only baseline capture"
real_stay_awake_hash_before=$(sha256_file "$real_stay_awake_marker")
real_stay_awake_stat_before=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' \
  -- "$real_stay_awake_marker")
real_stay_awake_acl_before="$evidence_dir/stay-awake.before.acl"
real_stay_awake_xattr_before="$evidence_dir/stay-awake.before.xattr"
getfacl -cp --absolute-names "$real_stay_awake_marker" >"$real_stay_awake_acl_before"
getfattr -d -m- --absolute-names "$real_stay_awake_marker" \
  >"$real_stay_awake_xattr_before" 2>/dev/null
real_plugin_root_identity=$(file_identity "$real_plugin_root")
real_plugin_digest_before="$evidence_dir/plugins.real.before.sha256"
tree_digest_noatime "$real_plugin_root" "$real_plugin_digest_before" ||
  die "could not capture the read-only real plugin tree baseline"
[[ $(file_identity "$real_plugin_root") == "$real_plugin_root_identity" ]] ||
  die "real plugin root changed during its read-only baseline capture"

isolated_home="$evidence_dir/isolated-home"
isolated_config_home="$isolated_home/.config"
isolated_cache_home="$isolated_home/.cache"
isolated_local_home="$isolated_home/.local"
isolated_data_home="$isolated_local_home/share"
isolated_state_home="$isolated_local_home/state"
mkdir -m 700 -- "$isolated_home"
isolated_home_identity=$(file_identity "$isolated_home")
mkdir -m 700 -- "$isolated_config_home" "$isolated_cache_home" "$isolated_local_home"
isolated_local_home_identity=$(file_identity "$isolated_local_home")
mkdir -m 700 -- "$isolated_data_home" "$isolated_state_home"
isolated_state_home_identity=$(file_identity "$isolated_state_home")
mkdir -m 700 -- "$isolated_config_home/omarchy"
plugin_root="$isolated_config_home/omarchy/plugins"
mkdir -m 700 -- "$plugin_root"
plugin_root_identity=$(file_identity "$plugin_root")
plugin_target="$plugin_root/$plugin_id"
shell_config="$isolated_config_home/omarchy/shell.json"
state_bridge="$isolated_state_home/omarchy"
safe_absolute_path "$isolated_home" || die "isolated HOME path is unsafe"
for isolated_path in "$isolated_local_home" "$isolated_config_home" "$isolated_cache_home" \
  "$isolated_data_home" "$isolated_state_home" "$state_bridge" "$plugin_root" \
  "$plugin_target" "$shell_config"; do
  safe_absolute_path "$isolated_path" || die "isolated XDG path is unsafe: $isolated_path"
done
[[ $isolated_state_home == "$isolated_home/.local/state" ]] ||
  die "isolated XDG state and HOME-relative state paths diverged"
[[ ! -e $state_bridge && ! -L $state_bridge ]] ||
  die "isolated continuity-state mountpoint already exists"
state_bridge_created=1
create_owned_directory "$state_bridge" 700 state_bridge_identity \
  "$isolated_state_home_identity" ||
  die_with_status "$?" "could not create the owned continuity-state mountpoint"
jq -S '
  .bar.centerAnchor = "omarchy.clock"
  | .bar.layout = {
      left: [{id: "omarchy.menu"}, {id: "omarchy.workspaces"}],
      center: [{id: "omarchy.clock"}],
      right: [{id: "omarchy.audio"}]
    }
  | .disabledPlugins = ["omarchy.agents", "omarchy.weather"]
' "$OMARCHY_PATH/config/omarchy/shell.json" >"$shell_config"
chmod 0600 -- "$shell_config"
[[ -f $shell_config && ! -L $shell_config &&
  $(stat -c '%u:%a' -- "$shell_config") == "$UID:600" ]] ||
  die "isolated shell.json is not a private regular file"
shell_backup="$evidence_dir/shell.isolated.before.json"
cp -a -- "$shell_config" "$shell_backup"
shell_identity_before=$(file_identity "$shell_config")
shell_hash_before=$(sha256_file "$shell_config")
shell_stat_before=$(stat -c '%a:%u:%g:%s:%Y' -- "$shell_config")
shell_hash_expected=$shell_hash_before
shell_canonical_hash_expected=$(canonical_json_file_hash "$shell_config")
shell_canonical_before="$evidence_dir/shell.isolated.before.canonical"
jq -S . "$shell_backup" >"$shell_canonical_before"
cmp -s -- "$shell_backup" "$shell_canonical_before" ||
  die "isolated shell.json must use canonical jq/FileView serialization"
jq -e --arg id "$plugin_id" --arg other "$other_panel_id" '
  ([.. | objects | .id? | select(. == $id)] | length) == 0
  and .bar.layout == {
    left: [{id: "omarchy.menu"}, {id: "omarchy.workspaces"}],
    center: [{id: "omarchy.clock"}],
    right: [{id: $other}]
  }
  and .disabledPlugins == ["omarchy.agents", "omarchy.weather"]
  and (.plugins | length) == 0
' "$shell_config" >/dev/null || die "isolated shell baseline lacks the ownership witness"
bar_position_before=$(jq -er '.bar.position | select(IN("top", "bottom", "left", "right"))' "$shell_backup")
bar_position_last_expected=$bar_position_before
safe_shell_default="$evidence_dir/safe-default-shell.json"
install -m 0400 -- "$shell_config" "$safe_shell_default"
safe_shell_default_identity=$(file_identity "$safe_shell_default")
safe_shell_default_hash=$(canonical_json_file_hash "$safe_shell_default")
[[ $safe_shell_default_hash == "$shell_canonical_hash_expected" ]] ||
  die "safe packaged default differs from the isolated baseline"

namespace_wrapper="$evidence_dir/isolated-shell-namespace"
  install -m 0700 /dev/stdin "$namespace_wrapper" <<'NAMESPACE_WRAPPER'
#!/usr/bin/bash -p
set +x
set +v
set +a
set +f
set +k
set +m
set +C
set -euo pipefail

fail() {
  printf 'isolated-shell-namespace: %s\n' "$*" >&2
  exit 1
}

unsafe_startup_environment=0
while IFS= read -r -d '' startup_entry; do
  case $startup_entry in
    BASH_ENV=|ENV=|BASH_COMPAT=|FUNCNEST=|\
      LD_PRELOAD=|LD_AUDIT=|LD_LIBRARY_PATH=|GLIBC_TUNABLES=|\
      QT_PLUGIN_PATH=|QT_QPA_PLATFORM_PLUGIN_PATH=|QML_IMPORT_PATH=|QML2_IMPORT_PATH=|\
      QML_PLUGIN_PATH=|QML_DISK_CACHE_PATH=|QML_FORCE_DISK_CACHE=|\
      QML_DISABLE_DISK_CACHE=1|TAR_OPTIONS=|RIPGREP_CONFIG_PATH=)
      ;;
    BASH_ENV=*|ENV=*|SHELLOPTS=*|BASHOPTS=*|BASH_COMPAT=*|FUNCNEST=*|\
      BASH_FUNC_*%%=*|LD_*=*|GLIBC_TUNABLES=*|\
      QT_PLUGIN_PATH=*|QT_QPA_PLATFORM_PLUGIN_PATH=*|QML_*=*|QML2_IMPORT_PATH=*|\
      TAR_OPTIONS=*|RIPGREP_CONFIG_PATH=*)
      unsafe_startup_environment=1
      break
      ;;
  esac
done </proc/$$/environ
(( unsafe_startup_environment == 0 )) || fail "unsafe inherited execution controls"
unset BASH_ENV ENV BASH_COMPAT FUNCNEST startup_entry unsafe_startup_environment
export -n SHELLOPTS BASHOPTS 2>/dev/null || true

[[ ${PATH:-} == /usr/share/omarchy/bin:/usr/bin ]] || fail "execution PATH changed"

safe_absolute_path() {
  local path=$1
  [[ $path =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  [[ $path != *//* && $path != */./* && $path != */../* && $path != */. && $path != */.. ]]
}

readonly mode=${1:-run}
readonly safe_default=${OAB_SAFE_SHELL_DEFAULT:-}
readonly real_state=${OAB_REAL_STATE_ROOT:-}
readonly state_mountpoint=${OAB_STATE_BRIDGE:-}
readonly outer_uid=${OAB_OUTER_UID:-}
readonly launcher=/usr/share/omarchy/bin/omarchy-launch-shell
[[ $mode == run || $mode == preflight ]] || fail "invalid mode"
[[ $outer_uid =~ ^[1-9][0-9]*$ && $EUID == "$outer_uid" ]] || fail "user identity changed"
[[ ${OMARCHY_PATH:-} == /usr/share/omarchy ]] || fail "OMARCHY_PATH changed"
safe_absolute_path "$safe_default" || fail "unsafe safe-default source"
safe_absolute_path "$real_state" || fail "unsafe real-state source"
safe_absolute_path "$state_mountpoint" || fail "unsafe state mountpoint"
[[ -f $safe_default && ! -L $safe_default &&
  $(stat -c '%u:%a' -- "$safe_default") == "$outer_uid:400" &&
  -f /usr/share/omarchy/config/omarchy/shell.json &&
  ! -L /usr/share/omarchy/config/omarchy/shell.json &&
  $(stat -c '%d:%i' -- "$safe_default") == \
    "$(stat -c '%d:%i' -- /usr/share/omarchy/config/omarchy/shell.json)" ]] ||
  fail "safe default was not bound exactly"
[[ -d $real_state && ! -L $real_state &&
  -d $state_mountpoint && ! -L $state_mountpoint &&
  $(stat -c '%d:%i' -- "$real_state") == "$(stat -c '%d:%i' -- "$state_mountpoint")" ]] ||
  fail "continuity state was not bound exactly"
[[ -L $launcher &&
  $(readlink -- "$launcher") == /usr/bin/omarchy-launch-shell &&
  -f /usr/bin/omarchy-launch-shell && ! -L /usr/bin/omarchy-launch-shell &&
  -x /usr/bin/omarchy-launch-shell ]] ||
  fail "packaged shell files changed"
interfaces=$(awk -F: 'NR > 2 { name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name); print name }' \
  /proc/net/dev) || fail "network namespace could not be inspected"
[[ $interfaces == lo ]] || fail "network namespace exposes a non-loopback interface"
! awk 'NR > 1 && NF > 0 { found=1 } END { exit(found ? 0 : 1) }' /proc/net/route ||
  fail "network namespace exposes an IPv4 route"

[[ $mode == run ]] || exit 0
exec "$launcher"
NAMESPACE_WRAPPER
namespace_wrapper_identity=$(file_identity "$namespace_wrapper")

OAB_SAFE_SHELL_DEFAULT="$safe_shell_default" OAB_REAL_STATE_ROOT="$real_state_root" \
  OAB_STATE_BRIDGE="$state_bridge" OAB_OUTER_UID="$UID" \
  bwrap --die-with-parent --unshare-user --uid "$UID" --gid "$(id -g)" --unshare-net \
  --ro-bind / / --dev-bind /dev /dev --proc /proc --tmpfs /tmp \
  --bind "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR" \
  --ro-bind "$evidence_dir" "$evidence_dir" \
  --bind "$isolated_home" "$isolated_home" \
  --bind "$real_state_root" "$state_bridge" \
  --ro-bind "$safe_shell_default" /usr/share/omarchy/config/omarchy/shell.json \
  -- "$namespace_wrapper" preflight >"$evidence_dir/namespace-preflight.log" 2>&1 ||
  die "private shell namespace preflight failed"
state_namespace_scaffold_is_valid || die "private namespace scaffold is not exact"
plugin_list_before="$evidence_dir/plugin-list.before.json"
session_monitors_normalized_before="$evidence_dir/session.monitors.before.json"
session_workspaces_normalized_before="$evidence_dir/session.workspaces.before.json"
session_clients_normalized_before="$evidence_dir/session.clients.before.json"
session_cursor_before="$evidence_dir/session.cursor.before.json"
session_layers_normalized_before="$evidence_dir/session.layers.before.json"
monitors_before="$evidence_dir/pre-headless.monitors.before.raw.json"
monitors_normalized_before="$evidence_dir/pre-headless.monitors.before.json"
workspaces_normalized_before="$evidence_dir/pre-headless.workspaces.before.json"
clients_normalized_before="$evidence_dir/pre-headless.clients.before.json"
cursor_before="$evidence_dir/pre-headless.cursor.before.json"
printf '%s\n' "$manager_override_before" >"$evidence_dir/user-manager-override.before"
printf '%s\n' "$hyprland_config_errors_before" >"$evidence_dir/hyprland-config-errors.before"
monitor_manager_fingerprint_before="$evidence_dir/hyprmoncfgd-unit.before.txt"
monitor_manager_fingerprint >"$monitor_manager_fingerprint_before"
monitor_status_before="$evidence_dir/hyprmoncfg-status.before.json"
capture_hyprmoncfg_status "$monitor_status_before" baseline ||
  die "could not capture the exact hyprmoncfg status baseline"
jq -e '
  (.monitors | length) == 1 and .monitors[0].name == "eDP-1"
  and all(.monitors[]; (.name | ascii_downcase) != "fallback")
' "$monitor_status_before" >/dev/null ||
  die "hyprmoncfg status does not expose the exact physical-monitor baseline"
monitor_manager_config_hash_before=$(sha256_file "$monitor_manager_config_file")
hyprland_lua_hash_before=$(sha256_file "$hyprland_lua_file")
monitor_manager_config_stat_before=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' \
  -- "$monitor_manager_config_file")
hyprland_lua_stat_before=$(stat -c '%d:%i:%u:%g:%f:%s:%Y:%Z:%W:%y:%z:%w:%h' \
  -- "$hyprland_lua_file")
monitor_manager_config_acl_before="$evidence_dir/hyprmoncfg-monitors.lua.before.acl"
monitor_manager_config_xattr_before="$evidence_dir/hyprmoncfg-monitors.lua.before.xattr"
hyprland_lua_acl_before="$evidence_dir/hyprland.lua.before.acl"
hyprland_lua_xattr_before="$evidence_dir/hyprland.lua.before.xattr"
getfacl -cp --absolute-names "$monitor_manager_config_file" >"$monitor_manager_config_acl_before"
getfattr -d -m- --absolute-names "$monitor_manager_config_file" \
  >"$monitor_manager_config_xattr_before" 2>/dev/null
getfacl -cp --absolute-names "$hyprland_lua_file" >"$hyprland_lua_acl_before"
getfattr -d -m- --absolute-names "$hyprland_lua_file" >"$hyprland_lua_xattr_before" 2>/dev/null
file_envelope_matches "$monitor_manager_config_file" "$monitor_manager_config_hash_before" \
  "$monitor_manager_config_stat_before" "$monitor_manager_config_acl_before" \
  "$monitor_manager_config_xattr_before" hyprmoncfg-monitors.lua.baseline-capture ||
  die "hyprmoncfg monitor profile changed during its baseline capture"
file_envelope_matches "$hyprland_lua_file" "$hyprland_lua_hash_before" \
  "$hyprland_lua_stat_before" "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
  hyprland.lua.baseline-capture ||
  die "root Hyprland Lua config changed during its baseline capture"
monitor_profiles_digest_before="$evidence_dir/hyprmoncfg-profiles.before.sha256"
tree_digest_noatime "$monitor_profiles_root" "$monitor_profiles_digest_before" ||
  die "could not capture the exact hyprmoncfg profile tree"
printf '%s\n' "$monitor_manager_config_hash_before" >"$evidence_dir/hyprmoncfg-monitors.lua.before.sha256"
printf '%s\n' "$hyprland_lua_hash_before" >"$evidence_dir/hyprland.lua.before.sha256"

plugin_source_manifest="$evidence_dir/plugin-source.manifest"
plugin_tree_matches_frozen_manifest "$plugin_source" "$plugin_source_manifest" ||
  die "development plugin does not match the frozen five-file manifest"
omarchy plugin validate "$plugin_source" >"$evidence_dir/plugin-validate.log"

note "verifying the frozen prebuilt release binary"
[[ -d $repo_root/target && ! -L $repo_root/target &&
  -d $repo_root/target/release && ! -L $repo_root/target/release &&
  -x $release_binary && -f $release_binary && ! -L $release_binary &&
  $(stat -c '%u:%a' -- "$release_binary") == "$UID:755" ]] ||
  die "the frozen prebuilt release binary path is not exact"
release_binary_full_identity=$(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' \
  -- "$release_binary") || die "could not pin the frozen release binary inode"
release_binary_sha256=$(sha256_file "$release_binary")
[[ $release_binary_sha256 == "$expected_release_binary_sha256" &&
  $(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' -- "$release_binary") == \
    "$release_binary_full_identity" &&
  $(sha256_file "$release_binary") == "$expected_release_binary_sha256" ]] ||
  die "prebuilt release binary differs from the frozen audited executable"

temporary_runtime="$XDG_RUNTIME_DIR/omarchy-ai-bar-live-smoke-$UID-$$"
safe_absolute_path "$temporary_runtime" || die "unsafe temporary runtime path"
[[ ! -e $temporary_runtime && ! -L $temporary_runtime ]] ||
  die "temporary runtime path unexpectedly exists"
temporary_runtime_created=1
create_owned_directory "$temporary_runtime" 700 temporary_runtime_identity "$runtime_root_identity" ||
  die_with_status "$?" "could not create the owned temporary runtime directory"
temporary_binary="$temporary_runtime/omarchy-ai-bar"
reviewed_source_boundary_matches ||
  die "reviewed Rust source changed before installing the frozen binary"
[[ $(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' -- "$release_binary") == \
    "$release_binary_full_identity" &&
  $(sha256_file "$release_binary") == "$expected_release_binary_sha256" ]] ||
  die "prebuilt release binary changed before its private copy"
install_owned_file "$release_binary" "$temporary_binary" 700 temporary_binary_identity \
  "$temporary_runtime_identity" ||
  die_with_status "$?" "could not install the owned temporary binary"
[[ $(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%Z:%W:%h' -- "$release_binary") == \
    "$release_binary_full_identity" &&
  $(sha256_file "$release_binary") == "$expected_release_binary_sha256" ]] ||
  die "prebuilt release binary changed while making its private copy"
temporary_binary_sha256=$(sha256_file "$temporary_binary")
[[ $temporary_binary_sha256 == "$expected_release_binary_sha256" ]] ||
  die "installed temporary binary does not match the frozen release binary"
temporary_binary_full_identity=$(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' \
  -- "$temporary_binary") || die "could not pin the installed temporary binary inode"
[[ $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
  $(stat -c '%u:%a' -- "$temporary_binary") == "$UID:700" &&
  $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
    "$temporary_binary_full_identity" &&
  $(sha256_file "$temporary_binary") == "$expected_release_binary_sha256" ]] ||
  die "installed temporary binary changed before its first execution"
/usr/bin/env -i "$temporary_binary" version --json >"$evidence_dir/binary-version.json"
jq -e '
  .name == "omarchy-ai-bar"
  and .version == "0.3.0"
  and (keys | sort) == ["name", "version"]
' "$evidence_dir/binary-version.json" >/dev/null || die "release binary identity is unexpected"
[[ $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
  $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
    "$temporary_binary_full_identity" &&
  $(sha256_file "$temporary_binary") == "$expected_release_binary_sha256" ]] ||
  die "installed temporary binary changed during its identity proof"

snapshot_wire="$evidence_dir/snapshot-wire.json"
[[ -f $snapshot_fixture && ! -L $snapshot_fixture ]] ||
  die "strict snapshot fixture is not a regular reviewed file"
snapshot_fixture_full_identity=$(stat -c \
  '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%y:%Z:%z:%W:%w:%h' -- "$snapshot_fixture") ||
  die "could not pin the strict snapshot fixture inode"
reviewed_source_boundary_matches &&
  [[ $(sha256_file "$snapshot_fixture") == "$expected_snapshot_fixture_sha256" ]] ||
  die "strict snapshot fixture changed before its read"
jq '
  walk(
    if type == "object" then
      with_entries(
        if (.key | IN(
          "duration_seconds", "retry_after", "input_tokens", "output_tokens",
          "cache_read_tokens", "cache_creation_tokens", "reasoning_tokens",
          "priced", "unpriced", "unmetered", "estimated", "total_tokens",
          "request_count", "standard_tokens", "priority_tokens"
        )) and .value != null then
          if (.value | type) == "number" and .value >= 0 and .value == (.value | floor)
          then .value |= tostring
          else error("non-u64 fixture value")
          end
        else . end
      )
    else . end
  )
' "$snapshot_fixture" >"$snapshot_wire"
[[ $(stat -c '%D:%i:%u:%g:%f:%s:%X:%x:%Y:%y:%Z:%z:%W:%w:%h' \
    -- "$snapshot_fixture") == "$snapshot_fixture_full_identity" &&
  $(sha256_file "$snapshot_fixture") == "$expected_snapshot_fixture_sha256" ]] &&
  reviewed_source_boundary_matches ||
  die "strict snapshot fixture changed during its read"

server_hello="$evidence_dir/server-hello.jsonl"
jq -cn --arg stream "$stream_id" '
  {
    type: "hello",
    protocol: {major: 1, minor: 0},
    stream_id: $stream,
    capabilities: [
      "display_snapshots", "runtime_actions", "action_progress", "compatibility_errors"
    ]
  }
' >"$server_hello"
snapshot_frame="$evidence_dir/server-snapshot.jsonl"
jq -cn --slurpfile snapshot "$snapshot_wire" \
  '{type: "snapshot", sequence: 1, snapshot: $snapshot[0]}' >"$snapshot_frame"

mock_log="$evidence_dir/mock-server.jsonl"
mock_handler="$evidence_dir/mock-connection-handler"
cat >"$mock_handler" <<'MOCK_HANDLER'
#!/usr/bin/bash -p
set +x
set +v
set +a
set +f
set +k
set +m
set +C
set -euo pipefail
umask 077
PATH=/usr/share/omarchy/bin:/usr/bin
export PATH
hash -r

log_event() {
  local record=$1
  flock -w 0.3 9
  printf '%s\n' "$record" >&9
  flock -u 9
}

exec 9>>"$OAB_LIVE_MOCK_LOG"
log_event "$(jq -cn --argjson pid "$BASHPID" '{event:"connected", handler_pid:$pid}')"

hello_seen=0
while IFS= read -r line; do
  (( ${#line} <= 65536 )) || exit 1
  message_type=$(jq -er '.type' <<<"$line") || exit 1
  case $message_type in
    hello)
      (( hello_seen == 0 )) || exit 1
      jq -e '
        type == "object"
        and (keys | sort) == ["bridge_version", "capabilities", "protocol", "session_id", "type"]
        and .type == "hello"
        and .protocol == {major: 1, minor: 0}
        and .bridge_version == {major: 0, minor: 1, patch: 0}
        and (.session_id | type == "string" and test("^[0-9a-f]{32}$"))
        and (.capabilities | type == "array" and length <= 32 and length == (unique | length))
        and (.capabilities | index("display_snapshots") != null)
        and (.capabilities | index("runtime_actions") != null)
        and (.capabilities | index("action_progress") != null)
        and (.capabilities | index("compatibility_errors") != null)
      ' <<<"$line" >/dev/null || exit 1
      hello_seen=1
      log_event "$(jq -cn '{event:"hello"}')"
      cat -- "$OAB_LIVE_SERVER_HELLO"
      cat -- "$OAB_LIVE_SNAPSHOT_FRAME"
      ;;
    snapshot_ack)
      (( hello_seen == 1 )) || exit 1
      jq -e 'type == "object" and (keys | sort) == ["sequence", "type"]
        and .sequence == 1' <<<"$line" >/dev/null || exit 1
      log_event "$(jq -cn '{event:"snapshot_ack", sequence:1}')"
      ;;
    action)
      (( hello_seen == 1 )) || exit 1
      jq -e '
        type == "object" and (keys | sort) == ["action", "request_id", "type"]
        and (.request_id | type == "number" and . > 0 and . <= 9007199254740991 and . == floor)
        and (.action | type == "object" and (keys | sort) == ["id"])
        and (.action.id | IN("open_panel", "close_panel", "refresh_all"))
      ' <<<"$line" >/dev/null || exit 1
      request_id=$(jq -er '.request_id' <<<"$line")
      action=$(jq -er '.action.id' <<<"$line")
      log_event "$(jq -cn --arg action "$action" --argjson request_id "$request_id" \
        '{event:"action", action:$action, request_id:$request_id}')"
      jq -cn --argjson request_id "$request_id" \
        '{type:"action_progress", request_id:$request_id, state:"completed"}'
      ;;
    *)
      exit 1
      ;;
  esac
done

log_event "$(jq -cn '{event:"disconnected"}')"
MOCK_HANDLER
chmod 0700 -- "$mock_handler"

production_runtime_created=1
create_owned_directory "$production_runtime" 700 production_runtime_identity "$evidence_dir_identity" ||
  die_with_status "$?" "could not create the owned private mock runtime directory"
export OAB_LIVE_MOCK_LOG="$mock_log"
export OAB_LIVE_SERVER_HELLO="$server_hello"
export OAB_LIVE_SNAPSHOT_FRAME="$snapshot_frame"
start_mock_server || die_with_status "$?" "mock display socket server did not start safely"
[[ $(stat -c '%u:%a' -- "$production_runtime") == "$UID:700" ]] ||
  die "mock runtime directory is not same-UID mode 0700"

note "proving the Rust bridge accepts the strict full snapshot wire"
[[ $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
  $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
    "$temporary_binary_full_identity" &&
  $(sha256_file "$temporary_binary") == "$expected_release_binary_sha256" ]] ||
  die "temporary executable changed before the strict bridge proof"
proof_client="$evidence_dir/proof-client-hello.jsonl"
jq -cn '
  {
    type: "hello",
    protocol: {major: 1, minor: 0},
    bridge_version: {major: 0, minor: 1, patch: 0},
    session_id: "0123456789abcdef0123456789abcdef",
    capabilities: [
      "display_snapshots", "runtime_actions", "action_progress", "compatibility_errors"
    ]
  }
' >"$proof_client"
{
  cat -- "$proof_client"
  sleep 1
} | timeout --kill-after=1s 5s /usr/bin/env -i \
  "$temporary_binary" bridge stdio --socket "$display_socket" \
  >"$evidence_dir/bridge-proof.jsonl" 2>"$evidence_dir/bridge-proof.stderr"
[[ ! -s $evidence_dir/bridge-proof.stderr ]] || die "strict bridge proof emitted diagnostics"
jq -s -e --slurpfile snapshot "$snapshot_wire" --arg stream "$stream_id" '
  length == 2
  and .[0] == {
    type: "hello", protocol: {major: 1, minor: 0}, stream_id: $stream,
    capabilities: [
      "display_snapshots", "runtime_actions", "action_progress", "compatibility_errors"
    ]
  }
  and .[1] == {type: "snapshot", sequence: 1, snapshot: $snapshot[0]}
' "$evidence_dir/bridge-proof.jsonl" >/dev/null || die "Rust bridge changed or rejected the strict snapshot"
[[ $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
  $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
    "$temporary_binary_full_identity" &&
  $(sha256_file "$temporary_binary") == "$expected_release_binary_sha256" ]] ||
  die "temporary executable changed during the strict bridge proof"
snapshot_ack_before=$(mock_event_count snapshot_ack)

note "copying the plugin into the private isolated plugin tree"
[[ ! -e $plugin_target && ! -L $plugin_target ]] || die "plugin target appeared during build"
plugin_target_manifest="$evidence_dir/plugin-target.manifest"
plugin_tree_matches_frozen_manifest \
  "$plugin_source" "$evidence_dir/plugin-source.before-copy.manifest" ||
  die "development plugin changed before its private copy"
cmp -s -- "$plugin_source_manifest" "$evidence_dir/plugin-source.before-copy.manifest" ||
  die "development plugin manifest changed before its private copy"
plugin_source_mode=$(stat -c '%a' -- "$plugin_source")
plugin_copied=1
create_owned_directory "$plugin_target" "$plugin_source_mode" plugin_target_identity \
  "$plugin_root_identity" "$plugin_target_manifest" plugin_target_manifest_valid ||
  die_with_status "$?" "could not create the owned plugin target"
copy_plugin_tree || die_with_status "$?" "copied plugin differs from source"
omarchy plugin validate "$plugin_target" >>"$evidence_dir/plugin-validate.log"
plugin_tree_matches_frozen_manifest \
  "$plugin_source" "$evidence_dir/plugin-source.before-shell.manifest" ||
  die "development plugin changed before shell replacement"
plugin_tree_matches_frozen_manifest \
  "$plugin_target" "$evidence_dir/plugin-target.before-shell.manifest" ||
  die "private plugin copy changed before shell replacement"
cmp -s -- "$plugin_source_manifest" "$evidence_dir/plugin-source.before-shell.manifest" &&
  cmp -s -- "$plugin_source_manifest" "$evidence_dir/plugin-target.before-shell.manifest" ||
  die "source and private plugin manifests diverged before shell replacement"
[[ $(file_identity "$temporary_binary") == "$temporary_binary_identity" &&
  $(stat -Lc '%D:%i:%u:%g:%f:%s:%Y:%Z:%W:%h' -- "$temporary_binary") == \
    "$temporary_binary_full_identity" &&
  $(sha256_file "$temporary_binary") == "$expected_release_binary_sha256" ]] ||
  die "temporary executable changed before shell replacement"
verify_real_user_state before-shell-replacement ||
  die "real shell/plugin state changed before the isolated shell launch"

note "restarting the shell in an isolated user service with the executable override"
[[ $(systemctl_user_query show -p LoadState --value "$transient_unit" 2>/dev/null) == not-found ]] ||
  die "transient service name unexpectedly exists: $transient_unit"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before the original-session baseline"
quickshell_instance_is_exact "$original_shell_pid" ||
  die "the packaged shell instance changed before the session baseline"
original_launcher_is_running_exact ||
  die "the packaged shell launcher changed before the session baseline"
process_has_frontend_environment "$original_shell_pid" "$HOME" "$real_xdg_config_home" \
  "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" ||
  die "the original shell environment changed before replacement"
process_has_session_transport_environment "$original_shell_pid" ||
  die "the original shell session transport changed before replacement"
wait_for_effective_shell_config "$real_shell_canonical_hash_before" ||
  die "the original shell effective config changed before replacement"
wait_for_shell_continuity "$original_shell_pid" "$HOME" "$real_xdg_config_home" \
  "$real_xdg_cache_home" "$real_xdg_data_home" "$real_xdg_state_home" \
  "$real_stay_awake_marker" || die "original shell continuity changed before replacement"
for (( attempt = 0; attempt < 50; attempt++ )); do
  if OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell listPlugins 2>/dev/null | jq -S 'sort_by(.id)' >"$plugin_list_before" &&
    jq -e --arg other "$other_panel_id" '
      any(.[]; .id == "omarchy.bar" and .active == true)
      and any(.[]; .id == $other and .enabled == true
        and (.kinds | index("bar-widget")) != null)
    ' "$plugin_list_before" >/dev/null; then
    break
  fi
  sleep 0.1
done
jq -e --arg other "$other_panel_id" '
  any(.[]; .id == "omarchy.bar" and .active == true)
  and any(.[]; .id == $other and .enabled == true
    and (.kinds | index("bar-widget")) != null)
' "$plugin_list_before" >/dev/null || die "original plugin registry did not settle before replacement"
plugin_list_hash_before=$(sha256_file "$plugin_list_before")
session_monitors_raw="$evidence_dir/session.monitors.before.raw.json"
hyprctl_bounded monitors all -j | jq -S . >"$session_monitors_raw"
jq -e '
  length == 1 and .[0].name == "eDP-1" and .[0].disabled == false
  and .[0].scale == 1.25 and .[0].focused == true
' "$session_monitors_raw" >/dev/null || die "desktop changed before the original-session baseline"
normalized_monitor_state <"$session_monitors_raw" >"$session_monitors_normalized_before"
session_monitors_hash_before=$(sha256_file "$session_monitors_normalized_before")
capture_normalized_workspace_state "$session_workspaces_normalized_before"
jq -e 'length > 0 and all(.[]; .id > 0 and .monitor == "eDP-1")' \
  "$session_workspaces_normalized_before" >/dev/null ||
  die "workspace topology changed before the original-session baseline"
capture_normalized_client_state "$session_clients_normalized_before"
hyprctl_bounded cursorpos -j | jq -S . >"$session_cursor_before"
focused_monitor_before=$(jq -er '.[] | select(.focused == true) | .name' "$session_monitors_raw")
active_workspace_id_before=$(jq -er '.[] | select(.focused == true) | .activeWorkspace.id' \
  "$session_monitors_raw")
[[ $active_workspace_id_before =~ ^[1-9][0-9]*$ ]] ||
  die "active workspace changed before the original-session baseline"
hyprland_config_errors_match ||
  die "Hyprland config errors changed before shell replacement"
verify_real_user_state immediate-pre-kill ||
  die "real shell/plugin state changed immediately before replacement"
quickshell_instance_is_exact "$original_shell_pid" ||
  die "the packaged shell instance changed at the replacement boundary"
original_shell_process_is_same ||
  die "the original shell process identity changed at the replacement boundary"
original_launcher_is_running_exact ||
  die "the original shell launcher identity changed at the replacement boundary"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear at the shell replacement boundary"
state_namespace_scaffold_is_valid ||
  die "private namespace scaffold changed at the shell replacement boundary"
quickshell_instance_is_exact "$original_shell_pid" ||
  die "the packaged shell instance changed while checking the private namespace"
original_shell_process_is_same ||
  die "the original shell process identity changed while checking the private namespace"
capture_quiescent_shell_layers "$session_layers_normalized_before" "$original_shell_pid" ||
  die "the original shell has summoned or non-quiescent layer UI at the replacement boundary"
manager_session_environment_matches ||
  die "user manager session environment changed at the shell replacement boundary"
process_has_session_transport_environment "$original_shell_pid" ||
  die "the original shell session transport changed at the replacement boundary"
session_is_safe_for_live_mutation ||
  die "session lock state changed while checking the private namespace"
quickshell_instance_is_exact "$original_shell_pid" && original_shell_process_is_same ||
  die "the original shell process changed after the layer-quiescence proof"
original_launcher_is_running_exact ||
  die "the original shell launcher changed after the layer-quiescence proof"
live_lock_is_held || die "live-smoke singleton lock changed before shell replacement"
shell_replaced=1 original_shell_stop_requested=1
timeout --kill-after=1s 5s quickshell kill --pid "$original_shell_pid" \
  >"$evidence_dir/original-shell-stop.log" 2>&1 ||
  die "could not request the exact original shell process to stop"
# A successful Quickshell 0.3.1 PID kill waits for disconnect. The additional
# stable all-display/process proof also covers wrapper-supervisor backoff and
# makes timeout/failure cleanup decisions use the same strong boundary.
wait_for_original_shell_exit_and_stable_absence ||
  die "original packaged-shell process did not remain absent after stop"
session_is_confirmed_unlocked ||
  die "session locked or became indeterminate before isolated-shell launch"
manager_session_environment_matches ||
  die "user manager session environment changed before isolated-shell launch"
transient_started=1
transient_submission_pending=1
transient_submission_absence_proven=0
timeout --kill-after=1s 10s systemd-run --user --unit="$transient_unit" --collect --property=Type=exec \
  --setenv="OMARCHY_AI_BAR_EXECUTABLE=$temporary_binary" \
  --setenv="OMARCHY_AI_BAR_DISPLAY_SOCKET=$display_socket" \
  --setenv="OAB_LIVE_HARNESS_TOKEN=$transient_token" \
  --setenv="OMARCHY_PATH=/usr/share/omarchy" \
  --setenv="OAB_SAFE_SHELL_DEFAULT=$safe_shell_default" \
  --setenv="OAB_REAL_STATE_ROOT=$real_state_root" \
  --setenv="OAB_STATE_BRIDGE=$state_bridge" \
  --setenv="OAB_OUTER_UID=$UID" \
  --setenv="PATH=/usr/share/omarchy/bin:/usr/bin" \
  --setenv="HOME=$isolated_home" \
  --setenv="XDG_CONFIG_HOME=$isolated_config_home" \
  --setenv="XDG_CACHE_HOME=$isolated_cache_home" \
  --setenv="XDG_DATA_HOME=$isolated_data_home" \
  --setenv="XDG_STATE_HOME=$isolated_state_home" \
  --setenv="CODEX_HOME=$isolated_home/.codex" \
  --setenv="CLAUDE_CONFIG_DIR=$isolated_home/.claude" \
  --setenv="FIREWORKS_AUTH_PATH=$isolated_config_home/fireworks/auth.ini" \
  --setenv="FIREWORKS_API_KEY=" \
  --setenv="FIREWORKS_ACCOUNT_ID=" \
  --setenv="OPENAI_API_KEY=" \
  --setenv="CODEX_API_KEY=" \
  --setenv="ANTHROPIC_API_KEY=" \
  --setenv="ANTHROPIC_AUTH_TOKEN=" \
  --setenv="LD_PRELOAD=" \
  --setenv="LD_AUDIT=" \
  --setenv="LD_LIBRARY_PATH=" \
  --setenv="GLIBC_TUNABLES=" \
  --setenv="QT_PLUGIN_PATH=" \
  --setenv="QT_QPA_PLATFORM_PLUGIN_PATH=" \
  --setenv="QML_IMPORT_PATH=" \
  --setenv="QML2_IMPORT_PATH=" \
  --setenv="QML_PLUGIN_PATH=" \
  --setenv="QML_DISK_CACHE_PATH=" \
  --setenv="QML_FORCE_DISK_CACHE=" \
  --setenv="QML_DISABLE_DISK_CACHE=1" \
  --setenv="BASH_ENV=" \
  --setenv="ENV=" \
  --setenv="BASH_COMPAT=" \
  --setenv="FUNCNEST=" \
  --setenv="TAR_OPTIONS=" \
  --setenv="RIPGREP_CONFIG_PATH=" \
  -- /usr/bin/bwrap --die-with-parent --unshare-user --uid "$UID" --gid "$(id -g)" \
  --unshare-net --ro-bind / / --dev-bind /dev /dev --proc /proc --tmpfs /tmp \
  --bind "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR" \
  --ro-bind "$temporary_binary" "$temporary_binary" \
  --ro-bind "$evidence_dir" "$evidence_dir" \
  --bind "$isolated_home" "$isolated_home" \
  --bind "$real_state_root" "$state_bridge" \
  --ro-bind "$safe_shell_default" /usr/share/omarchy/config/omarchy/shell.json \
  -- "$namespace_wrapper" >"$evidence_dir/systemd-run.log"
wait_for_shell || die "override shell did not become ready"
transient_unit_is_owned || die "transient override service ownership could not be proven"
transient_control_group=$(systemctl_user_query show -p ControlGroup --value "$transient_unit")
[[ $transient_control_group == /user.slice/*/"$transient_unit" &&
  $transient_control_group != *..* && $transient_control_group != *//* ]] ||
  die "transient override cgroup is unsafe"
transient_invocation=$(systemctl_user_query show -p InvocationID --value "$transient_unit")
[[ $transient_invocation =~ ^[0-9a-f]{32}$ ]] || die "transient invocation identity is invalid"
transient_unit_is_owned || die "transient override invocation changed unexpectedly"
transient_submission_pending=0
override_shell_pid=$(shell_pid) || die "override shell did not publish one bar PID"
[[ $override_shell_pid != "$original_shell_pid" ]] || die "shell PID did not change"
quickshell_instance_is_exact "$override_shell_pid" ||
  die "the transient shell is not the only packaged-shell instance across displays"
process_has_override "$override_shell_pid" || die "temporary shell did not receive the executable override"
process_has_frontend_environment "$override_shell_pid" "$isolated_home" "$isolated_config_home" \
  "$isolated_cache_home" "$isolated_data_home" "$isolated_state_home" ||
  die "temporary shell did not receive the isolated HOME/XDG environment"
process_has_session_transport_environment "$override_shell_pid" ||
  die "temporary shell did not inherit the canonical Omarchy session transport"
process_has_agent_isolation "$override_shell_pid" ||
  die "temporary shell retained a real agent credential/configuration path"
shell_namespace_is_valid "$override_shell_pid" ||
  die "temporary shell lost its exact private mount/network namespace"
wait_for_effective_shell_config "$shell_canonical_hash_expected" ||
  die "temporary shell did not load the exact isolated shell.json"
wait_for_session_safe_for_live_mutation ||
  die "temporary shell lock service did not settle in a stably clear state"
systemctl_user_query show "$transient_unit" \
  -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p ControlGroup \
  -p Environment -p InvocationID -p Job -p ExecStart -p Transient -p FragmentPath \
  >"$evidence_dir/transient-unit.initial.txt"

OMARCHY_SHELL_IPC_TIMEOUT=0.5s timeout --kill-after=0.1s 1s \
  omarchy-shell shell rescanPlugins >/dev/null || die "isolated plugin rescan failed"
wait_for_isolated_plugin_policy ||
  die "isolated plugin policy or copied plugin discovery did not settle"
wait_for_shell_continuity "$override_shell_pid" "$isolated_home" "$isolated_config_home" \
  "$isolated_cache_home" "$isolated_data_home" "$isolated_state_home" \
  "$state_bridge/indicators/stay-awake" ||
  die "isolated notification, clipboard, or stay-awake continuity did not recover"

session_is_safe_for_live_mutation ||
  die "session lock state changed before isolated plugin enablement"
config_mutated=1
run_shell_config_mutation omarchy plugin enable "$plugin_id" --section right >"$evidence_dir/plugin-enable.log"
plugin_entry_index_expected=$(jq -er --arg id "$plugin_id" '
  [.bar.layout.right | to_entries[] | select(.value == {id: $id})]
  | if length == 1 then .[0].key else empty end
' "$shell_config") || die "enabled plugin did not produce one exact right-section entry"
plugin_entry_json_expected=$(jq -cer --argjson index "$plugin_entry_index_expected" \
  '.bar.layout.right[$index]' "$shell_config")
[[ $plugin_entry_json_expected == '{"id":"local.omarchy-ai-bar"}' ]] ||
  die "enabled plugin entry contains unexpected fields"
jq -e --arg id "$plugin_id" '
  ([.. | objects | .id? | select(. == $id)] | length) == 1
' "$shell_config" >/dev/null || die "enabled plugin has an unexpected reference count"
plugin_entry_recorded=1
plugin_list_enabled="$evidence_dir/plugin-list.enabled.json"
for (( attempt = 0; attempt < 50; attempt++ )); do
  if OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell listPlugins 2>/dev/null | jq -S 'sort_by(.id)' \
      >"$plugin_list_enabled" &&
    jq -e --arg id "$plugin_id" '
      any(.[]; .id == $id and .enabled == true and (.kinds | index("service")) != null
        and (.kinds | index("bar-widget")) != null)
      and any(.[]; .id == "omarchy.agents" and .enabled == false)
    ' "$plugin_list_enabled" >/dev/null; then
    break
  fi
  sleep 0.1
done
jq -e --arg id "$plugin_id" '
  any(.[]; .id == $id and .enabled == true and (.kinds | index("service")) != null
    and (.kinds | index("bar-widget")) != null)
  and any(.[]; .id == "omarchy.agents" and .enabled == false)
' "$plugin_list_enabled" >/dev/null || die "enabled plugin registry did not settle"
plugin_list_enabled_hash=$(sha256_file "$plugin_list_enabled")
wait_for_geometry 1 "$evidence_dir/geometry.one-monitor.json" ||
  die "plugin widget was not drawn on eDP-1"
if ! wait_for_mock_count snapshot_ack "" "$((snapshot_ack_before + 1))"; then
  die "QML did not accept and acknowledge the strict snapshot"
fi
bridge_pid=$(wait_for_one_bridge) || die "could not resolve the QML bridge process"
process_has_override "$override_shell_pid" || die "shell lost its override"
printf '%s\n' "$bridge_pid" >"$evidence_dir/bridge.initial.pid"
refresh_before=$(mock_event_count action refresh_all)
[[ $refresh_before =~ ^[0-9]+$ ]] || die "mock refresh count was malformed"
[[ $(bounded_shell_ipc omarchy-ai-bar refreshAll) == ok ]] ||
  die "QML service refused the refresh-all request"
wait_for_mock_count action refresh_all "$((refresh_before + 1))" ||
  die "backend did not observe the refresh-all request"

note "proving the audited monitor-profile daemon ignores the nonce-bearing filtered connector"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before monitor-manager observation"
monitors_before_live=$(hyprctl_bounded monitors all -j)
jq -e '
  length == 1 and .[0].name == "eDP-1" and .[0].disabled == false
  and .[0].scale == 1.25 and .[0].focused == true
' <<<"$monitors_before_live" >/dev/null ||
  die "desktop monitor state changed before the live output mutation"
workspaces_before_live=$(hyprctl_bounded workspaces -j)
jq -e '
  length > 0 and all(.[]; .id > 0 and .monitor == "eDP-1")
' <<<"$workspaces_before_live" >/dev/null ||
  die "workspace state changed outside the one-monitor safety boundary"
current_active_workspace_id=$(jq -er '.[] | select(.focused == true) | .activeWorkspace.id' \
  <<<"$monitors_before_live")
[[ $current_active_workspace_id == "$active_workspace_id_before" ]] ||
  die "active workspace changed unexpectedly before the filtered headless proof"
hyprland_config_errors_match ||
  die "Hyprland config errors changed before the live output mutation"
tree_digest_noatime \
  "$monitor_profiles_root" "$evidence_dir/hyprmoncfg-profiles.before-headless.sha256" ||
  die "could not recapture hyprmoncfg profiles before the filtered headless proof"
cmp -s -- "$monitor_profiles_digest_before" \
  "$evidence_dir/hyprmoncfg-profiles.before-headless.sha256" ||
  die "hyprmoncfg profiles changed before the filtered headless proof"
printf '%s\n' "$monitor_manager_config_hash_before" >"$evidence_dir/hyprmoncfg-monitors.lua.before-headless.sha256"
printf '%s\n' "$hyprland_lua_hash_before" >"$evidence_dir/hyprland.lua.before-headless.sha256"
monitor_manager_fingerprint >"$evidence_dir/hyprmoncfgd-unit.before-headless.txt"
cmp -s -- "$monitor_manager_fingerprint_before" "$evidence_dir/hyprmoncfgd-unit.before-headless.txt" ||
  die "hyprmoncfgd unit definition changed before the live output mutation"
monitor_manager_running_exact || die "hyprmoncfgd process changed before the live output mutation"
hyprmoncfg_preview_is_clear ||
  die "hyprmoncfgd gained a pending display preview before the live output mutation"
capture_hyprmoncfg_status \
  "$evidence_dir/hyprmoncfg-status.before-headless.json" before-headless ||
  die "could not recapture hyprmoncfg status before the live output mutation"
cmp -s -- "$monitor_status_before" \
  "$evidence_dir/hyprmoncfg-status.before-headless.json" ||
  die "hyprmoncfg status changed before the filtered headless proof"
[[ $(monitor_watcher_scope_count) == 0 ]] || die "fallback monitor watcher appeared before headless creation"
session_is_safe_for_live_mutation ||
  die "session lock state changed at the filtered headless boundary"
live_lock_is_held || die "live-smoke singleton lock changed before the filtered headless proof"
monitor_manager_running_exact ||
  die "hyprmoncfgd process identity/state changed at the filtered headless boundary"
[[ $(monitor_watcher_scope_count) == 0 ]] ||
  die "fallback monitor watcher appeared at the filtered headless boundary"
file_envelope_matches "$monitor_manager_config_file" "$monitor_manager_config_hash_before" \
  "$monitor_manager_config_stat_before" "$monitor_manager_config_acl_before" \
  "$monitor_manager_config_xattr_before" hyprmoncfg-monitors.lua.at-headless-boundary ||
  die "hyprmoncfg monitor profile envelope changed at the filtered headless boundary"
file_envelope_matches "$hyprland_lua_file" "$hyprland_lua_hash_before" \
  "$hyprland_lua_stat_before" "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
  hyprland.lua.at-headless-boundary ||
  die "root Hyprland Lua config envelope changed at the filtered headless boundary"
tree_digest_noatime \
  "$monitor_profiles_root" "$evidence_dir/hyprmoncfg-profiles.at-headless-boundary.sha256" ||
  die "could not recapture hyprmoncfg profiles at the filtered headless boundary"
cmp -s -- "$monitor_profiles_digest_before" \
  "$evidence_dir/hyprmoncfg-profiles.at-headless-boundary.sha256" ||
  die "hyprmoncfg profiles changed at the filtered headless boundary"

hyprctl_bounded monitors all -j | jq -S . >"$monitors_before"
jq -e --arg monitor "$focused_monitor_before" --argjson workspace "$active_workspace_id_before" '
  length == 1 and .[0].name == $monitor and .[0].disabled == false
  and .[0].scale == 1.25 and .[0].focused == true
  and .[0].activeWorkspace.id == $workspace
' "$monitors_before" >/dev/null || die "pre-headless monitor state did not remain exact"
normalized_monitor_state <"$monitors_before" >"$monitors_normalized_before"
monitors_hash_before=$(sha256_file "$monitors_normalized_before")
capture_normalized_workspace_state "$workspaces_normalized_before"
jq -e 'length > 0 and all(.[]; .id > 0 and .monitor == "eDP-1")' \
  "$workspaces_normalized_before" >/dev/null ||
  die "pre-headless workspace state changed"
capture_normalized_client_state "$clients_normalized_before"
hyprctl_bounded cursorpos -j | jq -S . >"$cursor_before"

note "creating and configuring a reversible 1.5-scale headless output"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before headless-output creation"
if start_headless_event_watcher; then
  :
else
  watcher_status=$?
  die_with_status "$watcher_status" \
    "could not start and pin the Hyprland monitor-generation witness"
fi
[[ $(headless_event_sequence_state) == 0 ]] ||
  die "headless monitor-generation witness was not empty before creation"
compositor_identity_matches ||
  die "running compositor identity changed at the headless-output creation boundary"
output_created=1
create_owned_headless_output ||
  die_with_status "$?" "named headless output could not be created and pinned"
for (( attempt = 0; attempt < 50; attempt++ )); do
  hyprctl_bounded monitors all -j >"$evidence_dir/monitors.after-create.json"
  if [[ $(jq 'length' "$evidence_dir/monitors.after-create.json") == 2 ]]; then
    break
  fi
  sleep 0.1
done
jq -e --arg name "$headless_name" '
  length == 2 and any(.[]; .name == $name)
' "$evidence_dir/monitors.after-create.json" >/dev/null ||
  die "named headless output was not created exactly"
headless_output_is_owned || die "headless output identity changed after creation"
headless_position=$(jq -er '.[] | select(.name == "eDP-1")
  | [(.x + (.width / .scale | floor)), .y] | @tsv' "$monitors_before")
read -r headless_x headless_y <<<"$headless_position"
session_is_safe_for_live_mutation ||
  die "session lock state changed before headless-output configuration"
compositor_identity_matches ||
  die "running compositor identity changed at the headless-output configuration boundary"
configure_owned_headless_output_once "$headless_x" "$headless_y" ||
  die "headless-output configuration authority changed or Hyprland rejected the exact rule"
for (( attempt = 0; attempt < 80; attempt++ )); do
  if hyprctl_bounded monitors all -j | jq -e --arg name "$headless_name" \
    --argjson x "$headless_x" --argjson y "$headless_y" '
    length == 2
    and any(.[]; .name == "eDP-1" and .scale == 1.25 and .disabled == false)
    and any(.[]; .name == $name and .width == 1920 and .height == 1080
      and .x == $x and .y == $y and .scale == 1.5 and .transform == 0
      and ((.refreshRate - 60) | fabs) <= 0.2 and .disabled == false)
  ' >/dev/null; then
    break
  fi
  sleep 0.1
done
monitors_configured="$evidence_dir/monitors.configured.json"
hyprctl_bounded monitors all -j | jq -S . >"$monitors_configured"
jq -e --arg name "$headless_name" --argjson x "$headless_x" --argjson y "$headless_y" '
  length == 2
  and any(.[]; .name == "eDP-1" and .scale == 1.25 and .disabled == false)
  and any(.[]; .name == $name and .width == 1920 and .height == 1080
    and .x == $x and .y == $y and .scale == 1.5 and .transform == 0
    and ((.refreshRate - 60) | fabs) <= 0.2 and .disabled == false)
' "$monitors_configured" >/dev/null || die "headless scaling did not settle exactly"
# Cross both hyprmoncfgd's hotplug debounce and periodic poll boundaries while
# the filtered connector is present, then prove that the daemon ignored it.
sleep 7
live_lock_is_held || die "live-smoke singleton lock changed during the filtered headless proof"
compositor_identity_matches ||
  die "running compositor identity changed during the filtered headless proof"
monitor_manager_running_exact ||
  die "hyprmoncfgd process identity/state changed while the filtered output was present"
[[ $(monitor_watcher_scope_count) == 0 ]] ||
  die "fallback monitor watcher appeared while the filtered output was present"
hyprmoncfg_preview_is_clear ||
  die "hyprmoncfgd gained a display preview while the filtered output was present"
capture_hyprmoncfg_status \
  "$evidence_dir/hyprmoncfg-status.filtered-headless-settled.json" filtered-headless-settled ||
  die "could not capture hyprmoncfg status after the filtered-output settle window"
cmp -s -- "$monitor_status_before" \
  "$evidence_dir/hyprmoncfg-status.filtered-headless-settled.json" ||
  die "hyprmoncfg did not ignore the audited nonce-bearing filtered connector"
monitor_manager_fingerprint >"$evidence_dir/hyprmoncfgd-unit.filtered-headless-settled.txt"
cmp -s -- "$monitor_manager_fingerprint_before" \
  "$evidence_dir/hyprmoncfgd-unit.filtered-headless-settled.txt" ||
  die "hyprmoncfgd unit definition changed during the filtered-output settle window"
file_envelope_matches "$monitor_manager_config_file" "$monitor_manager_config_hash_before" \
  "$monitor_manager_config_stat_before" "$monitor_manager_config_acl_before" \
  "$monitor_manager_config_xattr_before" hyprmoncfg-monitors.lua.filtered-headless-settled ||
  die "hyprmoncfg monitor profile changed while the filtered output was present"
file_envelope_matches "$hyprland_lua_file" "$hyprland_lua_hash_before" \
  "$hyprland_lua_stat_before" "$hyprland_lua_acl_before" "$hyprland_lua_xattr_before" \
  hyprland.lua.filtered-headless-settled ||
  die "root Hyprland Lua config changed while the filtered output was present"
tree_digest_noatime \
  "$monitor_profiles_root" "$evidence_dir/hyprmoncfg-profiles.filtered-headless-settled.sha256" ||
  die "could not inspect hyprmoncfg profiles after the filtered-output settle window"
cmp -s -- "$monitor_profiles_digest_before" \
  "$evidence_dir/hyprmoncfg-profiles.filtered-headless-settled.sha256" ||
  die "hyprmoncfg profile tree changed while the filtered output was present"
hyprland_config_errors_match ||
  die "Hyprland config errors changed while the filtered output was present"
wait_for_geometry 2 "$evidence_dir/geometry.two-monitors.json" ||
  die "plugin widget was not drawn on both monitors"
assert_headless_workspace_state "$evidence_dir/workspaces.headless.json" \
  "$evidence_dir/clients.headless.json" ||
  die "headless output changed an existing workspace/client or lacked one owned empty workspace"

mapfile -t monitor_names < <(jq -r 'sort_by(.name) | .[].name' "$monitors_configured")
(( ${#monitor_names[@]} == 2 )) || die "expected exactly two monitor names"

note "exercising all four bar edges on both monitors"
for edge in top bottom left right; do
  session_is_safe_for_live_mutation ||
    die "session lock state was not stably clear during bar-edge proof"
  run_shell_config_mutation omarchy bar position "$edge" >"$evidence_dir/bar-position-$edge.log"
  wait_for_bar_position "$edge" || die "bar did not report edge $edge"
  wait_for_geometry 2 "$evidence_dir/geometry.$edge.json" ||
    die "widget geometry failed at edge $edge"
  hyprctl_bounded monitors all -j | jq -e --arg name "$headless_name" '
    any(.[]; .name == "eDP-1" and .scale == 1.25)
    and any(.[]; .name == $name and .scale == 1.5)
  ' >/dev/null || die "monitor scales drifted at edge $edge"

  closed_layers="$evidence_dir/layers.$edge.closed.json"
  wait_for_all_panels_closed 2 "$closed_layers" \
    "$evidence_dir/panel-geometry.$edge.closed.json" ||
    die "panel/dismiss UI was not fully closed before the $edge proof"
  for monitor in "${monitor_names[@]}"; do
    session_is_safe_for_live_mutation ||
      die "session lock state was not stably clear during per-monitor proof"
    other_monitor=${monitor_names[0]}
    [[ $other_monitor == "$monitor" ]] && other_monitor=${monitor_names[1]}
    focus_monitor "$monitor" || die "could not focus $monitor"
    move_cursor_to_monitor_center "$monitor"
    open_before=$(mock_event_count action open_panel)
    [[ $(bounded_shell_ipc shell summon "$plugin_id" '{}') == ok ]] ||
      die "could not summon $plugin_id on $monitor at $edge"
    wait_for_mock_count action open_panel "$((open_before + 1))" ||
      die "backend did not observe panel ownership on $monitor at $edge"
    opened_layers="$evidence_dir/layers.$edge.$monitor.open.json"
    wait_for_panel_layers "$monitor" "$other_monitor" "$opened_layers" ||
      die "panel/dismiss layers did not map exclusively to $monitor at $edge"
    wait_for_panel_geometry "$monitor" "$edge" \
      "$evidence_dir/panel-geometry.$edge.$monitor.json" ||
      die "panel card did not anchor to its widget on $monitor at $edge"
    assert_bar_layer_edge "$opened_layers" "$monitor" "$edge" ||
      die "bar layer did not anchor to $edge on $monitor"
    close_before=$(mock_event_count action close_panel)
    bounded_shell_ipc shell hide "$plugin_id" >/dev/null
    wait_for_mock_count action close_panel "$((close_before + 1))" ||
      die "backend did not observe panel close on $monitor at $edge"
    wait_for_all_panels_closed 2 \
      "$evidence_dir/layers.$edge.$monitor.after-hide.json" \
      "$evidence_dir/panel-geometry.$edge.$monitor.after-hide.json" ||
      die "panel/dismiss UI remained visible after hiding on $monitor at $edge"
  done
done

note "proving popout ownership transfers to another bar panel"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before popout-ownership proof"
focus_monitor "$headless_name" || die "could not focus the test output for ownership proof"
move_cursor_to_monitor_center "$headless_name"
open_before=$(mock_event_count action open_panel)
[[ $(bounded_shell_ipc shell summon "$plugin_id" '{}') == ok ]] || die "could not summon ownership source panel"
wait_for_mock_count action open_panel "$((open_before + 1))" || die "ownership source did not open"
close_before=$(mock_event_count action close_panel)
[[ $(bounded_shell_ipc shell summon "$other_panel_id" '{}') == ok ]] || die "could not summon $other_panel_id"
wait_for_mock_count action close_panel "$((close_before + 1))" ||
  die "opening $other_panel_id did not release Omarchy AI Bar ownership"
wait_for_panel_layers "$headless_name" eDP-1 \
  "$evidence_dir/layers.ownership-transferred.json" ||
  die "$other_panel_id did not take exclusive panel ownership on the test output"
wait_for_foreign_panel_ownership "$headless_name" \
  "$evidence_dir/panel-geometry.ownership-transferred.json" ||
  die "$other_panel_id did not become the exact foreign popout owner"
bounded_shell_ipc shell hide "$other_panel_id" >/dev/null
wait_for_all_panels_closed 2 \
  "$evidence_dir/layers.ownership-transfer.after-hide.json" \
  "$evidence_dir/panel-geometry.ownership-transfer.after-hide.json" ||
  die "$other_panel_id UI remained visible after the ownership proof"

note "restoring the isolated baseline bar edge before lifecycle recovery"
session_is_safe_for_live_mutation ||
  die "session lock state changed before isolated bar-edge restoration"
run_shell_config_mutation omarchy bar position "$bar_position_before" \
  >"$evidence_dir/bar-position-restore.log"
wait_for_bar_position "$bar_position_before" || die "isolated baseline bar edge did not return"
wait_for_geometry 2 "$evidence_dir/geometry.restored-edge.json" ||
  die "widget geometry did not settle at the isolated baseline edge"

note "proving bridge-process reconnect"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before bridge reconnect proof"
old_bridge_pid=$(wait_for_one_bridge) || die "bridge disappeared before reconnect proof"
hello_before=$(mock_event_count hello)
snapshot_ack_before=$(mock_event_count snapshot_ack)
is_exact_bridge_pid "$old_bridge_pid" || die "bridge identity changed before restart request"
[[ $(bounded_shell_ipc omarchy-ai-bar restartBridge) == ok ]] ||
  die "QML service refused the bridge restart request"
new_bridge_pid=$(wait_for_one_bridge "$old_bridge_pid") || die "bridge did not reconnect after termination"
wait_for_mock_count hello "" "$((hello_before + 1))" || die "mock backend did not observe bridge reconnect"
wait_for_mock_count snapshot_ack "" "$((snapshot_ack_before + 1))" ||
  die "reconnected bridge snapshot was not accepted by QML"
printf '%s\n%s\n' "$old_bridge_pid" "$new_bridge_pid" >"$evidence_dir/bridge.reconnect.pids"
wait_for_geometry 2 "$evidence_dir/geometry.after-bridge-reconnect.json" ||
  die "geometry did not survive bridge reconnect"

note "restarting the isolated Omarchy shell and proving recovery"
session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before isolated-shell restart"
shell_pid_before_restart=$(shell_pid)
hello_before=$(mock_event_count hello)
snapshot_ack_before=$(mock_event_count snapshot_ack)
transient_unit_is_owned || die "transient service identity changed before restart"
transient_invocation=""
transient_submission_pending=1
transient_submission_absence_proven=0
timeout --kill-after=1s 10s systemctl --user restart "$transient_unit"
wait_for_shell || die "isolated shell did not recover from restart"
transient_unit_is_owned || die "restarted transient service definition changed"
transient_invocation=$(systemctl_user_query show -p InvocationID --value "$transient_unit")
[[ $transient_invocation =~ ^[0-9a-f]{32}$ ]] || die "restarted transient invocation is invalid"
transient_unit_is_owned || die "restarted transient invocation changed unexpectedly"
transient_submission_pending=0
shell_pid_after_restart=$(shell_pid)
[[ $shell_pid_after_restart != "$shell_pid_before_restart" ]] || die "shell PID did not change on restart"
process_has_override "$shell_pid_after_restart" || die "restarted shell lost its executable override"
process_has_frontend_environment "$shell_pid_after_restart" "$isolated_home" "$isolated_config_home" \
  "$isolated_cache_home" "$isolated_data_home" "$isolated_state_home" ||
  die "restarted shell lost its isolated HOME/XDG environment"
process_has_session_transport_environment "$shell_pid_after_restart" ||
  die "restarted shell lost the canonical Omarchy session transport"
process_has_agent_isolation "$shell_pid_after_restart" ||
  die "restarted shell lost agent credential/configuration isolation"
quickshell_instance_is_exact "$shell_pid_after_restart" ||
  die "restarted transient shell is not the only packaged-shell instance"
shell_namespace_is_valid "$shell_pid_after_restart" ||
  die "restarted shell lost its exact private mount/network namespace"
wait_for_session_safe_for_live_mutation ||
  die "restarted transient shell lock service did not settle stably clear"
wait_for_effective_shell_config "$shell_canonical_hash_expected" ||
  die "restarted shell did not reload the exact isolated shell.json"
OMARCHY_SHELL_IPC_TIMEOUT=0.5s timeout --kill-after=0.1s 1s \
  omarchy-shell shell rescanPlugins >/dev/null || die "restarted isolated plugin rescan failed"
plugin_list_restarted="$evidence_dir/plugin-list.after-shell-restart.json"
for (( attempt = 0; attempt < 50; attempt++ )); do
  if OMARCHY_SHELL_IPC_TIMEOUT=0.2s timeout --kill-after=0.1s 0.5s \
    omarchy-shell shell listPlugins 2>/dev/null | jq -S 'sort_by(.id)' \
      >"$plugin_list_restarted" &&
    [[ $(sha256_file "$plugin_list_restarted") == "$plugin_list_enabled_hash" ]]; then
    break
  fi
  sleep 0.1
done
[[ -s $plugin_list_restarted &&
  $(sha256_file "$plugin_list_restarted") == "$plugin_list_enabled_hash" ]] ||
  die "restarted isolated plugin registry did not recover exactly"
wait_for_shell_continuity "$shell_pid_after_restart" "$isolated_home" \
  "$isolated_config_home" "$isolated_cache_home" "$isolated_data_home" \
  "$isolated_state_home" "$state_bridge/indicators/stay-awake" ||
  die "notification, clipboard, or stay-awake continuity failed after shell restart"
restart_bridge_pid=$(wait_for_one_bridge "$new_bridge_pid") || die "restarted shell did not launch a new bridge"
wait_for_mock_count hello "" "$((hello_before + 1))" || die "backend did not observe post-restart hello"
wait_for_mock_count snapshot_ack "" "$((snapshot_ack_before + 1))" ||
  die "post-restart bridge snapshot was not accepted by QML"
wait_for_geometry 2 "$evidence_dir/geometry.after-shell-restart.json" ||
  die "plugin geometry did not recover after shell restart"
printf '%s\n%s\n' "$shell_pid_before_restart" "$shell_pid_after_restart" \
  >"$evidence_dir/shell.restart.pids"
printf '%s\n' "$restart_bridge_pid" >"$evidence_dir/bridge.after-shell-restart.pid"
systemctl_user_query show "$transient_unit" \
  -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p ControlGroup \
  -p Environment -p InvocationID -p Job -p ExecStart -p Transient -p FragmentPath \
  >"$evidence_dir/transient-unit.after-restart.txt"

session_is_safe_for_live_mutation ||
  die "session lock state was not stably clear before post-restart panel proof"
focus_monitor "$headless_name" || die "could not focus the test output after shell restart"
move_cursor_to_monitor_center "$headless_name"
open_before=$(mock_event_count action open_panel)
[[ $(bounded_shell_ipc shell summon "$plugin_id" '{}') == ok ]] || die "post-restart summon failed"
wait_for_mock_count action open_panel "$((open_before + 1))" || die "post-restart open action was not observed"
wait_for_panel_layers "$headless_name" eDP-1 "$evidence_dir/layers.after-shell-restart.json" ||
  die "post-restart panel/dismiss layers did not map to the test output"
close_before=$(mock_event_count action close_panel)
bounded_shell_ipc shell hide "$plugin_id" >/dev/null
wait_for_mock_count action close_panel "$((close_before + 1))" ||
  die "post-restart close action was not observed"
wait_for_all_panels_closed 2 "$evidence_dir/layers.after-shell-restart-hide.json" \
  "$evidence_dir/panel-geometry.after-shell-restart-hide.json" ||
  die "post-restart panel/dismiss UI remained visible after hide"

plugin_tree_matches_frozen_manifest \
  "$plugin_source" "$evidence_dir/plugin-source.after.manifest" ||
  die "development plugin source changed during the live test"
plugin_tree_matches_frozen_manifest \
  "$plugin_target" "$evidence_dir/plugin-target.after-body.manifest" ||
  die "private plugin copy changed during the live test"
cmp -s -- "$plugin_source_manifest" "$evidence_dir/plugin-source.after.manifest" &&
  cmp -s -- "$plugin_source_manifest" "$evidence_dir/plugin-target.after-body.manifest" ||
  die "source and private plugin manifests diverged after the live proof"
run_isolated timeout --kill-after=0.1s 1s omarchy plugin list --json | jq -S 'sort_by(.id)' \
  >"$evidence_dir/plugin-list.during.json"
verify_real_user_state isolated-shell-active ||
  die "isolated shell touched the real shell/plugin state"

note "all live assertions passed; cleanup will now restore the session"
