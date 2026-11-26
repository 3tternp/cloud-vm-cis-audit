#!/bin/sh
# READ-ONLY Linux guest audit. Makes no changes to the system.
# Output protocol: one line per check ->  CIS|<id>|<PASS|FAIL|WARN|INFO>|<detail>
out() { printf 'CIS|%s|%s|%s\n' "$1" "$2" "$3"; }
have() { command -v "$1" >/dev/null 2>&1; }
active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

sshd_opt() {
  v=$(sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1)==k{print tolower($2); exit}')
  [ -z "$v" ] && v=$(grep -iE "^[[:space:]]*$1[[:space:]]" /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')
  echo "${v:-unknown}"
}

# --- SSH daemon hardening
if have sshd || [ -f /etc/ssh/sshd_config ]; then
  v=$(sshd_opt permitrootlogin)
  case "$v" in no|prohibit-password|without-password) out LIN-001 PASS "PermitRootLogin=$v";; unknown) out LIN-001 INFO "PermitRootLogin not determinable";; *) out LIN-001 FAIL "PermitRootLogin=$v";; esac
  v=$(sshd_opt passwordauthentication)
  case "$v" in no) out LIN-002 PASS "PasswordAuthentication=no";; unknown) out LIN-002 INFO "not determinable";; *) out LIN-002 WARN "PasswordAuthentication=$v (prefer keys)";; esac
  v=$(sshd_opt permitemptypasswords)
  case "$v" in no|unknown) out LIN-003 PASS "PermitEmptyPasswords=${v}";; *) out LIN-003 FAIL "PermitEmptyPasswords=$v";; esac
  v=$(sshd_opt x11forwarding)
  case "$v" in no|unknown) out LIN-004 PASS "X11Forwarding=${v}";; *) out LIN-004 WARN "X11Forwarding=$v";; esac
else
  out LIN-001 INFO "sshd not installed"
fi

# --- Accounts
d=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
[ -z "$d" ] && out LIN-010 PASS "no accounts with empty password" || out LIN-010 FAIL "empty password: $d"
d=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
[ -z "$d" ] && out LIN-011 PASS "only root has UID 0" || out LIN-011 FAIL "extra UID 0 accounts: $d"
m=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null | tail -1)
if [ -z "$m" ]; then out LIN-012 INFO "PASS_MAX_DAYS not set"
elif [ "$m" -le 365 ] 2>/dev/null; then out LIN-012 PASS "PASS_MAX_DAYS=$m"; else out LIN-012 WARN "PASS_MAX_DAYS=$m (>365)"; fi

# --- Host protection
fw=none
if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then fw=ufw
elif active firewalld; then fw=firewalld
elif have nft && [ "$(nft list ruleset 2>/dev/null | grep -c 'chain')" -gt 0 ]; then fw=nftables
elif have iptables && [ "$(iptables -S 2>/dev/null | grep -vc '^-P')" -gt 0 ]; then fw=iptables; fi
[ "$fw" = none ] && out LIN-020 WARN "no host firewall rules detected (cloud security groups may still apply)" || out LIN-020 PASS "host firewall: $fw"
if active auditd; then out LIN-021 PASS "auditd active"; else out LIN-021 WARN "auditd not active"; fi
if active chronyd || active chrony || active ntpd || active ntp || active systemd-timesyncd; then out LIN-022 PASS "time sync service active"; else out LIN-022 WARN "no time sync service active"; fi
v=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
[ "$v" = "2" ] && out LIN-023 PASS "ASLR=2" || out LIN-023 FAIL "kernel.randomize_va_space=${v:-unknown}"
if have getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then out LIN-024 PASS "SELinux enforcing"
elif have aa-status && aa-status --enabled 2>/dev/null; then out LIN-024 PASS "AppArmor enabled"
else out LIN-024 WARN "no mandatory access control (SELinux/AppArmor) enforcing"; fi
v=$(sysctl -n fs.suid_dumpable 2>/dev/null)
[ "$v" = "0" ] && out LIN-025 PASS "suid core dumps restricted" || out LIN-025 WARN "fs.suid_dumpable=${v:-unknown}"
if have ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ':23$'; then out LIN-026 FAIL "telnet port 23 listening"; else out LIN-026 PASS "no telnet listener"; fi

# --- Patching
if [ -f /var/run/reboot-required ]; then out LIN-030 WARN "reboot required to finish updates"; else out LIN-030 PASS "no pending reboot flag"; fi
if have apt-get; then
  n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst .*[Ss]ecurity')
  [ "${n:-0}" -eq 0 ] && out LIN-031 PASS "0 pending security updates (from local apt cache)" || out LIN-031 FAIL "$n pending security updates"
  if dpkg -s unattended-upgrades >/dev/null 2>&1; then out LIN-032 PASS "unattended-upgrades installed"; else out LIN-032 WARN "unattended-upgrades not installed"; fi
elif have dnf || have yum; then
  pm=$(have dnf && echo dnf || echo yum)
  n=$($pm -q updateinfo list security 2>/dev/null | grep -c '/\|RHSA\|ALAS\|ELSA')
  [ "${n:-0}" -eq 0 ] && out LIN-031 PASS "0 pending security advisories" || out LIN-031 FAIL "$n pending security advisories"
  if rpm -q dnf-automatic >/dev/null 2>&1 || rpm -q yum-cron >/dev/null 2>&1; then out LIN-032 PASS "automatic updates package installed"; else out LIN-032 WARN "no dnf-automatic/yum-cron"; fi
else
  out LIN-031 INFO "no supported package manager found"
fi
exit 0
