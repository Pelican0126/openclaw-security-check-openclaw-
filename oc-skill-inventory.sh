#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Global paths / 全局路径
# QUAR_DIR stores quarantined skills instead of immediate deletion
# QUAR_DIR 用于隔离可疑 skill，避免直接删除
OC_HOME="${OC_HOME:-$HOME/.openclaw}"
REPORT_ROOT="${REPORT_ROOT:-$OC_HOME/security-reports}"
QUAR_DIR="${QUAR_DIR:-$OC_HOME/skills.quarantine}"
mkdir -p "$REPORT_ROOT" 2>/dev/null || true
chmod 700 "$REPORT_ROOT" 2>/dev/null || true

# -------------------------------------------------------------------
# Helpers / 工具函数
# Timestamp helper for report and backup naming
# 时间戳函数，用于报告目录与备份文件命名
TS() { date +%F_%H%M%S; }

# Check command availability
# 检查命令是否存在
need() { command -v "$1" >/dev/null 2>&1; }

# Horizontal separator in terminal output
# 终端分隔线
hr() { echo "------------------------------------------------------------"; }

# -------------------------------------------------------------------
# Redaction / 脱敏
# Redact common secret forms in output reports
# 对常见密钥形态做脱敏，降低报告外泄风险
mask() {
  sed -E \
    -e 's/(sk-|AIzaSy|xox[baprs]-)[A-Za-z0-9._-]+/\1***REDACTED***/g' \
    -e 's/(Authorization:)[^\r\n]*/\1 ***REDACTED***/Ig' \
    -e 's/(Bearer )[A-Za-z0-9._-]+/\1***REDACTED***/Ig'
}

# -------------------------------------------------------------------
# Skills directory discovery / skills 目录探测
# Priority:
# 1) explicit SKILLS_DIR
# 2) $OC_HOME/workspace/skills
# 3) $OC_HOME/skills
# 4) find fallback
#
# 优先级：
# 1) 显式 SKILLS_DIR
# 2) $OC_HOME/workspace/skills
# 3) $OC_HOME/skills
# 4) find 兜底
detect_skills_dir() {
  if [[ -n "${SKILLS_DIR:-}" && -d "${SKILLS_DIR:-}" ]]; then echo "$SKILLS_DIR"; return 0; fi
  if [[ -d "$OC_HOME/workspace/skills" ]]; then echo "$OC_HOME/workspace/skills"; return 0; fi
  if [[ -d "$OC_HOME/skills" ]]; then echo "$OC_HOME/skills"; return 0; fi
  local d=""
  d="$(find "$OC_HOME" -maxdepth 6 -type d -name skills 2>/dev/null | head -n 1 || true)"
  if [[ -n "$d" ]]; then
    echo "$d"
  else
    echo ""
  fi
}

# -------------------------------------------------------------------
# Scan wrappers / 扫描封装
# Text scan includes docs (README/package scripts)
# 文本扫描包含文档（如 README / package 脚本）
scan_text() {
  local pattern="$1" path="$2"
  if need rg; then
    rg -n --hidden -S "$pattern" "$path" 2>/dev/null || true
  else
    grep -RInE "$pattern" "$path" 2>/dev/null || true
  fi
}

# Code scan excludes docs to reduce noise
# 代码扫描排除文档，减少噪音
scan_code() {
  local pattern="$1" path="$2"
  if need rg; then
    rg -n --hidden -S "$pattern" "$path" -g'!*.md' -g'!*.mdx' -g'!*.txt' -g'!*.rst' 2>/dev/null || true
  else
    grep -RInE --exclude='*.md' --exclude='*.mdx' --exclude='*.txt' --exclude='*.rst' "$pattern" "$path" 2>/dev/null || true
  fi
}

# -------------------------------------------------------------------
# Risk helpers / 风险辅助
# Priority order: HIGH > MED > LOW
# 优先级：HIGH > MED > LOW
risk_level() {
  local h1="$1" h2="$2" h3="$3" m1="$4" m2="$5" r="LOW"
  (( m1 > 0 || m2 > 0 )) && r="MED"
  (( h1 > 0 || h2 > 0 || h3 > 0 )) && r="HIGH"
  echo "$r"
}

# Pick first hit line from a section as reason
# 从指定 section 取首条命中作为 reason
first_hit() {
  local report="$1" section="$2"
  awk -v s="[$section]" '$0==s{on=1;next} /^\[/{on=0} on&&/^[^[]+:[0-9]+:/{print; exit}' "$report" 2>/dev/null || true
}

# -------------------------------------------------------------------
# Core scanner / 核心扫描
# Output:
# - writes detailed report to file
# - returns "risk|reason" on stdout
#
# 输出：
# - 报告写入文件
# - stdout 返回 "risk|reason"
scan_skill_dir() {
  local dir="$1" report="$2"

  # High-risk execution/obfuscation patterns
  # 高危执行/混淆模式
  local P_HIGH_EXEC='(bash -c|sh -c|subprocess|os\.system|eval\(|exec\(|python -c|perl -e|powershell -enc|base64[[:space:]]*-d|xxd[[:space:]]*-r|openssl[[:space:]]+enc)'
  # High-risk persistence/system modification patterns
  # 高危持久化/系统改动模式
  local P_HIGH_PERSIST='(crontab|systemctl|service[[:space:]]+|init\.d|rc\.local|authorized_keys|\.bashrc|\.profile|launchctl|schtasks|reg[[:space:]]+add)'
  # High-risk sensitive path references
  # 高危敏感路径引用
  local P_HIGH_SENSITIVE='(\.ssh|id_rsa|id_ed25519|known_hosts|auth-profiles\.json|\.env|/etc/shadow|/root/\.ssh)'
  # Medium-risk install-chain patterns
  # 中危安装链模式
  local P_MED_INSTALL='("postinstall"|"preinstall"|"install"[[:space:]]*:)|pip[[:space:]]+install|npm[[:space:]]+install|pnpm[[:space:]]+install|yarn[[:space:]]+add|go[[:space:]]+get'
  # Medium-risk long base64 blobs
  # 中危超长 base64 片段
  local P_MED_OBF='[A-Za-z0-9+/]{200,}={0,2}'

  {
    echo "# Skill Inventory Audit (静态+脱敏 / static+redacted)"
    echo "Time: $(date -Is)"
    echo "Dir : $dir"

    echo "[HIGH_EXEC_OR_OBFUSCATION]"
    scan_code "$P_HIGH_EXEC" "$dir" | sed -n '1,220p'

    echo "[HIGH_PERSISTENCE_OR_PRIVESC]"
    scan_code "$P_HIGH_PERSIST" "$dir" | sed -n '1,220p'

    echo "[HIGH_SENSITIVE_PATHS]"
    scan_code "$P_HIGH_SENSITIVE" "$dir" | sed -n '1,220p'

    echo "[MED_INSTALL_HOOKS]"
    scan_text "$P_MED_INSTALL" "$dir" | sed -n '1,220p'

    echo "[MED_LONG_BASE64_BLOCKS]"
    scan_code "$P_MED_OBF" "$dir" | sed -n '1,220p'
  } | mask >"$report"

  # Count hits by section / 按 section 统计命中数
  local h1 h2 h3 m1 m2
  h1="$(awk '/^\[HIGH_EXEC_OR_OBFUSCATION\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  h2="$(awk '/^\[HIGH_PERSISTENCE_OR_PRIVESC\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  h3="$(awk '/^\[HIGH_SENSITIVE_PATHS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  m1="$(awk '/^\[MED_INSTALL_HOOKS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  m2="$(awk '/^\[MED_LONG_BASE64_BLOCKS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"

  local risk reason
  risk="$(risk_level "$h1" "$h2" "$h3" "$m1" "$m2")"

  # Reason priority: high sections first, then medium
  # reason 优先级：先高危段，再中危段
  reason="$(first_hit "$report" "HIGH_EXEC_OR_OBFUSCATION")"
  if [[ -z "$reason" ]]; then reason="$(first_hit "$report" "HIGH_PERSISTENCE_OR_PRIVESC")"; fi
  if [[ -z "$reason" ]]; then reason="$(first_hit "$report" "HIGH_SENSITIVE_PATHS")"; fi
  if [[ -z "$reason" ]]; then reason="$(first_hit "$report" "MED_INSTALL_HOOKS")"; fi
  if [[ -z "$reason" ]]; then reason="$(first_hit "$report" "MED_LONG_BASE64_BLOCKS")"; fi
  reason="${reason:-NONE}"

  {
    echo "[SUMMARY]"
    echo "RISK_LEVEL: $risk"
    echo "REASON: $reason"
  } >>"$report"

  echo "$risk|$reason"
}

# View helper / 查看辅助
less_or_tail() {
  local file="$1"
  if need less; then
    less "$file"
  else
    tail -n 200 "$file"
  fi
}

# -------------------------------------------------------------------
# Main flow / 主流程
main() {
  hr
  echo "Skill Inventory Audit (已安装 Skill 审计)"

  # Resolve skills directory / 解析 skills 目录
  local skills=""
  skills="$(detect_skills_dir)"
  [[ -n "$skills" && -d "$skills" ]] || { echo "未找到 skills 目录 / skills directory not found"; exit 1; }
  export SKILLS_DIR="$skills"
  echo "SKILLS_DIR=$SKILLS_DIR"

  local report_dir="$REPORT_ROOT/inventory_$(TS)"
  mkdir -p "$report_dir"
  chmod 700 "$report_dir" 2>/dev/null || true

  # TSV summary table for downstream processing
  # TSV 汇总表，便于后续 grep/awk 处理
  local summary="$report_dir/summary.tsv"
  echo -e "RISK\tskill\treport\treason" >"$summary"

  echo "1) 审计全部 / Audit all skills"
  echo "2) 审计单个 / Audit one skill"
  read -r -p "选择 / Choose 1/2 (默认 default 1): " mode || true
  mode="${mode:-1}"

  audit_one() {
    # Audit one directory and append summary row
    # 审计单个目录并追加一行汇总
    local dir="$1" name report out risk reason
    name="$(basename "$dir")"
    report="$report_dir/${name}.txt"
    out="$(scan_skill_dir "$dir" "$report")"
    risk="${out%%|*}"
    reason="${out#*|}"
    printf "%s\t%s\t%s\t%s\n" "$risk" "$name" "$report" "$reason" >>"$summary"
    if [[ "$risk" != "LOW" ]]; then
      echo "[$risk] $name -> $reason"
    fi
  }

  if [[ "$mode" == "2" ]]; then
    # Single skill mode / 单个 skill 模式
    ls -1 "$SKILLS_DIR" 2>/dev/null | sed -n '1,200p'
    read -r -p "输入 skill 名称 / Enter skill name: " sname || true
    [[ -n "${sname:-}" ]] || exit 0
    [[ -d "$SKILLS_DIR/$sname" ]] || { echo "不存在 / Not found: $sname"; exit 1; }
    audit_one "$SKILLS_DIR/$sname"
  else
    # Full scan mode / 全量模式
    while IFS= read -r dir; do audit_one "$dir"; done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
  fi

  # Sort summary by risk priority: HIGH -> MED -> LOW
  # 汇总按风险排序：HIGH -> MED -> LOW
  local sorted="$report_dir/summary_sorted.tsv"
  {
    head -n 1 "$summary"
    tail -n +2 "$summary" | awk 'BEGIN{FS=OFS="\t"}{r=$1; if(r=="HIGH")k=1; else if(r=="MED")k=2; else k=3; print k,$0}' | sort -k1,1n -k3,3 | cut -f2-
  } >"$sorted"

  echo "完成 / Done: $sorted"

  while true; do
    # Use explicit ifs under set -e for stable control flow
    # 在 set -e 下使用显式 if，保证流程稳定
    echo "选择 / Choose: [V]查看摘要 View [Q]隔离 Quarantine [D]删除(先备份) Delete(backup first) [R]退出 Exit(默认/default)"
    read -r -p "输入 / Input V/Q/D/R: " action || true
    action="$(echo "${action:-R}" | tr '[:lower:]' '[:upper:]')"

    if [[ "$action" == "V" ]]; then
      less_or_tail "$sorted"
      continue
    fi
    if [[ "$action" == "R" ]]; then
      exit 0
    fi

    if [[ "$action" == "Q" ]]; then
      # Quarantine keeps evidence for later review
      # 隔离保留现场，便于后续复核
      read -r -p "输入要隔离的 skill 名称 / Skill to quarantine: " sname || true
      [[ -n "${sname:-}" ]] || continue
      [[ -d "$SKILLS_DIR/$sname" ]] || { echo "不存在 / Not found: $sname"; continue; }
      mkdir -p "$QUAR_DIR"
      local dest="$QUAR_DIR/${sname}_$(TS)"
      mv "$SKILLS_DIR/$sname" "$dest"
      chmod -R go-rwx "$dest" 2>/dev/null || true
      echo "已隔离 / Quarantined: $dest"
      continue
    fi

    if [[ "$action" == "D" ]]; then
      # Backup before delete to reduce irreversible mistakes
      # 删除前备份，降低误删不可恢复风险
      read -r -p "输入要删除的 skill 名称 / Skill to delete: " sname || true
      [[ -n "${sname:-}" ]] || continue
      [[ -d "$SKILLS_DIR/$sname" ]] || { echo "不存在 / Not found: $sname"; continue; }
      local bk="$report_dir/backup_${sname}_$(TS).tar.gz"
      tar -czf "$bk" -C "$SKILLS_DIR" "$sname" 2>/dev/null || true
      echo "已备份 / Backup: $bk"
      read -r -p "确认删除 / Confirm delete $sname ? (y/N) " yn || true
      [[ "${yn:-N}" =~ ^[Yy]$ ]] || { echo "已取消 / Cancelled"; continue; }
      rm -rf "$SKILLS_DIR/$sname"
      echo "已删除 / Deleted: $sname"
      continue
    fi

    echo "无效选项 / Invalid option"
  done
}

main "$@"

