#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Global paths / 全局路径
# Keep default behavior: skills installed under workspace/skills by default
# 保持原始行为：默认安装目录为 workspace/skills
OC_HOME="${OC_HOME:-$HOME/.openclaw}"
SKILLS_DIR="${SKILLS_DIR:-$OC_HOME/workspace/skills}"
REPORT_ROOT="${REPORT_ROOT:-$OC_HOME/security-reports}"
mkdir -p "$REPORT_ROOT" 2>/dev/null || true
chmod 700 "$REPORT_ROOT" 2>/dev/null || true

# -------------------------------------------------------------------
# Small helpers / 小工具函数
# Timestamp helper used by report/temp directory names
# 时间戳，用于报告目录与临时目录命名
TS() { date +%F_%H%M%S; }

# Check command existence
# 检查命令是否存在
need() { command -v "$1" >/dev/null 2>&1; }

# Horizontal rule for terminal readability
# 分隔线，提升终端可读性
hr() { echo "------------------------------------------------------------"; }

# -------------------------------------------------------------------
# Output redaction / 输出脱敏
# Hide common secret shapes in generated report for safer sharing
# 脱敏常见密钥形态，降低报告外泄风险
mask() {
  sed -E \
    -e 's/(sk-|AIzaSy|xox[baprs]-)[A-Za-z0-9._-]+/\1***REDACTED***/g' \
    -e 's/(Authorization:)[^\r\n]*/\1 ***REDACTED***/Ig' \
    -e 's/(Bearer )[A-Za-z0-9._-]+/\1***REDACTED***/Ig'
}

# -------------------------------------------------------------------
# Scan wrappers / 扫描封装
# Text scan includes docs; useful for install scripts/README/package files
# 文本扫描包含文档，适合发现 README/package 等里的可疑内容
scan_text() {
  local pattern="$1" path="$2"
  if need rg; then
    rg -n --hidden -S "$pattern" "$path" 2>/dev/null || true
  else
    grep -RInE "$pattern" "$path" 2>/dev/null || true
  fi
}

# Code scan excludes docs to reduce false positives
# 代码扫描排除文档，减少误报
scan_code() {
  local pattern="$1" path="$2"
  if need rg; then
    rg -n --hidden -S "$pattern" "$path" -g'!*.md' -g'!*.mdx' -g'!*.txt' -g'!*.rst' 2>/dev/null || true
  else
    grep -RInE --exclude='*.md' --exclude='*.mdx' --exclude='*.txt' --exclude='*.rst' "$pattern" "$path" 2>/dev/null || true
  fi
}

# View helper: prefer pager; fallback tail
# 报告查看：优先 less，缺失时回退 tail
less_or_tail() {
  local file="$1"
  if need less; then
    less "$file"
  else
    tail -n 200 "$file"
  fi
}

# -------------------------------------------------------------------
# Skill metadata helpers / Skill 元数据辅助函数
# Pick one SKILL.md when repo has multiple candidates (monorepo scenario)
# 当仓库有多个 SKILL.md 时交互选择（兼容 monorepo）
pick_skill_md() {
  local root="$1"
  mapfile -t candidates < <(find "$root" -maxdepth 6 -type f -name "SKILL.md" 2>/dev/null | sort)
  [[ ${#candidates[@]} -gt 0 ]] || { echo ""; return 1; }
  if [[ ${#candidates[@]} -eq 1 ]]; then
    echo "${candidates[0]}"
    return 0
  fi

  echo "发现多个 SKILL.md / Multiple SKILL.md found:"
  local i=1
  for p in "${candidates[@]}"; do
    echo "  [$i] ${p#$root/}"
    ((i++))
  done

  local choose
  read -r -p "选择序号 / Select index (默认 default 1): " choose || true
  choose="$(printf '%s' "${choose:-1}" | tr -d '\r')"
  echo "${candidates[$((choose-1))]}"
}

# Parse name from frontmatter; fallback to directory name
# 从 frontmatter 解析 name，解析失败则回退目录名
parse_skill_name() {
  local skill_md="$1" fallback="$2" name
  name="$(awk 'BEGIN{in=0} /^---[[:space:]]*$/{in=!in;next} in&&$1=="name:"{print $2;exit}' "$skill_md" 2>/dev/null | tr -d '"' | tr -d "'")"
  echo "${name:-$fallback}"
}

# -------------------------------------------------------------------
# Risk scoring / 风险分级
# HIGH takes precedence over MED and LOW
# 分级优先级：HIGH > MED > LOW
risk_level() {
  local h1="$1" h2="$2" h3="$3" m1="$4" m2="$5" r="LOW"
  (( m1 > 0 || m2 > 0 )) && r="MED"
  (( h1 > 0 || h2 > 0 || h3 > 0 )) && r="HIGH"
  echo "$r"
}

# -------------------------------------------------------------------
# Core scanner / 核心扫描逻辑
# Generate a report and return risk level on stdout
# 生成报告并通过 stdout 返回风险等级
scan_skill_dir() {
  local dir="$1" report="$2"

  # High-risk: dynamic execution / decoding / obfuscation-like commands
  # 高危：动态执行、解码执行、可疑混淆执行链
  local P_HIGH_EXEC='(bash -c|sh -c|subprocess|os\.system|eval\(|exec\(|python -c|perl -e|powershell -enc|base64[[:space:]]*-d|xxd[[:space:]]*-r|openssl[[:space:]]+enc)'
  # High-risk: persistence and privileged/system-level modifications
  # 高危：持久化与系统级改动
  local P_HIGH_PERSIST='(crontab|systemctl|service[[:space:]]+|init\.d|rc\.local|authorized_keys|\.bashrc|\.profile|launchctl|schtasks|reg[[:space:]]+add)'
  # High-risk: sensitive path access references
  # 高危：敏感路径引用
  local P_HIGH_SENSITIVE='(\.ssh|id_rsa|id_ed25519|known_hosts|auth-profiles\.json|\.env|/etc/shadow|/root/\.ssh)'
  # Medium-risk: install hook/dependency chain execution
  # 中危：安装钩子与依赖链执行
  local P_MED_INSTALL='("postinstall"|"preinstall"|"install"[[:space:]]*:)|pip[[:space:]]+install|npm[[:space:]]+install|pnpm[[:space:]]+install|yarn[[:space:]]+add|go[[:space:]]+get'
  # Medium-risk: very long base64 blocks (possible obfuscation payload)
  # 中危：超长 base64 片段（可能是混淆载荷）
  local P_MED_OBF='[A-Za-z0-9+/]{200,}={0,2}'

  {
    echo "# Skill Pre-Install Audit (静态+脱敏 / static+redacted)"
    echo "Time: $(date -Is)"
    echo "Dir : $dir"

    echo "[STRUCTURE]"
    # Snapshot repo shape first for quick human triage
    # 先给目录结构快照，便于人工快速判断仓库形态
    find "$dir" -maxdepth 3 -print 2>/dev/null | sed -n '1,220p'

    echo "[SYMLINK]"
    find "$dir" -type l -print 2>/dev/null || true

    echo "[EXECUTABLE_FILES]"
    # Executable files are reviewed with higher priority
    # 可执行文件优先人工复核
    find "$dir" -type f -perm -111 -print 2>/dev/null || true

    echo "[HIGH_EXEC_OR_OBFUSCATION]"
    scan_code "$P_HIGH_EXEC" "$dir" | sed -n '1,260p'

    echo "[HIGH_PERSISTENCE_OR_PRIVESC]"
    scan_code "$P_HIGH_PERSIST" "$dir" | sed -n '1,260p'

    echo "[HIGH_SENSITIVE_PATHS]"
    scan_code "$P_HIGH_SENSITIVE" "$dir" | sed -n '1,260p'

    echo "[MED_INSTALL_HOOKS]"
    scan_text "$P_MED_INSTALL" "$dir" | sed -n '1,260p'

    echo "[MED_LONG_BASE64_BLOCKS]"
    scan_code "$P_MED_OBF" "$dir" | sed -n '1,260p'
  } | mask >"$report"

  # Count hits per section / 按 section 统计命中数
  local h1 h2 h3 m1 m2
  h1="$(awk '/^\[HIGH_EXEC_OR_OBFUSCATION\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  h2="$(awk '/^\[HIGH_PERSISTENCE_OR_PRIVESC\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  h3="$(awk '/^\[HIGH_SENSITIVE_PATHS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  m1="$(awk '/^\[MED_INSTALL_HOOKS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"
  m2="$(awk '/^\[MED_LONG_BASE64_BLOCKS\]/{f=1;next}/^\[/{f=0} f&&/^[^[]+:[0-9]+:/{c++} END{print c+0}' "$report")"

  local risk
  risk="$(risk_level "$h1" "$h2" "$h3" "$m1" "$m2")"

  {
    echo "[SUMMARY]"
    echo "RISK_LEVEL: $risk"
  } >>"$report"

  echo "$risk"
}

# -------------------------------------------------------------------
# Main flow / 主流程
main() {
  hr
  echo "Skill Gate (安装前安全闸口 / pre-install security gate)"

  # Input can be local directory or Git URL
  # 输入可以是本地目录或 Git URL
  local src=""
  read -r -p "输入 Git URL 或本地目录 / Enter Git URL or local path: " src || true
  src="$(printf '%s' "${src:-}" | tr -d '\r')"
  [[ -n "${src:-}" ]] || { echo "空输入，退出 / Empty input, exit."; exit 0; }

  local stage="/tmp/oc_skill_gate_$(TS)"
  local work="$stage/work"
  mkdir -p "$work"
  echo "临时目录 / Temp dir: $stage"

  local root=""
  if [[ -d "$src" ]]; then
    # Local source: copy to staging to avoid touching original files
    # 本地源：先复制到临时区，避免污染原目录
    cp -a "$src" "$work/src"
    root="$work/src"
  else
    # Remote source: shallow clone for speed and less disk usage
    # 远程源：浅克隆降低耗时与磁盘占用
    need git || { echo "[FAIL] 需要 git / git is required"; rm -rf "$stage"; exit 1; }
    git clone --depth 1 "$src" "$work/repo" >/dev/null 2>&1 || { echo "[FAIL] git clone 失败 / failed"; rm -rf "$stage"; exit 1; }
    root="$work/repo"
  fi

  local skill_md skill_dir name
  skill_md="$(pick_skill_md "$root" || true)"
  [[ -n "$skill_md" ]] || { echo "[FAIL] 未找到 SKILL.md / SKILL.md not found"; rm -rf "$stage"; exit 1; }
  skill_dir="$(dirname "$skill_md")"
  name="$(parse_skill_name "$skill_md" "$(basename "$skill_dir")")"

  local report_dir="$REPORT_ROOT/gate_$(TS)"
  local report="$report_dir/report.txt"
  mkdir -p "$report_dir"
  chmod 700 "$report_dir" 2>/dev/null || true

  echo "目标 Skill / Target: $name"
  echo "开始扫描 / Scanning..."
  local risk
  risk="$(scan_skill_dir "$skill_dir" "$report")"
  echo "风险等级 / Risk: $risk"
  echo "报告路径 / Report: $report"

  while true; do
    # Use explicit ifs under set -e to avoid accidental exits
    # 在 set -e 下使用显式 if，避免短路语法触发误退出
    echo "选择 / Choose: [V]查看报告 View [I]安装 Install [R]清理并退出 Remove temp & exit(默认/default)"
    read -r -p "输入 / Input V/I/R: " action || true
    action="$(printf '%s' "${action:-R}" | tr -d '\r' | tr '[:lower:]' '[:upper:]')"

    if [[ "$action" == "V" ]]; then
      less_or_tail "$report"
      continue
    fi
    if [[ "$action" == "R" ]]; then
      rm -rf "$stage"
      echo "已退出，未安装 / Exit without install."
      exit 0
    fi

    if [[ "$action" == "I" ]]; then
      mkdir -p "$SKILLS_DIR"
      local target="$SKILLS_DIR/$name"

      # Confirm overwrite if target exists
      # 目标已存在时要求确认覆盖
      if [[ -e "$target" ]]; then
        read -r -p "[WARN] 目标已存在，是否覆盖 / Target exists, overwrite? (y/N) " yn || true
        yn="$(printf '%s' "${yn:-N}" | tr -d '\r')"
        [[ "${yn:-N}" =~ ^[Yy]$ ]] || { echo "取消安装 / Install cancelled"; continue; }
        rm -rf "$target"
      fi

      # Extra confirmation for high-risk installs
      # 高风险时二次确认，降低误装概率
      if [[ "$risk" == "HIGH" ]]; then
        echo "[HIGH] 检测到高风险，不建议安装 / High risk detected, not recommended."
        read -r -p "仍要安装 / Install anyway? (y/N) " yn2 || true
        yn2="$(printf '%s' "${yn2:-N}" | tr -d '\r')"
        [[ "${yn2:-N}" =~ ^[Yy]$ ]] || { echo "取消安装 / Install cancelled"; continue; }
      fi

      cp -a "$skill_dir" "$target"
      # Tighten permissions after installation
      # 安装后收紧权限，减少被非当前用户读取/篡改风险
      chmod -R go-rwx "$target" 2>/dev/null || true
      rm -rf "$stage"
      echo "安装完成 / Installed: $target"
      exit 0
    fi

    echo "无效选项 / Invalid option"
  done
}

main "$@"
