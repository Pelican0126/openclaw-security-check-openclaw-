#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Global paths / 全局路径
OC_HOME="${OC_HOME:-$HOME/.openclaw}"
REPORT_ROOT="${REPORT_ROOT:-$OC_HOME/security-reports}"
mkdir -p "$REPORT_ROOT" 2>/dev/null || true
chmod 700 "$REPORT_ROOT" 2>/dev/null || true

# -------------------------------------------------------------------
# Helpers / 工具函数
TS() { date +%F_%H%M%S; }                                    # timestamp / 时间戳
need() { command -v "$1" >/dev/null 2>&1; }                 # dependency check / 依赖检查
hr() { echo "------------------------------------------------------------"; }  # separator / 分隔线
to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }               # lowercase helper / 小写转换

# -------------------------------------------------------------------
# Noise filters / 噪音过滤
# Path filter: skip reports and sample/test/mock paths
# 路径过滤：跳过报告目录和样例/测试/mock 路径
should_ignore_path() {
  local path_l root_l report_l report_base_l
  path_l="$(to_lower "$1")"
  root_l="$(to_lower "$OC_HOME")"
  root_l="${root_l%/}"
  report_l="$(to_lower "$REPORT_ROOT")"
  report_l="${report_l%/}"
  report_base_l="${report_l##*/}"

  # Convert to OC_HOME-relative path when possible
  # 优先转换成 OC_HOME 相对路径再判断
  if [[ "$path_l" == "$root_l"/* ]]; then
    path_l="${path_l#"$root_l"/}"
  fi

  # Ignore configured report root (absolute or relative forms)
  # 忽略配置的报告目录（绝对/相对形态都兼容）
  [[ "$path_l" == "$report_l"/* || "$path_l" == "$report_l" ]] && return 0
  [[ -n "$report_base_l" && "$path_l" == "$report_base_l"/* ]] && return 0

  # Ignore common generated report directories and report files
  # 忽略常见生成报告目录与报告文件，避免自扫描
  [[ "$path_l" == security-reports/* ]] && return 0
  [[ "$path_l" == reports/* || "$path_l" == report/* ]] && return 0
  [[ "$path_l" =~ (^|/)(records\.tsv|summary\.txt|detail\.txt|report\.txt)$ ]] && return 0

  # Ignore sample/test/mock/tmp style directories
  # 忽略样例/测试/mock/tmp 目录，减少误报
  [[ "$path_l" =~ (^|/)(example|examples|sample|samples|demo|demos|test|tests|testing|mock|mocks|fixture|fixtures|tmp|temp)(/|$) ]] && return 0
  [[ "$path_l" =~ (^|/)(example_|sample_|demo_|mock_).* ]] && return 0
  return 1
}

# Context filter: skip placeholder/tutorial lines
# 语境过滤：跳过示例/占位语境行
should_ignore_context() {
  local text_l
  text_l="$(to_lower "$1")"
  [[ "$text_l" =~ (example|sample|demo|mock|dummy|fake|placeholder|replace_me|changeme|your_api_key|your-key|yourkey|for[[:space:]_-]?test) ]] && return 0
  return 1
}

# Key filter: skip obvious fake values
# Key 过滤：跳过明显占位值
is_placeholder_key() {
  local key_l
  key_l="$(to_lower "$1")"
  [[ "$key_l" =~ (example|sample|demo|mock|dummy|fake|placeholder|changeme|replace|yourkey|your_api_key) ]] && return 0
  [[ "$key_l" == *"abcdefghijklmnopqrstuvwxyz"* ]] && return 0
  [[ "$key_l" == *"xxxxx"* || "$key_l" == *"00000"* ]] && return 0
  return 1
}

# -------------------------------------------------------------------
# Scan wrapper / 扫描封装
# Return format: file:line:content
# 返回格式：file:line:content
scan_text() {
  local pattern="$1" path="$2"
  if need rg; then
    rg -n --hidden -S "$pattern" "$path" \
      -g '!security-reports/**' \
      -g '!reports/**' \
      -g '!report/**' \
      -g '!**/security-reports/**' \
      -g '!**/reports/**' \
      -g '!**/report/**' \
      -g '!**/example/**' \
      -g '!**/examples/**' \
      -g '!**/sample/**' \
      -g '!**/samples/**' \
      -g '!**/demo/**' \
      -g '!**/demos/**' \
      -g '!**/test/**' \
      -g '!**/tests/**' \
      -g '!**/mock/**' \
      -g '!**/mocks/**' \
      -g '!**/fixture/**' \
      -g '!**/fixtures/**' \
      -g '!**/tmp/**' \
      -g '!**/temp/**' 2>/dev/null || true
  else
    grep -RInE "$pattern" "$path" \
      --exclude-dir='security-reports' \
      --exclude-dir='reports' \
      --exclude-dir='report' \
      --exclude-dir='example' \
      --exclude-dir='examples' \
      --exclude-dir='sample' \
      --exclude-dir='samples' \
      --exclude-dir='demo' \
      --exclude-dir='demos' \
      --exclude-dir='test' \
      --exclude-dir='tests' \
      --exclude-dir='mock' \
      --exclude-dir='mocks' \
      --exclude-dir='fixture' \
      --exclude-dir='fixtures' \
      --exclude-dir='tmp' \
      --exclude-dir='temp' 2>/dev/null || true
  fi
}

# -------------------------------------------------------------------
# API family detection / API 家族识别
detect_family_by_key() {
  local key="$1"
  case "$key" in
    AIzaSy*) echo "googleapikey" ;;
    sk-ant-*) echo "anthropicapikey" ;;
    gsk_*) echo "groqapikey" ;;
    sk-*) echo "openaiapikey" ;;
    *) echo "apikey" ;;
  esac
}

# Variable name hints override shape fallback when available
# 有变量名提示时优先变量名识别，否则回退 key 形态
detect_family_by_var() {
  local var="$1" key="$2" up
  up="$(to_lower "$var")"
  case "$up" in
    *openai*) echo "openaiapikey" ;;
    *gemini*|*google*) echo "googleapikey" ;;
    *anthropic*|*claude*) echo "anthropicapikey" ;;
    *groq*) echo "groqapikey" ;;
    *xai*) echo "xaiapikey" ;;
    *moonshot*) echo "moonshotapikey" ;;
    *brave*) echo "braveapikey" ;;
    *) detect_family_by_key "$key" ;;
  esac
}

# -------------------------------------------------------------------
# Mask rules / 打码规则
# sk-     => sk- + first5 + *** + last5
# AIzaSy  => AIzaSy + first5 + *** + last4
# gsk_    => gsk_ + first5 + *** + last5
mask_api() {
  local key="$1"
  if [[ "$key" == sk-* ]]; then
    local body="${key#sk-}"
    printf 'sk-%s***%s\n' "${body:0:5}" "${body: -5}"
    return 0
  fi
  if [[ "$key" == AIzaSy* ]]; then
    local body="${key#AIzaSy}"
    printf 'AIzaSy%s***%s\n' "${body:0:5}" "${body: -4}"
    return 0
  fi
  if [[ "$key" == gsk_* ]]; then
    local body="${key#gsk_}"
    printf 'gsk_%s***%s\n' "${body:0:5}" "${body: -5}"
    return 0
  fi

  local len="${#key}"
  if (( len <= 10 )); then
    printf '%s***%s\n' "${key:0:1}" "${key: -1}"
  else
    printf '%s***%s\n' "${key:0:5}" "${key: -5}"
  fi
}

# -------------------------------------------------------------------
# Record extraction / 记录提取
# Record schema:
# family<TAB>raw_key<TAB>masked_key<TAB>file<TAB>line<TAB>leak_type
#
# 记录格式：
# family<TAB>raw_key<TAB>masked_key<TAB>file<TAB>line<TAB>leak_type
emit_shape_records() {
  local input="$1"
  local shape_pat='sk-ant-[A-Za-z0-9._-]{20,}|sk-[A-Za-z0-9._-]{20,}|AIzaSy[A-Za-z0-9_-]{30,}|gsk_[A-Za-z0-9]{20,}'

  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    local file="${row%%:*}"
    local rem="${row#*:}"
    local line_no="${rem%%:*}"
    local content="${rem#*:}"

    should_ignore_path "$file" && continue
    should_ignore_context "$content" && continue

    while IFS= read -r key; do
      [[ -n "$key" ]] || continue
      is_placeholder_key "$key" && continue
      local family masked
      family="$(detect_family_by_key "$key")"
      masked="$(mask_api "$key")"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$family" "$key" "$masked" "$file" "$line_no" "明文形态(Plain Shape)"
    done < <(printf '%s\n' "$content" | grep -oE "$shape_pat" 2>/dev/null || true)
  done <<< "$input"
}

emit_assign_records() {
  local input="$1"
  local assign_pat='[A-Za-z0-9_]*API[_-]?KEY[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*["'\'']?[A-Za-z0-9._-]{8,}'

  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    local file="${row%%:*}"
    local rem="${row#*:}"
    local line_no="${rem%%:*}"
    local content="${rem#*:}"

    should_ignore_path "$file" && continue
    should_ignore_context "$content" && continue

    while IFS= read -r pair; do
      [[ -n "$pair" ]] || continue
      local var key family masked
      var="$(printf '%s\n' "$pair" | sed -E 's/[[:space:]]*[:=].*$//')"
      key="$(printf '%s\n' "$pair" | sed -E 's/^.*[:=][[:space:]]*["'\'']?([A-Za-z0-9._-]{8,}).*$/\1/')"
      [[ -n "$key" ]] || continue
      is_placeholder_key "$key" && continue
      family="$(detect_family_by_var "$var" "$key")"
      masked="$(mask_api "$key")"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$family" "$key" "$masked" "$file" "$line_no" "明文赋值(Plain Assignment)"
    done < <(printf '%s\n' "$content" | grep -oE "$assign_pat" 2>/dev/null || true)
  done <<< "$input"
}

# -------------------------------------------------------------------
# Report builders / 报告构建
# Summary format:
# 泄露类型(Leak Type)|泄露的api(打码/Masked API)|泄露次数(Count)|备注(Note)
build_summary_report() {
  local records="$1" report="$2"
  awk -F '\t' '
    BEGIN { OFS="|" }
    {
      id = $1 SUBSEP $2
      dedup = id SUBSEP $4 SUBSEP $5 SUBSEP $6
      if (seen[dedup]++) next

      if (!(id in order_idx)) {
        n++
        order[n] = id
        order_idx[id] = n
        family[id] = $1
        masked[id] = "【" $3 "】"
      }
      cnt[id]++
    }
    END {
      print "泄露类型(Leak Type)|泄露的api(打码/Masked API)|泄露次数(Count)|备注(Note)"
      if (n == 0) {
        print "未发现泄露(No Leak)|N/A|泄露次数0次(0)|N/A"
        exit
      }
      for (i = 1; i <= n; i++) {
        id = order[i]
        print family[id], masked[id], "泄露次数" cnt[id] "次(Count=" cnt[id] ")", "-"
      }
    }
  ' "$records" >"$report"
}

# Detail format:
# 泄露类型(Leak Type)|泄露的api(打码/Masked API)|泄露次数(Count)|泄露位置1(Position 1):...，泄露类型(Type):...|...
build_detail_report() {
  local records="$1" report="$2"
  awk -F '\t' '
    BEGIN { OFS="|" }
    {
      id = $1 SUBSEP $2
      dedup = id SUBSEP $4 SUBSEP $5 SUBSEP $6
      if (seen[dedup]++) next

      if (!(id in order_idx)) {
        n++
        order[n] = id
        order_idx[id] = n
        family[id] = $1
        masked[id] = "【" $3 "】"
      }

      cnt[id]++
      k = cnt[id]
      detail[id, k] = "泄露位置" k "(Position " k "):" $4 ":" $5 "，泄露类型(Type):" $6
    }
    END {
      print "泄露类型(Leak Type)|泄露的api(打码/Masked API)|泄露次数(Count)|泄露明细(Details)"
      if (n == 0) {
        print "未发现泄露(No Leak)|N/A|泄露次数0次(0)|N/A"
        exit
      }
      for (i = 1; i <= n; i++) {
        id = order[i]
        line = family[id] OFS masked[id] OFS "泄露次数" cnt[id] "次(Count=" cnt[id] ")"
        for (j = 1; j <= cnt[id]; j++) {
          line = line OFS detail[id, j]
        }
        print line
      }
    }
  ' "$records" >"$report"
}

# -------------------------------------------------------------------
# Terminal render helpers / 终端渲染辅助
# Generic viewer: less first, tail fallback
# 通用查看：优先 less，缺失时回退 tail
less_or_tail() {
  local file="$1"
  if need less; then
    less "$file"
  else
    tail -n 200 "$file"
  fi
}

# Render detail report as a readable terminal table
# 将详细报告渲染成终端表格，便于阅读
render_detail_table() {
  local file="$1"
  # Use terminal width to auto-size details column; fallback to a safe default
  # 基于终端宽度自动计算“明细”列宽，取不到宽度时使用安全默认值
  local term_cols="${COLUMNS:-0}"
  if [[ "$term_cols" -lt 100 ]]; then
    term_cols=140
  fi

  awk -F '|' -v term_cols="$term_cols" '
    # Fixed-width columns for key info; details column is auto computed and wrapped
    # 关键信息列固定宽度；明细列自动计算并折行
    function rep(ch, n, out, i) { out=""; for (i=0; i<n; i++) out = out ch; return out }
    function trim(s) { gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
    function print_sep() { printf "%s-+-%s-+-%s-+-%s\n", rep("-", w1), rep("-", w2), rep("-", w3), rep("-", w4) }
    function print_wrapped_row(t, a, c, d, pos, seg, first) {
      if (d == "") d = "-"
      first = 1
      for (pos = 1; pos <= length(d); pos += w4) {
        seg = substr(d, pos, w4)
        if (first) {
          printf "%-*s | %-*s | %-*s | %-*s\n", w1, t, w2, a, w3, c, w4, seg
          first = 0
        } else {
          printf "%-*s | %-*s | %-*s | %-*s\n", w1, "", w2, "", w3, "", w4, seg
        }
      }
      if (first) {
        printf "%-*s | %-*s | %-*s | %-*s\n", w1, t, w2, a, w3, c, w4, "-"
      }
    }
    BEGIN {
      # Keep left columns stable to improve scanability
      # 左侧列固定，保证阅读时快速定位
      w1 = 24
      w2 = 30
      w3 = 20

      # 3 separators: " | " => 9 chars total
      # 3 组分隔符 " | " 共 9 个字符
      fixed = w1 + w2 + w3 + 9
      w4 = term_cols - fixed
      if (w4 < 40) w4 = 40

      h1 = "Leak Type / 泄露类型"
      h2 = "Masked API / 打码API"
      h3 = "Count / 次数"
      h4 = "Details / 明细"
      printf "%-*s | %-*s | %-*s | %-*s\n", w1, h1, w2, h2, w3, h3, w4, h4
      print_sep()
    }
    NR == 1 { next }  # Skip raw header row in detail.txt / 跳过 detail.txt 原始表头
    {
      t = trim($1)
      a = trim($2)
      c = trim($3)

      # Merge all detail segments; display on wrapped lines
      # 合并全部明细段落，并按列宽自动折行
      d = ""
      for (i = 4; i <= NF; i++) {
        part = trim($i)
        if (part == "") continue
        if (d == "") d = part
        else d = d " ; " part
      }

      print_wrapped_row(t, a, c, d)
      print_sep()
    }
  ' "$file"
}

# -------------------------------------------------------------------
# Main flow / 主流程
main() {
  hr
  echo "API Key Leak Audit (仅 APIKey 泄露审计 / API key only)"

  [[ -d "$OC_HOME" ]] || { echo "目录不存在 / Directory not found: $OC_HOME"; exit 1; }

  local report_dir="$REPORT_ROOT/apikey_$(TS)"
  local records="$report_dir/records.tsv"
  local summary_report="$report_dir/summary.txt"
  local detail_report="$report_dir/detail.txt"
  mkdir -p "$report_dir"
  chmod 700 "$report_dir" 2>/dev/null || true

  # API key only patterns (no token/bearer/cookie)
  # 仅 API key 模式（不扫 token/bearer/cookie）
  local P_SHAPE='sk-ant-[A-Za-z0-9._-]{20,}|sk-[A-Za-z0-9._-]{20,}|AIzaSy[A-Za-z0-9_-]{30,}|gsk_[A-Za-z0-9]{20,}'
  local P_ASSIGN='[A-Za-z0-9_]*API[_-]?KEY[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*["'\'']?[A-Za-z0-9._-]{8,}'

  local shape_hits assign_hits
  shape_hits="$(scan_text "$P_SHAPE" "$OC_HOME")"
  assign_hits="$(scan_text "$P_ASSIGN" "$OC_HOME")"

  {
    emit_shape_records "$shape_hits"
    emit_assign_records "$assign_hits"
  } >"$records"

  build_summary_report "$records" "$summary_report"
  build_detail_report "$records" "$detail_report"
  chmod 600 "$records" "$summary_report" "$detail_report" 2>/dev/null || true

  echo "简易报告 / Summary: $summary_report"
  echo "详细报告 / Detail: $detail_report"
  echo "说明 / Note: 示例/样本/测试/mock/tmp 路径与占位 key 已过滤"

  while true; do
    echo "选择 / Choose: [S]简易报告 Summary(默认/default) [D]详细报告表格 Detail Table [V]详细原文 Detail Raw [R]退出 Exit"
    read -r -p "输入 / Input S/D/V/R: " action || true
    action="$(printf '%s' "${action:-S}" | tr -d '\r' | tr '[:lower:]' '[:upper:]')"
    case "$action" in
      S|S*) less_or_tail "$summary_report" ;;
      D|D*) render_detail_table "$detail_report" ;;
      V|V*) less_or_tail "$detail_report" ;;
      R|R*) exit 0 ;;
      *) echo "无效选项 / Invalid option" ;;
    esac
  done
}

main "$@"
