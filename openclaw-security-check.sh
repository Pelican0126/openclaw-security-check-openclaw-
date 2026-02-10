#!/usr/bin/env bash
set -euo pipefail

# Horizontal separator for clearer CLI output
# 分隔线：让 CLI 输出更清晰
hr() { echo "------------------------------------------------------------"; }

main() {
  # Single entry point that dispatches to sub-audits
  # 统一入口：按菜单分发到三个子审计脚本
  hr
  echo "OpenClaw Security Check (安全检查入口)"
  echo "1) Skill Gate (安装前扫描 / pre-install)"
  echo "2) Skill Inventory (已装审计 / installed audit)"
  echo "3) API Key Leak Audit (仅 APIKey 泄露审计)"
  echo "R) Exit (退出)"

  # Default to inventory mode for routine checks
  # 默认选择 inventory，适合日常巡检
  local c=""
  read -r -p "选择 / Choose 1/2/3/R (默认 default 2): " c || true
  c="$(printf '%s' "${c:-2}" | tr -d '\r')"

  case "$c" in
    # Pre-install gate scan / 安装前闸口扫描
    1) oc-skill-gate ;;
    # Installed skills inventory scan / 已安装技能审计
    2) oc-skill-inventory ;;
    # API key leak audit / API key 泄露审计
    3) oc-secrets-audit ;;
    # Exit / 退出
    R|r) exit 0 ;;
    # Invalid option / 非法选项
    *) echo "无效选项 / Invalid option"; exit 1 ;;
  esac
}

main "$@"
