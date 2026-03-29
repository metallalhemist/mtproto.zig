#!/usr/bin/env bash
#
# collect_prompt.sh — Собирает VALIDATION.md из шаблона промпта + исходных файлов проекта.
#
# Использование:
#   ./collect_prompt.sh              # генерирует VALIDATION.md
#   ./collect_prompt.sh output.md    # генерирует в указанный файл
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="${1:-${SCRIPT_DIR}/VALIDATION.md}"
PROMPT_FILE="${SCRIPT_DIR}/VALIDATION_PROMPT.md"

# Исходные файлы проекта в порядке "от основы к прикладному"
SOURCE_FILES=(
    "build.zig"
    "src/main.zig"
    "src/config.zig"
    "src/crypto/crypto.zig"
    "src/protocol/constants.zig"
    "src/protocol/obfuscation.zig"
    "src/protocol/tls.zig"
    "src/proxy/proxy.zig"
)

# --- Проверки ---
if [[ ! -f "$PROMPT_FILE" ]]; then
    echo "ERROR: Файл промпта не найден: $PROMPT_FILE" >&2
    echo "Создайте VALIDATION_PROMPT.md с текстом задания для модели." >&2
    exit 1
fi

for f in "${SOURCE_FILES[@]}"; do
    if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
        echo "ERROR: Исходный файл не найден: ${f}" >&2
        exit 1
    fi
done

# --- Сборка ---
{
    # 1. Промпт
    cat "$PROMPT_FILE"

    # 2. Разделитель
    echo ""
    echo "---"
    echo ""
    echo ""
    echo "# Source Code"
    echo ""

    # 3. Каждый исходный файл
    for f in "${SOURCE_FILES[@]}"; do
        echo "## \`${f}\`"
        echo ""
        echo '```zig'
        cat "${SCRIPT_DIR}/${f}"
        echo '```'
        echo ""
    done
} > "$OUTPUT"

LINES=$(wc -l < "$OUTPUT" | tr -d ' ')
echo "OK: ${OUTPUT} (${LINES} lines)"
