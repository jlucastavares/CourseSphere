#!/usr/bin/env sh
# Demonstra o balanceamento de carga: faz N requisições ao /api/health
# pelo Nginx e mostra qual instância do backend respondeu cada uma.
#   sh scripts/demo_balanceamento.sh [requisicoes] [url]
N="${1:-10}"
URL="${2:-http://localhost:8080/api/health}"
i=1
while [ "$i" -le "$N" ]; do
  inst=$(curl -s -D - -o /dev/null "$URL" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-instance"{print $2}')
  echo "Requisicao $i -> atendida por $inst"
  echo "$inst" >> /tmp/.demo_lb_$$
  i=$((i + 1))
done
echo ""
echo "Resumo:"
sort /tmp/.demo_lb_$$ | uniq -c
rm -f /tmp/.demo_lb_$$
