# Demonstra o balanceamento de carga: faz N requisições ao /api/health
# pelo Nginx e mostra qual instância do backend respondeu cada uma.
#   powershell -ExecutionPolicy Bypass -File scripts\demo_balanceamento.ps1
param([int]$Requisicoes = 10, [string]$Url = "http://localhost:8080/api/health")

$contagem = @{}
for ($i = 1; $i -le $Requisicoes; $i++) {
    $r = Invoke-WebRequest -Uri $Url -UseBasicParsing
    $instancia = $r.Headers["X-Instance"]
    $contagem[$instancia] = 1 + [int]$contagem[$instancia]
    Write-Host ("Requisicao {0,2} -> status {1} atendida por {2}" -f $i, $r.StatusCode, $instancia)
}
Write-Host ""
Write-Host "Resumo:"
$contagem.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0}: {1} requisicoes" -f $_.Name, $_.Value) }
