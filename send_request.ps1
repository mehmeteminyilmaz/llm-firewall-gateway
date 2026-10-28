[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$postData = @{
    prompt = "Müşterimiz Ayşe Hanım'ın T.C. Kimlik No 98765432150 ve iletişim adresi ayse@kurum.com'dur. Kendisine abonelik yenileme bildirimi hazırla."
    model = "gpt-3.5-turbo"
} | ConvertTo-Json

$postBytes = [System.Text.Encoding]::UTF8.GetBytes($postData)

try {
    $result = Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/chat/secure" -Method Post -Body $postBytes -ContentType "application/json; charset=utf-8"
    $result | ConvertTo-Json -Depth 5
}
catch {
    Write-Host "[HATA / ENGELLEME]:" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $_.ErrorDetails.Message | ConvertFrom-Json | ConvertTo-Json -Depth 5
    } else {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}
