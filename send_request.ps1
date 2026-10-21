[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$postData = @{
    prompt = 'Müşterinin T.C. Kimlik numarası 12345678901 ve e-postası test@sirket.com. API anahtarımız sk-live9876543210abcdef1234567890abcdef. Bu kullanıcıya hoş geldin mesajı üret.'
    model = 'gpt-3.5-turbo'
} | ConvertTo-Json

$postBytes = [System.Text.Encoding]::UTF8.GetBytes($postData)

$result = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/chat/secure' -Method Post -Body $postBytes -ContentType 'application/json; charset=utf-8'

$result | ConvertTo-Json -Depth 5
