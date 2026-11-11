# Script para subir os 3 processos da Aula 05 (sso-escola) em janelas separadas:
#   1. IdP (Provedor de Identidade) -> http://idp.localhost:9000
#   2. Notas (Aplicação SP 1)       -> http://notas.localhost:8081
#   3. Biblioteca (Aplicação SP 2)  -> http://biblioteca.localhost:8082

$pastaAula05 = $PSScriptRoot

Write-Host "Iniciando os 3 servidores da Aula 05 (sso-escola)..." -ForegroundColor Cyan

Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = '1. [IdP] Provedor de Identidade (:9000)'; Set-Location '$pastaAula05'; mvn spring-boot:run '-Dspring-boot.run.profiles=idp'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = '2. [Notas] Aplicacao SP 1 (:8081)'; Set-Location '$pastaAula05'; mvn spring-boot:run '-Dspring-boot.run.profiles=notas'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = '3. [Biblioteca] Aplicacao SP 2 (:8082)'; Set-Location '$pastaAula05'; mvn spring-boot:run '-Dspring-boot.run.profiles=biblioteca'"

Write-Host "Aguarde ~10 segundos para os 3 servidores subirem e abra no navegador:" -ForegroundColor Green
Write-Host "  -> Notas:      http://notas.localhost:8081/minhas-notas" -ForegroundColor Yellow
Write-Host "  -> Biblioteca: http://biblioteca.localhost:8082" -ForegroundColor Yellow
Write-Host "  -> IdP:        http://idp.localhost:9000" -ForegroundColor Yellow
Write-Host "Usuarios (senha de todos: Escola@2026): ana (ALUNO), carlos (PROFESSOR), marta (BIBLIOTECARIO)" -ForegroundColor Gray
