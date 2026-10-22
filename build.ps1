# =============================================================
#  Сборка GrandMenVPN в один .exe
#  Запуск:  powershell -ExecutionPolicy Bypass -File .\build.ps1
# =============================================================
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

Write-Host "=== [1/4] Проверка зависимостей ===" -ForegroundColor Cyan
$pyinstaller = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $pyinstaller) {
    Write-Host "pyinstaller не найден. Установите: pip install pyinstaller" -ForegroundColor Red
    exit 1
}
foreach ($f in @("main.py", "GrandMenVPN.spec", "sing-box.exe", "amneziawg-go.exe",
                 "awg.exe", "wintun.dll", "nssm.exe")) {
    if (-not (Test-Path $f)) {
        Write-Host "НЕТ ФАЙЛА: $f" -ForegroundColor Red
        exit 1
    }
}
Write-Host "Все обязательные файлы на месте." -ForegroundColor Green

Write-Host "=== [2/4] Rule-set российских подсетей (geoip-ru.srs) ===" -ForegroundColor Cyan
if (Test-Path "geoip-ru.srs") {
    $kb = [math]::Round((Get-Item "geoip-ru.srs").Length / 1KB, 1)
    Write-Host "geoip-ru.srs уже есть ($kb КБ)" -ForegroundColor Green
} else {
    $url = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
    Write-Host "Скачиваю $url ..." -ForegroundColor DarkGray
    try {
        Invoke-WebRequest -Uri $url -OutFile "geoip-ru.srs" -UseBasicParsing -TimeoutSec 90
        $kb = [math]::Round((Get-Item "geoip-ru.srs").Length / 1KB, 1)
        Write-Host "Готово: $kb КБ" -ForegroundColor Green
    } catch {
        Write-Host "Не удалось скачать: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Приложение будет работать без раздельного роутинга RU." -ForegroundColor Yellow
    }
}

Write-Host "=== [2b/4] Список RU-подсетей (ru-cidr.txt) ===" -ForegroundColor Cyan
if (Test-Path "ru-cidr.txt") {
    Write-Host "ru-cidr.txt уже есть: $((Get-Content 'ru-cidr.txt').Count) подсетей" -ForegroundColor Green
} elseif (Test-Path ".\sing-box.exe") {
    # Декомпилируем официальный geoip-ru.srs в исходный JSON и достаём ip_cidr
    try {
        & ".\sing-box.exe" rule-set decompile --output "ru-cidr.json" "geoip-ru.srs" 2>$null
        if (-not (Test-Path "ru-cidr.json")) {
            & ".\sing-box.exe" rule-set decompile "geoip-ru.srs" > "ru-cidr.json" 2>$null
        }
        if (Test-Path "ru-cidr.json") {
            $rules = (Get-Content "ru-cidr.json" -Raw | ConvertFrom-Json).rules
            $cidrs = @()
            foreach ($r in $rules) { if ($r.ip_cidr) { $cidrs += $r.ip_cidr } }
            if ($cidrs.Count -gt 100) {
                $cidrs | Sort-Object -Unique | Set-Content "ru-cidr.txt" -Encoding UTF8
                Write-Host "Готово: $($cidrs.Count) подсетей" -ForegroundColor Green
            } else {
                Write-Host "Не удалось разобрать JSON (подсетей: $($cidrs.Count))" -ForegroundColor Yellow
            }
            Remove-Item "ru-cidr.json" -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "Декомпиляция не удалась: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if (-not (Test-Path "ru-cidr.txt")) {
    Write-Host "ru-cidr.txt не создан — приложение получит список само при первом запуске" -ForegroundColor Yellow
}

Write-Host "=== [3/4] Сборка через PyInstaller ===" -ForegroundColor Cyan
if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
if (Test-Path "dist")  { Remove-Item "dist"  -Recurse -Force }
pyinstaller --noconfirm --clean GrandMenVPN.spec
if ($LASTEXITCODE -ne 0) {
    Write-Host "Сборка провалилась" -ForegroundColor Red
    exit 1
}

Write-Host "=== [4/4] Проверка результата ===" -ForegroundColor Cyan
$exe = "dist\GrandMenVPN.exe"
if (-not (Test-Path $exe)) {
    Write-Host "Файл $exe не создан!" -ForegroundColor Red
    exit 1
}

# в dist должна остаться ровно ОДИН файл
Get-ChildItem "dist" -File | Where-Object { $_.Name -ne "GrandMenVPN.exe" } | ForEach-Object {
    Write-Host "Удаляю лишний файл из dist: $($_.Name)" -ForegroundColor DarkGray
    Remove-Item $_.FullName -Force
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host ""
Write-Host "ГОТОВО: $exe  ($size МБ)" -ForegroundColor Green
Write-Host "Внешние бинарники распаковываются при запуске в %ProgramData%\GrandMenVPN\bin" -ForegroundColor DarkGray
Write-Host "Запуск:  .\dist\GrandMenVPN.exe" -ForegroundColor Cyan
