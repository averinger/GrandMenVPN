# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# --- внешние бинарники ---
# Они лежат ВНУТРИ exe (режим "один файл"), но при запуске приложение
# распаковывает их в %ProgramData%\GrandMenVPN\bin с закрытым ACL:
# sing-box 1.12+ отказывается стартовать elevated из папки, доступной
# на запись не-админам (а _MEIPASS в %TEMP% — именно такая).
binaries = [
    ('sing-box.exe', '.'),        # основной прокси-клиент
    ('amneziawg-go.exe', '.'),    # демон AmneziaWG
    ('awg.exe', '.'),             # утилита настройки интерфейса
    ('wintun.dll', '.'),          # TUN-драйвер (x64)
    ('nssm.exe', '.'),            # установщик службы Windows
]

# --- официальный rule-set с российскими подсетями (SagerNet/sing-geoip) ---
datas = []
if os.path.exists('geoip-ru.srs'):
    datas.append(('geoip-ru.srs', '.'))
# готовый список RU-подсетей (для авто-сплита в режиме WARP)
if os.path.exists('ru-cidr.txt'):
    datas.append(('ru-cidr.txt', '.'))

# --- ресурсы python-пакетов (customtkinter тянет картинки/данные) ---
hiddenimports = []
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='GrandMenVPN',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=r'C:\Temp\GrandMenVPN',
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,   # требуем права администратора (нужны для TUN и службы)
)
