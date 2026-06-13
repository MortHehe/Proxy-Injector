# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['ui_app.py'],
    pathex=[],
    binaries=[('C:\\Users\\meidy\\AppData\\Local\\Python\\pythoncore-3.14-64\\Lib\\site-packages\\pydivert\\windivert_dll', 'pydivert/windivert_dll')],
    datas=[],
    hiddenimports=['pydivert.windivert_dll'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PixelProxyInjectorUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PixelProxyInjectorUI',
)
