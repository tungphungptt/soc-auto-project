# Chay tren Windows 10/11

1. Cai Python 3.10+; danh dau Add python to PATH.
2. Giai nen ZIP, mo CMD/PowerShell tai `3_AUTOMATION_THANG`.
3. Chay `python demo.py --execute-mock` hoac nhan `RUN_DEMO.bat`.
4. Chay `python -m unittest discover -s tests -v` hoac `RUN_TESTS.bat`.
5. Demo thu cong: `python demo.py --execute-mock --manual-approval`.

De chay 3 dich vu rieng: mo 3 terminal, lan luot `python -m soclab ai`, `python -m soclab firewall`, `python -m soclab automation`. O terminal Automation muon cho chinh sach thao tac tren Mock: `$env:SOC_DRY_RUN='false'` truoc khi khoi dong. Terminal thu tu: `python send_event.py examples/01_bruteforce.json`.

Cac thong so OPNsense/live KHONG bat mac dinh; khong chay voi IP cong ty/doanh nghiep neu chua duoc phe duyet.
