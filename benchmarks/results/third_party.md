Versions: msscan 0.2.0 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13 modelaudit 0.2.58

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) | ModelAudit | ModelAudit (critical) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: fickling suite | 1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| benign: modelaudit suite | 21 | 0/21 | 0/21 | 0/21 | 1/21 | 0/21 | 1/21 | 0/21 | 0/21 | 0/21 |
| benign: modelscan suite | 1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| benign: picklescan suite | 14 | 0/14 | 6/14 | 0/14 | 0/14 | 0/14 | 4/14 | 0/14 | 3/14 | 0/14 |
| malicious: modelaudit suite | 49 | 46/49 | 46/49 | 18/49 | 19/49 | 19/49 | 18/49 | 18/49 | 49/49 | 45/49 |
| malicious: modelscan suite | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| malicious: picklescan suite | 94 | 94/94 | 94/94 | 94/94 | 94/94 | 28/94 | 88/94 | 77/94 | 89/94 | 88/94 |

| Detection rate (malicious) | 144 | 141/144 = 0.979 (0.941 to 0.993) | 141/144 = 0.979 (0.941 to 0.993) | 113/144 = 0.785 (0.711 to 0.844) | 114/144 = 0.792 (0.718 to 0.850) | 48/144 = 0.333 (0.262 to 0.414) | 107/144 = 0.743 (0.666 to 0.807) | 96/144 = 0.667 (0.586 to 0.738) | 139/144 = 0.965 (0.921 to 0.985) | 134/144 = 0.931 (0.877 to 0.962) |
| False positive rate (benign) | 37 | 0/37 = 0.000 (0.000 to 0.094) | 7/37 = 0.189 (0.095 to 0.342) | 0/37 = 0.000 (0.000 to 0.094) | 2/37 = 0.054 (0.015 to 0.177) | 0/37 = 0.000 (0.000 to 0.094) | 6/37 = 0.162 (0.077 to 0.311) | 0/37 = 0.000 (0.000 to 0.094) | 4/37 = 0.108 (0.043 to 0.247) | 1/37 = 0.027 (0.005 to 0.138) |

| Files not scanned or with errors | | 0 | 0 | 6 | 6 | 57 | 51 | 51 | 7 | 7 |
| Wall time (s, one process, includes imports) | | 0.1 | 0.1 | 0.3 | 0.3 | 0.3 | 2.1 | 2.1 | 76.2 | 76.2 |
