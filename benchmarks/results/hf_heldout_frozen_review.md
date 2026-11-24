Hub corpus: 4032 files from 1938 repositories.

All files (picklescan, modelscan, fickling and ModelAudit receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| security-test | 6 | 0/6 | 0/6 | 0/6 | 2/6 | 0/6 | 2/6 | 2/6 | 0/6 | 2/6 |
| code-by-design | 254 | 11/254 | 136/254 | 3/220 | 107/220 | 1/220 | 50/220 | 74/220 | 114/220 | 214/220 |
| nonstandard | 143 | 2/143 | 131/143 | 0/129 | 0/129 | 0/129 | 0/129 | 128/129 | 1/129 | 2/129 |
| benign | 3626 | 1/3626 = 0.000 (0.000 to 0.002) | 4/3626 = 0.001 (0.000 to 0.003) | 0/1964 = 0.000 (0.000 to 0.002) | 524/1964 = 0.267 (0.248 to 0.287) | 0/1964 = 0.000 (0.000 to 0.002) | 254/1964 = 0.129 (0.115 to 0.145) | 741/1964 = 0.377 (0.356 to 0.399) | 338/1964 = 0.172 (0.156 to 0.189) | 1018/1964 = 0.518 (0.496 to 0.540) |
| no attack (code-by-design, nonstandard, benign) | 4023 | 14/4023 = 0.003 (0.002 to 0.006) | 271/4023 = 0.067 (0.060 to 0.076) | 3/2313 = 0.001 (0.000 to 0.004) | 631/2313 = 0.273 (0.255 to 0.291) | 1/2313 = 0.000 (0.000 to 0.002) | 304/2313 = 0.131 (0.118 to 0.146) | 943/2313 = 0.408 (0.388 to 0.428) | 453/2313 = 0.196 (0.180 to 0.213) | 1234/2313 = 0.534 (0.513 to 0.554) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| security-test | 2 | 0/2 | 0/2 | 0/2 | 2/2 | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| code-by-design | 141 | 11/141 | 117/141 | 3/141 | 107/141 | 1/141 | 50/141 | 74/141 | 84/141 | 141/141 |
| nonstandard | 127 | 0/127 | 127/127 | 0/127 | 0/127 | 0/127 | 0/127 | 127/127 | 0/127 | 1/127 |
| benign | 1079 | 0/1079 = 0.000 (0.000 to 0.004) | 2/1079 = 0.002 (0.001 to 0.007) | 0/1079 = 0.000 (0.000 to 0.004) | 511/1079 = 0.474 (0.444 to 0.503) | 0/1079 = 0.000 (0.000 to 0.004) | 254/1079 = 0.235 (0.211 to 0.262) | 741/1079 = 0.687 (0.658 to 0.714) | 330/1079 = 0.306 (0.279 to 0.334) | 924/1079 = 0.856 (0.834 to 0.876) |
| no attack (code-by-design, nonstandard, benign) | 1347 | 11/1347 = 0.008 (0.005 to 0.015) | 246/1347 = 0.183 (0.163 to 0.204) | 3/1347 = 0.002 (0.001 to 0.007) | 618/1347 = 0.459 (0.432 to 0.485) | 1/1347 = 0.001 (0.000 to 0.004) | 304/1347 = 0.226 (0.204 to 0.249) | 942/1347 = 0.699 (0.674 to 0.723) | 414/1347 = 0.307 (0.283 to 0.333) | 1066/1347 = 0.791 (0.769 to 0.812) |
