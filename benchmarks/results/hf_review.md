Hub corpus: 8541 files from 2789 repositories.

All files (picklescan, modelscan, fickling and ModelAudit receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 19 | 19/19 | 19/19 | 9/18 | 9/18 | 6/18 | 9/18 | 9/18 | 16/18 | 16/18 |
| security-test | 27 | 6/27 | 8/27 | 0/20 | 0/20 | 2/20 | 0/20 | 0/20 | 4/20 | 7/20 |
| code-by-design | 400 | 2/400 | 115/400 | 1/225 | 85/225 | 1/225 | 23/225 | 76/225 | 148/225 | 211/225 |
| nonstandard | 80 | 0/80 | 58/80 | 0/55 | 1/55 | 0/55 | 1/55 | 54/55 | 1/55 | 2/55 |
| benign | 8015 | 4/8015 = 0.000 (0.000 to 0.001) | 17/8015 = 0.002 (0.001 to 0.003) | 0/2377 = 0.000 (0.000 to 0.002) | 548/2377 = 0.231 (0.214 to 0.248) | 0/2377 = 0.000 (0.000 to 0.002) | 146/2377 = 0.061 (0.052 to 0.072) | 1228/2377 = 0.517 (0.497 to 0.537) | 1227/2377 = 0.516 (0.496 to 0.536) | 1394/2377 = 0.586 (0.567 to 0.606) |
| no attack (code-by-design, nonstandard, benign) | 8495 | 6/8495 = 0.001 (0.000 to 0.002) | 190/8495 = 0.022 (0.019 to 0.026) | 1/2657 = 0.000 (0.000 to 0.002) | 634/2657 = 0.239 (0.223 to 0.255) | 1/2657 = 0.000 (0.000 to 0.002) | 170/2657 = 0.064 (0.055 to 0.074) | 1358/2657 = 0.511 (0.492 to 0.530) | 1376/2657 = 0.518 (0.499 to 0.537) | 1607/2657 = 0.605 (0.586 to 0.623) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling | ModelAudit (critical) | ModelAudit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 12 | 12/12 | 12/12 | 9/12 | 9/12 | 6/12 | 9/12 | 9/12 | 12/12 | 12/12 |
| security-test | 4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| code-by-design | 90 | 2/90 | 79/90 | 1/90 | 85/90 | 1/90 | 23/90 | 76/90 | 79/90 | 90/90 |
| nonstandard | 54 | 0/54 | 54/54 | 0/54 | 0/54 | 0/54 | 1/54 | 54/54 | 0/54 | 1/54 |
| benign | 1550 | 1/1550 = 0.001 (0.000 to 0.004) | 5/1550 = 0.003 (0.001 to 0.008) | 0/1550 = 0.000 (0.000 to 0.002) | 548/1550 = 0.354 (0.330 to 0.378) | 0/1550 = 0.000 (0.000 to 0.002) | 146/1550 = 0.094 (0.081 to 0.110) | 1228/1550 = 0.792 (0.771 to 0.812) | 1214/1550 = 0.783 (0.762 to 0.803) | 1304/1550 = 0.841 (0.822 to 0.859) |
| no attack (code-by-design, nonstandard, benign) | 1694 | 3/1694 = 0.002 (0.001 to 0.005) | 138/1694 = 0.081 (0.069 to 0.095) | 1/1694 = 0.001 (0.000 to 0.003) | 633/1694 = 0.374 (0.351 to 0.397) | 1/1694 = 0.001 (0.000 to 0.003) | 170/1694 = 0.100 (0.087 to 0.116) | 1358/1694 = 0.802 (0.782 to 0.820) | 1293/1694 = 0.763 (0.742 to 0.783) | 1395/1694 = 0.823 (0.805 to 0.841) |
