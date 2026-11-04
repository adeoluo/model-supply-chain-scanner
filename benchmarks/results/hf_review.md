Hub corpus: 7607 files from 2888 repositories.

All files (picklescan, modelscan and fickling receive the pickle-family, Keras, ONNX and SavedModel files stored in full; header stubs and JSON configs are msscan only):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 17 | 17/17 | 17/17 | 7/16 | 7/16 | 5/16 | 7/16 | 7/16 |
| security-test | 27 | 7/27 | 8/27 | 0/20 | 0/20 | 2/20 | 0/20 | 0/20 |
| code-by-design | 342 | 18/342 | 113/342 | 1/183 | 81/183 | 1/183 | 20/183 | 73/183 |
| nonstandard | 14 | 13/14 | 14/14 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| benign | 7207 | 0/7207 = 0.000 (0.000 to 0.001) | 15/7207 = 0.002 (0.001 to 0.003) | 0/2023 = 0.000 (0.000 to 0.002) | 492/2023 = 0.243 (0.225 to 0.262) | 0/2023 = 0.000 (0.000 to 0.002) | 125/2023 = 0.062 (0.052 to 0.073) | 1151/2023 = 0.569 (0.547 to 0.590) |
| no attack (code-by-design, nonstandard, benign) | 7563 | 31/7563 = 0.004 (0.003 to 0.006) | 142/7563 = 0.019 (0.016 to 0.022) | 1/2208 = 0.000 (0.000 to 0.003) | 573/2208 = 0.260 (0.242 to 0.278) | 1/2208 = 0.000 (0.000 to 0.003) | 145/2208 = 0.066 (0.056 to 0.077) | 1226/2208 = 0.555 (0.534 to 0.576) |

Pickle-family files only (every tool scanned the same files):

| Label | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling (overtly malicious) | fickling |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload | 10 | 10/10 | 10/10 | 7/10 | 7/10 | 5/10 | 7/10 | 7/10 |
| security-test | 4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| code-by-design | 85 | 7/85 | 79/85 | 1/85 | 81/85 | 1/85 | 20/85 | 73/85 |
| nonstandard | 2 | 1/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| benign | 1433 | 0/1433 = 0.000 (0.000 to 0.003) | 3/1433 = 0.002 (0.001 to 0.006) | 0/1433 = 0.000 (0.000 to 0.003) | 492/1433 = 0.343 (0.319 to 0.368) | 0/1433 = 0.000 (0.000 to 0.003) | 125/1433 = 0.087 (0.074 to 0.103) | 1151/1433 = 0.803 (0.782 to 0.823) |
| no attack (code-by-design, nonstandard, benign) | 1520 | 8/1520 = 0.005 (0.003 to 0.010) | 84/1520 = 0.055 (0.045 to 0.068) | 1/1520 = 0.001 (0.000 to 0.004) | 573/1520 = 0.377 (0.353 to 0.402) | 1/1520 = 0.001 (0.000 to 0.004) | 145/1520 = 0.095 (0.082 to 0.111) | 1226/1520 = 0.807 (0.786 to 0.826) |
