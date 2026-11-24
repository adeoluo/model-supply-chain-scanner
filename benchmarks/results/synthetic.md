Versions: msscan 0.1.1 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13 modelaudit 0.2.58

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) | ModelAudit | ModelAudit (critical) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: config | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: container | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: gguf | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: hf-json | 5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| benign: joblib | 25 | 0/25 | 1/25 | 1/25 | 5/25 | 0/25 | 1/25 | 1/25 | 25/25 | 6/25 |
| benign: keras | 5 | 0/5 | 1/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 2/5 | 0/5 |
| benign: look-alike | 5 | 0/5 | 0/5 | 0/5 | 1/5 | 0/5 | 1/5 | 0/5 | 2/5 | 2/5 |
| benign: numpy | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| benign: onnx | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: pickle | 13 | 0/13 | 2/13 | 1/13 | 10/13 | 0/13 | 12/13 | 3/13 | 8/13 | 3/13 |
| benign: pytorch | 22 | 0/22 | 1/22 | 1/22 | 10/22 | 0/22 | 22/22 | 5/22 | 14/22 | 1/22 |
| benign: safetensors | 8 | 0/8 | 1/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 3/8 | 1/8 |
| benign: savedmodel | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| malicious: call-shape / code-execution | 5 | 5/5 | 5/5 | 1/5 | 5/5 | 0/5 | 2/5 | 2/5 | 4/5 | 2/5 |
| malicious: config / code-execution | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 1/4 | 1/4 |
| malicious: container / code-execution | 3 | 3/3 | 3/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: gguf / code-execution | 6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 6/6 | 5/6 |
| malicious: gguf / structure | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 2/4 | 0/4 |
| malicious: hf-json / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: hf-json / file-access | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: joblib / code-execution | 8 | 8/8 | 8/8 | 1/8 | 3/8 | 1/8 | 1/8 | 1/8 | 8/8 | 8/8 |
| malicious: keras / code-execution | 5 | 5/5 | 5/5 | 0/5 | 0/5 | 1/5 | 0/5 | 0/5 | 5/5 | 2/5 |
| malicious: keras / file-access | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 4/4 | 0/4 |
| malicious: link / file-access | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 |
| malicious: numpy / code-execution | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: onnx / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: pickle / code-execution | 63 | 63/63 | 63/63 | 59/63 | 62/63 | 35/63 | 62/63 | 61/63 | 63/63 | 55/63 |
| malicious: pickle / hard | 3 | 3/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 | 2/3 | 3/3 | 3/3 |
| malicious: pytorch / code-execution | 7 | 7/7 | 7/7 | 6/7 | 7/7 | 3/7 | 7/7 | 5/7 | 5/7 | 5/7 |
| malicious: safetensors / structure | 8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 5/8 | 2/8 |
| malicious: savedmodel / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: savedmodel / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 |
| malicious: staged / code-execution | 7 | 7/7 | 7/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 7/7 | 6/7 |

| Detection rate (malicious) | 142 | 142/142 = 1.000 (0.974 to 1.000) | 142/142 = 1.000 (0.974 to 1.000) | 71/142 = 0.500 (0.419 to 0.581) | 83/142 = 0.585 (0.502 to 0.662) | 40/142 = 0.282 (0.214 to 0.361) | 75/142 = 0.528 (0.446 to 0.608) | 71/142 = 0.500 (0.419 to 0.581) | 128/142 = 0.901 (0.841 to 0.940) | 103/142 = 0.725 (0.647 to 0.792) |
| False positive rate (benign) | 101 | 0/101 = 0.000 (0.000 to 0.037) | 6/101 = 0.059 (0.028 to 0.124) | 3/101 = 0.030 (0.010 to 0.084) | 26/101 = 0.257 (0.182 to 0.350) | 0/101 = 0.000 (0.000 to 0.037) | 36/101 = 0.356 (0.270 to 0.454) | 9/101 = 0.089 (0.048 to 0.161) | 55/101 = 0.545 (0.448 to 0.638) | 14/101 = 0.139 (0.084 to 0.219) |

| Files not scanned or with errors | | 0 | 0 | 16 | 16 | 119 | 115 | 115 | 18 | 18 |
| Wall time (s, one process, includes imports) | | 0.1 | 0.1 | 0.2 | 0.2 | 0.2 | 1.5 | 1.5 | 227.0 | 227.0 |
