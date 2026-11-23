Versions: msscan 0.1.1 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13 modelaudit 0.2.58

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) | ModelAudit | ModelAudit (critical) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: config | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: container | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: gguf | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: hf-json | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: joblib | 24 | 0/24 | 0/24 | 0/24 | 4/24 | 0/24 | 0/24 | 0/24 | 24/24 | 24/24 |
| benign: keras | 4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 1/4 | 0/4 |
| benign: look-alike | 5 | 0/5 | 0/5 | 0/5 | 1/5 | 0/5 | 1/5 | 0/5 | 2/5 | 2/5 |
| benign: numpy | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| benign: onnx | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: pickle | 10 | 0/10 | 0/10 | 0/10 | 9/10 | 0/10 | 10/10 | 1/10 | 6/10 | 4/10 |
| benign: pytorch | 21 | 0/21 | 0/21 | 0/21 | 9/21 | 0/21 | 21/21 | 4/21 | 21/21 | 21/21 |
| benign: safetensors | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 1/6 | 0/6 |
| benign: savedmodel | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| malicious: call-shape / code-execution | 5 | 5/5 | 5/5 | 1/5 | 5/5 | 0/5 | 2/5 | 2/5 | 4/5 | 1/5 |
| malicious: config / code-execution | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 1/4 | 1/4 |
| malicious: container / code-execution | 3 | 3/3 | 3/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: gguf / code-execution | 6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 6/6 | 5/6 |
| malicious: gguf / structure | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 2/4 | 0/4 |
| malicious: hf-json / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: joblib / code-execution | 8 | 8/8 | 8/8 | 1/8 | 3/8 | 1/8 | 1/8 | 1/8 | 8/8 | 8/8 |
| malicious: keras / code-execution | 5 | 5/5 | 5/5 | 0/5 | 0/5 | 1/5 | 0/5 | 0/5 | 5/5 | 2/5 |
| malicious: keras / file-access | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 |
| malicious: numpy / code-execution | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: onnx / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 |
| malicious: pickle / code-execution | 63 | 63/63 | 63/63 | 59/63 | 62/63 | 35/63 | 62/63 | 61/63 | 63/63 | 55/63 |
| malicious: pickle / hard | 3 | 3/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 | 2/3 | 3/3 | 3/3 |
| malicious: pytorch / code-execution | 7 | 7/7 | 7/7 | 6/7 | 7/7 | 3/7 | 7/7 | 5/7 | 5/7 | 5/7 |
| malicious: safetensors / structure | 8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 5/8 | 2/8 |
| malicious: savedmodel / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| malicious: savedmodel / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 |
| malicious: staged / code-execution | 7 | 7/7 | 7/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 7/7 | 6/7 |

| Detection rate (malicious) | 136 | 136/136 = 1.000 (0.973 to 1.000) | 136/136 = 1.000 (0.973 to 1.000) | 71/136 = 0.522 (0.439 to 0.604) | 83/136 = 0.610 (0.526 to 0.688) | 40/136 = 0.294 (0.224 to 0.376) | 75/136 = 0.551 (0.468 to 0.633) | 71/136 = 0.522 (0.439 to 0.604) | 124/136 = 0.912 (0.852 to 0.949) | 102/136 = 0.750 (0.671 to 0.815) |
| False positive rate (benign) | 91 | 0/91 = 0.000 (0.000 to 0.041) | 1/91 = 0.011 (0.002 to 0.060) | 0/91 = 0.000 (0.000 to 0.041) | 23/91 = 0.253 (0.175 to 0.351) | 0/91 = 0.000 (0.000 to 0.041) | 32/91 = 0.352 (0.261 to 0.454) | 5/91 = 0.055 (0.024 to 0.122) | 56/91 = 0.615 (0.513 to 0.709) | 52/91 = 0.571 (0.469 to 0.668) |

| Files not scanned or with errors | | 0 | 0 | 12 | 12 | 107 | 108 | 108 | 16 | 16 |
| Wall time (s, one process, includes imports) | | 0.2 | 0.2 | 0.3 | 0.3 | 0.3 | 1.8 | 1.8 | 64.4 | 64.4 |
