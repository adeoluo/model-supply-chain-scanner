Versions: msscan 0.1.0 picklescan 1.0.5 modelscan 0.8.8 fickling 0.1.13

| Group | Files | msscan (high) | msscan (medium) | picklescan | picklescan --strict | modelscan | fickling | fickling (overtly malicious) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| benign: gguf | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: hf-json | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: joblib | 24 | 0/24 | 0/24 | 0/24 | 4/24 | 0/24 | 0/24 | 0/24 |
| benign: keras | 3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| benign: numpy | 6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| benign: onnx | 2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign: pickle | 10 | 0/10 | 0/10 | 0/10 | 9/10 | 0/10 | 10/10 | 1/10 |
| benign: pytorch | 21 | 0/21 | 0/21 | 0/21 | 9/21 | 0/21 | 21/21 | 4/21 |
| benign: safetensors | 4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| benign: savedmodel | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| malicious: gguf / code-execution | 6 | 6/6 | 6/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| malicious: gguf / structure | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| malicious: hf-json / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: joblib / code-execution | 8 | 8/8 | 8/8 | 1/8 | 3/8 | 1/8 | 1/8 | 1/8 |
| malicious: keras / code-execution | 4 | 4/4 | 4/4 | 0/4 | 0/4 | 1/4 | 0/4 | 0/4 |
| malicious: keras / file-access | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| malicious: numpy / code-execution | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| malicious: onnx / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| malicious: pickle / code-execution | 63 | 63/63 | 63/63 | 59/63 | 62/63 | 35/63 | 62/63 | 61/63 |
| malicious: pickle / hard | 3 | 1/3 | 2/3 | 1/3 | 3/3 | 0/3 | 3/3 | 2/3 |
| malicious: pytorch / code-execution | 7 | 7/7 | 7/7 | 6/7 | 7/7 | 3/7 | 7/7 | 5/7 |
| malicious: safetensors / structure | 8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| malicious: savedmodel / code-execution | 2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| malicious: savedmodel / file-access | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |

| Detection rate (malicious) | 116 | 114/116 = 0.983 (0.939 to 0.995) | 115/116 = 0.991 (0.953 to 0.998) | 69/116 = 0.595 (0.504 to 0.680) | 77/116 = 0.664 (0.574 to 0.743) | 40/116 = 0.345 (0.265 to 0.435) | 73/116 = 0.629 (0.539 to 0.712) | 69/116 = 0.595 (0.504 to 0.680) |
| False positive rate (benign) | 78 | 0/78 = 0.000 (0.000 to 0.047) | 0/78 = 0.000 (0.000 to 0.047) | 0/78 = 0.000 (0.000 to 0.047) | 22/78 = 0.282 (0.194 to 0.390) | 0/78 = 0.000 (0.000 to 0.047) | 31/78 = 0.397 (0.296 to 0.508) | 5/78 = 0.064 (0.028 to 0.141) |

| Files not scanned or with errors | | 0 | 0 | 10 | 10 | 90 | 93 | 93 |
| Wall time (s, one process, includes imports) | | 0.2 | 0.2 | 0.4 | 0.4 | 0.6 | 4.2 | 4.2 |
