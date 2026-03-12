# Android ADB Scanner

- apt-get update && apt full-upgrade && apt install zmap golang -y
- go build adb.go
- then run the payload below
## Recommendation
- **Speed:** `1.3 Mpps` or higher
- **Use a better payload** for better results.

## Command

```bash
zmap -p 5555 -q -r0 | ./adb -p 5555 -c 10000 -t 10s
