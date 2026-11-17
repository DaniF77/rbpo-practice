// =============================================================================
// REST API для ИАС БИ — Go
// Компиляция: go build -o api api.go
// Запуск:     ./api            (из папки pr4, под root: нужен Masscan)
//   POST /scan       {"target":"127.0.0.1"} — запустить Nmap, Masscan и Nikto параллельно и вернуть инцидент
//   GET  /incidents  — результаты всех проведённых сканирований
//   GET  /health     — проверка, что сервис жив
// =============================================================================
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type ScanRequest struct {
	Target string `json:"target"`
}

var (
	mu    sync.Mutex
	scans = make(map[string]any) // цель -> последний результат (единая схема из analyze.py)
)

// run запускает внешнюю команду с ограничением по времени; вывод — в файл, если он задан
func run(timeout time.Duration, outFile string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		cmd.Stdout = f
	}
	return cmd.Run()
}

// scanTarget: три сканера работают одновременно (горутины), затем разбор и экспертная система
func scanTarget(target string) (map[string]any, error) {
	dir, err := os.MkdirTemp("", "ias_scan_")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // Nmap -> XML -> C++ парсер -> JSON
		defer wg.Done()
		xml := filepath.Join(dir, "nmap.xml")
		if err := run(120*time.Second, "", "nmap", "-sV", "-oX", xml, target); err != nil {
			log.Println("nmap:", err)
			return
		}
		if err := run(30*time.Second, filepath.Join(dir, "nmap_parsed.json"), "./nmap_parser", xml); err != nil {
			log.Println("nmap_parser:", err)
		}
	}()
	go func() { // Masscan
		defer wg.Done()
		if err := run(120*time.Second, "", "masscan", "-p1-1000,6443,10250", target, "--rate", "100", "--wait", "3",
			"-oJ", filepath.Join(dir, "masscan.json")); err != nil {
			log.Println("masscan:", err)
		}
	}()
	go func() { // Nikto
		defer wg.Done()
		if err := run(120*time.Second, "", "nikto", "-h", target, "-maxtime", "60s", "-nointeractive",
			"-Format", "json", "-o", filepath.Join(dir, "nikto.json")); err != nil {
			log.Println("nikto:", err)
		}
	}()
	wg.Wait()

	// разбор и решение об инциденте — Python (parsers.py + expert_system.py)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "analyze.py", dir, target).Output()
	if err != nil {
		return nil, fmt.Errorf("analyze.py: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
}

// POST /scan
func scanHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || net.ParseIP(req.Target) == nil {
		http.Error(w, `{"error":"нужен JSON {\"target\":\"<IP-адрес>\"}"}`, http.StatusBadRequest) // защита от инъекции в команды
		return
	}
	result, err := scanTarget(req.Target)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	mu.Lock()
	scans[req.Target] = result
	mu.Unlock()
	json.NewEncoder(w).Encode(result)
}

// GET /incidents
func incidentsHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	mu.Lock()
	defer mu.Unlock()
	json.NewEncoder(w).Encode(scans)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func main() {
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/incidents", incidentsHandler)
	http.HandleFunc("/health", healthHandler)
	fmt.Println("API запущен на 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
