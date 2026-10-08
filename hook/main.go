// The backend's side of the trial of the entry of "my sites": asked before
// a request is sent on, it starts the environment (a docker container) if
// it is not running, answers once it takes connections, and stops those
// nobody asked for in a while. It also answers certificate challenges, to
// show they reach it.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type env struct {
	mu   sync.Mutex
	addr string
	seen time.Time
	up   bool
}

func main() {
	// name=address pairs: env1=127.0.0.1:18101
	envs := map[string]*env{}
	for _, a := range os.Args[1:] {
		name, addr, _ := strings.Cut(a, "=")
		envs[name] = &env{addr: addr}
	}
	idle := 60 * time.Second
	// An environment takes requests once it answers one: docker listens on
	// its port before the web server inside does.
	alive := func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			return false
		}
		defer c.Close()
		// PHP-FPM speaks no HTTP: it is there once its port takes a connection
		// (reached at the container's own address, where docker listens for nobody).
		if strings.HasSuffix(addr, ":9000") {
			return true
		}
		_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Write([]byte("HEAD / HTTP/1.0\r\nHost: ready\r\n\r\n")); err != nil {
			return false
		}
		buf := make([]byte, 5)
		n, _ := c.Read(buf)
		return n == 5 && string(buf) == "HTTP/"
	}
	http.HandleFunc("/ask", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("env")
		e := envs[name]
		if e == nil {
			http.Error(w, "no such environment", http.StatusNotFound)
			return
		}
		// One at a time for an environment: those that come while it starts wait for the one start.
		e.mu.Lock()
		defer e.mu.Unlock()
		e.seen = time.Now()
		if e.up && alive(e.addr) {
			return
		}
		began := time.Now()
		if out, err := exec.Command("docker", "start", name).CombinedOutput(); err != nil {
			log.Printf("start %s: %v %s", name, err, out)
			http.Error(w, "cannot start", http.StatusServiceUnavailable)
			return
		}
		for i := 0; i < 200 && !alive(e.addr); i++ {
			time.Sleep(50 * time.Millisecond)
		}
		if !alive(e.addr) {
			http.Error(w, "did not come up", http.StatusServiceUnavailable)
			return
		}
		e.up = true
		log.Printf("started %s in %d ms", name, time.Since(began).Milliseconds())
	})
	http.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "challenge %s for %s reached the backend\n", strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/"), r.Host)
	})
	go func() {
		for range time.Tick(5 * time.Second) {
			for name, e := range envs {
				e.mu.Lock()
				if e.up && time.Since(e.seen) > idle {
					if err := exec.Command("docker", "stop", "-t", "2", name).Run(); err == nil {
						e.up = false
						log.Printf("stopped %s: idle", name)
					}
				}
				e.mu.Unlock()
			}
		}
	}()
	log.Fatal(http.ListenAndServe("127.0.0.1:18090", nil))
}
