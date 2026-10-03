package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	port := flag.String("port", "8081", "Port to listen on")
	serviceName := flag.String("name", "internal-admin-service", "Service name")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		resp := map[string]any{
			"service":        *serviceName,
			"path":           r.URL.Path,
			"method":         r.Method,
			"received_user":  r.Header.Get("X-ZTNA-Subject"),
			"received_email": r.Header.Get("X-ZTNA-Email"),
			"received_roles": r.Header.Get("X-ZTNA-Roles"),
			"device_trust":   r.Header.Get("X-ZTNA-Device-Trust"),
			"request_id":     r.Header.Get("X-ZTNA-Request-ID"),
			"all_headers":    headers,
		}

		log.Printf("[%s] Request served for user: %s (req_id: %s)\n",
			*serviceName, r.Header.Get("X-ZTNA-Subject"), r.Header.Get("X-ZTNA-Request-ID"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf(":%s", *port)
	log.Printf("[INFO] Upstream mock service %q listening on %s\n", *serviceName, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Service stopped: %v", err)
	}
}
