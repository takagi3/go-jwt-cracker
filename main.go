package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"
)

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwt struct {
	header             *jwtHeader
	payload            string
	message, signature []byte
}

func parseJWT(input string) (*jwt, error) {
	parts := strings.Split(input, ".")
	decodedParts := make([][]byte, len(parts))
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt: does not contain 3 parts (header, payload, signature)")
	}
	for i := range parts {
		decodedParts[i] = make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[i])))
		if _, err := base64.RawURLEncoding.Decode(decodedParts[i], []byte(parts[i])); err != nil {
			return nil, err
		}
	}
	var parsedHeader jwtHeader
	if err := json.Unmarshal(decodedParts[0], &parsedHeader); err != nil {
		return nil, err
	}
	return &jwt{
		header:    &parsedHeader,
		payload:   string(decodedParts[1]),
		message:   []byte(parts[0] + "." + parts[1]),
		signature: decodedParts[2],
	}, nil
}

func generateSignature(message, secret []byte) []byte {
	hasher := hmac.New(sha256.New, secret)
	hasher.Write(message)
	return hasher.Sum(nil)
}

func generateSecrets(alphabet string, n int, jobs chan<- string, done <-chan struct{}) {
	if n <= 0 {
		close(jobs)
		return
	}

	var helper func(string)
	helper = func(input string) {
		if len(input) == n {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		for _, char := range alphabet {
			s := input + string(char)
			select {
			case <-done:
				return
			case jobs <- s:
			}
			helper(s)
		}
	}
	helper("")
	close(jobs)
}

func main() {
	token := flag.String("token", "", "The full HS256 jwt token to crack")
	alphabet := flag.String("alphabet", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "The alphabet to use for the brute force")
	prefix := flag.String("prefix", "", "A string that is always prefixed to the secret")
	suffix := flag.String("suffix", "", "A string that is always suffixed to the secret")
	maxLength := flag.Int("maxlen", 12, "The max length of the string generated during the brute force")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
	flag.Parse()

	if *token == "" {
		fmt.Println("Parameter token is empty\n")
		flag.Usage()
		return
	}
	if *alphabet == "" {
		fmt.Println("Parameter alphabet is empty\n")
		flag.Usage()
		return
	}
	if *maxLength == 0 {
		fmt.Println("Parameter maxlen is 0\n")
		flag.Usage()
		return
	}

	parsed, err := parseJWT(*token)
	if err != nil {
		fmt.Printf("Could not parse JWT: %v\n", err)
		return
	}

	fmt.Printf("Parsed JWT:\n- Algorithm: %s\n- Type: %s\n- Payload: %s\n- Signature (hex): %s\n\n",
		parsed.header.Algorithm,
		parsed.header.Type,
		parsed.payload,
		hex.EncodeToString(parsed.signature))

	if strings.ToUpper(parsed.header.Algorithm) != "HS256" {
		fmt.Println("Unsupported algorithm")
		return
	}

	combinations := big.NewInt(0)
	for i := 1; i <= *maxLength; i++ {
		alen, mlen := big.NewInt(int64(len(*alphabet))), big.NewInt(int64(i))
		combinations.Add(combinations, alen.Exp(alen, mlen, nil))
	}
	fmt.Printf("There are %s combinations to attempt\nCracking JWT secret...\n", combinations.String())

	done := make(chan struct{})
	jobs := make(chan string, 1000)
	var wg sync.WaitGroup
	var found bool
	var attempts uint64
	var mu sync.Mutex

	// プログレスバー表示用ゴルーチン
	stopProgress := make(chan struct{})
	go func() {
		barWidth := 40
		var lastAttempts uint64
		for {
			select {
			case <-stopProgress:
				return
			default:
			}
			mu.Lock()
			progress := float64(attempts) / float64(combinations.Int64())
			if progress > 1.0 {
				progress = 1.0
			}
			filled := int(progress * float64(barWidth))
			bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
			percent := int(progress * 100)
			hashesPerSec := attempts - lastAttempts
			remaining := combinations.Uint64() - attempts
			var etaStr string
			if hashesPerSec > 0 {
				etaSec := int(remaining / hashesPerSec)
				h := etaSec / 3600
				m := (etaSec % 3600) / 60
				s := etaSec % 60
				if h > 0 {
					etaStr = fmt.Sprintf("ETA: %dh%02dm%02ds", h, m, s)
				} else if m > 0 {
					etaStr = fmt.Sprintf("ETA: %dm%02ds", m, s)
				} else {
					etaStr = fmt.Sprintf("ETA: %ds", s)
				}
			} else {
				etaStr = "ETA: --"
			}
			fmt.Printf("\r[%s] %3d%% (%d/%s) %d hashes/sec %s", bar, percent, attempts, combinations.String(), hashesPerSec, etaStr)
			lastAttempts = attempts
			mu.Unlock()
			runtime.Gosched()
			time.Sleep(1 * time.Second)
		}
	}()

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for secret := range jobs {
				select {
				case <-done:
					return
				default:
				}
				mu.Lock()
				attempts++
				mu.Unlock()
				if bytes.Equal(parsed.signature, generateSignature(parsed.message, []byte(*prefix+secret+*suffix))) {
					mu.Lock()
					if !found {
						fmt.Printf("\n\nFound secret in %d attempts: %s\n", attempts, *prefix+secret+*suffix)
						found = true
						close(done)
					}
					mu.Unlock()
					return
				}
			}
		}()
	}

	go generateSecrets(*alphabet, *maxLength, jobs, done)

	wg.Wait()
	close(stopProgress)
	if !found {
		fmt.Printf("\nNo secret found in %d attempts\n", attempts)
	}
}
