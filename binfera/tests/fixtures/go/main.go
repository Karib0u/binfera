// The Go register ABI fixture for the decompiler tests: build.sh builds it for Windows x86-64.
package main

import (
	"os"
	"strings"
)

type Config struct {
	Host string
	Port int
}

//go:noinline
func greet(name string, times int) string {
	var b strings.Builder
	for i := 0; i < times; i++ {
		b.WriteString("hello ")
		b.WriteString(name)
	}
	return b.String()
}

//go:noinline
func (c *Config) Ready() bool {
	return c.Port != 0 && strings.HasPrefix(c.Host, "example")
}

//go:noinline
func readFirst(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 16)
	n, err := f.Read(buf)
	return buf[:n], err
}

func main() {
	c := &Config{Host: "example.org", Port: len(os.Args)}
	if !c.Ready() {
		os.Exit(2)
	}
	os.Stdout.WriteString(greet(c.Host, 2))
	data, _ := readFirst(os.Args[0])
	os.Exit(len(data))
}
