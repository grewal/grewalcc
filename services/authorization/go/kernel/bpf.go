// FILE: services/authorization/go/kernel/bpf.go
package kernel

// This go:generate directive is the bridge between our C and Go code.
// It invokes the bpf2go tool from the cilium/ebpf library to compile
// our C-based eBPF program (firewall.c) and embed it as a Go byte slice
// into a new, auto-generated file (firewall_bpfel.go).
//
// This makes our build process self-contained and reproducible.
// Run `go generate ./...` from the `go` directory to execute this.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" firewall firewall.c -- -I/usr/include/bpf
