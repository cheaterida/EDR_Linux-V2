// Package bpf loads the CO-RE probes with cilium/ebpf and decodes ring-buffer
// records into edr/internal/event values.
//
// The generated bindings (bpf_bpfel.go / bpf_bpfel.o) are produced by
// `go generate ./internal/bpf/` and checked in so ordinary builds do not need
// clang or a vmlinux.h.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I./probes -I/usr/include" bpf ./probes/probes.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I./probes -I/usr/include" lsm ./probes/lsm.bpf.c
