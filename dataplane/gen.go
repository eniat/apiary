package main

//go:generate go tool bpf2go -cc clang -type event redirect redirect.bpf.c
