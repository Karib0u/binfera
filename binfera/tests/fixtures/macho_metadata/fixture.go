package main

//go:noinline
func combine(left, right int64) int64 { return left*3 + right }
func main() { println(combine(12, 7)) }
