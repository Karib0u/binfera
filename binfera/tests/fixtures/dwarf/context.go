package main

type Record struct {
    Count int
    Total int
}

//go:noinline
func update(record *Record, amount int) int {
    record.Count += amount
    record.Total += record.Count
    return record.Total
}

//go:noinline
func pair(value int) (int, int) { return value + 1, value + 2 }

func main() {
    record := Record{Count: 3}
    first, second := pair(4)
    println(update(&record, first), second)
}
