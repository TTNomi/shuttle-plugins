package vmess

import (
	"math/rand"
	"time"
)

const delta int64 = 30

func GenerateTimestamp() int64 {
	return time.Now().Unix() + rand.Int63n(delta*2) - delta
}

func Roll(n int) int {
	return rand.Intn(n)
}
