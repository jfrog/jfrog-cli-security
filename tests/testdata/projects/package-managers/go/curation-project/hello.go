package main

import (
	"fmt"

	"example.com/localmod"
	"rsc.io/quote"
)

func main() {
	fmt.Println(quote.Hello())
	fmt.Println(localmod.Hello())
}
