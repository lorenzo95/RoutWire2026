package main

import (
	"fmt"
	"os"

	"routewire/internal/mesh"
)

func main() {
	d := mesh.NewDeriver(os.Args[1])
	for _, n := range os.Args[2:] {
		k, err := d.NodeWGKey(n)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s priv=%s pub=%s\n", n, k.String(), k.PublicKey().String())
	}
}
