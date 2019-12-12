package main

import (
	"fmt"
	"os"

	"github.com/gaterace/safebox/pkg/sssa"
)

// command line utility to generate 3 secrets from a master key,
// any two of which can reconstruct the master key
func main() {

	if (len(os.Args) != 2) || (len(os.Args[1]) != 32) {
		fmt.Printf("master key not supplied or length not 32\n")
		fmt.Printf("Usage: %s <master_key>\n", os.Args[0])
		os.Exit(1)
	}
	secret := os.Args[1]

	shares, err := sssa.Create(2, 3, secret)

	if err != nil {
		panic(err)
	}

	for k, share := range shares {
		if sssa.IsValidShare(share) {
			fmt.Printf("k: %d, share: %s\n", k, share)
		} else {
			fmt.Printf("k: %d is invalid\n", k)
		}
	}

	recover, err := sssa.Combine(shares[0:2])
	if err != nil {
		panic(err)
	}

	fmt.Printf("recover: %s\n", recover)

}
