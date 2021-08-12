package main

import (
	"embed"
	"fmt"
	"log"
)

//go:embed certs/*
var content embed.FS

func main() {
	files, err := content.ReadDir("certs")
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		fmt.Println(file.Name())
	}
}
