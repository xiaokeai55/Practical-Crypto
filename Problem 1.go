package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func encrypt(k, text string) {
	cypherText := ""
	for i, s := range text {
		cypherText += string(((s + rune(k[i])) % 26) + 65) // A 65
	}
	fmt.Println(cypherText)
}

func decrypt(k, text string) {
	plainText := ""
	for i, s := range text {
		plainText += string(((s - rune(k[i]) + 26) % 26) + 65) // A 65
	}
	fmt.Println(plainText)
}

func keyGene(k, text string) string {
	new := ""
	length := len(text)
	for i := 0; i < length; i++ {
		if i == len(k) {
			i = 0
			length -= len(k)
		}
		new += string(k[i])
	}
	return new
}

// Main function
func main() {
	op := os.Args[1]

	key := strings.ToUpper(os.Args[2])
	if len(key) > 32 {
		fmt.Println("Invalid key length")
		return
	}
	filename := os.Args[3]
	file, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("reading file failed")
		return
	}
	data := string(file[:])
	data = strings.ToUpper(regexp.MustCompile("[^a-zA-Z]+").ReplaceAllString(data, ""))
	switch op {
	case "vigenere-encrypt":
		newkey := keyGene(key, data)
		encrypt(newkey, data)
	case "vigenere-decrypt":
		newkey := keyGene(key, data)
		decrypt(newkey, data)
	default:
		fmt.Println("Invalid operation")
		return
	}
}
