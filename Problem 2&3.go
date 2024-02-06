package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func calcIC(text string) float64 {
	count := [26]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for _, i := range text {
		count[i-65] += 1
	}
	IC := 0.0
	for i := 0; i < 26; i++ {
		IC += float64(count[i] * (count[i] - 1))
	}
	IC = float64(IC) / float64((len(text) * (len(text) - 1)))

	return IC
}

func keylen(text string) int {
	best := 0.0
	result := 0
	for key := 1; key <= 20; key++ {
		total := 0.0
		for i := 0; i < key; i++ {
			IC := ""
			for j := i; j < len(text); j += key {
				IC += string(text[j])
			}
			total += calcIC(IC)
		}
		avg := total / float64(key)
		if avg > best {
			best = avg
			result = key
		}
	}
	return result
}

func analyze(text string, keylen int) string {
	key := ""

	for i := 0; i < keylen; i++ {
		split := ""
		for j := i; j < len(text); j += keylen {
			split += string(text[j])
		}
		key += decryptLetter(split)
	}

	return key
}

func decryptLetter(split string) string {
	for i := 0; i < 26; i++ {
		new := ""
		for _, j := range split {
			new += string((int(j)+i-65)%26 + 65)
		}
		if checkFreq(new) {
			return string(26 - i + 65)
		}
	}
	return "@"
}

func checkFreq(split string) bool {
	f := make([]int, 26)
	for _, i := range split {
		f[int(i)-65]++
	}
	max := 0
	letter := ""
	for i := 0; i < 26; i++ {
		if f[i] > max {
			max = f[i]
			letter = string(i + 65)
		}
	}
	if letter == "E" {
		return true
	}
	return false
}

// Main function
func main() {
	op := os.Args[1]
	filename := os.Args[2]
	file, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("reading file failed")
		return
	}
	data := string(file[:])
	data = strings.ToUpper(regexp.MustCompile("[^a-zA-Z]+").ReplaceAllString(data, ""))

	switch op {
	case "vigenere-cryptanalyze":
		keylength, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Println("Keylength should be int type")
		}
		key := analyze(data, keylength)
		fmt.Printf("The most possible key is %s\n", key)
	case "vigenere-keylength":
		k := keylen(data)
		fmt.Printf("The most possible key length is %d\n", k)
	default:
		fmt.Println("Invalid operation")
		return
	}
}
