// Command lys-secrets is the lys desktop's freedesktop Secret Service.
package main

import "fmt"

func main() {
	fmt.Println(greet("world"))
}

func greet(name string) string {
	return "hello, " + name
}
