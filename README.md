# goha
A simple HTTP client supporting Basic and Digest access authentication.

## Installation

```bash
go get github.com/FeNoMeNa/goha
```

## Quick Start

```go
package main

import (
	"fmt"

	"github.com/FeNoMeNa/goha"
)

func main() {
	c := goha.NewClient("username", "password")

	resp, err := c.Get("http://localhost:8080/")

	if err != nil {
		return
	}

	fmt.Println(resp.StatusCode)
}
```
