// Command fidoprobe opens the attached security key and says what it is.
//
// It sends only CTAPHID_INIT, a ping, and -- when asked -- a wink. None of
// those creates, reads or changes a credential.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-macos/fido"
)

func main() {
	wink := flag.Bool("wink", false, "make the key blink, to show which one it is")
	flag.Parse()

	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()

	k, err := fido.Open(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fidoprobe: %v\n", err)
		os.Exit(1)
	}
	defer k.Close()
	fmt.Printf("key       %s\n", k)

	msg := []byte("go-macos/fido")
	echo, err := k.Ping(ctx, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fidoprobe: ping: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(echo, msg) {
		fmt.Fprintf(os.Stderr, "fidoprobe: the key echoed %q, not %q\n", echo, msg)
		os.Exit(1)
	}
	fmt.Printf("ping      %d byte(s) echoed exactly\n", len(echo))

	if *wink {
		if err := k.Wink(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "fidoprobe: wink: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("wink      sent -- the key should have blinked")
	}
}
