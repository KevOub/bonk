package main

import (
	"fmt"

	fsnotify "github.com/go-fsnotify/fsnotify"
)

func main() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	//
	done := make(chan bool)

	//
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				fmt.Printf("EVENT! %#v\n", event)

				// watch for errors
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add("/Users/skdomino/Desktop/test.html"); err != nil {
		fmt.Println("ERROR", err)
	}

	<-done
}
