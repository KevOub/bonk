package main

import (
	"log"

	"github.com/fsnotify/fsnotify"
)

func WatchAudit(path string) {
	// create new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// add path to log
	watcher.Add(path)
	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("modified file:", event.Name)

				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	// err = watcher.Add("/tmp/foo")
	// if err != nil {
	// log.Fatal(err)
	// }
	<-done
}

func init() {
	WatchAudit("/var/log/audit/audit.log")
}

func main() {

}
