package main	

import (	
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"fmt"
	"crypto/tls"
	"bytes"

)

var chatUrl = "https://jch.irif.fr:8082/peers/"

func main() {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	req, err := http.NewRequest("GET", chatUrl, nil)
	if err != nil {
		log.Printf("NewRequest: %v", err)
		return
	}

	r, err := client.Do(req)
	if err != nil {
		log.Printf("Get: %v", err)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		log.Printf("Read: %v", err)
		return
	}
	
	//parser
	
	ids := bytes.Split(body, []byte{byte('\n')})
	fmt.Printf("%v\n",string(ids[0]))
	/*
	if len(ids) > 0 {
		last := len(ids) - 1
		if len(ids[last]) == 0 {
			ids = ids[:last-1] //?
		}
	}
	for i, id := range ids {
		fmt.Printf("Id %v: %v\n", i, string(id))
		
	}
	*/
}
