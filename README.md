DC test framework basic network library, can be used alone

```shell
dep ensure -add github.com/ykswang/dc-networking@v1.0.1
```

Document with godoc
```shell script
godoc -http=:8080
```
Go to  http://127.0.0.1:8080/pkg/github.com/ykswang/dc_network

Sample Code

```go
package main

import (
	"fmt"
	"testing"
	"github.com/ykswang/dc_network"
)

func TestGet(t *testing.T) {
	url := "http://freeapi.ipip.net/8.8.8.8"
	client := dc_network.NewHttpClient()
	fmt.Printf("[get]: --> %s\n", url)
	resp, err := client.Get(url, nil)
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	defer resp.Close()
	body, err := resp.ToString()
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	fmt.Printf("[get]: <-- [code: %d][body: %s]\n", resp.GetStatusCode(), body)
}

func TestTraceGet(t *testing.T) {
	url := "http://freeapi.ipip.net/8.8.8.8"
	client := dc_network.NewHttpClient()
	client.SetTrace(true)
	client.Transport.Proxy = nil    // Skip proxy
	fmt.Printf("[get]: --> %s\n", url)
	resp, err := client.Get(url, nil)
	if err != nil {
		t.Errorf("Request error: %+v\n", err)
	}
	defer resp.Close()
	body, err := resp.ToString()
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	fmt.Printf("[get]: <-- [code: %d][body: %s]\n", resp.GetStatusCode(), body)
	fmt.Printf("status code: %d\n", resp.GetStatusCode())
	fmt.Printf("------ trace info -----------\n")
	fmt.Printf("DNS: %.2fms\n", resp.TraceInfo.DNSDuration.Seconds()*1000.0)
	fmt.Printf("TLSHandshake: %.2fms\n", resp.TraceInfo.TLSHandshakeDuration.Seconds()*1000.0)
	fmt.Printf("TCPConnect: %.2fms\n", resp.TraceInfo.ConnectDuration.Seconds()*1000.0)
	fmt.Printf("ServerProcess: %.2fms\n", resp.TraceInfo.ServerDuration.Seconds()*1000.0)
	fmt.Printf("Total: %.2fms\n", resp.TraceInfo.TotalDuration.Seconds()*1000.0)
}

func TestPostForm(t *testing.T) {
	url := "https://jsonplaceholder.typicode.com/posts"
	client := dc_network.NewHttpClient()
	bodyMap := map[string]string{"name": "www.baidu.com"}
	fmt.Printf("[post]: --> [url: %s][body: %+v]\n", url, bodyMap)
	resp, err := client.PostForm(url,nil, bodyMap)
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	defer resp.Close()
	body, err := resp.ToString()
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	fmt.Printf("[post]: <-- [code: %d][body: %s]\n", resp.GetStatusCode(), body)
}

func TestPostString(t *testing.T) {
	url := "https://jsonplaceholder.typicode.com/posts"
	client := dc_network.NewHttpClient()
	bodyString := "www.baidu.com"
	fmt.Printf("[post]: --> [url: %s][body: %s]\n", url, bodyString)
	resp, err := client.PostString(url,nil, bodyString)
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	defer resp.Close()
	body, err := resp.ToString()
	if err != nil {
		t.Errorf("IO error: %+v\n", err)
	}
	fmt.Printf("[post]: <-- [code: %d][body: %s]\n", resp.GetStatusCode(), body)
}
```