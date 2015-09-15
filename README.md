# httpcap
HTTP traffic analyzer 

build 

```
sudo apt-get install libpcap-dev

git https://github.com/kshvakov/httpcap.git && cd httpcap

go build --ldflags '-extldflags "-static" -s' 
```

use 

```
httpcap -h
Usage of /httpcap:
  -bpf_filter string
         (default "tcp and port 80")
  -device string
         (default "lo")
  -response_codes string
        20x 30x 40x etc
  -slow_request_time int
        in milliseconds

sudo httpcap 

-[ QUERY 0.000782 s]-:
Code:200
Method:GET
RequestUri:/login/


-[ QUERY 0.000681 s]-:
Code:200
Method:GET
RequestUri:/login/


-[ QUERY 0.000689 s]-:
Code:405
Method:PUT
RequestUri:/login/


-[ QUERY 0.000579 s]-:
Code:301
Method:GET
RequestUri:/login

```