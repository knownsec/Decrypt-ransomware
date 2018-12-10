# Lucky malware decrypt tools

* cry32.lucky: lucky malware encrypt sample
* decrypt.py: python3 decrypt script
* Original examp/[nmare@cock.li]examp.txt.sk7U5SliVpjFwTHt.lucky file md5 value: 15685e6c264da29e5db60a6d75c4b33b

```
$ file cry32.lucky
cry32.lucky: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
$ pip3 install -r requirements.txt
$ mkdir result
$ python3 lucky-decrypt.py lucky-key.json examp/\[nmare@cock.li\]examp.txt.sk7U5SliVpjFwTHt.lucky
$ md5sum result/examp.txt
15685e6c264da29e5db60a6d75c4b33b  result/examp.txt
```

