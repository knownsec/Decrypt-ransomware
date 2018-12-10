#!/usr/bin/env python3

import time, os, re, sys
import filetype
import json
from Crypto.Cipher import AES
from multiprocessing import Process, Queue

printablestr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
printstr2 = "ABCDEFGHIJPQRSTUVWdefghijklmnopqrstuvwx3456789"

def getrandstr(seed: int) -> str:
    rand = Random(seed)
    strlist = [printablestr[rand.random()%0x3e] for _ in range(60)]
    return "".join(strlist)
    
def gensession(seed: int) -> str:
    rand = Random(seed)
    strlist = [printstr2[rand.random()%0x2e] for _ in range(0x10)]
    return "".join(strlist)

class Random:
    def __init__(self, seed):
        self.seed = seed
    def random(self):
        self.seed = 214013 * self.seed + 2531011
        return (self.seed >> 16)&0x7FFF

class DecryptFile:
    def __init__(self, filename, key=None, timestamp=None):
        # self.filename = filename
        regex = rb"(\[[\w/\+=]+\]):(\[[\w/\+=]+\])"
        with open(filename, "rb") as f:
            data = f.read()
        t = re.findall(regex, data)
        if len(t) > 0:
            self.ckey = t[0][0][1:-1].decode()
            data = re.sub(regex, b"", data)
        else:
            self.ckey = None
        data_len = len(data)
        if data_len > 10000000:
            if data_len > 499999999:
                index = data_len // 1280 * 16
            elif data_len > 99999999:
                index = data_len // 480 * 16
            else:
                index = data_len // 80 * 16
            self.data = data[:index]
            self.mul_data = data[index:]
        else:
            pad = data_len % 0x10
            if pad > 0:
                self.mul_data = data[-pad:]
                data = data[:-pad]
            else:
                self.mul_data = b""
            self.data = data
        tmp = re.findall("\](.*)\.([A-Wd-x3-9]+)\.lucky", filename)
        if len(tmp) == 1:
            self.new_file = tmp[0][0]
            self.session = tmp[0][1]
            # assert len(self.session)==16, "error session: %s"%self.session
            self.dir = None
        else:
            self.new_file = None
            self.session = None
            self.dir = filename
        if key != None:
            self.key = key
        elif self.ckey in key_dict:
            self.key = key_dict[self.ckey]
        else:
            self.key = None
        if timestamp:
            self.timestamp = timestamp
        else:
            self.timestamp = int(os.stat(filename).st_mtime)

    def decryptfile(self) -> bool:
        assert(self.key), "Need key"
        assert(self.new_file), "Need new file"
        a = AES.new(self.key, AES.MODE_ECB)
        assert(len(self.data)%16 == 0)
        result = a.decrypt(self.data)
        result += self.mul_data
        # if not self.check_file2(result):
        #     return False
        with open("result/" + self.new_file, "wb") as f:
            f.write(result)
        return True

    def check_file(self, data: bytes) -> bool:
        for matcher in filetype.TYPES:
            if matcher.match(data):
                return True
        else:
            return False

    def check_file2(self, data: bytes) -> bool:
        return  b"]:[" == data[-20:-17]
    
    def run_session(self):
        assert(self.session), "Need Session"
        for x in range(1000000):
            tmp_session = gensession(self.timestamp - x)
            if tmp_session == self.session:
                self.timestamp = self.timestamp - x
                print("right session timestamp: %d"%self.timestamp)
                return True
        else:
            return False
    
    def run(self):
        if self.key:
            self.decryptfile()
        else:
            assert(self.timestamp), "Need timestamp!"
            # if not self.run_session():
            #     print("Bad!")
            #     print(self.session)
            #     return
            q = Queue()
            pro = Process(target=printn, args=(q,))
            pro.start()
            for x in range(2592000):
                q.put(x)
                skey = getrandstr(self.timestamp - x)
                self.key = skey[:32]
                if self.decryptfile():
                    print("success %d, key: %s"%(x, self.key))
                    pro.terminate()
                    return self.key
            else:
                pro.terminate()

def printn(que):
    while True:
        print("schedule: %d"%que.get(True), end="\r", flush=True)

def main(filename):
    key = None
    timestamp = None
    df = DecryptFile(filename, key, timestamp)
    k = df.run()
    ckey = df.ckey
    if ckey and ckey not in key_dict and k:
        key_dict[ckey] = k
        data = json.dumps(key_dict, indent=1)
        with open(sys.argv[1], "w") as f1:
            f1.write(data)

done = 0

def target_run(x):
    global done
    timestamp = 1543010556 - x
    session = "4dD3dD3tl6mtftQx"
    tmp_session = gensession(timestamp)
    if tmp_session == session:
        print("right: x => %d, timestamp: %d"%(x, timestamp))
        done = 1
        return True

def test():
    for x in range(1000000):
        if target_run(x):
            break
    # p = Pool(6)
    # r = p.imap(target_run, range(1000000))
    # while True:
    #     try:
    #         r.next()
    #     except StopIteration:
    #         break
    #     if done:
    #         p.close()
    #         break
        
if __name__ == "__main__":
    argc = len(sys.argv)
    if argc == 1:
        test()
        exit(0)
    with open(sys.argv[1], "r") as f:
        key_dict = json.loads(f.read())
    fname = sys.argv[2]
    if ".lucky" not in fname:
        for fn in os.listdir(fname):
            main(fname + fn)
    else:
        main(fname)

