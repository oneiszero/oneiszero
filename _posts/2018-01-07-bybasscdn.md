#绕过CDN查找网站真实IP的一些方法

## 0x00 前言

现在很多大网站基本上都使用了CDN进行加速访问，方便快速响应用户的请求，提高用户访问体验。这种做法对于我们日常的渗透测试来说，CDN的虚假IP确实很干扰我们的测试。如何绕过CDN，找到网站的真实IP，对于从事安全行业的人员来说至关重要。

## 0x01 验证是否存在CDN

### ping
假设如下存在cdn
➜ ~ ping www.xxx.xyz

PING 539b1c6d114eec86.360safedns.com (221.221.221.221): 56 data bytes

Request timeout for icmp_seq 0

Request timeout for icmp_seq 1

Request timeout for icmp_seq 2

很多厂商可能让www使用cdn，空域名不使用CDN缓存。
所以直接ping xxx.com可能就能得到真实IP

###多地ping服务
使用各种多地 ping 的服务，查看对应 IP 地址是否唯一，如果不唯一多半是使用了CDN， 多地 Ping 网站有：

http://ping.chinaz.com/ 

http://ping.aizhan.com/

http://ce.cloud.360.cn/


## 0x02绕过CDN查找网站真实IP
###查询历史DNS记录
查看 IP 与 域名绑定的历史记录，可能会存在使用 CDN 前的记录，相关查询网站有：

https://dnsdb.io/zh-cn/

https://x.threatbook.cn/

http://toolbar.netcraft.com/site_report?url=

http://viewdns.info/


###让服务器主动连接
* 在可上传图片的地方利用目标获取存放在自己服务器的图片，或者任何可pull自己资源的点，review log即可拿到。

* 通过注册等方式让目标主动发邮件过来，此时查看邮件源码里面就会包含服务器的真实 IP 了。此方法对于大公司几率小，因为出口可能是统一的邮件服务器。可以尝试扫其MailServer网段。

* rss订阅：一般也会得到真实的IP地址，通过rss订阅的方式，可以查找到订阅的消息中真实IP。 

* 利用网站漏洞，如phpinfo之类的探针、XSS盲打、命令执行反弹shell、SSRF。


### 查询子域名
毕竟 CDN 还是不便宜的，所以很多站长可能只会对主站或者流量大的子站点做了 CDN，而很多小站子站点又跟主站在同一台服务器或者同一个C段内，此时就可以通过查询子域名对应的 IP 来辅助查找网站的真实IP。

### nslookup
由于cdn不可能覆盖的非常完全，那么可以采用国外多地ping的方式，或者多收集一些小国家的冷门dns然后nslookup domain.com dnsserver。

提示：要找国外冷门DNS才行，像谷歌的DNS，国内用的人越来越多了，很多CDN提供商都把谷歌DNS作为国内市场之一，所以，你查到的结果会和国内差不了多少。或者查询域名的NS记录，其域名记录中的MX记录，TXT记录等很有可能指向的是真实ip或同C段服务器。

首先收集好偏门的dns字典，然后轮训一个目标的方式，输出这些dns查询出的不同结果。Bypass CDN脚本如下：
https://gist.github.com/Tr3jer/98f66fe250eb8b39667f0ef85e4ce5e5

```
#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#__author__ == Tr3jer_CongRong

import re
import sys
import time
import threading
import dns.resolver

class Bypass_CDN:

    def __init__(self,domain,dns_dict):
        self.domain = domain
        self.myResolver = dns.resolver.Resolver()
        self.dns_list = set([d.strip() for d in open(dns_dict)])
        self.good_dns_list,self.result_ip = set(),set()

    def test_dns_server(self,server):
        self.myResolver.lifetime = self.myResolver.timeout = 2.0
        try:
            self.myResolver.nameservers = [server]
            sys.stdout.write('[+] Check Dns Server %s \r' % server)
            sys.stdout.flush()
            answer = self.myResolver.query('google-public-dns-a.google.com')
            if answer[0].address == '8.8.8.8':
                self.good_dns_list.add(server)
        except:
            pass

    def load_dns_server(self):
        print '[+] Load Dns Servers ...'
        threads = []
        for i in self.dns_list:
            threads.append(threading.Thread(target=self.test_dns_server,args=(i,)))
        for t in threads:
            t.start()
            while True:
                if len(threading.enumerate()) < len(self.dns_list) / 2:
                    break
                else:
                    time.sleep(1)
        print '\n[+] Release The Thread ...'
        for j in threads: j.join()
        print '[+] %d Dns Servers Available' % len(self.good_dns_list)

    def ip(self,dns_server):
        self.myResolver.nameservers = [dns_server]
        try:
            result = self.myResolver.query(self.domain)
            for i in result:
                self.result_ip.add(str(i.address))
        except:
            pass

    def run(self):
        self.load_dns_server()
        print '[+] Dns Servers Test Target Cdn ...'
        threads = []
        for i in self.good_dns_list:
            threads.append(threading.Thread(target=self.ip,args=(i,)))
        for t in threads:
            t.start()
            while True:
                if len(threading.enumerate()) < len(self.good_dns_list) / 2:
                    break
                else:
                    time.sleep(1)
        for j in threads: j.join()
        for i in self.result_ip: print i

if __name__ == '__main__':
    dns_dict = 'foreign_dns_servers.txt'
    bypass = Bypass_CDN(sys.argv[1],dns_dict)
    bypass.run()
 
```



## 0x03参考
https://xianzhi.aliyun.com/forum/topic/265/

http://xiaix.me/rao-guo-cdncha-zhao-wang-zhan-zhen-shi-ip/

 
 
    
 
 
 



