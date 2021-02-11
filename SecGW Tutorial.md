# disclaimer
Данная статья описывает базовые принципы настройки SRX и StrongSwan. Однако при грамотной настройки SRX в части firewall эту конфигурацию можно использовать.
# Настройка SecGW для аутентификации по сертификатам 
[original on juniper.net](https://www.juniper.net/documentation/en_US/release-independent/nce/topics/example/pki-example-pki-in-junos-configuring.html)
## Настройки для SecGW
#### Создаем профиль на SecGW
`set security pki ca-profile myCA ca-identity vSRX_root_CA_A1`
`set security pki ca-profile myCA revocation-check disable`
#### Создаем ключ на SecGW
`request security pki generate-key-pair certificate-id myCert size 1024 type rsa`
#### Создаем Certificate request с SecGW
`request security pki generate-certificate-request certificate-id myCert subject "CN=vsrx3 OU=VPN_Father, O=Internet Inc, L=Moscow,ST=RU,C=RU" filename myCert-req domain-name vsrx3`

```
Generated certificate request
-----BEGIN CERTIFICATE REQUEST-----
MIIBvTCCASYCAQAwWjEVMBMGA1UEAxMMdnNyeDMgT1U9UkFOMRYwFAYDVQQKEw1J
bGRpeWFyb3YgSW5jMQ8wDQYDVQQHEwZNb3Njb3cxCzAJBgNVBAgTAlJVMQswCQYD
VQQGEwJSVTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2g2m5UKtJbGCjWOC
a1ILbiFXSFGlUn8fuwlm0jOAjy7/W1V4IxwAaoXQc7ipQMPIqvnXu1AnSdsPmal+
Y8P6dsohsfxNWWeRydcmLt2GQwFmQxSxiwlLMvGtuNeerQDw2c40LY0F+SgllKI1
0LsZQkBNIN3olsQ2d3cYrDRj+F8CAwEAAaAjMCEGCSqGSIb3DQEJDjEUMBIwEAYD
VR0RBAkwB4IFdnNyeDMwDQYJKoZIhvcNAQEFBQADgYEAFRBQh1Ek9GRorVahLV7J
vzZ8sb9I5k+RqaHQ9m9cJbG9zAjuV7S0JPlTkBKByZx8LDa6IJFjQYr5gLRnYMjD
goruBZyCCwhLeM1G2ru7GG2Wv0hdbg+TMfQwR9qFfJISvNj2DFJcONXkHlFy0OKR
AJdZZZf3lHP7Oj5Q40kOGwO=
-----END CERTIFICATE REQUEST-----
Fingerprint:
48:c3:8e:db:93:ad:bc:62:77:aa:2b:e4:2d:06:f3:4e:5a:3e:07:1c (sha1)
fd:46:cd:01:14:e3:3d:45:85:b2:71:7e:be:4b:db:6a (md5)
```

```
root@vSRX3> show security pki certificate-request certificate-id myCert
Certificate identifier: myCert
 Issued to: vsrx3 OU=VPN_Father
 Public key algorithm: rsaEncryption(1024 bits)
```
На Linux машине с openssl
`OpenSSL 1.1.1 11 Sep 2018`

#### Создаем свой Certificate Authority
Первая команда создаёт корневой ключ, тот самый секретный.
`openssl genrsa -out rootCA.key 2048`

```
root@train:/home/megapuser/vsrx3_ca# openssl genrsa -out rootCA.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
...................+++++
..........................................................+++++
e is 65537 (0x010001)
```

#### Вторая команда создаёт корневой сертификат.
openssl req -x509 -new -key rootCA.key -days 10000 -out rootCA.crt

```
root@train:/home/megapuser/vsrx3_ca# openssl req -x509 -new -key rootCA.key -days 10000 -out rootCA.crt
Can't load /root/.rnd into RNG
140142071431616:error:2406F079:VPN_Fatherdom number generator:VPN_FatherD_load_file:Cannot open file:../crypto/VPN_Fatherd/VPN_Fatherdfile.c:88:Filename=/root/.rnd
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:RU
State or Province Name (full name) [Some-State]:RU
Locality Name (eg, city) []:Moscow
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Internet Inc
Organizational Unit Name (eg, section) []:VPN_Father
Common Name (e.g. server FQDN or YOUR name) []:root_ca
Email Address []:
```
Запрос на сертификат (CSR). что сделали на SRX надо скопировать на linux и вставить в новый файл, к примеру `myCert.req`
Затем подписать CSR командой:
`openssl x509 -req -in myCert.req -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out vsrx3_secgw.crt -days 5000`

```
Signature ok
subject=CN = vsrx3 OU=VPN_Father, O = Internet Inc, L = Moscow, ST = RU, C = RU
Getting CA Private Key
```

Получаем файлы:
```
root@train:/home/megapuser/vsrx3_ca# ls -la
total 28
drwxr-xr-x 2 megapuser megapuser 4096 Feb 11 08:30 ./
drwxr-xr-x 19 megapuser megapuser 4096 Feb 11 08:26 ../
-rw-r--r-- 1 megapuser megapuser 680 Feb 11 08:26 myCert.req
-rw-r--r-- 1 megapuser megapuser 1326 Feb 11 08:28 rootCA.crt
-rw------- 1 megapuser megapuser 1675 Feb 11 08:27 rootCA.key
-rw-r--r-- 1 megapuser megapuser  41 Feb 11 08:30 rootCA.srl
-rw-r--r-- 1 megapuser megapuser 1013 Feb 11 08:30 vsrx3_secgw.crt
```
Копируем на vSRX файлы vsrx3_secgw.crt и rootCA.crt
local certificate — vsrx3_secgw.crt 
CA certificate — rootCA.crt
### Устанавливаем сертификаты в SRX
#### Локальный сертификат
```
request security pki local-certificate load certificate-id myCert filename /var/tmp/vsrx3_secgw.crt 
Local certificate loaded successfully
```
#### CA сертификат
```
request security pki ca-certificate load ca-profile myCA filename /var/tmp/rootCA.crt
Fingerprint:
 9a:59:d8:c3:6f:01:01:64:43:f5:ad:98:bb:9d:b6:d1:25:fe:80:2e (sha1)
 a8:82:78:85:7f:02:c5:ef:6a:33:2c:dd:be:12:f9:d1 (md5)
Do you want to load this CA certificate ? [yes,no] (no) yes
CA certificate for profile myCA loaded successfully
```

## Проверка 
#### Локальный сертификат
`show security pki local-certificate certificate-id myCert detail`
#### CA сертификат
`show security pki ca-certificate ca-profile myCA detail`
### Verify 
#### Локальный сертификат
```
request security pki local-certificate verify certificate-id myCert
Local certificate myCert verification success
```
#### CA сертификат
```
request security pki ca-certificate verify ca-profile myCA
CA certificate myCA verified successfully
```

## Configuring IPsec VPN
Juniper said:
>The steps for configuring a VPN using a certificate are similar to the steps for configuring a VPN using preshared keys. The only difference is the authentication method used for the IKE (Phase 1) policy. No changes are required for the IPsec (Phase 2) configuration because the use of certificates is part of Phase 1 negotiations.

Это значит. что если у вас уже создана vpn ipsec конфигурация, то она не затрагивается, меняется только ike
Конфигурация SecGW для примера, в идеале в таком виде на product лучше не использовать так как тут неверно настроены правила фаерволла.

На SecGW есть 2 интерфейса, ge-0/0/0 предоставляет интернет доступ.
ge-0/0/1 смотрит во "внутреннюю" сеть и принимает IKЕ т.е. к нему устанавливается IPsec.
```
 Logical interface ge-0/0/0.0
  Flags: Up SNMP-Traps 0x4000 Encapsulation: ENET2
  Security: Zone: untrust
  Allowed host-inbound traffic : http ping ssh
  inet 10.90.3.33/24
 Logical interface ge-0/0/1.0
  Flags: Up SNMP-Traps 0x4000 Encapsulation: ENET2
  Security: Zone: trust
  Allowed host-inbound traffic : ike ping ssh
  inet 192.168.1.1/24
```
Пример конфигурации для SecGW
```
set access profile RADIUS authentication-order radius
set access profile RADIUS radius-server 192.168.1.5 port 1712
set access profile RADIUS radius-server 192.168.1.5 secret "$9$TF/t1IcMLNDikPQzAtWL.........."
set access profile RADIUS radius-server 192.168.1.5 source-address 192.168.1.1
set access profile RADIUS radius-server 192.168.1.5 routing-instance vr-oam
set security ike proposal rsa-prop1 authentication-method rsa-signatures <-- main point
set security ike proposal rsa-prop1 encryption-algorithm aes-256-cbc
set security ike proposal rsa-prop1 authentication-algorithm sha-256
set security ike proposal rsa-prop1 dh-group group19
set security ike proposal rsa-prop1 lifetime-seconds 600
set security ike policy ike-policy1 mode aggressive
set security ike policy ike-policy1 proposals rsa-prop1
set security ike policy ike-policy1 certificate local-certificate myCert <-- main point
set security ike policy ike-policy1 certificate peer-certificate-type x509-signature <-- main point
set security ike gateway ike-gate ike-policy ike-policy1
set security ike gateway ike-gate dynamic distinguished-name wildcard "C=RU, ST=RU, L=Moscow, O=Internet Inc" <-- main point
set security ike gateway ike-gate dynamic ike-user-type group-ike-id
set security ike gateway ike-gate local-identity distinguished-name
set security ike gateway ike-gate external-interface ge-0/0/1.0
set security ike gateway ike-gate aaa access-profile RADIUS
set security ike gateway ike-gate version v2-only
set security ike gateway ike-gate dead-peer-detection interval 60
set security ike gateway ike-gate dead-peer-detection threshold 5
set security ipsec proposal ipsec-proposal-2 protocol esp
set security ipsec proposal ipsec-proposal-2 authentication-algorithm hmac-sha-256-128
set security ipsec proposal ipsec-proposal-2 encryption-algorithm aes-256-cbc
set security ipsec proposal ipsec-proposal-2 lifetime-seconds 900
set security ipsec policy ipsec-policy perfect-forward-secrecy keys group14
set security ipsec policy ipsec-policy proposals ipsec-proposal-2
set security ipsec vpn ipsec-vpn bind-interface st0.0
set security ipsec vpn ipsec-vpn ike gateway ike-gate
set security ipsec vpn ipsec-vpn ike no-anti-replay
set security ipsec vpn ipsec-vpn ike proxy-identity local 0.0.0.0/0
set security ipsec vpn ipsec-vpn ike proxy-identity remote 0.0.0.0/0
set security ipsec vpn ipsec-vpn ike proxy-identity service any
set security ipsec vpn ipsec-vpn ike ipsec-policy ipsec-policy
commit check
commit
```
## Настройки для StrongSwan
##### Сначала создаем ключ и CSR
`openssl req -new -newkey rsa:1024 -nodes -keyout client1.key -out client1.csr`

###### На сервер Linux где создавали корневой сертификат нужно подписать запрос от клиента.
т.е. копируем файл client1.csr на машину где создавали CA. Подписываем CSR выполнив команду ниже.
`openssl x509 -req -in client1.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out client1.crt -days 5000`
```
Signature ok
subject=C = RU, ST = RU, L = Moscow, O = Internet Inc, OU = VPN_Father, CN = client  <-- это то, что мы вбивали при генерации CSR.
Getting CA Private Key
```
##### Конвертация .crt to .pem. 
_Необязательный шаг конвертации_


`openssl x509 -in client1.crt -out client1.pem -outform PEM`<br>
`openssl x509 -in rootCA.crt -out rootCA.pem -outform PEM`<br>
`cp rootCA.pem /etc/ipsec.d/cacerts/`<br>
`cp client1.pem /etc/ipsec.d/certs/`<br>
`cp client1.key /etc/ipsec.d/client1.key.pem  <-- it is the same format. I think do not need to convert them if you see lines -----BEGIN CERTIFICATE--- and so on... base64`<br>

##### Добавляем новую запись в файл ipsec.secret
в нем указываем, что для RSA аутентификации будем использовать ключ, что мы сгенерили, при создании CSR.\s\s
Слева от __:__ ничего нет, кроме пробела
`" : RSA client1.key.pem"`
```
conn vsrx1
 leftcert=client1.pem
 leftsendcert=always
 rightauth=pubkey
 leftauth=pubkey
 leftid="CN=client1 OU=VPN_Father, O=Internet Inc, L=Moscow, ST=RU, C=RU"
 rightid="CN=vsrx3 OU=VPN_Father, O=Internet Inc, L=Moscow, ST=RU, C=RU"
 left=192.168.1.100
 right=192.168.1.1
 leftsubnet=172.16.0.2/32
 rightsubnet=0.0.0.0/0
 type=tunnel
 keyexchange=ikev2
 auto=start
 ike=aes256-sha256-prfsha256-ecp256
 esp=aes256-sha256-ecp256
 closeaction=restart
```
На этом конфигурация SecGW и StrongSwan завершена.<br>
можно выполнить команду `ipsec restart` и затем посмотреть статус туннеля.
```
root@user-virtual-machine:/home/user# ipsec statusall
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.15.0-122-generic, x86_64):
 uptime: 26 minutes, since Feb 11 18:30:25 2021
 malloc: sbrk 2568192, mmap 0, used 387376, free 2180816
 worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 8
 loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 VPN_Fatherdom nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
Listening IP addresses:
 192.168.1.100
Connections:
    vsrx1: 192.168.1.100...192.168.1.1 IKEv2
    vsrx1:  local: [C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=client] uses public key authentication
    vsrx1:  cert: "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=client"
    vsrx1:  remote: [CN=vsrx3 OU=VPN_Father, O=Internet Inc, L=Moscow, ST=RU, C=RU] uses public key authentication
    vsrx1:  child: 172.16.0.2/32 === 0.0.0.0/0 TUNNEL
Security Associations (1 up, 0 connecting):
    vsrx1[3]: ESTABLISHED 5 minutes ago, 192.168.1.100[C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=client]...192.168.1.1[CN=vsrx3 OU=VPN_Father, O=Internet Inc, L=Moscow, ST=RU, C=RU]
    vsrx1[3]: IKEv2 SPIs: 14ad5a62a803228d_i* d16b198946436497_r, public key reauthentication in 2 hours
    vsrx1[3]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256
    vsrx1{3}: INSTALLED, TUNNEL, reqid 2, ESP SPIs: c22ed726_i de5b6a8d_o
    vsrx1{3}: AES_CBC_256/HMAC_SHA2_256_128, 1287962 bytes_i (902 pkts, 12s ago), 22103 bytes_o (294 pkts, 12s ago), rekeying in 37 minutes
    vsrx1{3}:  172.16.0.2/32 === 0.0.0.0/0
```
далее я привожу пример всех не пустых ipsec list* команд со стороны strongswan.
```
root@user-virtual-machine:/home/user# ipsec listcerts
List of X.509 End Entity Certificates:
 subject: "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=client"
 issuer:  "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=root_ca"
 serial:  74:eb:46:98:d5:f1:d6:6d:25:32:e3:16:5d:3b:0f:63:74:00:ef:3d
 validity: not before Feb 11 16:03:41 2021, ok
       not after Oct 21 17:03:41 2034, ok
 pubkey:  RSA 1024 bits, has private key
 keyid:   28:48:f3:14:d1:03:28:73:8d:ac:30:7a:ca:83:d9:79:44:22:d7:d8
 subjkey:  49:16:73:9a:b3:a5:cf:02:85:18:b8:84:a1:8c:18:f3:82:4e:48:17
 subject: "CN=vsrx3 OU=VPN_Father, O=Internet Inc, L=Moscow, ST=RU, C=RU"
 issuer:  "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=root_ca"
 serial:  74:eb:46:98:d5:f1:d6:6d:25:32:e3:16:5d:3b:0f:63:74:00:ef:3c
 validity: not before Feb 11 13:30:59 2021, ok
       not after Oct 21 14:30:59 2034, ok
 pubkey:  RSA 1024 bits
 keyid:   96:e9:5c:ac:01:e0:80:4b:a0:9e:fb:1d:20:f6:48:b8:e0:82:2e:4a
 subjkey:  b4:ef:98:67:e6:0c:13:a8:71:87:67:92:e6:59:7e:7d:8b:78:30:e3
root@user-virtual-machine:/home/user#
```
```
root@user-virtual-machine:/home/user# ipsec listcacerts
List of X.509 CA Certificates:
 subject: "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=root_ca"
 issuer:  "C=RU, ST=RU, L=Moscow, O=Internet Inc, OU=VPN_Father, CN=root_ca"
 serial:  0b:fb:b5:b7:6e:81:48:7f:4c:c8:ab:ec:3f:2f:aa:cc:9f:8e:f1:70
 validity: not before Feb 11 13:28:26 2021, ok
       not after Jun 29 14:28:26 2048, ok
 pubkey:  RSA 2048 bits
 keyid:   b4:7e:75:89:ca:1c:8c:70:2c:23:5b:44:02:08:87:ba:14:14:30:61
 subjkey:  56:ef:66:9f:b5:96:70:91:1f:e4:24:1b:17:17:55:17:b9:8a:d9:e4
 authkey:  56:ef:66:9f:b5:96:70:91:1f:e4:24:1b:17:17:55:17:b9:8a:d9:e4
root@user-virtual-machine:/home/user#
```
