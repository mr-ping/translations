# 健壮的SSL/TLS加密：导论

作为一篇介绍性质的文章，本章节适用于熟悉Web、HTTP 和 Apache，但是对安全不甚精通的读者。本文并不打算写成SSL协议的权威指南，也不打算讨论组织内部证书管理的具体技术细节，更不会涉及关于专利和使用的法律问题。本文的目标是通过将各种概念、定义和示例进行整合，从而为使用`mod_ssl`的用户提供一个通用的背景知识，并以此为起点来进行进一步的探索。

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [加密技术](#%E5%8A%A0%E5%AF%86%E6%8A%80%E6%9C%AF)
  - [加密算法](#%E5%8A%A0%E5%AF%86%E7%AE%97%E6%B3%95)
    - [传统加密](#%E4%BC%A0%E7%BB%9F%E5%8A%A0%E5%AF%86)
    - [公钥加密](#%E5%85%AC%E9%92%A5%E5%8A%A0%E5%AF%86)
  - [消息摘要](#%E6%B6%88%E6%81%AF%E6%91%98%E8%A6%81)
  - [数字签名](#%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D)
- [证书](#%E8%AF%81%E4%B9%A6)
  - [证书内容](#%E8%AF%81%E4%B9%A6%E5%86%85%E5%AE%B9)
  - [证书签发机构](#%E8%AF%81%E4%B9%A6%E7%AD%BE%E5%8F%91%E6%9C%BA%E6%9E%84)
    - [证书链](#%E8%AF%81%E4%B9%A6%E9%93%BE)
    - [创建根证书](#%E5%88%9B%E5%BB%BA%E6%A0%B9%E8%AF%81%E4%B9%A6)
    - [证书管理](#%E8%AF%81%E4%B9%A6%E7%AE%A1%E7%90%86)
- [安全套接字层（SSL）](#%E5%AE%89%E5%85%A8%E5%A5%97%E6%8E%A5%E5%AD%97%E5%B1%82%EF%BC%88ssl%EF%BC%89)
  - [Establishing a Session](#establishing-a-session)
  - [建立会话](#%E5%BB%BA%E7%AB%8B%E4%BC%9A%E8%AF%9D)
  - [Key Exchange Method](#key-exchange-method)
  - [密钥交换方法](#%E5%AF%86%E9%92%A5%E4%BA%A4%E6%8D%A2%E6%96%B9%E6%B3%95)
  - [Cipher for Data Transfer](#cipher-for-data-transfer)
  - [数据传输密码](#%E6%95%B0%E6%8D%AE%E4%BC%A0%E8%BE%93%E5%AF%86%E7%A0%81)
  - [Digest Function](#digest-function)
  - [摘要函数](#%E6%91%98%E8%A6%81%E5%87%BD%E6%95%B0)
  - [Handshake Sequence Protocol](#handshake-sequence-protocol)
  - [握手过程协议](#%E6%8F%A1%E6%89%8B%E8%BF%87%E7%A8%8B%E5%8D%8F%E8%AE%AE)
  - [Data Transfer](#data-transfer)
  - [数据传输](#%E6%95%B0%E6%8D%AE%E4%BC%A0%E8%BE%93)
  - [Securing HTTP Communication](#securing-http-communication)
  - [保护HTTP通信](#%E4%BF%9D%E6%8A%A4http%E9%80%9A%E4%BF%A1)
- [References](#references)
- [参考文献](#%E5%8F%82%E8%80%83%E6%96%87%E7%8C%AE)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## 加密技术

只有理解了加密算法，消息摘要函数（又名单向或者散列函数）和数字签名，才能对SSL有所了解。这些技术是整篇教材(参见 [AC96]) 的主题，并且为大家提供了隐私保护、完整性检查和身份验证的基础知识。

### 加密算法
假设爱丽丝打算给她的银行发送一条信息来对部分资金进行转账。由于信息中包含有爱丽丝的账户和转账金额信息，她当然希望自己的信息受到隐私保护。其中一种方法就是利用加密算法，这项技术会将她的信息转换成加密格式，除非进行解密，否则这种格式的信息是不可读的。信息被加密之后，就只能使用密钥要进行解密，如果没有密钥，信息就没有任何用处。一个好的加密算法能够给攻击者造成足够大的困难，让其不得不放弃将信息解码成原样的想法。
 
我们有两类加密算法：传统加密和公钥加密。

#### 传统加密
也被成为对称加密，需要信息的发送者和接收者共享密钥，此密钥是是一个保密的信息片段，用来加密和解密消息。除非此密钥被泄露，不然除了发送者和接收者外没人能够读取信息。如果爱丽丝和银行拥有同一个密钥，那么他们之间就可以传递经过隐私保护的消息。不过，在发送者和接收者通讯之前进行密钥的共享，并且保证密钥的绝对安全同样是个艰巨的任务。

#### 公钥加密
也被称作非对称加密。这种算法通过使用两个不同的密钥来解决密钥交换所带来的问题，其中每个密钥都可以被用来加密消息。如果其中一个被用来加密消息，另外一个就必须用来进行消息的解密。如此一来，可以简单的通过将其中一个密钥公开发布（公钥），另一个保持私密（私钥）的方式来实现消息的安全接收。   

每个人都可以通过公钥来加密一段消息，但是只有拥有私钥的接收者才能够读取它。这样一来，爱丽丝就可以通过使用公钥来加密消息的方式，发送经过隐私处理的消息给密钥对的拥有者（银行）。只有银行可以解密消息。   

### 消息摘要

尽管爱丽丝可以通过加密消息的方式进行隐私处理，但是消息仍旧有被其他人篡改或者替换掉的风险，这样对方就可以将钱款转账到自己名下了。我们有一种可以确保爱丽丝消息完成性的方法，就是创建一个消息的简单摘要，随同消息一起发送给银行。银行利用接收到的消息同样自己创建一个摘要，并且把两份摘要进行比对，如果摘要相同，说明消息在传输中是完整的、未被破坏的。   

这种摘要技术在这儿被称作消息摘要、单向函数或者哈希函数。消息摘要可以生成简短并且定长的信息，以此去表示体积很大且长度不定的消息。摘要算法为不同的消息生成唯一的摘要值。消息摘要的设计非常巧妙，想要从摘要值判断出消息本体几乎是不可能的，而且理论上任何两个不同的消息都不可能产生相同的摘要值。这样就消除了保持摘要值不变的情况下替换掉消息体的可能性。   

此时，爱丽丝还面对着另外一个挑战，找到一个安全的方式将摘要传送给银行。如果传送方式不安全，摘要本身的完整性就会大打折扣，那么基于它进行的原始消息体完整性检测就无从谈起了。只有在摘要被安全传送的前提下，其相关消息的完整性判断才有意义。
 
安全传送摘要的其中一个方法就是数字签名。

### 数字签名
当爱丽丝给银行发送消息的时候，银行需要确认发送者就是爱丽丝本人，这样攻击者就无法对她的账户进行转账操作。为达到以上目的，爱丽丝可以创建一个包含消息的数字签名。

创建数字签名时，包含了消息摘要和一些其他信息（如序列号），并且这些信息都是经由发送者的私钥加密过的。虽然任何一个拿着公钥的人都可以解密签名，但是只有发送者拥有私钥。这就意味着只有发送者才能对消息进行签名。将摘要包含在签名中意味着此签名只对此条消息有效。同时，签名也能保证消息的完整性，因为没有其他人可以篡改摘要并且对其重新签名。

为了避免签名被攻击者劫持并进行重放攻击，签名会包含一个唯一的序列号。这样就可以防止因为银行收到非真实用户的消息而引起的欺诈索赔。

## 证书

尽管爱丽丝现在能够向银行发送经过隐私保护的信息，为其签名并且保证消息的完整性，但是她依旧需要确认与之通讯的对方是她所期望的银行。这就意味着她需要确认所使用的公钥是银行所持有的密钥对的一部分，而不是属于攻击者。同样的，银行也需要验证消息签名来自于持有私钥的爱丽丝本人。

如果彼此都持有用于验证对方身份的证书，确认公钥合法性并且证书来自于可信机构，那么双方就都可以确定对方身份与自己所期望一致。这样的可信机构被称作证书签发机构，并且证书可被用于身份验证。

### 证书内容

证书会将公钥与个人的真实身份以及服务器或者其他实体关联起来，形成主体。如表一所示，与主体有关的信息包括身份信息（专用名称）和公钥。证书还同样包括此证书签发机构的身份信息和签名，还有证书的有效期。它还有可能包括额外的信息（扩展信息）以及序列号等用于证书签发机构使用的行政信息。

**表１：证书信息**

|------|------|
|------|------|
| 主体（Subject） | 专有名称（Distinguished Name）, 公钥（Public Key） |
| 签发者（Issuer）  | 专有名称（Distinguished Name）, 签名（Signature） |
| 有效期（Period of Validity）  | 起始日期（Not Before Date）, 到期日期（Not After Date） |
| 行政信息（Administrative Information）  | 版本（Version）, 序列号（Serial Number） |
| 扩展信息（Extended Information） |  基本约束（Basic Constraints）, 网景标志等（Netscape Flags, etc.） |

专有名称用于在特定情况下提供身份验证，例如某人可能拥有一个私人证书，以及作为雇员所持有的证书。X.509 标准 [X509]定义了专有名称的字段、字段名和字段的缩写（见表２）。

**表２：专有名称信息**

|专有名称字段（DN Field）|  缩写（Abbrev.） |介绍（Description）| 示例（Example）|
|------|------|------|------|
|公用名（Common Name）  |CN |认证名称（Name being certified）|  CN=Joe Average|
|组织或公司（Organization or Company） | O |    关联的组织名称（Name is associated with this organization）|    O=Snake Oil, Ltd.|
|组织单位（Organizational Unit）|   OU| 关联的组织单位，如部门（Name is associated with this organization unit, such as a department）  |OU=Research Institute|
|城市／地区（City/Locality）|   L|  所在城市名称（Name is located in this City）|   L=Snake City|
|州／省（State/Province）   |ST|    所在州／省的名称（Name is located in this State/Province）| ST=Desert|
|国家（Country）|   C|  所在国家名称（Name is located in this Country (ISO code)）  |C=XZ|

证书签发机构有可能会制定自己的政策来指定哪些专有字段名称是必须的或是可选的。它也可以对字段内容提出要求，作为签发用户证书的需要。例如网景浏览器就要求证书的公用名字段使用通配符形式来反映服务器域名，如 *.snakeoil.com。

二进制格式的证书被定义为使用ASN.1标记方式。这种标记方法定义了如何指定内容和用于进行二进制形式转换的编码规则。证书的二进制编码使用Distinguished Encoding Rules (DER)，这种编码规则基于更为常用的Basic Encoding Rules (BER)而来。对于那些无法处理二进制数据的传输来说，可以将二进制转换为Base64编码[MIME]的数据。其中有种编码版本叫做PEM ("Privacy Enhanced Mail") ，它会将编码后的内容放置于用于判断的起始行和结束行之间。

> Example of a PEM-encoded certificate (snakeoil.crt)
> 
> -----BEGIN CERTIFICATE----- 
> MIIC7jCCAlegAwIBAgIBATANBgkqhkiG9w0BAQQFADCBqTELMAkGA1UEBhMCWFkx
> FTATBgNVBAgTDFNuYWtlIERlc2VydDETMBEGA1UEBxMKU25ha2UgVG93bjEXMBUG
> A1UEChMOU25ha2UgT2lsLCBMdGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhv
> cml0eTEVMBMGA1UEAxMMU25ha2UgT2lsIENBMR4wHAYJKoZIhvcNAQkBFg9jYUBz
> bmFrZW9pbC5kb20wHhcNOTgxMDIxMDg1ODM2WhcNOTkxMDIxMDg1ODM2WjCBpzEL
> MAkGA1UEBhMCWFkxFTATBgNVBAgTDFNuYWtlIERlc2VydDETMBEGA1UEBxMKU25h
> a2UgVG93bjEXMBUGA1UEChMOU25ha2UgT2lsLCBMdGQxFzAVBgNVBAsTDldlYnNl
> cnZlciBUZWFtMRkwFwYDVQQDExB3d3cuc25ha2VvaWwuZG9tMR8wHQYJKoZIhvcN
> AQkBFhB3d3dAc25ha2VvaWwuZG9tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
> gQDH9Ge/s2zcH+da+rPTx/DPRp3xGjHZ4GG6pCmvADIEtBtKBFAcZ64n+Dy7Np8b
> vKR+yy5DGQiijsH1D/j8HlGE+q4TZ8OFk7BNBFazHxFbYI4OKMiCxdKzdif1yfaa
> lWoANFlAzlSdbxeGVHoT0K+gT5w3UxwZKv2DLbCTzLZyPwIDAQABoyYwJDAPBgNV
> HRMECDAGAQH/AgEAMBEGCWCGSAGG+EIBAQQEAwIAQDANBgkqhkiG9w0BAQQFAAOB
> gQAZUIHAL4D09oE6Lv2k56Gp38OBDuILvwLg1v1KL8mQR+KFjghCrtpqaztZqcDt
> 2q2QoyulCgSzHbEGmi0EsdkPfg6mp0penssIFePYNI+/8u9HT4LuKMJX15hxBam7
> dUHzICxBVC1lnHyYGjDuAMhe396lYAn8bCld1/L4NMGBCQ==
> -----END CERTIFICATE-----

### 证书签发机构

在发放证书之前，证书签发机构需验证证书请求信息，以保证密钥对的私钥拥有者的真实身份。例如，如果爱丽丝申请了个人证书，那签发机构就必须确认证书的申请者就是爱丽丝本人。

#### 证书链

证书签发机构也可以为其他证书签发机构颁发证书。当检验证书的时候，爱丽丝可能需要逐级向上检验证书的颁发者，直到找到为她信赖的那个。她可以选择只信任有限级颁发者链的证书以减少链条中遇到不合格证书的风险。

#### 创建根证书

前边讲到过，每个证书都需要一个可以向上追溯的颁发者来保证证书主体身份和合法性。这就带来了一个问题，谁来保证没有更上层的顶层颁发者的权威性呢？这种特殊情况下，证书是“自签名”的，证书的颁发者就是证书主体本身。虽然浏览器都提前内置了许多知名的可信证书签发机构，但是如果要选择信任一个自签名的证书还是得加倍小心。将根机构的公钥大范围发布将会显著降低此密钥的信任风险，如果有人冒充此机构来发布公钥将很容易被识别数来。

许多的企业，如Thawte和VeriSign都建立了自己的证书签发机构。他们提供如下服务：

- 验证证书申请
- 处理证书申请
- 颁发和管理证书

如果你想创建自己的证书签发机构也不是不行。尽管互联网环境中危机重重，但如果在可以轻松验证个人和服务器身份的内网中用用还是不错的。

#### 证书管理

创建证书签发机构需要强大的行政团队、技术能力和管理架构，责任重大。证书签发机构不仅仅负责颁发证书，还需要管理它们，要决定证书的有效时间，证书的续签以及对以往颁发的失效效证书(证书吊销列表 Certificate Revocation Lists, or CRLs)的管理。

举例来说，如果爱丽丝以公司雇员的身份拥有一份证书，那当她离职后，她所持有的证书需要被吊销掉。由于证书是在进行主体身份查验后颁发的，然后被分发给主体进行通讯，所以不可能去通知证书本身它已经被吊销。因此当检验证书的合法性的时候，联系证书签发机构去检查吊销证书列表就显得尤为重要了，而且这个过程常常需要人工操作。

> Note
> 
> If you use a Certificate Authority that browsers are not configured to
> trust by default, it is necessary to load the Certificate Authority
> certificate into the browser, enabling the browser to validate server
> certificates signed by that Certificate Authority. Doing so may be
> dangerous, since once loaded, the browser will accept all certificates
> signed by that Certificate Authority.


## 安全套接字层（SSL）

安全套接字层协议存在于面向连接的网络层协议(例如TCP/IP)和应用层协议(例如HTTP)之间。SSL为服务器和客户端之间提供了安全通讯的可能，它允许进行双向验证，并且拥有用于完整性检验和隐私加密的数字签名技术。

SSL协议设计之初就为加密、摘要、签名等特定算法提供了很大的选择空间。这就允许根据法律条款、使用协议和其他条件来进行针对特定服务器的算法选择，并且使得协议享受到新算法所带来的优势。算法的选择是在建立协议会话之后，由客户端和服务器双方协商的。

**表四: 安全套接字协议版本**

|版本（Version）    |来源（Source） |介绍（Description）|
|----|----|----|
|SSL v2.0|  供应商标准 (来自于网景公司)|    实现的第一个SSL协议|
|SSL v3.0|  过期的互联网草案 (来自于网景公司) [SSL3]    |修订以避免特定安全攻击, 添加非RSA密码，支持证书链|
|TLS v1.0|  推荐的互联网标准 (来自 IETF) [TLS1]|    对SSL 3.0进行修订，更新MAC层使用HMAC算法, add block padding for block ciphers, 消息标准化以及更全面的警示信息|
|TLS v1.1|  推荐的互联网标准 (来自 IETF) [TLS11]|   Update of TLS 1.0 to add protection against Cipher block chaining (CBC) attacks.|
|TLS v1.2|  推荐的互联网标准 (来自 IETF) [TLS12]|   Update of TLS 1.2 deprecating MD5 as hash, and adding incompatibility to SSL so it will never negotiate the use of SSLv2.|

There are a number of versions of the SSL protocol, as shown in Table 4. As noted there, one of the benefits in SSL 3.0 is that it adds support of certificate chain loading. This feature allows a server to pass a server certificate along with issuer certificates to the browser. Chain loading also permits the browser to validate the server certificate, even if Certificate Authority certificates are not installed for the intermediate issuers, since they are included in the certificate chain. SSL 3.0 is the basis for the Transport Layer Security [TLS] protocol standard, currently in development by the Internet Engineering Task Force (IETF).  
如表4所示，SSL协议版本有很多个。正如上边所述，SSL3.0最大的进步是支持了证书链的加载。此特性允许服务器将服务器证书随颁发者证书一起传递到浏览器当中。链条加载同样允许浏览器验证服务器证书，甚至于中间签发机构的证书没有安装也不受影响，因为中间签发机构已经被包含在证书链当中了。SSL3.0是传输安全层 [TLS]协议的基础标准， 此协议由互联网工程任务组(IETF)开发。

### Establishing a Session
### 建立会话
The SSL session is established by following a handshake sequence between client and server, as shown in Figure 1. This sequence may vary, depending on whether the server is configured to provide a server certificate or request a client certificate. Although cases exist where additional handshake steps are required for management of cipher information, this article summarizes one common scenario. See the SSL specification for the full range of possibilities.  
如图１所示，SSL会话是通过客户端和服务器的握手过程建立的。由于服务器可以配置是否提供服务器端证书或者是否请求客户端证书，因此该握手过程可能会有所不同。尽管出于密码信息管理的需要，有需要额外握手过程的情况存在，但本文只总结这一种常见场景。如果想要对此有更全面的了解，可以去阅读SSL规范。

> Note
> 注意：
> 
> Once an SSL session has been established, it may be reused. This
> avoids the performance penalty of repeating the many steps needed to
> start a session. To do this, the server assigns each SSL session a
> unique session identifier which is cached in the server and which the
> client can use in future connections to reduce the handshake time
> (until the session identifier expires from the cache of the server).
> SSL回话被建立之后，是可以被复用的。这就避免了为重建回话而重复这些复杂步骤所带来的性能问题。为了实现这个特性，服务器会给每个SSL会话分配一个会话识别码，并将其缓存于服务器中。如果稍后客户端想要重启回话就可以利用此特性减少握手所用时间（直到会话识别码过期）。

![此处输入图片的描述][1]   
图１: 简化的SSL握手过程

The elements of the handshake sequence, as used by the client and server, are listed below:  
以下列出握手过程中客户端和服务器所用到的元素：

1. Negotiate the Cipher Suite to be used during data transfer
2. Establish and share a session key between client and server
3. Optionally authenticate the server to the client
4. Optionally authenticate the client to the server

1. 协商传输过程中需要用到的密码套件
2. 建立并共享用于在客户端和服务器端传送数据的会话密钥
3. 可选的服务器端验证
4. 可选的客户端验证

The first step, Cipher Suite Negotiation, allows the client and server to choose a Cipher Suite supported by both of them. The SSL3.0 protocol specification defines 31 Cipher Suites. A Cipher Suite is defined by the following components:   
第一步是协商密码套件，客户端和服务器端选出双方都支持的密码套件。SSL3.0协议规范定义了31中密码套件。密码套件的组成要素如下所示：

- Key Exchange Method
- 密钥交换方法
- Cipher for Data Transfer
- 数据传输密码
- Message Digest for creating the Message Authentication Code (MAC)
- 用于创建消息验证码（MAC）的消息摘要

These three elements are described in the sections that follow.  
这三种要素下边会为大家一一介绍。

### Key Exchange Method
### 密钥交换方法

The key exchange method defines how the shared secret symmetric cryptography key used for application data transfer will be agreed upon by client and server. SSL 2.0 uses RSA key exchange only, while SSL 3.0 supports a choice of key exchange algorithms including RSA key exchange (when certificates are used), and Diffie-Hellman key exchange (for exchanging keys without certificates, or without prior communication between client and server).  　
密钥交换方法定义了应用数据传输所需的共享对称密钥是如何如何被客户端和服务器协商出来的。SSL2.0只支持RSA密钥交换，SSL 3.0支持了密钥交换算法的选择，这些选择包括RSA密钥交换（当使用证书时）和Diffie-Hellman密钥交换（无证书或客户端和服务器无预先沟通的情况）。

One variable in the choice of key exchange methods is digital signatures -- whether or not to use them, and if so, what kind of signatures to use. Signing with a private key provides protection against a man-in-the-middle-attack during the information exchange used to generating the shared key [AC96, p516].  
影响密钥交换方法选择的一个因素是是否使用数字签名和使用了何种数字签名。使用私钥进行签名可以保护用于生成共享密钥的信息交换不受中间人攻击的影响。

### Cipher for Data Transfer
### 数据传输密码
SSL uses conventional symmetric cryptography, as described earlier, for encrypting messages in a session. There are nine choices of how to encrypt, including the option not to encrypt:   
如前所述，SSL使用传统的对称密码对会话时的消息进行加密。下面是九种加密算法（包括不进行加密在内）：

- No encryption
- 不进行加密
- Stream Ciphers
- 流密码
 - RC4 with 40-bit keys
 - 40位密码的RC4
 - RC4 with 128-bit keys
 - 128位密码的RC4
- CBC Block Ciphers
- CBC分组密码
 - RC2 with 40 bit key
 - 40位密码的RC2
 - DES with 40 bit key
 - 40位密码的DES
 - DES with 56 bit key
 - 56位密码的DES
 - Triple-DES with 168 bit key
 - 168位密码的Triple-DES
 - Idea (128 bit key)
 - 128位密码的Idea
 - Fortezza (96 bit key)
 - 96位密码的Fortezza

"CBC" refers to Cipher Block Chaining, which means that a portion of the previously encrypted cipher text is used in the encryption of the current block. "DES" refers to the Data Encryption Standard [AC96, ch12], which has a number of variants (including DES40 and 3DES_EDE). "Idea" is currently one of the best and cryptographically strongest algorithms available, and "RC2" is a proprietary algorithm from RSA DSI [AC96, ch13].  
"CBC" 是密码分组链接的简称，意思是将以前加密密文的一部分用于当前块的加密。"DES"是数据教密标准的简称 [AC96, ch12]，它拥有许多变种(DES40 、 3DES_EDE等)。"Idea" 是现今可用的加密算法中最好、最强大的。"RC2"是RSA DSI的专有算法 [AC96, ch13]。

### Digest Function
### 摘要函数
The choice of digest function determines how a digest is created from a record unit. SSL supports the following:
选择何种摘要函数决定了摘要如何生成，SSL支持如下摘要算法：

- No digest (Null choice)
- 不进行摘要计算（空选项）
- MD5, a 128-bit hash
- MD5，一种128位哈希值
- 安全散列算法 (SHA-1),160位哈希值

The message digest is used to create a Message Authentication Code (MAC) which is encrypted with the message to verify integrity and to protect against replay attacks.  
消息摘要将消息进行加密来创建消息验证码，用于验证消息的完整性并防止重放攻击。

### Handshake Sequence Protocol
### 握手过程协议
The handshake sequence uses three protocols:  
握手过程使用了三种协议：

- The SSL Handshake Protocol for performing the client and server SSL session establishment.
- 用于实现SSL会话创建的SSL握手协议。
- The SSL Change Cipher Spec Protocol for actually establishing agreement on the Cipher Suite for the session.
- 用于真正为会话建立密码套件协商的SSL变更密码规范协议。
- The SSL Alert Protocol for conveying SSL error messages between client and server.
- 用于标示客户端和服务器端SSL错误消息的SSL报警协议。

These protocols, as well as application protocol data, are encapsulated in the SSL Record Protocol, as shown in Figure 2. An encapsulated protocol is transferred as data by the lower layer protocol, which does not examine the data. The encapsulated protocol has no knowledge of the underlying protocol.  
包括应用协议数据在内的这些所有协议都被封装在SSL记录协议中。如图２所示。封装好的协议直接被当做普通数据在底层协议中传输而不进行数据校检。封装后的协议对底层协议一无所知。

![此处输入图片的描述][2]  
图 2: SSL 协议栈

The encapsulation of SSL control protocols by the record protocol means that if an active session is renegotiated the control protocols will be transmitted securely. If there was no previous session, the Null cipher suite is used, which means there will be no encryption and messages will have no integrity digests, until the session has been established.  
SSL记录协议对SSL控制协议的封装可以是的SSL控制协议在活动会话重新谈判的情形下安全的传输。如果之前没有会话存在，就会使用空的密码套件，也就是说不存在封装、消息、完整的摘要，直到建立会话。

### Data Transfer
### 数据传输

The SSL Record Protocol, shown in Figure 3, is used to transfer application and SSL Control data between the client and server, where necessary fragmenting this data into smaller units, or combining multiple higher level protocol data messages into single units. It may compress, attach digest signatures, and encrypt these units before transmitting them using the underlying reliable transport protocol (Note: currently, no major SSL implementations include support for compression).  
如图3所示，SSL记录协议用于在客户端和服务器之间传输应用程序和SSL控制数据，必要时将这些数据分段为较小单元，或将多个较高级协议数据消息组合成单个单元。还可能涉及到压缩，摘要签名附件并且在使用底层传输层传递数据前进行加密。（注意：当今主流SSL实现并不支持压缩功能）

![此处输入图片的描述][3]
图 3: SSL记录协议

### Securing HTTP Communication
### 保护HTTP通信

One common use of SSL is to secure Web HTTP communication between a browser and a webserver. This does not preclude the use of non-secured HTTP - the secure version (called HTTPS) is the same as plain HTTP over SSL, but uses the URL scheme https rather than http, and a different server port (by default, port 443). This functionality is a large part of what mod_ssl provides for the Apache webserver.  
SSL的一个常见应用场景是保护浏览器和WEB服务器间的HTTP通讯。这并不排除使用未受保护的HTTP，安全版的HTTPS实际上就是基于SSL的普通HTTP，只不过用的方案名是https而不是http而已，当然服务器端口也成了默认的443。这是阿帕奇Web服务器mod_ssl所提供的重要功能。

## References
## 参考文献
[AC96]    
Bruce Schneier, Applied Cryptography, 2nd Edition, Wiley, 1996. See http://www.counterpane.com/ for various other materials by Bruce Schneier.

[ASN1]  
ITU-T Recommendation X.208, Specification of Abstract Syntax Notation One (ASN.1), last updated 2008. See http://www.itu.int/ITU-T/asn1/.

[X509]  
ITU-T Recommendation X.509, The Directory - Authentication Framework. For references, see http://en.wikipedia.org/wiki/X.509.

[PKCS]  
Public Key Cryptography Standards (PKCS), RSA Laboratories Technical Notes, See http://www.rsasecurity.com/rsalabs/pkcs/.

[MIME]  
N. Freed, N. Borenstein, Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies, RFC2045. See for instance http://tools.ietf.org/html/rfc2045.

[SSL3]  
Alan O. Freier, Philip Karlton, Paul C. Kocher, The SSL Protocol Version 3.0, 1996. See http://www.netscape.com/eng/ssl3/draft302.txt.

[TLS1]  
Tim Dierks, Christopher Allen, The TLS Protocol Version 1.0, 1999. See http://ietf.org/rfc/rfc2246.txt.

[TLS11]  
The TLS Protocol Version 1.1, 2006. See http://tools.ietf.org/html/rfc4346.

[TLS12]  
The TLS Protocol Version 1.2, 2008. See http://tools.ietf.org/html/rfc5246.


----------


原文链接：[SSL/TLS Strong Encryption: An Introduction](http://httpd.apache.org/docs/2.4/ssl/ssl_intro.html)


  [1]: https://httpd.apache.org/docs/trunk/en/images/ssl_intro_fig1.gif
  [2]: https://httpd.apache.org/docs/trunk/en/images/ssl_intro_fig2.gif
  [3]: https://httpd.apache.org/docs/trunk/en/images/ssl_intro_fig3.gif

