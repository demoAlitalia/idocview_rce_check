# I DOC VIEW RCE的检测脚本(CVE-2023-23743、QVD-2023-45061)

### 免责声明

本脚本仅供合法的有授权的测试使用，切勿用于未授权场景，切勿用于任何非法途径！！

任何人使用此Poc进行非法操作造成的后果，本人不承担任何责任！！！

### 如何使用

```
python ./check.py
```
![](https://github.com/demoAlitalia/idocview_rce_check/blob/main/img/use.png)
### 目前支持的检测版本

版本检测种类区分

- 特征区分
- A.响应包.text当中即可抓取

- -  flag 0——>直接抓取
             	1、  V.12   V11.8.6_20210730  

- - -  测试过的版本      V.13.10.1_20231115  V.14.4.28_20240328

- -  flag 1——>判断是否有前缀，抓取并过滤
    - 测试过的版本： Version: movit-tech_13.10.2_20231129； Version：econage_11.8.6_20210730

- B.在响应中的超链

- - flag 2——> 无法直接抓取，隐藏在超链中
             	1、特征：?v=9.11.3_20191229          
    - 测试过的版本：Version：9.7.1_20190817；Version：8.3.19_20180702；Version：7.5.5_20170731

-  C.响应包中无版本号
           暂不支持检测该版本 
- -  测试过的版本：Version：6.8.3_20160731
                  

### TO Do List

1、增加请求响应的缓存（默认缓存1小时后刷新），可以主动清除缓存

2、增加批量检测

3、增加一键利用

4、增加其他漏洞检测

~~5、增加基于poc的检测~~

- 增加后台弱口令漏洞检测
        影响范围：12版本以下大部分有
- upload任意接口文件读取漏洞检测、
        影响范围：待确定
- system任意文件读取漏洞检测、
        影响范围：待确定
- SSRF漏洞检测
        影响范围：待确定

### 已更新

- 2024-05-22 更新check_Poc.py，基于半poc包的检测
