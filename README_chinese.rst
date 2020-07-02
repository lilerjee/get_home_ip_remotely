.. _readme_chinese:

介绍
----

自动远程获取家里的路由器动态公共IP.

| 家里：
|   获取路由器的动态公共IP，加密后通过邮件发送出去。

| 远程：
|   从邮件服务器里面获取加密的IP邮件，解密后更新hosts文件里面指定域名对应的IP。


部署
----

安装依赖库::

    $ pip3 install -r requirements.txt

家里：

#. 确定家里的路由器的IP是否公有，如果不是，让你的ISP开通。
#. 在浏览器里面登录路由器，并研究那个页面里面有动态的公有IP，
   在cookies里面是哪个字段可以提供免密码用户登录，使用什么样的正则表达式可以获取动态公有IP。

   例如::

        # Config of getting public IP from router
        ROUTER_IP_URL = 'http://192.168.0.1/userRpm/StatusRpm.htm'
        AUTHORIZATION_HEADERS = {
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        IP_REGEX = r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

#. 修改文件'`config.py`', 对怎么获取IP、邮箱与加密进行配置。
#. 添加cron job（Linux）或者Windows计划，以发送动态公有IP（需要修改下面的路径）：

   cron job(Linux)::

       0 8-20 * * * /usr/bin/python3 /the/path/to/project/get_home_ip_remotely/get_ip_then_send_via_email.py

   Add Windows计划::

       $ schtasks /create /tn send_ip /sc HOURLY /tr "D:\Python36\python.exe D:\path_to_project\get_home_ip_remotely\get_ip_then_send_via_email.py" /ST 09:00  /ET 18:00

远程:

#. 修改文件'`config.py`'，对邮件与解密进行配置（如果使用同一个配置文件或许就再需要修改了）
#. 在'`domain.txt`'文件里面添加需要进行IP映射的域名，一行一个域名，可以用符合'`#`'进行注释。
#. 添加cron job（linux）或者Windows计划，以用来从邮件服务器里面获取IP并对hosts文件进行更新（需要修改下面的路径）：

   cron job（Linux，需要root权限以更新文件`/etc/hosts`）::

       01 8-20 * * * /usr/bin/python3 /the/path/to/project/get_home_ip_remotely/pull_update_ip.py

   添加Window计划::

       $ schtasks /create /tn update_ip /sc HOURLY /tr "D:\Python36\python.exe D:\path_to_project\get_home_ip_remotely\pull_update_ip.py" /ST 09:01 /ET 18:01 /ru system
   
怎么运行单元测试
----------------

首先，修改配置文件'`config.py`'。

- 运行所有的单元测试用例::
  
      $ cd /project/root/dir
      $ python3 -m unittest discover tests -v
 
  或者::

      $ cd /project/root/dir
      $ python3 -m unittest -v
  
- 运行某些模块下面的单元测试用例或者莫个单元测试用例::
  
      $ cd /project/root/dir
      $ python3 -m unittest -v tests.test_get_ip_then_send_via_email
      $ python3 -m unittest -v tests.test_pull_update_ip
            
      $ python3 -m unittest -v tests.test_pull_update_ip.TestDecryptText
      $ python3 -m unittest -v tests.test_pull_update_ip.TestUpdateHosts
  
License
-------

Apache License 2.0
