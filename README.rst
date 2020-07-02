Introduction
------------

`中文介绍 <./README_chinese.rst>`_

Get the dynamic public IP from router at home remotely.

| At home:
|   Get the dynamic public IP from router at home, encrypt it, and send it via email automatically.

| At remote:
|   Pull the public IP from email server, decrypt it and update hosts with it automatically.

Deployment
----------

Install the required lib::

    $ pip3 install -r requirements.txt

At home:

#. Make sure your router IP is public, if not, ask for your ISP to get it.
#. Log in your router with browser, and research which page can get the IP,
   what is authorization filed in cookies, and what is regular expression of
   getting ip in the page source.

   Example::

        # Config of getting public IP from router
        ROUTER_IP_URL = 'http://192.168.0.1/userRpm/StatusRpm.htm'
        AUTHORIZATION_HEADERS = {
            'Authorization': 'Basic YWRtaW46SklNNDgxNDg2MGppbQ=='}
        IP_REGEX = r'wanPara\s+=\s+new\s+Array\(.*?"(\d+\.\d+\.\d+\.\d+)",'

#. Modify file '`config.py`' for getting the IP, email, and encryption.
#. Add a cron job(Linux) or Windows job for sending the IP(need modify the following path).

   cron job(Linux)::

        0 8-20 * * * /usr/bin/python3 /the/path/to/project/get_home_ip_remotely/get_ip_then_send_via_email.py

   Add Windows job::

        $ schtasks /create /tn send_ip /sc HOURLY /tr "D:\Python36\python.exe D:\path_to_project\get_home_ip_remotely\get_ip_then_send_via_email.py" /ST 09:00  /ET 18:00

At remote:

#. Modify file '`config.py`' for email, and decryption(may not if using the same config file).
#. Add domains which will be filled into hosts with the public IP in the file 'domain.txt',
   one domain per line, and can comment a domain with hash '#'.
#. Add a cron job(Linux) or Windows job for pulling and updating the IP(need modify the following path).

   cron job(Linux, need root right to update `/etc/hosts`)::

       01 8-20 * * * /usr/bin/python3 /the/path/to/project/get_home_ip_remotely/pull_update_ip.py

   Add Windows job::

        $ schtasks /create /tn update_ip /sc HOURLY /tr "D:\Python36\python.exe D:\path_to_project\get_home_ip_remotely\pull_update_ip.py" /ST 09:01 /ET 18:01 /ru system


How to run unittest
-------------------

First, modify the config file '`config.py`'.

* Run all tests::

    $ cd /project/root/dir
    $ python3 -m unittest discover tests -v

Or
   ::

        $ cd /project/root/dir
        $ python3 -m unittest -v

* Run some module's tests or some test::

    $ cd /project/root/dir
    $ python3 -m unittest -v tests.test_get_ip_then_send_via_email
    $ python3 -m unittest -v tests.test_pull_update_ip

    $ python3 -m unittest -v tests.test_pull_update_ip.TestDecryptText
    $ python3 -m unittest -v tests.test_pull_update_ip.TestUpdateHosts

   
License
-------

Apache License 2.0 
