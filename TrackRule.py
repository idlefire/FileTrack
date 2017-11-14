# -*-conding=utf-8-*-

from urllib.parse import urlparse
from FielRule import FileRule
from gevent.queue import PriorityQueue


class TrackRule:
    def __init__(self, url, option):
        self.url = url
        self.url_list = PriorityQueue()
        self.dir_list = []
        self.file = option.file
        self.dir = option.dir

    def white_list(self, whitelist):
        for url_item in whitelist:
            is_suffix = whitelist[url_item].get('suffix', False)
            name = whitelist[url_item].get('name', [])
            if is_suffix:
                url_suffix = whitelist[url_item].get('filename')
                for filename_item in url_suffix:
                    for name_item in name:
                        rule = name_item.get('rule_true')
                        if isinstance(rule, str):
                            rule = list(name_item.get('rule_true'))
                        for rule_item in rule:
                            self.dir_list.append({
                                "rule_true_filename": "{}.{}".format(rule_item, filename_item),
                            })
            else:
                for name_item in name:
                        rule = name_item.get('rule_true')
                        if isinstance(rule, str):
                            rule = [name_item.get('rule_true')]
                        for rule_item in rule:
                            self.dir_list.append({
                                "rule_true_filename": rule_item,
                            })

    def url_parse(self):
        dir_url = []
        url_parse = urlparse(self.url)
        url_path = url_parse.path.split('/')
        url = "{}://{}".format(url_parse.scheme, url_parse.netloc)
        dir_url.append(url)
        _dir = ''
        if len(url_path) > 2:
            if '.' in url_path[-1]:
                url_path.pop()
            for path_item in url_path:
                if not path_item:
                    continue
                _dir = '/' + path_item
                dir_url.append(url+_dir)
        return {"dir_url": dir_url}

    def add_url(self):
        url_list = self.url_parse().get('dir_url', [])
        i = 1
        for url_item in url_list:
            if self.file:
                for dir_item in self.dir_list:
                    rule = dir_item.get('rule_true_filename', '')
                    _dict = {}
                    _dict['rule_true'] = '{}/{}'.format(url_item, rule)
                    self.url_list.put((i, _dict))
                    i += 1
            if self.dir:
                f = open('dircommon.txt', 'r')
                for dir_item in f.readlines():
                    dir_item = dir_item.strip()
                    _dict = {}
                    _dict['rule_true'] = '{}/{}'.format(url_item, dir_item)
                    self.url_list.put((i, _dict))
                    i += 1

    def main(self):
        if self.file:
            whitelist = FileRule.get("whitelist", "")
            balcklist = FileRule.get("blacklist", "")
            self.white_list(whitelist)
        self.add_url()
        return self.url_list
