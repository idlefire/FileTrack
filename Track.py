# -*-coding=utf-8-*-
import sys
import logging
import optparse

from TrackRequest import TrackRequest
from gevent.queue import PriorityQueue
from TrackRule import TrackRule
from gevent import monkey
import gevent
import traceback
monkey.patch_all()

format_str = '%(asctime)s %(message)s'
logging.basicConfig(format=format_str, level=logging.INFO)
logger = logging.getLogger('FileTrack')


class FileTrack:
    def __init__(self, url, option):
        self.url = url
        self.url_list = PriorityQueue()
        self.threads = 50
        self.vul_url = []
        self.option = option

    def run(self):
        self.main()

    def main(self):
        logger.info('[+] 测试 url: {}'.format(self.url))
        Track_req = TrackRequest(self.url)
        Track_req.check_url()
        Track_rule = TrackRule(self.url, self.option)
        self.url_list = Track_rule.main()
        # pprint(self.url_list)
        gevent_list = [gevent.spawn(self.file_track) for num in range(self.threads)]
        try:
            gevent.joinall(gevent_list)
        except traceback as _:
            traceback.print_exc()
            sys.exit(1)

    def file_track(self):
        while not self.url_list.empty():
            url = self.url_list.get(timeout=1)[1]
            url = url.get('rule_true')
            Track_req = TrackRequest(url)
            vul_url = Track_req.check_url_info()
            if vul_url:
                self.vul_url.append(vul_url)


if __name__ == '__main__':
    opt = optparse.OptionParser("Usage: %prog -[f|d] http://domain.com")
    opt.add_option('-f', '--file', dest='file', action='store_true', help='Track vulnerability file...')
    opt.add_option('-d', '--dir', dest='dir', action='store_true', help='Track directory leaked...')
    (option, arg) = opt.parse_args()

    if len(arg) != 1 or (option.file and option.dir):
        opt.print_help()
        sys.exit(0)

    Track = FileTrack(arg[0], option)
    Track.run()
