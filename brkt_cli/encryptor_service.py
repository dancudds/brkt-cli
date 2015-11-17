# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

import abc
import json
import logging
import re
import urllib2

ENCRYPT_SUCCESSFUL = 'finished'
ENCRYPT_FAILED = 'failed'
ENCRYPTOR_STATUS_PORT = 8000
FAILURE_CODE_UNSUPPORTED_GUEST = 'unsupported_guest'

log = logging.getLogger(__name__)


class BaseEncryptorService(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, hostname, port=ENCRYPTOR_STATUS_PORT):
        self.hostname = hostname
        self.port = port

    @abc.abstractmethod
    def is_encryptor_up(self):
        pass

    @abc.abstractmethod
    def get_status(self):
        pass


class EncryptorService(BaseEncryptorService):

    def is_encryptor_up(self):
        try:
            self.get_status()
            log.debug("Successfully got encryptor status")
            return True
        except Exception as e:
            log.debug("Couldn't get encryptor status: %s", e)
            return False

    def get_status(self, timeout_secs=2):
        url = 'http://%s:%d/encryption_status' % (self.hostname, self.port)
        r = urllib2.urlopen(url, timeout=timeout_secs)
        data = r.read()
        info = json.loads(data)
        info['percent_complete'] = 0
        if info['state'] == ENCRYPT_SUCCESSFUL:
            info['percent_complete'] = 100
        elif info['bytes_total'] > 0:
            ratio = float(info['bytes_written']) / info['bytes_total']
            info['percent_complete'] = int(100 * ratio)
        return info
