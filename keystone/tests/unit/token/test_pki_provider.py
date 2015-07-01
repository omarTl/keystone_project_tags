# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.tests import unit as tests
from keystone.token.providers import pki


class TestPkiTokenProvider(tests.TestCase):
    def setUp(self):
        super(TestPkiTokenProvider, self).setUp()
        self.provider = pki.Provider()

    def test_supports_bind_authentication_returns_true(self):
        self.assertTrue(self.provider._supports_bind_authentication)

    def test_need_persistence_return_true(self):
        self.assertTrue(self.provider.needs_persistence)
