# Copyright 2015-2016 Yelp Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import mock

from paasta_tools.secret_tools import _get_secret_name_from_ref
from paasta_tools.secret_tools import get_hmac_for_secret
from paasta_tools.secret_tools import is_secret_ref


def test_is_secret_ref():
    assert is_secret_ref('SECRET(aaa-bbb-222_111)')
    assert not is_secret_ref('SECRET(#!$)')
    # herein is a lesson on how tests are hard:
    assert not is_secret_ref('anything_else')


def test__get_secret_name_from_ref():
    assert _get_secret_name_from_ref('SECRET(aaa-bbb-222_111)') == 'aaa-bbb-222_111'


def test_get_hmac_for_secret():
    with mock.patch(
        'paasta_tools.secret_tools.open', autospec=False,
    ) as mock_open, mock.patch(
        'json.load', autospec=True,
    ) as mock_json_load, mock.patch(
        'paasta_tools.secret_tools._get_secret_name_from_ref', autospec=True,
    ) as mock_get_secret_name_from_ref:
        mock_json_load.return_value = {
            'environments': {
                'dev': {'signature': 'notArealHMAC'},
            },
        }
        mock_config = mock.Mock(get_vault_environment=mock.Mock(return_value='dev'))
        mock_get_secret_name_from_ref.return_value = 'secretsquirrel'

        ret = get_hmac_for_secret("SECRET(secretsquirrel)", "service-name", "/nail/blah", mock_config)
        mock_get_secret_name_from_ref.assert_called_with("SECRET(secretsquirrel)")
        mock_open.assert_called_with("/nail/blah/service-name/secrets/secretsquirrel.json", "r")
        assert ret == 'notArealHMAC'
