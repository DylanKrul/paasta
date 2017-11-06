# Copyright 2015-2017 Yelp Inc.
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
import json
import os
import re

from paasta_tools.utils import SystemPaastaConfig

SECRET_REGEX = "^SECRET\([A-Za-z0-9_-]*\)$"


def is_secret_ref(val: str) -> bool:
    pattern = re.compile(SECRET_REGEX)
    return True if pattern.match(val) else False


def get_hmac_for_secret(
        val: str,
        service: str,
        soa_dir: str,
        system_paasta_config: SystemPaastaConfig,
) -> str:
    secret_name = _get_secret_name_from_ref(val)
    try:
        secret_path = os.path.join(soa_dir, service, "secrets", "{}.json".format(secret_name))
        with open(secret_path, 'r') as json_secret_file:
            secret_file = json.load(json_secret_file)
            return secret_file['environments'][system_paasta_config.get_vault_environment()]['signature']
    except IOError as e:
        print("Failed to load json secret at {}".format(secret_path))
        return None


def _get_secret_name_from_ref(val: str) -> str:
    return val.split('(')[1][:-1]
