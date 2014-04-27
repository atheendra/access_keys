# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
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

from keystone import auth
from keystone import exception
from keystone.common import dependency
from keystone import identity
from keystone.openstack.common import log as logging


METHOD_NAME = 'access_key'

LOG = logging.getLogger(__name__)


class AccessKeyAuthInfo(object):
    def __init__(self, auth_payload):
        self.identity_api = identity.Manager()
        self.access_id = None
        self.secret = None
        self._validate_and_normalize_auth_data(auth_payload)

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'access' not in auth_payload:
            raise exception.ValidationError(attribute='access',
                                            target=METHOD_NAME)
        if 'secret' not in auth_payload:
            raise exception.ValidationError(attribute='secret',
                                            target=METHOD_NAME)
        self.access_id = auth_payload['access']
        self.secret = auth_payload['secret']

@dependency.requires('identity_api')
class AccessKey(auth.AuthMethodHandler):
    """Currently, only the SQL backend supports this authentication method"""

    def authenticate(self, context, auth_payload, user_context):
        access_key_info = AccessKeyAuthInfo(auth_payload)

        try:
            self.identity_api.authenticate_ak(
                access_key_id=access_key_info.access_id,
                access_key_secret=access_key_info.secret
            )
        except AssertionError as e:
            msg = _(str(e))
            raise exception.Unauthorized(msg)

        user_context["user_id"] = "e95252ec01334813a27c2272ca4687cb"

        """Try to authenticate against the identity backend.
        user_info = UserAuthInfo(auth_payload)

        try:
            self.identity_api.authenticate_with_tfa(
                user_id=user_info.user_id,
                password=user_info.password,
                tfa_password=user_info.tfa_password)
        except AssertionError as e:
            # TODO: maybe it's better to distinguish between invalid username/password
            # and invalid second-factor password
            msg = _(str(e))
            raise exception.Unauthorized(msg)

        if 'user_id' not in user_context:
            user_context['user_id'] = user_info.user_id"""