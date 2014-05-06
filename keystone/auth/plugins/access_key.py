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
from keystone.openstack.common.gettextutils import _


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
            user_ref = self.identity_api.authenticate_ak(
                            access_key_id=access_key_info.access_id,
                            access_key_secret=access_key_info.secret
                       )
        except AssertionError as e:
            msg = _(unicode(e))
            raise exception.Unauthorized(msg)

        if 'user_id' not in user_context:
            user_context['user_id'] = user_ref.get('id')