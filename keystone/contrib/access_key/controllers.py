# Copyright 2014 OpenStack Foundation
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

"""Main entry point into the Access Key Credentials service.
"""

import abc
import uuid

import six

from keystoneclient.contrib.access_key import utils as access_key_utils

from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import jsonutils
from keystone import token

@dependency.requires('assignment_api', 'catalog_api', 'credential_api',
                     'identity_api', 'token_api')
#@six.add_metaclass(abc.ABCMeta)
class AccessKeyControllerCommon(object):
    @abc.abstractmethod
    def authenticate(self, context, credentials=None):
        """Validate a signed Access Key request and provide a token.

        Other services (such as Nova) use this **admin** call to determine
        if a request they signed received is from a valid user.

        If it is a valid signature, an OpenStack token that maps
        to the user/tenant is returned to the caller, along with
        all the other details returned from a normal token validation
        call.

        The returned token is useful for making calls to other
        OpenStack services within the context of the request.

        :param context: standard context
        :param credentials: dict of Access Key signature
        :returns: token: OpenStack token equivalent to access key along
                         with the corresponding service catalog and roles
        """
        raise exception.NotImplemented()



    def create_credential(self, context, user_id, tenant_id):
        """Create a secret/access pair for use with ec2 style auth.

        Generates a new set of credentials that map the user/tenant
        pair.

        :param context: standard context
        :param user_id: id of user
        :param tenant_id: id of tenant
        :returns: credential: dict of ec2 credential
        """

        self.identity_api.get_user(user_id)
        self.assignment_api.get_project(tenant_id)
        trust_id = self._get_trust_id_for_request(context)
        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex,
                'trust_id': trust_id}
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': tenant_id,
                    'blob': jsonutils.dumps(blob),
                    'id': credential_id,
                    'type': 'ec2'}
        self.credential_api.create_credential(credential_id, cred_ref)
        return {'credential': self._convert_v3_to_ec2_credential(cred_ref)}

    def get_credentials(self, user_id):
        """List all credentials for a user.

        :param user_id: id of user
        :returns: credentials: list of ec2 credential dicts
        """

        self.identity_api.get_user(user_id)
        credential_refs = self.credential_api.list_credentials(
            user_id=user_id)
        return {'credentials':
                [self._convert_v3_to_ec2_credential(credential)
                    for credential in credential_refs]}

    def get_credential(self, user_id, credential_id):
        """Retrieve a user's access/secret pair by the access key.

        Grab the full access/secret pair for a given access key.

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: credential: dict of ec2 credential
        """

        self.identity_api.get_user(user_id)
        return {'credential': self._get_credentials(credential_id)}

    def delete_credential(self, user_id, credential_id):
        """Delete a user's access/secret pair.

        Used to revoke a user's access/secret pair

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: bool: success
        """

        self.identity_api.get_user(user_id)
        self._get_credentials(credential_id)
        ec2_credential_id = utils.hash_access_key(credential_id)
        return self.credential_api.delete_credential(ec2_credential_id)

    @staticmethod
    def _convert_v3_to_ec2_credential(credential):
        # Prior to bug #1259584 fix, blob was stored unserialized
        # but it should be stored as a json string for compatibility
        # with the v3 credentials API.  Fall back to the old behavior
        # for backwards compatibility with existing DB contents
        try:
            blob = jsonutils.loads(credential['blob'])
        except TypeError:
            blob = credential['blob']
        return {'user_id': credential.get('user_id'),
                'tenant_id': credential.get('project_id'),
                'access': blob.get('access'),
                'secret': blob.get('secret')}

    def _get_credentials(self, credential):
        """Return credentials from an ID.

        :param credential_id: id of credential
        :raises exception.Unauthorized: when credential id is invalid
        :returns: credential: dict of ec2 credential.
        """

        ec2_credential_id = utils.hash_access_key(credential)
        creds = self.credential_api.get_credential(ec2_credential_id)
        if not creds:
            raise exception.Unauthorized(message='EC2 access key not found.')
        return self._convert_v3_to_ec2_credential(creds)


@dependency.requires('policy_api', 'token_provider_api')
class AccessKeyController(AccessKeyControllerCommon, controller.V2Controller):

    @controller.v2_deprecated
    def authenticate(self, context, credentials=None):

        if 'accesskey' not in credentials:
            raise exception.Unauthorized(message='Invalid access key authentication request')

        creds_ref = self._get_credentials(credentials['accesskey'])

        tenant_ref = self.assignment_api.get_project(creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(creds_ref['user_id'])
        metadata_ref = {}
        metadata_ref['roles'] = (
        self.assignment_api.get_roles_for_user_and_project(
            user_ref['id'], tenant_ref['id']))

        trust_id = creds_ref.get('trust_id')
        if trust_id:
            metadata_ref['trust_id'] = trust_id
            metadata_ref['trustee_user_id'] = user_ref['id']

        roles = metadata_ref.get('roles', [])
        if not roles:
            raise exception.Unauthorized(message='User not valid for tenant.')
        roles_ref = [self.assignment_api.get_role(role_id)
                     for role_id in roles]

        catalog_ref = self.catalog_api.get_catalog(
            user_ref['id'], tenant_ref['id'], metadata_ref)


        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The token provider does not explicitly care about user_ref version
        # in this case, but the data is stored in the token itself and should
        # match the version
        user_ref = self.v3_to_v2_user(user_ref)
        auth_token_data = dict(user=user_ref,
                               tenant=tenant_ref,
                               metadata=metadata_ref,
                               id='placeholder')
        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref, catalog_ref)
        return token_data

    @controller.v2_deprecated
    def get_credential(self, context, user_id, credential_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(AccessKeyController, self).get_credential(user_id,
                                                         credential_id)

    @controller.v2_deprecated
    def get_credentials(self, context, user_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(AccessKeyController, self).get_credentials(user_id)

    @controller.v2_deprecated
    def create_credential(self, context, user_id, tenant_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(AccessKeyController, self).create_credential(context, user_id,
                                                                  tenant_id)

    @controller.v2_deprecated
    def delete_credential(self, context, user_id, credential_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
            self._assert_owner(user_id, credential_id)
        return super(AccessKeyController, self).delete_credential(user_id,
                                                                  credential_id)

    def _assert_identity(self, context, user_id):
        """Check that the provided token belongs to the user.

        :param context: standard context
        :param user_id: id of user
        :raises exception.Forbidden: when token is invalid

        """
        try:
            token_ref = self.token_api.get_token(context['token_id'])
        except exception.TokenNotFound as e:
            raise exception.Unauthorized(e)

        if token_ref['user'].get('id') != user_id:
            raise exception.Forbidden(_('Token belongs to another user'))

    def _is_admin(self, context):
        """Wrap admin assertion error return statement.

        :param context: standard context
        :returns: bool: success

        """
        try:
            # NOTE(morganfainberg): policy_api is required for assert_admin
            # to properly perform policy enforcement.
            self.assert_admin(context)
            return True
        except exception.Forbidden:
            return False

    def _assert_owner(self, user_id, credential_id):
        """Ensure the provided user owns the credential.

        :param user_id: expected credential owner
        :param credential_id: id of credential object
        :raises exception.Forbidden: on failure

        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        cred_ref = self.credential_api.get_credential(ec2_credential_id)
        if user_id != cred_ref['user_id']:
            raise exception.Forbidden(_('Credential belongs to another user'))

#class AccessKeyController(identity.controllers.UserV3):

    #@controller.protected()
    #def reset_access_key(self, context, user_id):
        '''token_id = context.get('token_id')
        token_ref = self.token_api.get_token(token_id)
        user_id_from_token = token_ref['user']['id']

        # You have to be either the user, or an admin
        if user_id_from_token != user_id and self.assert_admin(context) is not None:
            raise exception.Forbidden('Token belongs to another user')

        user = self.get_user(context, user_id)['user']
        user['access_key'] = utils.generate_access_key_secret()
        super(AccessKeyController, self).update_user(context, user_id, user)
        return {'secret': user['access_key']}'''