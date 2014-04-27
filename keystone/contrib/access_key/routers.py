from keystone.common import wsgi
from keystone.contrib.access_key import controllers

class AccessKeyExtension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        access_key_controller = controllers.AccessKeyController()
        # validation
        mapper.connect(
            '/aktokens',
            controller=access_key_controller,
            action='authenticate',
            conditions=dict(method=['POST']))

        # crud
        mapper.connect(
            '/users/{user_id}/credentials/access_key',
            controller=access_key_controller,
            action='create_credential',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/users/{user_id}/credentials/access_key',
            controller=access_key_controller,
            action='get_credentials',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users/{user_id}/credentials/access_key/{credential_id}',
            controller=access_key_controller,
            action='get_credential',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users/{user_id}/credentials/access_key/{credential_id}',
            controller=access_key_controller,
            action='delete_credential',
            conditions=dict(method=['DELETE']))