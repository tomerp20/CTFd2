import boto3
from botocore.exceptions import ClientError

class CognitoUserManager:
    def __init__(self, user_pool_id, client_id, region_name='us-east-1'):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client = boto3.client('cognito-idp', region_name=region_name)

    def create_user(self, username, password, attributes):
        try:
            response = self.client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=attributes,
                TemporaryPassword=password
            )
            return response
        except ClientError as e:
            print(f"Error creating user: {e}")
            return None

    def delete_user(self, username):
        try:
            response = self.client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            return response
        except ClientError as e:
            print(f"Error deleting user: {e}")
            return None

    def update_user_attributes(self, username, attributes):
        try:
            response = self.client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=attributes
            )
            return response
        except ClientError as e:
            print(f"Error updating user attributes: {e}")
            return None

    def authenticate_user(self, username, password):
        try:
            response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            return response
        except ClientError as e:
            print(f"Error authenticating user: {e}")
            return None
