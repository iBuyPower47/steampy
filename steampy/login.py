import time

from http import HTTPStatus
import base64
import rsa
from requests import Session, Response
from protobufs.enums_pb2 import ESessionPersistence
from protobufs.steammessages_auth.steamclient_pb2 import *

from steampy import guard
from steampy.models import SteamUrl
from steampy.utils import create_cookie


class LoginExecutor:
    def __init__(self, username: str, password: str, shared_secret: str, session: Session) -> None:
        self.username = username
        self.password = password
        self.one_time_code = ''
        self.shared_secret = shared_secret
        self.session = session
        self.refresh_token = ''

    def _api_call(self, method: str, service: str, endpoint: str, version: str = 'v1', params: dict = None) -> Response:
        url = '/'.join((SteamUrl.API_URL, service, endpoint, version))
        # All requests from the login page use the same 'Referer' and 'Origin' values
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/', 'Origin': SteamUrl.COMMUNITY_URL}
        if method.upper() == 'GET':
            return self.session.get(url, params=params, headers=headers, timeout=15)
        elif method.upper() == 'POST':
            return self.session.post(url, data=params, headers=headers, timeout=15)
        else:
            raise ValueError('Method must be either GET or POST')

    def login(self) -> Session:
        rsa_params = self._fetch_rsa_params_protobuf()
        encrypted_password = self._encrypt_password_protobuf(rsa_params)
        rsa_timestamp = rsa_params.timestamp
        auth_session = self._begin_auth_session_protobuf(
            encrypted_password=encrypted_password,
            rsa_timestamp=rsa_timestamp,
        )

        self.one_time_code = guard.generate_one_time_code(self.shared_secret)
        self._update_auth_session_protobuf(
            client_id=auth_session.client_id,
            steamid=auth_session.steamid,
            code_type=EAuthSessionGuardType.k_EAuthSessionGuardType_DeviceCode,
        )

        session = self._poll_auth_session_status_protobuf(
            client_id=auth_session.client_id,
            request_id=auth_session.request_id,
        )

        self.refresh_token = session.refresh_token
        finalized_response = self._finalize_login()
        self._perform_redirects(finalized_response.json())
        self.set_session_cookies()

        return self.session


    def set_session_cookies(self):
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]
        community_cookie_dic = self.session.cookies.get_dict(domain=community_domain)
        store_cookie_dic = self.session.cookies.get_dict(domain=store_domain)
        for name in ('steamLoginSecure', 'sessionid', 'steamRefresh_steam', 'steamCountry'):
            cookie = self.session.cookies.get_dict()[name]
            if name in ["steamLoginSecure"]:
                store_cookie = create_cookie(name, store_cookie_dic[name], store_domain)
            else:
                store_cookie = create_cookie(name, cookie, store_domain)

            if name in ["sessionid", "steamLoginSecure"]:
                community_cookie = create_cookie(name, community_cookie_dic[name], community_domain)
            else:
                community_cookie = create_cookie(name, cookie, community_domain)

            self.session.cookies.set(**community_cookie)
            self.session.cookies.set(**store_cookie)

    def _fetch_rsa_params_protobuf(self) -> CAuthentication_GetPasswordRSAPublicKey_Response:
        self.session.get(SteamUrl.COMMUNITY_URL)
        rsa_params = self._fetch_rsa_params_protobuf_api_call()
        return rsa_params

    def _fetch_rsa_params_protobuf_api_call(self) -> CAuthentication_GetPasswordRSAPublicKey_Response:
        message = CAuthentication_GetPasswordRSAPublicKey_Request(account_name=self.username)
        response = self._api_call(
            "GET", "IAuthenticationService", "GetPasswordRSAPublicKey", "v1",
            {"input_protobuf_encoded": str(base64.b64encode(message.SerializeToString()), "utf8")}
        )
        return CAuthentication_GetPasswordRSAPublicKey_Response.FromString(response.content)

    def _encrypt_password_protobuf(self, rsa_params: CAuthentication_GetPasswordRSAPublicKey_Response) -> str:
        publickey_exp = int(rsa_params.publickey_exp, 16)  # type:ignore
        publickey_mod = int(rsa_params.publickey_mod, 16)  # type:ignore
        public_key = rsa.PublicKey(
            n=publickey_mod,
            e=publickey_exp,
        )
        encrypted_password = rsa.encrypt(
            message=self.password.encode("utf-8"),
            pub_key=public_key,
        )
        return str(base64.b64encode(encrypted_password), "utf8")

    def _begin_auth_session_protobuf(
            self,
            encrypted_password: str,
            rsa_timestamp: int,
    ) -> CAuthentication_BeginAuthSessionViaCredentials_Response:
        message = CAuthentication_BeginAuthSessionViaCredentials_Request(
            account_name=self.username,
            encrypted_password=encrypted_password,
            encryption_timestamp=rsa_timestamp,
            remember_login=True,
            platform_type=EAuthTokenPlatformType.k_EAuthTokenPlatformType_MobileApp,
            persistence=ESessionPersistence.k_ESessionPersistence_Persistent
        )
        response = self._api_call(
            "POST", "IAuthenticationService", "BeginAuthSessionViaCredentials", "v1",
            {"input_protobuf_encoded": str(base64.b64encode(message.SerializeToString()), "utf8")}
        )
        return CAuthentication_BeginAuthSessionViaCredentials_Response.FromString(response.content)

    def _update_auth_session_protobuf(
            self,
            client_id: int,
            steamid: int,
            code_type: int,
    ) -> Response:
        message = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request(
            client_id=client_id,
            steamid=steamid,
            code=self.one_time_code,
            code_type=code_type,
        )
        resp = self._api_call(
            "POST",
            "IAuthenticationService",
            "UpdateAuthSessionWithSteamGuardCode",
            "v1",
            {"input_protobuf_encoded": str(base64.b64encode(message.SerializeToString()), "utf8")},
        )
        return resp

    def _poll_auth_session_status_protobuf(
            self,
            client_id: int,
            request_id: bytes,
    ) -> CAuthentication_PollAuthSessionStatus_Response:
        message = CAuthentication_PollAuthSessionStatus_Request(
            client_id=client_id,
            request_id=request_id,
        )
        response = self._api_call(
            "POST", "IAuthenticationService", "PollAuthSessionStatus", "v1",
            {"input_protobuf_encoded": str(base64.b64encode(message.SerializeToString()), "utf8")}
        )
        return CAuthentication_PollAuthSessionStatus_Response.FromString(response.content)

    def _finalize_login(self) -> Response:
        sessionid = self.session.cookies['sessionid']
        redir = f'{SteamUrl.COMMUNITY_URL}/login/home/?goto='
        files = {
            'nonce': (None, self.refresh_token),
            'sessionid': (None, sessionid),
            'redir': (None, redir)
        }
        headers = {
            'Referer': redir,
            'Origin': 'https://steamcommunity.com'
        }
        return self.session.post("https://login.steampowered.com/jwt/finalizelogin", headers=headers, files=files,
                                 timeout=15)

    def _perform_redirects(self, response_dict: dict) -> None:
        parameters = response_dict.get('transfer_info')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for pass_data in parameters:
            pass_data['params'].update({'steamID': response_dict['steamID']})
            multipart_fields = {
                key: (None, str(value))
                for key, value in pass_data['params'].items()
            }
            self.session.post(pass_data['url'], files=multipart_fields, timeout=15)
