from typing import Optional

from steampy.steam_error_codes import STEAM_ERROR_CODES


class SevenDaysHoldException(Exception):
    pass


class TooManyRequests(Exception):
    pass


class ApiException(Exception):
    pass


class LoginRequired(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class CaptchaRequired(Exception):
    pass


class ConfirmationExpected(Exception):
    pass


class ProxyConnectionError(Exception):
    pass


class SteamError(Exception):
    def __init__(self, error_code: int, error_msg: Optional[str] = None):
        self.error_code = error_code
        self.error_msg = error_msg

    def __str__(self) -> str:
        return str({
            'error': STEAM_ERROR_CODES.get(self.error_code, self.error_code),
            'msg': self.error_msg,
            'code': self.error_code,
        })


class SendOfferError(Exception):
    """Error sending trade offer."""


class SteamServerDownError(SendOfferError):
    """Steam servers may be down."""


class TradeOffersLimitError(SendOfferError):
    """Trade offers limit reached."""


class AccountOverflowError(SendOfferError):
    """Account overflow."""


class TradeBanError(SendOfferError):
    """Account has a trade ban."""


class ProfileSettingsError(SendOfferError):
    """Incorrect profile settings."""


class TradelinkError(SendOfferError):
    """Trade link may be incorrect."""


class MobileConfirmationError(Exception):
    """Base mobile confirmation error."""


class NotFoundMobileConfirmationError(MobileConfirmationError):
    """No offer found pending mobile confirmation."""


class InvalidAuthenticatorError(MobileConfirmationError):
    """Invalid authenticator."""


class InvalidConfirmationPageError(MobileConfirmationError):
    """Invalid confirmation page."""
