"""Custom exceptions for Blind AI SDK."""


class BlindAIError(Exception):
    """Base exception for all Blind AI SDK errors."""

    pass


class ThreatBlockedError(BlindAIError):
    """Raised when a threat is detected and blocked.

    Attributes:
        message: Error message
        threat_level: Severity level (low, medium, high, critical)
        threats: List of detected threats
        response: Full API response
    """

    def __init__(
        self,
        message: str,
        threat_level: str,
        threats: list,
        response: dict,
    ):
        """Initialize ThreatBlockedError.

        Args:
            message: Error message
            threat_level: Severity level
            threats: List of threats detected
            response: Full API response
        """
        super().__init__(message)
        self.threat_level = threat_level
        self.threats = threats
        self.response = response


class APIError(BlindAIError):
    """Raised when API request fails.

    Attributes:
        message: Error message
        status_code: HTTP status code
        response: Response data if available
    """

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        """Initialize APIError.

        Args:
            message: Error message
            status_code: HTTP status code
            response: Response data
        """
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class TimeoutError(BlindAIError):
    """Raised when API request times out."""

    pass


class ConfigurationError(BlindAIError):
    """Raised when SDK is misconfigured."""

    pass


class RetryExhaustedError(BlindAIError):
    """Raised when all retry attempts are exhausted.

    Attributes:
        message: Error message
        attempts: Number of attempts made
        last_error: The last error encountered
    """

    def __init__(self, message: str, attempts: int, last_error: Exception):
        """Initialize RetryExhaustedError.

        Args:
            message: Error message
            attempts: Number of attempts
            last_error: Last error encountered
        """
        super().__init__(message)
        self.attempts = attempts
        self.last_error = last_error
