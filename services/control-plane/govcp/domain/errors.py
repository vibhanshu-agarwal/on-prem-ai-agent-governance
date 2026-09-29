"""Domain errors. The API layer maps these to HTTP status codes."""


class DomainError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str, **details):
        super().__init__(message)
        self.message = message
        self.details = details


class NotFound(DomainError):
    status = 404
    code = "not_found"


class Conflict(DomainError):
    status = 409
    code = "conflict"


class Forbidden(DomainError):
    status = 403
    code = "forbidden"


class Unauthorized(DomainError):
    status = 401
    code = "unauthorized"


class RateLimited(DomainError):
    status = 429
    code = "rate_limited"


class InvalidRequest(DomainError):
    status = 422
    code = "invalid_request"


class DelegationDenied(Forbidden):
    code = "delegation_denied"


class StalePreview(Conflict):
    code = "stale_preview"


class AdapterError(DomainError):
    status = 502
    code = "adapter_error"
