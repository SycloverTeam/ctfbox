
class CtfboxError(Exception):
    pass


class FlaskSessionHelperError(CtfboxError):
    pass


class ProvideArgumentError(CtfboxError):
    pass


class HashAuthArgumentError(CtfboxError):
    pass


class GeneratePayloadError(CtfboxError):
    pass
