
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


class HttprawError(CtfboxError):
    pass


class ScanError(CtfboxError):
    pass


class RepairError(CtfboxError):
    pass


class DumpError(CtfboxError):
    pass


class GitParseError(DumpError):
    pass


class SvnParseError(DumpError):
    pass


class DSStoreParseError(DumpError):
    pass
