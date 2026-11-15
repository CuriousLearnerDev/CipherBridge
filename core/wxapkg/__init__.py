"""微信小程序 .wxapkg 纯 Python 反编译."""

from core.wxapkg.decrypt import (
    decrypt_wxapkg,
    guess_appid_from_path,
    is_encrypted,
    looks_like_wxapkg,
    WxapkgDecryptError,
)
from core.wxapkg.unpack import unpack_bytes, parse_file_table, WxapkgUnpackError
from core.wxapkg.pipeline import (
    DecompileResult,
    MiniprogramInfo,
    decompile_wxapkg,
    default_package_roots,
    default_workspace,
    discover_miniprograms,
    list_wxapkg_files,
)
from core.wxapkg.scanner import collect_crypto_scripts, scripts_as_dict

__all__ = [
    "DecompileResult",
    "MiniprogramInfo",
    "WxapkgDecryptError",
    "WxapkgUnpackError",
    "collect_crypto_scripts",
    "decompile_wxapkg",
    "decrypt_wxapkg",
    "default_package_roots",
    "default_workspace",
    "discover_miniprograms",
    "guess_appid_from_path",
    "is_encrypted",
    "list_wxapkg_files",
    "looks_like_wxapkg",
    "parse_file_table",
    "scripts_as_dict",
    "unpack_bytes",
]
