r"""
"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_libfuncs
else:
    import _ida_libfuncs

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "this":
            set(self, name, value)
        elif name == "thisown":
            self.this.own(value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref

SWIG_PYTHON_LEGACY_BOOL = _ida_libfuncs.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

class idasgn_header_t(object):
    r"""
    Proxy of C++ idasgn_header_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    magic: "char [6]" = property(_ida_libfuncs.idasgn_header_t_magic_get, _ida_libfuncs.idasgn_header_t_magic_set, doc=r"""magic""")
    version: "uchar" = property(_ida_libfuncs.idasgn_header_t_version_get, _ida_libfuncs.idasgn_header_t_version_set, doc=r"""version""")
    processor_id: "uchar" = property(_ida_libfuncs.idasgn_header_t_processor_id_get, _ida_libfuncs.idasgn_header_t_processor_id_set, doc=r"""processor_id""")
    file_formats: "uint32" = property(_ida_libfuncs.idasgn_header_t_file_formats_get, _ida_libfuncs.idasgn_header_t_file_formats_set, doc=r"""file_formats""")
    ostype: "uint16" = property(_ida_libfuncs.idasgn_header_t_ostype_get, _ida_libfuncs.idasgn_header_t_ostype_set, doc=r"""ostype""")
    apptype: "uint16" = property(_ida_libfuncs.idasgn_header_t_apptype_get, _ida_libfuncs.idasgn_header_t_apptype_set, doc=r"""apptype""")
    flags: "uint16" = property(_ida_libfuncs.idasgn_header_t_flags_get, _ida_libfuncs.idasgn_header_t_flags_set, doc=r"""flags""")
    number_of_modules_v5: "uint16" = property(_ida_libfuncs.idasgn_header_t_number_of_modules_v5_get, _ida_libfuncs.idasgn_header_t_number_of_modules_v5_set, doc=r"""number_of_modules_v5""")
    ctype_crc: "uint16" = property(_ida_libfuncs.idasgn_header_t_ctype_crc_get, _ida_libfuncs.idasgn_header_t_ctype_crc_set, doc=r"""ctype_crc""")
    ctype_name: "char [12]" = property(_ida_libfuncs.idasgn_header_t_ctype_name_get, _ida_libfuncs.idasgn_header_t_ctype_name_set, doc=r"""ctype_name""")
    libname_length: "uchar" = property(_ida_libfuncs.idasgn_header_t_libname_length_get, _ida_libfuncs.idasgn_header_t_libname_length_set, doc=r"""libname_length""")
    ctype_crc_alt: "uint16" = property(_ida_libfuncs.idasgn_header_t_ctype_crc_alt_get, _ida_libfuncs.idasgn_header_t_ctype_crc_alt_set, doc=r"""ctype_crc_alt""")
    number_of_modules: "uint32" = property(_ida_libfuncs.idasgn_header_t_number_of_modules_get, _ida_libfuncs.idasgn_header_t_number_of_modules_set, doc=r"""number_of_modules""")
    pattern_length: "uint16" = property(_ida_libfuncs.idasgn_header_t_pattern_length_get, _ida_libfuncs.idasgn_header_t_pattern_length_set, doc=r"""pattern_length""")
    ctype_crc_3v: "uint16" = property(_ida_libfuncs.idasgn_header_t_ctype_crc_3v_get, _ida_libfuncs.idasgn_header_t_ctype_crc_3v_set, doc=r"""ctype_crc_3v""")

    def __init__(self):
        r"""
        __init__(self) -> idasgn_header_t
        """
        _ida_libfuncs.idasgn_header_t_swiginit(self, _ida_libfuncs.new_idasgn_header_t())
    __swig_destroy__ = _ida_libfuncs.delete_idasgn_header_t

# Register idasgn_header_t in _ida_libfuncs:
_ida_libfuncs.idasgn_header_t_swigregister(idasgn_header_t)
SIGN_HEADER_MAGIC = _ida_libfuncs.SIGN_HEADER_MAGIC

SIGN_HEADER_VERSION = _ida_libfuncs.SIGN_HEADER_VERSION

OSTYPE_MSDOS = _ida_libfuncs.OSTYPE_MSDOS

OSTYPE_WIN = _ida_libfuncs.OSTYPE_WIN

OSTYPE_OS2 = _ida_libfuncs.OSTYPE_OS2

OSTYPE_NETW = _ida_libfuncs.OSTYPE_NETW

OSTYPE_UNIX = _ida_libfuncs.OSTYPE_UNIX

OSTYPE_OTHER = _ida_libfuncs.OSTYPE_OTHER

APPT_CONSOLE = _ida_libfuncs.APPT_CONSOLE

APPT_GRAPHIC = _ida_libfuncs.APPT_GRAPHIC

APPT_PROGRAM = _ida_libfuncs.APPT_PROGRAM

APPT_LIBRARY = _ida_libfuncs.APPT_LIBRARY

APPT_DRIVER = _ida_libfuncs.APPT_DRIVER

APPT_1THREAD = _ida_libfuncs.APPT_1THREAD

APPT_MTHREAD = _ida_libfuncs.APPT_MTHREAD

APPT_16BIT = _ida_libfuncs.APPT_16BIT

APPT_32BIT = _ida_libfuncs.APPT_32BIT

APPT_64BIT = _ida_libfuncs.APPT_64BIT

LS_STARTUP = _ida_libfuncs.LS_STARTUP

LS_CTYPE = _ida_libfuncs.LS_CTYPE

LS_CTYPE2 = _ida_libfuncs.LS_CTYPE2

LS_CTYPE_ALT = _ida_libfuncs.LS_CTYPE_ALT

LS_ZIP = _ida_libfuncs.LS_ZIP

LS_CTYPE_3V = _ida_libfuncs.LS_CTYPE_3V



def get_idasgn_header_by_short_name(out_header: "idasgn_header_t", name: "char const *") -> "qstring *":
    r"""
    get_idasgn_header_by_short_name(out_header, name) -> str
    Get idasgn header by a short signature name.

    @param out_header: (C++: idasgn_header_t *) buffer for the signature file header
    @param name: (C++: const char *) short name of a signature
    @return: true in case of success
    """
    return _ida_libfuncs.get_idasgn_header_by_short_name(out_header, name)

def get_idasgn_path_by_short_name(name: "char const *") -> "qstring *":
    r"""
    get_idasgn_path_by_short_name(name) -> str
    Get idasgn full path by a short signature name.

    @param name: (C++: const char *) short name of a signature
    @return: true in case of success
    """
    return _ida_libfuncs.get_idasgn_path_by_short_name(name)


