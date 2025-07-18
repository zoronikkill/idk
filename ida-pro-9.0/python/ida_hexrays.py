r"""
"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_hexrays
else:
    import _ida_hexrays

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

SWIG_PYTHON_LEGACY_BOOL = _ida_hexrays.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

import ida_pro
import ida_xref
import ida_typeinf
import ida_idp
import ida_gdl

def _kludge_force_declare_TPopupMenu(arg1: "TPopupMenu const *") -> "void":
    r"""
    _kludge_force_declare_TPopupMenu(arg1)

    Parameters
    ----------
    arg1: TPopupMenu const *

    """
    return _ida_hexrays._kludge_force_declare_TPopupMenu(arg1)
class array_of_bitsets(object):
    r"""
    Proxy of C++ qvector< bitset_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> array_of_bitsets
        __init__(self, x) -> array_of_bitsets

        @param x: qvector< bitset_t > const &
        """
        _ida_hexrays.array_of_bitsets_swiginit(self, _ida_hexrays.new_array_of_bitsets(*args))
    __swig_destroy__ = _ida_hexrays.delete_array_of_bitsets

    def push_back(self, *args) -> "bitset_t &":
        r"""
        push_back(self, x)

        @param x: bitset_t const &

        push_back(self) -> bitset_t
        """
        return _ida_hexrays.array_of_bitsets_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.array_of_bitsets_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.array_of_bitsets_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.array_of_bitsets_empty(self)

    def at(self, _idx: "size_t") -> "bitset_t const &":
        r"""
        at(self, _idx) -> bitset_t

        @param _idx: size_t
        """
        return _ida_hexrays.array_of_bitsets_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.array_of_bitsets_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.array_of_bitsets_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: bitset_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.array_of_bitsets_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=bitset_t())

        @param x: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.array_of_bitsets_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.array_of_bitsets_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.array_of_bitsets_truncate(self)

    def swap(self, r: "array_of_bitsets") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< bitset_t > &
        """
        return _ida_hexrays.array_of_bitsets_swap(self, r)

    def extract(self) -> "bitset_t *":
        r"""
        extract(self) -> bitset_t
        """
        return _ida_hexrays.array_of_bitsets_extract(self)

    def inject(self, s: "bitset_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: bitset_t *
        @param len: size_t
        """
        return _ida_hexrays.array_of_bitsets_inject(self, s, len)

    def __eq__(self, r: "array_of_bitsets") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< bitset_t > const &
        """
        return _ida_hexrays.array_of_bitsets___eq__(self, r)

    def __ne__(self, r: "array_of_bitsets") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< bitset_t > const &
        """
        return _ida_hexrays.array_of_bitsets___ne__(self, r)

    def begin(self, *args) -> "qvector< bitset_t >::const_iterator":
        r"""
        begin(self) -> bitset_t
        """
        return _ida_hexrays.array_of_bitsets_begin(self, *args)

    def end(self, *args) -> "qvector< bitset_t >::const_iterator":
        r"""
        end(self) -> bitset_t
        """
        return _ida_hexrays.array_of_bitsets_end(self, *args)

    def insert(self, it: "bitset_t", x: "bitset_t") -> "qvector< bitset_t >::iterator":
        r"""
        insert(self, it, x) -> bitset_t

        @param it: qvector< bitset_t >::iterator
        @param x: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets_insert(self, it, x)

    def erase(self, *args) -> "qvector< bitset_t >::iterator":
        r"""
        erase(self, it) -> bitset_t

        @param it: qvector< bitset_t >::iterator

        erase(self, first, last) -> bitset_t

        @param first: qvector< bitset_t >::iterator
        @param last: qvector< bitset_t >::iterator
        """
        return _ida_hexrays.array_of_bitsets_erase(self, *args)

    def find(self, *args) -> "qvector< bitset_t >::const_iterator":
        r"""
        find(self, x) -> bitset_t

        @param x: bitset_t const &

        """
        return _ida_hexrays.array_of_bitsets_find(self, *args)

    def has(self, x: "bitset_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets_has(self, x)

    def add_unique(self, x: "bitset_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets_add_unique(self, x)

    def _del(self, x: "bitset_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: bitset_t const &

        """
        return _ida_hexrays.array_of_bitsets__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.array_of_bitsets___len__(self)

    def __getitem__(self, i: "size_t") -> "bitset_t const &":
        r"""
        __getitem__(self, i) -> bitset_t

        @param i: size_t
        """
        return _ida_hexrays.array_of_bitsets___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "bitset_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets___setitem__(self, i, v)

    def append(self, x: "bitset_t") -> "void":
        r"""
        append(self, x)

        @param x: bitset_t const &
        """
        return _ida_hexrays.array_of_bitsets_append(self, x)

    def extend(self, x: "array_of_bitsets") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< bitset_t > const &
        """
        return _ida_hexrays.array_of_bitsets_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register array_of_bitsets in _ida_hexrays:
_ida_hexrays.array_of_bitsets_swigregister(array_of_bitsets)
class mopvec_t(object):
    r"""
    Proxy of C++ qvector< mop_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> mopvec_t
        __init__(self, x) -> mopvec_t

        @param x: qvector< mop_t > const &
        """
        _ida_hexrays.mopvec_t_swiginit(self, _ida_hexrays.new_mopvec_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_mopvec_t

    def push_back(self, *args) -> "mop_t &":
        r"""
        push_back(self, x)

        @param x: mop_t const &

        push_back(self) -> mop_t
        """
        return _ida_hexrays.mopvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.mopvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.mopvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mopvec_t_empty(self)

    def at(self, _idx: "size_t") -> "mop_t const &":
        r"""
        at(self, _idx) -> mop_t

        @param _idx: size_t
        """
        return _ida_hexrays.mopvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.mopvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.mopvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: mop_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.mopvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=mop_t())

        @param x: mop_t const &
        """
        return _ida_hexrays.mopvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.mopvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.mopvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.mopvec_t_truncate(self)

    def swap(self, r: "mopvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< mop_t > &
        """
        return _ida_hexrays.mopvec_t_swap(self, r)

    def extract(self) -> "mop_t *":
        r"""
        extract(self) -> mop_t
        """
        return _ida_hexrays.mopvec_t_extract(self)

    def inject(self, s: "mop_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: mop_t *
        @param len: size_t
        """
        return _ida_hexrays.mopvec_t_inject(self, s, len)

    def __eq__(self, r: "mopvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< mop_t > const &
        """
        return _ida_hexrays.mopvec_t___eq__(self, r)

    def __ne__(self, r: "mopvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< mop_t > const &
        """
        return _ida_hexrays.mopvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< mop_t >::const_iterator":
        r"""
        begin(self) -> mop_t
        """
        return _ida_hexrays.mopvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< mop_t >::const_iterator":
        r"""
        end(self) -> mop_t
        """
        return _ida_hexrays.mopvec_t_end(self, *args)

    def insert(self, it: "mop_t", x: "mop_t") -> "qvector< mop_t >::iterator":
        r"""
        insert(self, it, x) -> mop_t

        @param it: qvector< mop_t >::iterator
        @param x: mop_t const &
        """
        return _ida_hexrays.mopvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< mop_t >::iterator":
        r"""
        erase(self, it) -> mop_t

        @param it: qvector< mop_t >::iterator

        erase(self, first, last) -> mop_t

        @param first: qvector< mop_t >::iterator
        @param last: qvector< mop_t >::iterator
        """
        return _ida_hexrays.mopvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< mop_t >::const_iterator":
        r"""
        find(self, x) -> mop_t

        @param x: mop_t const &

        """
        return _ida_hexrays.mopvec_t_find(self, *args)

    def has(self, x: "mop_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: mop_t const &
        """
        return _ida_hexrays.mopvec_t_has(self, x)

    def add_unique(self, x: "mop_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: mop_t const &
        """
        return _ida_hexrays.mopvec_t_add_unique(self, x)

    def _del(self, x: "mop_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: mop_t const &

        """
        return _ida_hexrays.mopvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.mopvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "mop_t const &":
        r"""
        __getitem__(self, i) -> mop_t

        @param i: size_t
        """
        return _ida_hexrays.mopvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "mop_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: mop_t const &
        """
        return _ida_hexrays.mopvec_t___setitem__(self, i, v)

    def append(self, x: "mop_t") -> "void":
        r"""
        append(self, x)

        @param x: mop_t const &
        """
        return _ida_hexrays.mopvec_t_append(self, x)

    def extend(self, x: "mopvec_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< mop_t > const &
        """
        return _ida_hexrays.mopvec_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register mopvec_t in _ida_hexrays:
_ida_hexrays.mopvec_t_swigregister(mopvec_t)
class mcallargs_t(object):
    r"""
    Proxy of C++ qvector< mcallarg_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> mcallargs_t
        __init__(self, x) -> mcallargs_t

        @param x: qvector< mcallarg_t > const &
        """
        _ida_hexrays.mcallargs_t_swiginit(self, _ida_hexrays.new_mcallargs_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_mcallargs_t

    def push_back(self, *args) -> "mcallarg_t &":
        r"""
        push_back(self, x)

        @param x: mcallarg_t const &

        push_back(self) -> mcallarg_t
        """
        return _ida_hexrays.mcallargs_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.mcallargs_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.mcallargs_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mcallargs_t_empty(self)

    def at(self, _idx: "size_t") -> "mcallarg_t const &":
        r"""
        at(self, _idx) -> mcallarg_t

        @param _idx: size_t
        """
        return _ida_hexrays.mcallargs_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.mcallargs_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.mcallargs_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: mcallarg_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.mcallargs_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=mcallarg_t())

        @param x: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.mcallargs_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.mcallargs_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.mcallargs_t_truncate(self)

    def swap(self, r: "mcallargs_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< mcallarg_t > &
        """
        return _ida_hexrays.mcallargs_t_swap(self, r)

    def extract(self) -> "mcallarg_t *":
        r"""
        extract(self) -> mcallarg_t
        """
        return _ida_hexrays.mcallargs_t_extract(self)

    def inject(self, s: "mcallarg_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: mcallarg_t *
        @param len: size_t
        """
        return _ida_hexrays.mcallargs_t_inject(self, s, len)

    def __eq__(self, r: "mcallargs_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< mcallarg_t > const &
        """
        return _ida_hexrays.mcallargs_t___eq__(self, r)

    def __ne__(self, r: "mcallargs_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< mcallarg_t > const &
        """
        return _ida_hexrays.mcallargs_t___ne__(self, r)

    def begin(self, *args) -> "qvector< mcallarg_t >::const_iterator":
        r"""
        begin(self) -> mcallarg_t
        """
        return _ida_hexrays.mcallargs_t_begin(self, *args)

    def end(self, *args) -> "qvector< mcallarg_t >::const_iterator":
        r"""
        end(self) -> mcallarg_t
        """
        return _ida_hexrays.mcallargs_t_end(self, *args)

    def insert(self, it: "mcallarg_t", x: "mcallarg_t") -> "qvector< mcallarg_t >::iterator":
        r"""
        insert(self, it, x) -> mcallarg_t

        @param it: qvector< mcallarg_t >::iterator
        @param x: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< mcallarg_t >::iterator":
        r"""
        erase(self, it) -> mcallarg_t

        @param it: qvector< mcallarg_t >::iterator

        erase(self, first, last) -> mcallarg_t

        @param first: qvector< mcallarg_t >::iterator
        @param last: qvector< mcallarg_t >::iterator
        """
        return _ida_hexrays.mcallargs_t_erase(self, *args)

    def find(self, *args) -> "qvector< mcallarg_t >::const_iterator":
        r"""
        find(self, x) -> mcallarg_t

        @param x: mcallarg_t const &

        """
        return _ida_hexrays.mcallargs_t_find(self, *args)

    def has(self, x: "mcallarg_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t_has(self, x)

    def add_unique(self, x: "mcallarg_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t_add_unique(self, x)

    def _del(self, x: "mcallarg_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: mcallarg_t const &

        """
        return _ida_hexrays.mcallargs_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.mcallargs_t___len__(self)

    def __getitem__(self, i: "size_t") -> "mcallarg_t const &":
        r"""
        __getitem__(self, i) -> mcallarg_t

        @param i: size_t
        """
        return _ida_hexrays.mcallargs_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "mcallarg_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t___setitem__(self, i, v)

    def append(self, x: "mcallarg_t") -> "void":
        r"""
        append(self, x)

        @param x: mcallarg_t const &
        """
        return _ida_hexrays.mcallargs_t_append(self, x)

    def extend(self, x: "mcallargs_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< mcallarg_t > const &
        """
        return _ida_hexrays.mcallargs_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register mcallargs_t in _ida_hexrays:
_ida_hexrays.mcallargs_t_swigregister(mcallargs_t)
class block_chains_vec_t(object):
    r"""
    Proxy of C++ qvector< block_chains_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> block_chains_vec_t
        __init__(self, x) -> block_chains_vec_t

        @param x: qvector< block_chains_t > const &
        """
        _ida_hexrays.block_chains_vec_t_swiginit(self, _ida_hexrays.new_block_chains_vec_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_block_chains_vec_t

    def push_back(self, *args) -> "block_chains_t &":
        r"""
        push_back(self, x)

        @param x: block_chains_t const &

        push_back(self) -> block_chains_t
        """
        return _ida_hexrays.block_chains_vec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.block_chains_vec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.block_chains_vec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.block_chains_vec_t_empty(self)

    def at(self, _idx: "size_t") -> "block_chains_t const &":
        r"""
        at(self, _idx) -> block_chains_t

        @param _idx: size_t
        """
        return _ida_hexrays.block_chains_vec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.block_chains_vec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.block_chains_vec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: block_chains_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.block_chains_vec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=block_chains_t())

        @param x: block_chains_t const &
        """
        return _ida_hexrays.block_chains_vec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.block_chains_vec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.block_chains_vec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.block_chains_vec_t_truncate(self)

    def swap(self, r: "block_chains_vec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< block_chains_t > &
        """
        return _ida_hexrays.block_chains_vec_t_swap(self, r)

    def extract(self) -> "block_chains_t *":
        r"""
        extract(self) -> block_chains_t
        """
        return _ida_hexrays.block_chains_vec_t_extract(self)

    def inject(self, s: "block_chains_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: block_chains_t *
        @param len: size_t
        """
        return _ida_hexrays.block_chains_vec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< block_chains_t >::const_iterator":
        r"""
        begin(self) -> block_chains_t
        """
        return _ida_hexrays.block_chains_vec_t_begin(self, *args)

    def end(self, *args) -> "qvector< block_chains_t >::const_iterator":
        r"""
        end(self) -> block_chains_t
        """
        return _ida_hexrays.block_chains_vec_t_end(self, *args)

    def insert(self, it: "block_chains_t", x: "block_chains_t") -> "qvector< block_chains_t >::iterator":
        r"""
        insert(self, it, x) -> block_chains_t

        @param it: qvector< block_chains_t >::iterator
        @param x: block_chains_t const &
        """
        return _ida_hexrays.block_chains_vec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< block_chains_t >::iterator":
        r"""
        erase(self, it) -> block_chains_t

        @param it: qvector< block_chains_t >::iterator

        erase(self, first, last) -> block_chains_t

        @param first: qvector< block_chains_t >::iterator
        @param last: qvector< block_chains_t >::iterator
        """
        return _ida_hexrays.block_chains_vec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.block_chains_vec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "block_chains_t const &":
        r"""
        __getitem__(self, i) -> block_chains_t

        @param i: size_t
        """
        return _ida_hexrays.block_chains_vec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "block_chains_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: block_chains_t const &
        """
        return _ida_hexrays.block_chains_vec_t___setitem__(self, i, v)

    def append(self, x: "block_chains_t") -> "void":
        r"""
        append(self, x)

        @param x: block_chains_t const &
        """
        return _ida_hexrays.block_chains_vec_t_append(self, x)

    def extend(self, x: "block_chains_vec_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< block_chains_t > const &
        """
        return _ida_hexrays.block_chains_vec_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register block_chains_vec_t in _ida_hexrays:
_ida_hexrays.block_chains_vec_t_swigregister(block_chains_vec_t)
class user_numforms_t(object):
    r"""
    Proxy of C++ std::map< operand_locator_t,number_format_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "operand_locator_t") -> "number_format_t &":
        r"""
        at(self, _Keyval) -> number_format_t

        @param _Keyval: operand_locator_t const &
        """
        return _ida_hexrays.user_numforms_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.user_numforms_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> user_numforms_t
        """
        _ida_hexrays.user_numforms_t_swiginit(self, _ida_hexrays.new_user_numforms_t())
    __swig_destroy__ = _ida_hexrays.delete_user_numforms_t

# Register user_numforms_t in _ida_hexrays:
_ida_hexrays.user_numforms_t_swigregister(user_numforms_t)
class lvar_mapping_t(object):
    r"""
    Proxy of C++ std::map< lvar_locator_t,lvar_locator_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "lvar_locator_t") -> "lvar_locator_t &":
        r"""
        at(self, _Keyval) -> lvar_locator_t

        @param _Keyval: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_mapping_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.lvar_mapping_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> lvar_mapping_t
        """
        _ida_hexrays.lvar_mapping_t_swiginit(self, _ida_hexrays.new_lvar_mapping_t())
    __swig_destroy__ = _ida_hexrays.delete_lvar_mapping_t

# Register lvar_mapping_t in _ida_hexrays:
_ida_hexrays.lvar_mapping_t_swigregister(lvar_mapping_t)
class hexwarns_t(object):
    r"""
    Proxy of C++ qvector< hexwarn_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> hexwarns_t
        __init__(self, x) -> hexwarns_t

        @param x: qvector< hexwarn_t > const &
        """
        _ida_hexrays.hexwarns_t_swiginit(self, _ida_hexrays.new_hexwarns_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_hexwarns_t

    def push_back(self, *args) -> "hexwarn_t &":
        r"""
        push_back(self, x)

        @param x: hexwarn_t const &

        push_back(self) -> hexwarn_t
        """
        return _ida_hexrays.hexwarns_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.hexwarns_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.hexwarns_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.hexwarns_t_empty(self)

    def at(self, _idx: "size_t") -> "hexwarn_t const &":
        r"""
        at(self, _idx) -> hexwarn_t

        @param _idx: size_t
        """
        return _ida_hexrays.hexwarns_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.hexwarns_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.hexwarns_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: hexwarn_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.hexwarns_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=hexwarn_t())

        @param x: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.hexwarns_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.hexwarns_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.hexwarns_t_truncate(self)

    def swap(self, r: "hexwarns_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< hexwarn_t > &
        """
        return _ida_hexrays.hexwarns_t_swap(self, r)

    def extract(self) -> "hexwarn_t *":
        r"""
        extract(self) -> hexwarn_t
        """
        return _ida_hexrays.hexwarns_t_extract(self)

    def inject(self, s: "hexwarn_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: hexwarn_t *
        @param len: size_t
        """
        return _ida_hexrays.hexwarns_t_inject(self, s, len)

    def __eq__(self, r: "hexwarns_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< hexwarn_t > const &
        """
        return _ida_hexrays.hexwarns_t___eq__(self, r)

    def __ne__(self, r: "hexwarns_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< hexwarn_t > const &
        """
        return _ida_hexrays.hexwarns_t___ne__(self, r)

    def begin(self, *args) -> "qvector< hexwarn_t >::const_iterator":
        r"""
        begin(self) -> hexwarn_t
        """
        return _ida_hexrays.hexwarns_t_begin(self, *args)

    def end(self, *args) -> "qvector< hexwarn_t >::const_iterator":
        r"""
        end(self) -> hexwarn_t
        """
        return _ida_hexrays.hexwarns_t_end(self, *args)

    def insert(self, it: "hexwarn_t", x: "hexwarn_t") -> "qvector< hexwarn_t >::iterator":
        r"""
        insert(self, it, x) -> hexwarn_t

        @param it: qvector< hexwarn_t >::iterator
        @param x: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< hexwarn_t >::iterator":
        r"""
        erase(self, it) -> hexwarn_t

        @param it: qvector< hexwarn_t >::iterator

        erase(self, first, last) -> hexwarn_t

        @param first: qvector< hexwarn_t >::iterator
        @param last: qvector< hexwarn_t >::iterator
        """
        return _ida_hexrays.hexwarns_t_erase(self, *args)

    def find(self, *args) -> "qvector< hexwarn_t >::const_iterator":
        r"""
        find(self, x) -> hexwarn_t

        @param x: hexwarn_t const &

        """
        return _ida_hexrays.hexwarns_t_find(self, *args)

    def has(self, x: "hexwarn_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t_has(self, x)

    def add_unique(self, x: "hexwarn_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t_add_unique(self, x)

    def _del(self, x: "hexwarn_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: hexwarn_t const &

        """
        return _ida_hexrays.hexwarns_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.hexwarns_t___len__(self)

    def __getitem__(self, i: "size_t") -> "hexwarn_t const &":
        r"""
        __getitem__(self, i) -> hexwarn_t

        @param i: size_t
        """
        return _ida_hexrays.hexwarns_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "hexwarn_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t___setitem__(self, i, v)

    def append(self, x: "hexwarn_t") -> "void":
        r"""
        append(self, x)

        @param x: hexwarn_t const &
        """
        return _ida_hexrays.hexwarns_t_append(self, x)

    def extend(self, x: "hexwarns_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< hexwarn_t > const &
        """
        return _ida_hexrays.hexwarns_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register hexwarns_t in _ida_hexrays:
_ida_hexrays.hexwarns_t_swigregister(hexwarns_t)
class ctree_items_t(object):
    r"""
    Proxy of C++ qvector< citem_t * > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> ctree_items_t
        __init__(self, x) -> ctree_items_t

        @param x: qvector< citem_t * > const &
        """
        _ida_hexrays.ctree_items_t_swiginit(self, _ida_hexrays.new_ctree_items_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_ctree_items_t

    def push_back(self, *args) -> "citem_t *&":
        r"""
        push_back(self, x)

        @param x: citem_t *const &

        push_back(self) -> citem_t *&
        """
        return _ida_hexrays.ctree_items_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.ctree_items_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.ctree_items_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.ctree_items_t_empty(self)

    def at(self, _idx: "size_t") -> "citem_t *const &":
        r"""
        at(self, _idx) -> citem_t

        @param _idx: size_t
        """
        return _ida_hexrays.ctree_items_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.ctree_items_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.ctree_items_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: citem_t *const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.ctree_items_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.ctree_items_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.ctree_items_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.ctree_items_t_truncate(self)

    def swap(self, r: "ctree_items_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< citem_t * > &
        """
        return _ida_hexrays.ctree_items_t_swap(self, r)

    def extract(self) -> "citem_t **":
        r"""
        extract(self) -> citem_t **
        """
        return _ida_hexrays.ctree_items_t_extract(self)

    def inject(self, s: "citem_t **", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: citem_t **
        @param len: size_t
        """
        return _ida_hexrays.ctree_items_t_inject(self, s, len)

    def __eq__(self, r: "ctree_items_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< citem_t * > const &
        """
        return _ida_hexrays.ctree_items_t___eq__(self, r)

    def __ne__(self, r: "ctree_items_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< citem_t * > const &
        """
        return _ida_hexrays.ctree_items_t___ne__(self, r)

    def begin(self, *args) -> "qvector< citem_t * >::const_iterator":
        r"""
        begin(self) -> qvector< citem_t * >::iterator
        begin(self) -> qvector< citem_t * >::const_iterator
        """
        return _ida_hexrays.ctree_items_t_begin(self, *args)

    def end(self, *args) -> "qvector< citem_t * >::const_iterator":
        r"""
        end(self) -> qvector< citem_t * >::iterator
        end(self) -> qvector< citem_t * >::const_iterator
        """
        return _ida_hexrays.ctree_items_t_end(self, *args)

    def insert(self, it: "qvector< citem_t * >::iterator", x: "citem_t") -> "qvector< citem_t * >::iterator":
        r"""
        insert(self, it, x) -> qvector< citem_t * >::iterator

        @param it: qvector< citem_t * >::iterator
        @param x: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< citem_t * >::iterator":
        r"""
        erase(self, it) -> qvector< citem_t * >::iterator

        @param it: qvector< citem_t * >::iterator

        erase(self, first, last) -> qvector< citem_t * >::iterator

        @param first: qvector< citem_t * >::iterator
        @param last: qvector< citem_t * >::iterator
        """
        return _ida_hexrays.ctree_items_t_erase(self, *args)

    def find(self, *args) -> "qvector< citem_t * >::const_iterator":
        r"""
        find(self, x) -> qvector< citem_t * >::iterator

        @param x: citem_t *const &

        find(self, x) -> qvector< citem_t * >::const_iterator

        @param x: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t_find(self, *args)

    def has(self, x: "citem_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t_has(self, x)

    def add_unique(self, x: "citem_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t_add_unique(self, x)

    def _del(self, x: "citem_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: citem_t *const &

        """
        return _ida_hexrays.ctree_items_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.ctree_items_t___len__(self)

    def __getitem__(self, i: "size_t") -> "citem_t *const &":
        r"""
        __getitem__(self, i) -> citem_t

        @param i: size_t
        """
        return _ida_hexrays.ctree_items_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "citem_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t___setitem__(self, i, v)

    def append(self, x: "citem_t") -> "void":
        r"""
        append(self, x)

        @param x: citem_t *const &
        """
        return _ida_hexrays.ctree_items_t_append(self, x)

    def extend(self, x: "ctree_items_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< citem_t * > const &
        """
        return _ida_hexrays.ctree_items_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register ctree_items_t in _ida_hexrays:
_ida_hexrays.ctree_items_t_swigregister(ctree_items_t)
class user_labels_t(object):
    r"""
    Proxy of C++ std::map< int,qstring > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "int const &") -> "_qstring< char > &":
        r"""
        at(self, _Keyval) -> _qstring< char > &

        @param _Keyval: int const &
        """
        return _ida_hexrays.user_labels_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.user_labels_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> user_labels_t
        """
        _ida_hexrays.user_labels_t_swiginit(self, _ida_hexrays.new_user_labels_t())
    __swig_destroy__ = _ida_hexrays.delete_user_labels_t

# Register user_labels_t in _ida_hexrays:
_ida_hexrays.user_labels_t_swigregister(user_labels_t)
class user_cmts_t(object):
    r"""
    Proxy of C++ std::map< treeloc_t,citem_cmt_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "treeloc_t") -> "citem_cmt_t &":
        r"""
        at(self, _Keyval) -> citem_cmt_t

        @param _Keyval: treeloc_t const &
        """
        return _ida_hexrays.user_cmts_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.user_cmts_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> user_cmts_t
        """
        _ida_hexrays.user_cmts_t_swiginit(self, _ida_hexrays.new_user_cmts_t())
    __swig_destroy__ = _ida_hexrays.delete_user_cmts_t

# Register user_cmts_t in _ida_hexrays:
_ida_hexrays.user_cmts_t_swigregister(user_cmts_t)
class user_iflags_t(object):
    r"""
    Proxy of C++ std::map< citem_locator_t,int32 > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "citem_locator_t") -> "int &":
        r"""
        at(self, _Keyval) -> int &

        @param _Keyval: citem_locator_t const &
        """
        return _ida_hexrays.user_iflags_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.user_iflags_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> user_iflags_t
        """
        _ida_hexrays.user_iflags_t_swiginit(self, _ida_hexrays.new_user_iflags_t())
    __swig_destroy__ = _ida_hexrays.delete_user_iflags_t

# Register user_iflags_t in _ida_hexrays:
_ida_hexrays.user_iflags_t_swigregister(user_iflags_t)
class user_unions_t(object):
    r"""
    Proxy of C++ std::map< ea_t,intvec_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "unsigned long long const &") -> "qvector< int > &":
        r"""
        at(self, _Keyval) -> intvec_t

        @param _Keyval: unsigned long long const &
        """
        return _ida_hexrays.user_unions_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.user_unions_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> user_unions_t
        """
        _ida_hexrays.user_unions_t_swiginit(self, _ida_hexrays.new_user_unions_t())
    __swig_destroy__ = _ida_hexrays.delete_user_unions_t

# Register user_unions_t in _ida_hexrays:
_ida_hexrays.user_unions_t_swigregister(user_unions_t)
class cinsnptrvec_t(object):
    r"""
    Proxy of C++ qvector< cinsn_t * > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> cinsnptrvec_t
        __init__(self, x) -> cinsnptrvec_t

        @param x: qvector< cinsn_t * > const &
        """
        _ida_hexrays.cinsnptrvec_t_swiginit(self, _ida_hexrays.new_cinsnptrvec_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_cinsnptrvec_t

    def push_back(self, *args) -> "cinsn_t *&":
        r"""
        push_back(self, x)

        @param x: cinsn_t *const &

        push_back(self) -> cinsn_t *&
        """
        return _ida_hexrays.cinsnptrvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.cinsnptrvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.cinsnptrvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.cinsnptrvec_t_empty(self)

    def at(self, _idx: "size_t") -> "cinsn_t *const &":
        r"""
        at(self, _idx) -> cinsn_t

        @param _idx: size_t
        """
        return _ida_hexrays.cinsnptrvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.cinsnptrvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.cinsnptrvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: cinsn_t *const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.cinsnptrvec_t_resize(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.cinsnptrvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.cinsnptrvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.cinsnptrvec_t_truncate(self)

    def swap(self, r: "cinsnptrvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< cinsn_t * > &
        """
        return _ida_hexrays.cinsnptrvec_t_swap(self, r)

    def extract(self) -> "cinsn_t **":
        r"""
        extract(self) -> cinsn_t **
        """
        return _ida_hexrays.cinsnptrvec_t_extract(self)

    def inject(self, s: "cinsn_t **", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: cinsn_t **
        @param len: size_t
        """
        return _ida_hexrays.cinsnptrvec_t_inject(self, s, len)

    def __eq__(self, r: "cinsnptrvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< cinsn_t * > const &
        """
        return _ida_hexrays.cinsnptrvec_t___eq__(self, r)

    def __ne__(self, r: "cinsnptrvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< cinsn_t * > const &
        """
        return _ida_hexrays.cinsnptrvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< cinsn_t * >::const_iterator":
        r"""
        begin(self) -> qvector< cinsn_t * >::iterator
        begin(self) -> qvector< cinsn_t * >::const_iterator
        """
        return _ida_hexrays.cinsnptrvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< cinsn_t * >::const_iterator":
        r"""
        end(self) -> qvector< cinsn_t * >::iterator
        end(self) -> qvector< cinsn_t * >::const_iterator
        """
        return _ida_hexrays.cinsnptrvec_t_end(self, *args)

    def insert(self, it: "qvector< cinsn_t * >::iterator", x: "cinsn_t") -> "qvector< cinsn_t * >::iterator":
        r"""
        insert(self, it, x) -> qvector< cinsn_t * >::iterator

        @param it: qvector< cinsn_t * >::iterator
        @param x: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< cinsn_t * >::iterator":
        r"""
        erase(self, it) -> qvector< cinsn_t * >::iterator

        @param it: qvector< cinsn_t * >::iterator

        erase(self, first, last) -> qvector< cinsn_t * >::iterator

        @param first: qvector< cinsn_t * >::iterator
        @param last: qvector< cinsn_t * >::iterator
        """
        return _ida_hexrays.cinsnptrvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< cinsn_t * >::const_iterator":
        r"""
        find(self, x) -> qvector< cinsn_t * >::iterator

        @param x: cinsn_t *const &

        find(self, x) -> qvector< cinsn_t * >::const_iterator

        @param x: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t_find(self, *args)

    def has(self, x: "cinsn_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t_has(self, x)

    def add_unique(self, x: "cinsn_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t_add_unique(self, x)

    def _del(self, x: "cinsn_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: cinsn_t *const &

        """
        return _ida_hexrays.cinsnptrvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.cinsnptrvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "cinsn_t *const &":
        r"""
        __getitem__(self, i) -> cinsn_t

        @param i: size_t
        """
        return _ida_hexrays.cinsnptrvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "cinsn_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t___setitem__(self, i, v)

    def append(self, x: "cinsn_t") -> "void":
        r"""
        append(self, x)

        @param x: cinsn_t *const &
        """
        return _ida_hexrays.cinsnptrvec_t_append(self, x)

    def extend(self, x: "cinsnptrvec_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< cinsn_t * > const &
        """
        return _ida_hexrays.cinsnptrvec_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register cinsnptrvec_t in _ida_hexrays:
_ida_hexrays.cinsnptrvec_t_swigregister(cinsnptrvec_t)
class eamap_t(object):
    r"""
    Proxy of C++ std::map< ea_t,cinsnptrvec_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "unsigned long long const &") -> "cinsnptrvec_t &":
        r"""
        at(self, _Keyval) -> cinsnptrvec_t

        @param _Keyval: unsigned long long const &
        """
        return _ida_hexrays.eamap_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.eamap_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> eamap_t
        """
        _ida_hexrays.eamap_t_swiginit(self, _ida_hexrays.new_eamap_t())
    __swig_destroy__ = _ida_hexrays.delete_eamap_t

# Register eamap_t in _ida_hexrays:
_ida_hexrays.eamap_t_swigregister(eamap_t)
class boundaries_t(object):
    r"""
    Proxy of C++ std::map< cinsn_t *,rangeset_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def at(self, _Keyval: "cinsn_t") -> "rangeset_t &":
        r"""
        at(self, _Keyval) -> rangeset_t

        @param _Keyval: cinsn_t *const &
        """
        return _ida_hexrays.boundaries_t_at(self, _Keyval)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.boundaries_t_size(self)

    def __init__(self):
        r"""
        __init__(self) -> boundaries_t
        """
        _ida_hexrays.boundaries_t_swiginit(self, _ida_hexrays.new_boundaries_t())
    __swig_destroy__ = _ida_hexrays.delete_boundaries_t

# Register boundaries_t in _ida_hexrays:
_ida_hexrays.boundaries_t_swigregister(boundaries_t)

def user_iflags_second(p: "user_iflags_iterator_t") -> "int32 const &":
    r"""
    user_iflags_second(p) -> int32 const &
    Get reference to the current map value.

    @param p: (C++: user_iflags_iterator_t)
    """
    return _ida_hexrays.user_iflags_second(p)
class cfuncptr_t(object):
    r"""
    Proxy of C++ qrefcnt_t< cfunc_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self, p) -> cfuncptr_t

        @param p: cfunc_t *

        __init__(self, r) -> cfuncptr_t

        @param r: qrefcnt_t< cfunc_t > const &
        """
        _ida_hexrays.cfuncptr_t_swiginit(self, _ida_hexrays.new_cfuncptr_t(*args))

    def reset(self) -> "void":
        r"""
        reset(self)
        """
        return _ida_hexrays.cfuncptr_t_reset(self)

    def __deref__(self) -> "cfunc_t *":
        r"""
        __deref__(self) -> cfunc_t
        """
        return _ida_hexrays.cfuncptr_t___deref__(self)

    def __ref__(self) -> "cfunc_t &":
        r"""
        __ref__(self) -> cfunc_t
        """
        return _ida_hexrays.cfuncptr_t___ref__(self)

    def __ptrval__(self) -> "size_t":
        r"""
        __ptrval__(self) -> size_t
        """
        return _ida_hexrays.cfuncptr_t___ptrval__(self)
    __swig_destroy__ = _ida_hexrays.delete_cfuncptr_t
    entry_ea: "ea_t" = property(_ida_hexrays.cfuncptr_t_entry_ea_get, _ida_hexrays.cfuncptr_t_entry_ea_set, doc=r"""entry_ea""")
    mba: "mba_t *" = property(_ida_hexrays.cfuncptr_t_mba_get, _ida_hexrays.cfuncptr_t_mba_set, doc=r"""mba""")
    body: "cinsn_t" = property(_ida_hexrays.cfuncptr_t_body_get, _ida_hexrays.cfuncptr_t_body_set, doc=r"""body""")
    argidx: "intvec_t &" = property(_ida_hexrays.cfuncptr_t_argidx_get, doc=r"""argidx""")
    maturity: "ctree_maturity_t" = property(_ida_hexrays.cfuncptr_t_maturity_get, _ida_hexrays.cfuncptr_t_maturity_set, doc=r"""maturity""")
    user_labels: "user_labels_t *" = property(_ida_hexrays.cfuncptr_t_user_labels_get, _ida_hexrays.cfuncptr_t_user_labels_set, doc=r"""user_labels""")
    user_cmts: "user_cmts_t *" = property(_ida_hexrays.cfuncptr_t_user_cmts_get, _ida_hexrays.cfuncptr_t_user_cmts_set, doc=r"""user_cmts""")
    numforms: "user_numforms_t *" = property(_ida_hexrays.cfuncptr_t_numforms_get, _ida_hexrays.cfuncptr_t_numforms_set, doc=r"""numforms""")
    user_iflags: "user_iflags_t *" = property(_ida_hexrays.cfuncptr_t_user_iflags_get, _ida_hexrays.cfuncptr_t_user_iflags_set, doc=r"""user_iflags""")
    user_unions: "user_unions_t *" = property(_ida_hexrays.cfuncptr_t_user_unions_get, _ida_hexrays.cfuncptr_t_user_unions_set, doc=r"""user_unions""")
    refcnt: "int" = property(_ida_hexrays.cfuncptr_t_refcnt_get, _ida_hexrays.cfuncptr_t_refcnt_set, doc=r"""refcnt""")
    statebits: "int" = property(_ida_hexrays.cfuncptr_t_statebits_get, _ida_hexrays.cfuncptr_t_statebits_set, doc=r"""statebits""")
    hdrlines: "int" = property(_ida_hexrays.cfuncptr_t_hdrlines_get, _ida_hexrays.cfuncptr_t_hdrlines_set, doc=r"""hdrlines""")
    treeitems: "citem_pointers_t" = property(_ida_hexrays.cfuncptr_t_treeitems_get, _ida_hexrays.cfuncptr_t_treeitems_set, doc=r"""treeitems""")

    def release(self) -> "void":
        r"""
        release(self)
        """
        return _ida_hexrays.cfuncptr_t_release(self)

    def build_c_tree(self) -> "void":
        r"""
        build_c_tree(self)
        """
        return _ida_hexrays.cfuncptr_t_build_c_tree(self)

    def verify(self, aul: "allow_unused_labels_t", even_without_debugger: "bool") -> "void":
        r"""
        verify(self, aul, even_without_debugger)

        @param aul: enum allow_unused_labels_t
        @param even_without_debugger: bool
        """
        return _ida_hexrays.cfuncptr_t_verify(self, aul, even_without_debugger)

    def print_dcl(self) -> "void":
        r"""
        print_dcl(self)
        """
        return _ida_hexrays.cfuncptr_t_print_dcl(self)

    def print_func(self, vp: "vc_printer_t") -> "void":
        r"""
        print_func(self, vp)

        @param vp: vc_printer_t &
        """
        return _ida_hexrays.cfuncptr_t_print_func(self, vp)

    def get_func_type(self, type: "tinfo_t") -> "bool":
        r"""
        get_func_type(self, type) -> bool

        @param type: tinfo_t *
        """
        return _ida_hexrays.cfuncptr_t_get_func_type(self, type)

    def get_lvars(self) -> "lvars_t *":
        r"""
        get_lvars(self) -> lvars_t
        """
        return _ida_hexrays.cfuncptr_t_get_lvars(self)

    def get_stkoff_delta(self) -> "sval_t":
        r"""
        get_stkoff_delta(self) -> sval_t
        """
        return _ida_hexrays.cfuncptr_t_get_stkoff_delta(self)

    def find_label(self, label: "int") -> "citem_t *":
        r"""
        find_label(self, label) -> citem_t

        @param label: int
        """
        return _ida_hexrays.cfuncptr_t_find_label(self, label)

    def remove_unused_labels(self) -> "void":
        r"""
        remove_unused_labels(self)
        """
        return _ida_hexrays.cfuncptr_t_remove_unused_labels(self)

    def get_user_cmt(self, loc: "treeloc_t", rt: "cmt_retrieval_type_t") -> "char const *":
        r"""
        get_user_cmt(self, loc, rt) -> char const *

        @param loc: treeloc_t const &
        @param rt: enum cmt_retrieval_type_t
        """
        return _ida_hexrays.cfuncptr_t_get_user_cmt(self, loc, rt)

    def set_user_cmt(self, loc: "treeloc_t", cmt: "char const *") -> "void":
        r"""
        set_user_cmt(self, loc, cmt)

        @param loc: treeloc_t const &
        @param cmt: char const *
        """
        return _ida_hexrays.cfuncptr_t_set_user_cmt(self, loc, cmt)

    def get_user_iflags(self, loc: "citem_locator_t") -> "int32":
        r"""
        get_user_iflags(self, loc) -> int32

        @param loc: citem_locator_t const &
        """
        return _ida_hexrays.cfuncptr_t_get_user_iflags(self, loc)

    def set_user_iflags(self, loc: "citem_locator_t", iflags: "int32") -> "void":
        r"""
        set_user_iflags(self, loc, iflags)

        @param loc: citem_locator_t const &
        @param iflags: int32
        """
        return _ida_hexrays.cfuncptr_t_set_user_iflags(self, loc, iflags)

    def has_orphan_cmts(self) -> "bool":
        r"""
        has_orphan_cmts(self) -> bool
        """
        return _ida_hexrays.cfuncptr_t_has_orphan_cmts(self)

    def del_orphan_cmts(self) -> "int":
        r"""
        del_orphan_cmts(self) -> int
        """
        return _ida_hexrays.cfuncptr_t_del_orphan_cmts(self)

    def get_user_union_selection(self, ea: "ea_t", path: "intvec_t") -> "bool":
        r"""
        get_user_union_selection(self, ea, path) -> bool

        @param ea: ea_t
        @param path: intvec_t *
        """
        return _ida_hexrays.cfuncptr_t_get_user_union_selection(self, ea, path)

    def set_user_union_selection(self, ea: "ea_t", path: "intvec_t") -> "void":
        r"""
        set_user_union_selection(self, ea, path)

        @param ea: ea_t
        @param path: intvec_t const &
        """
        return _ida_hexrays.cfuncptr_t_set_user_union_selection(self, ea, path)

    def save_user_labels(self) -> "void":
        r"""
        save_user_labels(self)
        """
        return _ida_hexrays.cfuncptr_t_save_user_labels(self)

    def save_user_cmts(self) -> "void":
        r"""
        save_user_cmts(self)
        """
        return _ida_hexrays.cfuncptr_t_save_user_cmts(self)

    def save_user_numforms(self) -> "void":
        r"""
        save_user_numforms(self)
        """
        return _ida_hexrays.cfuncptr_t_save_user_numforms(self)

    def save_user_iflags(self) -> "void":
        r"""
        save_user_iflags(self)
        """
        return _ida_hexrays.cfuncptr_t_save_user_iflags(self)

    def save_user_unions(self) -> "void":
        r"""
        save_user_unions(self)
        """
        return _ida_hexrays.cfuncptr_t_save_user_unions(self)

    def get_line_item(self, line: "char const *", x: "int", is_ctree_line: "bool", phead: "ctree_item_t", pitem: "ctree_item_t", ptail: "ctree_item_t") -> "bool":
        r"""
        get_line_item(self, line, x, is_ctree_line, phead, pitem, ptail) -> bool

        @param line: char const *
        @param x: int
        @param is_ctree_line: bool
        @param phead: ctree_item_t *
        @param pitem: ctree_item_t *
        @param ptail: ctree_item_t *
        """
        return _ida_hexrays.cfuncptr_t_get_line_item(self, line, x, is_ctree_line, phead, pitem, ptail)

    def get_warnings(self) -> "hexwarns_t &":
        r"""
        get_warnings(self) -> hexwarns_t
        """
        return _ida_hexrays.cfuncptr_t_get_warnings(self)

    def get_eamap(self) -> "eamap_t &":
        r"""
        get_eamap(self) -> eamap_t
        """
        return _ida_hexrays.cfuncptr_t_get_eamap(self)

    def get_boundaries(self) -> "boundaries_t &":
        r"""
        get_boundaries(self) -> boundaries_t
        """
        return _ida_hexrays.cfuncptr_t_get_boundaries(self)

    def get_pseudocode(self) -> "strvec_t const &":
        r"""
        get_pseudocode(self) -> strvec_t
        """
        return _ida_hexrays.cfuncptr_t_get_pseudocode(self)

    def refresh_func_ctext(self) -> "void":
        r"""
        refresh_func_ctext(self)
        """
        return _ida_hexrays.cfuncptr_t_refresh_func_ctext(self)

    def gather_derefs(self, ci: "ctree_item_t", udm: "udt_type_data_t"=None) -> "bool":
        r"""
        gather_derefs(self, ci, udm=None) -> bool

        @param ci: ctree_item_t const &
        @param udm: udt_type_data_t *
        """
        return _ida_hexrays.cfuncptr_t_gather_derefs(self, ci, udm)

    def find_item_coords(self, *args) -> "PyObject *":
        r"""
        find_item_coords(self, item, px, py) -> bool

        @param item: citem_t const *
        @param px: int *
        @param py: int *

        find_item_coords(self, item) -> (int, int), bool

        @param item: citem_t const *
        """
        return _ida_hexrays.cfuncptr_t_find_item_coords(self, *args)

    def locked(self) -> "bool":
        r"""
        locked(self) -> bool
        """
        return _ida_hexrays.cfuncptr_t_locked(self)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_hexrays.cfuncptr_t___str__(self)

# Register cfuncptr_t in _ida_hexrays:
_ida_hexrays.cfuncptr_t_swigregister(cfuncptr_t)
class qvector_history_t(object):
    r"""
    Proxy of C++ qvector< history_item_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_history_t
        __init__(self, x) -> qvector_history_t

        @param x: qvector< history_item_t > const &
        """
        _ida_hexrays.qvector_history_t_swiginit(self, _ida_hexrays.new_qvector_history_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_history_t

    def push_back(self, *args) -> "history_item_t &":
        r"""
        push_back(self, x)

        @param x: history_item_t const &

        push_back(self) -> history_item_t
        """
        return _ida_hexrays.qvector_history_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_history_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_history_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_history_t_empty(self)

    def at(self, _idx: "size_t") -> "history_item_t const &":
        r"""
        at(self, _idx) -> history_item_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_history_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_history_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_history_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: history_item_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_history_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=history_item_t())

        @param x: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_history_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_history_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_history_t_truncate(self)

    def swap(self, r: "qvector_history_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< history_item_t > &
        """
        return _ida_hexrays.qvector_history_t_swap(self, r)

    def extract(self) -> "history_item_t *":
        r"""
        extract(self) -> history_item_t
        """
        return _ida_hexrays.qvector_history_t_extract(self)

    def inject(self, s: "history_item_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: history_item_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_history_t_inject(self, s, len)

    def __eq__(self, r: "qvector_history_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< history_item_t > const &
        """
        return _ida_hexrays.qvector_history_t___eq__(self, r)

    def __ne__(self, r: "qvector_history_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< history_item_t > const &
        """
        return _ida_hexrays.qvector_history_t___ne__(self, r)

    def begin(self, *args) -> "qvector< history_item_t >::const_iterator":
        r"""
        begin(self) -> history_item_t
        """
        return _ida_hexrays.qvector_history_t_begin(self, *args)

    def end(self, *args) -> "qvector< history_item_t >::const_iterator":
        r"""
        end(self) -> history_item_t
        """
        return _ida_hexrays.qvector_history_t_end(self, *args)

    def insert(self, it: "history_item_t", x: "history_item_t") -> "qvector< history_item_t >::iterator":
        r"""
        insert(self, it, x) -> history_item_t

        @param it: qvector< history_item_t >::iterator
        @param x: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< history_item_t >::iterator":
        r"""
        erase(self, it) -> history_item_t

        @param it: qvector< history_item_t >::iterator

        erase(self, first, last) -> history_item_t

        @param first: qvector< history_item_t >::iterator
        @param last: qvector< history_item_t >::iterator
        """
        return _ida_hexrays.qvector_history_t_erase(self, *args)

    def find(self, *args) -> "qvector< history_item_t >::const_iterator":
        r"""
        find(self, x) -> history_item_t

        @param x: history_item_t const &

        """
        return _ida_hexrays.qvector_history_t_find(self, *args)

    def has(self, x: "history_item_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t_has(self, x)

    def add_unique(self, x: "history_item_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t_add_unique(self, x)

    def _del(self, x: "history_item_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: history_item_t const &

        """
        return _ida_hexrays.qvector_history_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_history_t___len__(self)

    def __getitem__(self, i: "size_t") -> "history_item_t const &":
        r"""
        __getitem__(self, i) -> history_item_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_history_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "history_item_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t___setitem__(self, i, v)

    def append(self, x: "history_item_t") -> "void":
        r"""
        append(self, x)

        @param x: history_item_t const &
        """
        return _ida_hexrays.qvector_history_t_append(self, x)

    def extend(self, x: "qvector_history_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< history_item_t > const &
        """
        return _ida_hexrays.qvector_history_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_history_t in _ida_hexrays:
_ida_hexrays.qvector_history_t_swigregister(qvector_history_t)
class history_t(qvector_history_t):
    r"""
    Proxy of C++ qstack< history_item_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def pop(self) -> "history_item_t":
        r"""
        pop(self) -> history_item_t
        """
        return _ida_hexrays.history_t_pop(self)

    def top(self, *args) -> "history_item_t &":
        r"""
        top(self) -> history_item_t
        """
        return _ida_hexrays.history_t_top(self, *args)

    def push(self, v: "history_item_t") -> "void":
        r"""
        push(self, v)

        @param v: history_item_t const &
        """
        return _ida_hexrays.history_t_push(self, v)

    def __init__(self):
        r"""
        __init__(self) -> history_t
        """
        _ida_hexrays.history_t_swiginit(self, _ida_hexrays.new_history_t())
    __swig_destroy__ = _ida_hexrays.delete_history_t

# Register history_t in _ida_hexrays:
_ida_hexrays.history_t_swigregister(history_t)
class cinsn_list_t_iterator(object):
    r"""
    Proxy of C++ cinsn_list_t_iterator class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cur: "cinsn_t const &" = property(_ida_hexrays.cinsn_list_t_iterator_cur_get, doc=r"""cur""")

    def __next__(self) -> "void":
        r"""
        __next__(self)
        """
        return _ida_hexrays.cinsn_list_t_iterator___next__(self)

    def __eq__(self, x: "cinsn_list_t_iterator") -> "bool":
        r"""
        __eq__(self, x) -> bool

        @param x: cinsn_list_t_iterator const *
        """
        return _ida_hexrays.cinsn_list_t_iterator___eq__(self, x)

    def __ne__(self, x: "cinsn_list_t_iterator") -> "bool":
        r"""
        __ne__(self, x) -> bool

        @param x: cinsn_list_t_iterator const *
        """
        return _ida_hexrays.cinsn_list_t_iterator___ne__(self, x)

    next = __next__


    def __init__(self):
        r"""
        __init__(self) -> cinsn_list_t_iterator
        """
        _ida_hexrays.cinsn_list_t_iterator_swiginit(self, _ida_hexrays.new_cinsn_list_t_iterator())
    __swig_destroy__ = _ida_hexrays.delete_cinsn_list_t_iterator

# Register cinsn_list_t_iterator in _ida_hexrays:
_ida_hexrays.cinsn_list_t_iterator_swigregister(cinsn_list_t_iterator)
class cinsn_list_t(object):
    r"""
    Proxy of C++ qlist< cinsn_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> cinsn_list_t
        __init__(self, x) -> cinsn_list_t

        @param x: qlist< cinsn_t > const &
        """
        _ida_hexrays.cinsn_list_t_swiginit(self, _ida_hexrays.new_cinsn_list_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_cinsn_list_t

    def swap(self, x: "cinsn_list_t") -> "void":
        r"""
        swap(self, x)

        @param x: qlist< cinsn_t > &
        """
        return _ida_hexrays.cinsn_list_t_swap(self, x)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.cinsn_list_t_empty(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.cinsn_list_t_size(self)

    def front(self, *args) -> "cinsn_t const &":
        r"""
        front(self) -> cinsn_t
        """
        return _ida_hexrays.cinsn_list_t_front(self, *args)

    def back(self, *args) -> "cinsn_t const &":
        r"""
        back(self) -> cinsn_t
        """
        return _ida_hexrays.cinsn_list_t_back(self, *args)

    def rbegin(self, *args) -> "qlist< cinsn_t >::const_reverse_iterator":
        r"""
        rbegin(self) -> qlist< cinsn_t >::reverse_iterator
        rbegin(self) -> qlist< cinsn_t >::const_reverse_iterator
        """
        return _ida_hexrays.cinsn_list_t_rbegin(self, *args)

    def rend(self, *args) -> "qlist< cinsn_t >::const_reverse_iterator":
        r"""
        rend(self) -> qlist< cinsn_t >::reverse_iterator
        rend(self) -> qlist< cinsn_t >::const_reverse_iterator
        """
        return _ida_hexrays.cinsn_list_t_rend(self, *args)

    def push_front(self, x: "cinsn_t") -> "void":
        r"""
        push_front(self, x)

        @param x: cinsn_t const &
        """
        return _ida_hexrays.cinsn_list_t_push_front(self, x)

    def push_back(self, *args) -> "cinsn_t &":
        r"""
        push_back(self, x)

        @param x: cinsn_t const &

        push_back(self) -> cinsn_t
        """
        return _ida_hexrays.cinsn_list_t_push_back(self, *args)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.cinsn_list_t_clear(self)

    def pop_front(self) -> "void":
        r"""
        pop_front(self)
        """
        return _ida_hexrays.cinsn_list_t_pop_front(self)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.cinsn_list_t_pop_back(self)

    def splice(self, pos: "qlist< cinsn_t >::iterator", other: "cinsn_list_t", first: "qlist< cinsn_t >::iterator", last: "qlist< cinsn_t >::iterator") -> "void":
        r"""
        splice(self, pos, other, first, last)

        @param pos: qlist< cinsn_t >::iterator
        @param other: qlist< cinsn_t > &
        @param first: qlist< cinsn_t >::iterator
        @param last: qlist< cinsn_t >::iterator
        """
        return _ida_hexrays.cinsn_list_t_splice(self, pos, other, first, last)

    def __eq__(self, x: "cinsn_list_t") -> "bool":
        r"""
        __eq__(self, x) -> bool

        @param x: qlist< cinsn_t > const &
        """
        return _ida_hexrays.cinsn_list_t___eq__(self, x)

    def __ne__(self, x: "cinsn_list_t") -> "bool":
        r"""
        __ne__(self, x) -> bool

        @param x: qlist< cinsn_t > const &
        """
        return _ida_hexrays.cinsn_list_t___ne__(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.cinsn_list_t___len__(self)

    def __getitem__(self, i: "size_t") -> "cinsn_t const &":
        r"""
        __getitem__(self, i) -> cinsn_t

        @param i: size_t
        """
        return _ida_hexrays.cinsn_list_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "cinsn_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: cinsn_t const &
        """
        return _ida_hexrays.cinsn_list_t___setitem__(self, i, v)

    def remove(self, v: "cinsn_t") -> "bool":
        r"""
        remove(self, v) -> bool

        @param v: cinsn_t const &
        """
        return _ida_hexrays.cinsn_list_t_remove(self, v)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator

    def find(self, item):
        if item is not None:
            it = self.begin()
            for i in range(self.size()):
                if it.cur == item:
                    return it
                next(it)

    def index(self, item):
        if item is not None:
            it = self.begin()
            for i in range(self.size()):
                if it.cur == item:
                    return i
                next(it)

    def at(self, index):
        it = self.begin()
        for i in range(self.size()):
            if i == index:
                return it.cur
            next(it)


    def begin(self) -> "cinsn_list_t_iterator":
        r"""
        begin(self) -> cinsn_list_t_iterator
        """
        return _ida_hexrays.cinsn_list_t_begin(self)

    def end(self) -> "cinsn_list_t_iterator":
        r"""
        end(self) -> cinsn_list_t_iterator
        """
        return _ida_hexrays.cinsn_list_t_end(self)

    def insert(self, *args) -> "cinsn_list_t_iterator":
        r"""
        insert(self, i, v)

        @param i: size_t
        @param v: cinsn_t const &

        insert(self, p, x) -> cinsn_list_t_iterator

        @param p: cinsn_list_t_iterator
        @param x: cinsn_t const &
        """
        return _ida_hexrays.cinsn_list_t_insert(self, *args)

    def erase(self, p: "cinsn_list_t_iterator") -> "void":
        r"""
        erase(self, p)

        @param p: cinsn_list_t_iterator
        """
        return _ida_hexrays.cinsn_list_t_erase(self, p)

# Register cinsn_list_t in _ida_hexrays:
_ida_hexrays.cinsn_list_t_swigregister(cinsn_list_t)
class qvector_lvar_t(object):
    r"""
    Proxy of C++ qvector< lvar_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_lvar_t
        __init__(self, x) -> qvector_lvar_t

        @param x: qvector< lvar_t > const &
        """
        _ida_hexrays.qvector_lvar_t_swiginit(self, _ida_hexrays.new_qvector_lvar_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_lvar_t

    def push_back(self, *args) -> "lvar_t &":
        r"""
        push_back(self, x)

        @param x: lvar_t const &

        push_back(self) -> lvar_t
        """
        return _ida_hexrays.qvector_lvar_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_lvar_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_lvar_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_lvar_t_empty(self)

    def at(self, _idx: "size_t") -> "lvar_t const &":
        r"""
        at(self, _idx) -> lvar_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_lvar_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_lvar_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_lvar_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: lvar_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_lvar_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=lvar_t())

        @param x: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_lvar_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_lvar_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_lvar_t_truncate(self)

    def swap(self, r: "qvector_lvar_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< lvar_t > &
        """
        return _ida_hexrays.qvector_lvar_t_swap(self, r)

    def extract(self) -> "lvar_t *":
        r"""
        extract(self) -> lvar_t
        """
        return _ida_hexrays.qvector_lvar_t_extract(self)

    def inject(self, s: "lvar_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: lvar_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_lvar_t_inject(self, s, len)

    def __eq__(self, r: "qvector_lvar_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< lvar_t > const &
        """
        return _ida_hexrays.qvector_lvar_t___eq__(self, r)

    def __ne__(self, r: "qvector_lvar_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< lvar_t > const &
        """
        return _ida_hexrays.qvector_lvar_t___ne__(self, r)

    def begin(self, *args) -> "qvector< lvar_t >::const_iterator":
        r"""
        begin(self) -> lvar_t
        """
        return _ida_hexrays.qvector_lvar_t_begin(self, *args)

    def end(self, *args) -> "qvector< lvar_t >::const_iterator":
        r"""
        end(self) -> lvar_t
        """
        return _ida_hexrays.qvector_lvar_t_end(self, *args)

    def insert(self, it: "lvar_t", x: "lvar_t") -> "qvector< lvar_t >::iterator":
        r"""
        insert(self, it, x) -> lvar_t

        @param it: qvector< lvar_t >::iterator
        @param x: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< lvar_t >::iterator":
        r"""
        erase(self, it) -> lvar_t

        @param it: qvector< lvar_t >::iterator

        erase(self, first, last) -> lvar_t

        @param first: qvector< lvar_t >::iterator
        @param last: qvector< lvar_t >::iterator
        """
        return _ida_hexrays.qvector_lvar_t_erase(self, *args)

    def find(self, *args) -> "qvector< lvar_t >::const_iterator":
        r"""
        find(self, x) -> lvar_t

        @param x: lvar_t const &

        """
        return _ida_hexrays.qvector_lvar_t_find(self, *args)

    def has(self, x: "lvar_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t_has(self, x)

    def add_unique(self, x: "lvar_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t_add_unique(self, x)

    def _del(self, x: "lvar_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: lvar_t const &

        """
        return _ida_hexrays.qvector_lvar_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_lvar_t___len__(self)

    def __getitem__(self, i: "size_t") -> "lvar_t const &":
        r"""
        __getitem__(self, i) -> lvar_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_lvar_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "lvar_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t___setitem__(self, i, v)

    def append(self, x: "lvar_t") -> "void":
        r"""
        append(self, x)

        @param x: lvar_t const &
        """
        return _ida_hexrays.qvector_lvar_t_append(self, x)

    def extend(self, x: "qvector_lvar_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< lvar_t > const &
        """
        return _ida_hexrays.qvector_lvar_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_lvar_t in _ida_hexrays:
_ida_hexrays.qvector_lvar_t_swigregister(qvector_lvar_t)
class qvector_carg_t(object):
    r"""
    Proxy of C++ qvector< carg_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_carg_t
        __init__(self, x) -> qvector_carg_t

        @param x: qvector< carg_t > const &
        """
        _ida_hexrays.qvector_carg_t_swiginit(self, _ida_hexrays.new_qvector_carg_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_carg_t

    def push_back(self, *args) -> "carg_t &":
        r"""
        push_back(self, x)

        @param x: carg_t const &

        push_back(self) -> carg_t
        """
        return _ida_hexrays.qvector_carg_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_carg_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_carg_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_carg_t_empty(self)

    def at(self, _idx: "size_t") -> "carg_t const &":
        r"""
        at(self, _idx) -> carg_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_carg_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_carg_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_carg_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: carg_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_carg_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=carg_t())

        @param x: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_carg_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_carg_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_carg_t_truncate(self)

    def swap(self, r: "qvector_carg_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< carg_t > &
        """
        return _ida_hexrays.qvector_carg_t_swap(self, r)

    def extract(self) -> "carg_t *":
        r"""
        extract(self) -> carg_t
        """
        return _ida_hexrays.qvector_carg_t_extract(self)

    def inject(self, s: "carg_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: carg_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_carg_t_inject(self, s, len)

    def __eq__(self, r: "qvector_carg_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< carg_t > const &
        """
        return _ida_hexrays.qvector_carg_t___eq__(self, r)

    def __ne__(self, r: "qvector_carg_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< carg_t > const &
        """
        return _ida_hexrays.qvector_carg_t___ne__(self, r)

    def begin(self, *args) -> "qvector< carg_t >::const_iterator":
        r"""
        begin(self) -> carg_t
        """
        return _ida_hexrays.qvector_carg_t_begin(self, *args)

    def end(self, *args) -> "qvector< carg_t >::const_iterator":
        r"""
        end(self) -> carg_t
        """
        return _ida_hexrays.qvector_carg_t_end(self, *args)

    def insert(self, it: "carg_t", x: "carg_t") -> "qvector< carg_t >::iterator":
        r"""
        insert(self, it, x) -> carg_t

        @param it: qvector< carg_t >::iterator
        @param x: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< carg_t >::iterator":
        r"""
        erase(self, it) -> carg_t

        @param it: qvector< carg_t >::iterator

        erase(self, first, last) -> carg_t

        @param first: qvector< carg_t >::iterator
        @param last: qvector< carg_t >::iterator
        """
        return _ida_hexrays.qvector_carg_t_erase(self, *args)

    def find(self, *args) -> "qvector< carg_t >::const_iterator":
        r"""
        find(self, x) -> carg_t

        @param x: carg_t const &

        """
        return _ida_hexrays.qvector_carg_t_find(self, *args)

    def has(self, x: "carg_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t_has(self, x)

    def add_unique(self, x: "carg_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t_add_unique(self, x)

    def _del(self, x: "carg_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: carg_t const &

        """
        return _ida_hexrays.qvector_carg_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_carg_t___len__(self)

    def __getitem__(self, i: "size_t") -> "carg_t const &":
        r"""
        __getitem__(self, i) -> carg_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_carg_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "carg_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t___setitem__(self, i, v)

    def append(self, x: "carg_t") -> "void":
        r"""
        append(self, x)

        @param x: carg_t const &
        """
        return _ida_hexrays.qvector_carg_t_append(self, x)

    def extend(self, x: "qvector_carg_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< carg_t > const &
        """
        return _ida_hexrays.qvector_carg_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_carg_t in _ida_hexrays:
_ida_hexrays.qvector_carg_t_swigregister(qvector_carg_t)
class qvector_ccase_t(object):
    r"""
    Proxy of C++ qvector< ccase_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_ccase_t
        __init__(self, x) -> qvector_ccase_t

        @param x: qvector< ccase_t > const &
        """
        _ida_hexrays.qvector_ccase_t_swiginit(self, _ida_hexrays.new_qvector_ccase_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_ccase_t

    def push_back(self, *args) -> "ccase_t &":
        r"""
        push_back(self, x)

        @param x: ccase_t const &

        push_back(self) -> ccase_t
        """
        return _ida_hexrays.qvector_ccase_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_ccase_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_ccase_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_ccase_t_empty(self)

    def at(self, _idx: "size_t") -> "ccase_t const &":
        r"""
        at(self, _idx) -> ccase_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_ccase_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_ccase_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_ccase_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: ccase_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_ccase_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=ccase_t())

        @param x: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_ccase_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_ccase_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_ccase_t_truncate(self)

    def swap(self, r: "qvector_ccase_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< ccase_t > &
        """
        return _ida_hexrays.qvector_ccase_t_swap(self, r)

    def extract(self) -> "ccase_t *":
        r"""
        extract(self) -> ccase_t
        """
        return _ida_hexrays.qvector_ccase_t_extract(self)

    def inject(self, s: "ccase_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: ccase_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_ccase_t_inject(self, s, len)

    def __eq__(self, r: "qvector_ccase_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< ccase_t > const &
        """
        return _ida_hexrays.qvector_ccase_t___eq__(self, r)

    def __ne__(self, r: "qvector_ccase_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< ccase_t > const &
        """
        return _ida_hexrays.qvector_ccase_t___ne__(self, r)

    def begin(self, *args) -> "qvector< ccase_t >::const_iterator":
        r"""
        begin(self) -> ccase_t
        """
        return _ida_hexrays.qvector_ccase_t_begin(self, *args)

    def end(self, *args) -> "qvector< ccase_t >::const_iterator":
        r"""
        end(self) -> ccase_t
        """
        return _ida_hexrays.qvector_ccase_t_end(self, *args)

    def insert(self, it: "ccase_t", x: "ccase_t") -> "qvector< ccase_t >::iterator":
        r"""
        insert(self, it, x) -> ccase_t

        @param it: qvector< ccase_t >::iterator
        @param x: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< ccase_t >::iterator":
        r"""
        erase(self, it) -> ccase_t

        @param it: qvector< ccase_t >::iterator

        erase(self, first, last) -> ccase_t

        @param first: qvector< ccase_t >::iterator
        @param last: qvector< ccase_t >::iterator
        """
        return _ida_hexrays.qvector_ccase_t_erase(self, *args)

    def find(self, *args) -> "qvector< ccase_t >::const_iterator":
        r"""
        find(self, x) -> ccase_t

        @param x: ccase_t const &

        """
        return _ida_hexrays.qvector_ccase_t_find(self, *args)

    def has(self, x: "ccase_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t_has(self, x)

    def add_unique(self, x: "ccase_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t_add_unique(self, x)

    def _del(self, x: "ccase_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: ccase_t const &

        """
        return _ida_hexrays.qvector_ccase_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_ccase_t___len__(self)

    def __getitem__(self, i: "size_t") -> "ccase_t const &":
        r"""
        __getitem__(self, i) -> ccase_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_ccase_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "ccase_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t___setitem__(self, i, v)

    def append(self, x: "ccase_t") -> "void":
        r"""
        append(self, x)

        @param x: ccase_t const &
        """
        return _ida_hexrays.qvector_ccase_t_append(self, x)

    def extend(self, x: "qvector_ccase_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< ccase_t > const &
        """
        return _ida_hexrays.qvector_ccase_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_ccase_t in _ida_hexrays:
_ida_hexrays.qvector_ccase_t_swigregister(qvector_ccase_t)
class qvector_catchexprs_t(object):
    r"""
    Proxy of C++ qvector< catchexpr_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_catchexprs_t
        __init__(self, x) -> qvector_catchexprs_t

        @param x: qvector< catchexpr_t > const &
        """
        _ida_hexrays.qvector_catchexprs_t_swiginit(self, _ida_hexrays.new_qvector_catchexprs_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_catchexprs_t

    def push_back(self, *args) -> "catchexpr_t &":
        r"""
        push_back(self, x)

        @param x: catchexpr_t const &

        push_back(self) -> catchexpr_t
        """
        return _ida_hexrays.qvector_catchexprs_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_catchexprs_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_catchexprs_t_empty(self)

    def at(self, _idx: "size_t") -> "catchexpr_t const &":
        r"""
        at(self, _idx) -> catchexpr_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_catchexprs_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_catchexprs_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: catchexpr_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=catchexpr_t())

        @param x: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_catchexprs_t_truncate(self)

    def swap(self, r: "qvector_catchexprs_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< catchexpr_t > &
        """
        return _ida_hexrays.qvector_catchexprs_t_swap(self, r)

    def extract(self) -> "catchexpr_t *":
        r"""
        extract(self) -> catchexpr_t
        """
        return _ida_hexrays.qvector_catchexprs_t_extract(self)

    def inject(self, s: "catchexpr_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: catchexpr_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_catchexprs_t_inject(self, s, len)

    def __eq__(self, r: "qvector_catchexprs_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< catchexpr_t > const &
        """
        return _ida_hexrays.qvector_catchexprs_t___eq__(self, r)

    def __ne__(self, r: "qvector_catchexprs_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< catchexpr_t > const &
        """
        return _ida_hexrays.qvector_catchexprs_t___ne__(self, r)

    def begin(self, *args) -> "qvector< catchexpr_t >::const_iterator":
        r"""
        begin(self) -> catchexpr_t
        """
        return _ida_hexrays.qvector_catchexprs_t_begin(self, *args)

    def end(self, *args) -> "qvector< catchexpr_t >::const_iterator":
        r"""
        end(self) -> catchexpr_t
        """
        return _ida_hexrays.qvector_catchexprs_t_end(self, *args)

    def insert(self, it: "catchexpr_t", x: "catchexpr_t") -> "qvector< catchexpr_t >::iterator":
        r"""
        insert(self, it, x) -> catchexpr_t

        @param it: qvector< catchexpr_t >::iterator
        @param x: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< catchexpr_t >::iterator":
        r"""
        erase(self, it) -> catchexpr_t

        @param it: qvector< catchexpr_t >::iterator

        erase(self, first, last) -> catchexpr_t

        @param first: qvector< catchexpr_t >::iterator
        @param last: qvector< catchexpr_t >::iterator
        """
        return _ida_hexrays.qvector_catchexprs_t_erase(self, *args)

    def find(self, *args) -> "qvector< catchexpr_t >::const_iterator":
        r"""
        find(self, x) -> catchexpr_t

        @param x: catchexpr_t const &

        """
        return _ida_hexrays.qvector_catchexprs_t_find(self, *args)

    def has(self, x: "catchexpr_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t_has(self, x)

    def add_unique(self, x: "catchexpr_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t_add_unique(self, x)

    def _del(self, x: "catchexpr_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: catchexpr_t const &

        """
        return _ida_hexrays.qvector_catchexprs_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_catchexprs_t___len__(self)

    def __getitem__(self, i: "size_t") -> "catchexpr_t const &":
        r"""
        __getitem__(self, i) -> catchexpr_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_catchexprs_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "catchexpr_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t___setitem__(self, i, v)

    def append(self, x: "catchexpr_t") -> "void":
        r"""
        append(self, x)

        @param x: catchexpr_t const &
        """
        return _ida_hexrays.qvector_catchexprs_t_append(self, x)

    def extend(self, x: "qvector_catchexprs_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< catchexpr_t > const &
        """
        return _ida_hexrays.qvector_catchexprs_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_catchexprs_t in _ida_hexrays:
_ida_hexrays.qvector_catchexprs_t_swigregister(qvector_catchexprs_t)
class qvector_ccatchvec_t(object):
    r"""
    Proxy of C++ qvector< ccatch_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> qvector_ccatchvec_t
        __init__(self, x) -> qvector_ccatchvec_t

        @param x: qvector< ccatch_t > const &
        """
        _ida_hexrays.qvector_ccatchvec_t_swiginit(self, _ida_hexrays.new_qvector_ccatchvec_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_qvector_ccatchvec_t

    def push_back(self, *args) -> "ccatch_t &":
        r"""
        push_back(self, x)

        @param x: ccatch_t const &

        push_back(self) -> ccatch_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.qvector_ccatchvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.qvector_ccatchvec_t_empty(self)

    def at(self, _idx: "size_t") -> "ccatch_t const &":
        r"""
        at(self, _idx) -> ccatch_t

        @param _idx: size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.qvector_ccatchvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.qvector_ccatchvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: ccatch_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=ccatch_t())

        @param x: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.qvector_ccatchvec_t_truncate(self)

    def swap(self, r: "qvector_ccatchvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< ccatch_t > &
        """
        return _ida_hexrays.qvector_ccatchvec_t_swap(self, r)

    def extract(self) -> "ccatch_t *":
        r"""
        extract(self) -> ccatch_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_extract(self)

    def inject(self, s: "ccatch_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: ccatch_t *
        @param len: size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_inject(self, s, len)

    def __eq__(self, r: "qvector_ccatchvec_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< ccatch_t > const &
        """
        return _ida_hexrays.qvector_ccatchvec_t___eq__(self, r)

    def __ne__(self, r: "qvector_ccatchvec_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< ccatch_t > const &
        """
        return _ida_hexrays.qvector_ccatchvec_t___ne__(self, r)

    def begin(self, *args) -> "qvector< ccatch_t >::const_iterator":
        r"""
        begin(self) -> ccatch_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< ccatch_t >::const_iterator":
        r"""
        end(self) -> ccatch_t
        """
        return _ida_hexrays.qvector_ccatchvec_t_end(self, *args)

    def insert(self, it: "ccatch_t", x: "ccatch_t") -> "qvector< ccatch_t >::iterator":
        r"""
        insert(self, it, x) -> ccatch_t

        @param it: qvector< ccatch_t >::iterator
        @param x: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< ccatch_t >::iterator":
        r"""
        erase(self, it) -> ccatch_t

        @param it: qvector< ccatch_t >::iterator

        erase(self, first, last) -> ccatch_t

        @param first: qvector< ccatch_t >::iterator
        @param last: qvector< ccatch_t >::iterator
        """
        return _ida_hexrays.qvector_ccatchvec_t_erase(self, *args)

    def find(self, *args) -> "qvector< ccatch_t >::const_iterator":
        r"""
        find(self, x) -> ccatch_t

        @param x: ccatch_t const &

        """
        return _ida_hexrays.qvector_ccatchvec_t_find(self, *args)

    def has(self, x: "ccatch_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_has(self, x)

    def add_unique(self, x: "ccatch_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_add_unique(self, x)

    def _del(self, x: "ccatch_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: ccatch_t const &

        """
        return _ida_hexrays.qvector_ccatchvec_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "ccatch_t const &":
        r"""
        __getitem__(self, i) -> ccatch_t

        @param i: size_t
        """
        return _ida_hexrays.qvector_ccatchvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "ccatch_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t___setitem__(self, i, v)

    def append(self, x: "ccatch_t") -> "void":
        r"""
        append(self, x)

        @param x: ccatch_t const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_append(self, x)

    def extend(self, x: "qvector_ccatchvec_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< ccatch_t > const &
        """
        return _ida_hexrays.qvector_ccatchvec_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register qvector_ccatchvec_t in _ida_hexrays:
_ida_hexrays.qvector_ccatchvec_t_swigregister(qvector_ccatchvec_t)
class cblock_posvec_t(object):
    r"""
    Proxy of C++ qvector< cblock_pos_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> cblock_posvec_t
        __init__(self, x) -> cblock_posvec_t

        @param x: qvector< cblock_pos_t > const &
        """
        _ida_hexrays.cblock_posvec_t_swiginit(self, _ida_hexrays.new_cblock_posvec_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_cblock_posvec_t

    def push_back(self, *args) -> "cblock_pos_t &":
        r"""
        push_back(self, x)

        @param x: cblock_pos_t const &

        push_back(self) -> cblock_pos_t
        """
        return _ida_hexrays.cblock_posvec_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.cblock_posvec_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.cblock_posvec_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.cblock_posvec_t_empty(self)

    def at(self, _idx: "size_t") -> "cblock_pos_t const &":
        r"""
        at(self, _idx) -> cblock_pos_t

        @param _idx: size_t
        """
        return _ida_hexrays.cblock_posvec_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.cblock_posvec_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.cblock_posvec_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: cblock_pos_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.cblock_posvec_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=cblock_pos_t())

        @param x: cblock_pos_t const &
        """
        return _ida_hexrays.cblock_posvec_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.cblock_posvec_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.cblock_posvec_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.cblock_posvec_t_truncate(self)

    def swap(self, r: "cblock_posvec_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< cblock_pos_t > &
        """
        return _ida_hexrays.cblock_posvec_t_swap(self, r)

    def extract(self) -> "cblock_pos_t *":
        r"""
        extract(self) -> cblock_pos_t
        """
        return _ida_hexrays.cblock_posvec_t_extract(self)

    def inject(self, s: "cblock_pos_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: cblock_pos_t *
        @param len: size_t
        """
        return _ida_hexrays.cblock_posvec_t_inject(self, s, len)

    def begin(self, *args) -> "qvector< cblock_pos_t >::const_iterator":
        r"""
        begin(self) -> cblock_pos_t
        """
        return _ida_hexrays.cblock_posvec_t_begin(self, *args)

    def end(self, *args) -> "qvector< cblock_pos_t >::const_iterator":
        r"""
        end(self) -> cblock_pos_t
        """
        return _ida_hexrays.cblock_posvec_t_end(self, *args)

    def insert(self, it: "cblock_pos_t", x: "cblock_pos_t") -> "qvector< cblock_pos_t >::iterator":
        r"""
        insert(self, it, x) -> cblock_pos_t

        @param it: qvector< cblock_pos_t >::iterator
        @param x: cblock_pos_t const &
        """
        return _ida_hexrays.cblock_posvec_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< cblock_pos_t >::iterator":
        r"""
        erase(self, it) -> cblock_pos_t

        @param it: qvector< cblock_pos_t >::iterator

        erase(self, first, last) -> cblock_pos_t

        @param first: qvector< cblock_pos_t >::iterator
        @param last: qvector< cblock_pos_t >::iterator
        """
        return _ida_hexrays.cblock_posvec_t_erase(self, *args)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.cblock_posvec_t___len__(self)

    def __getitem__(self, i: "size_t") -> "cblock_pos_t const &":
        r"""
        __getitem__(self, i) -> cblock_pos_t

        @param i: size_t
        """
        return _ida_hexrays.cblock_posvec_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "cblock_pos_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: cblock_pos_t const &
        """
        return _ida_hexrays.cblock_posvec_t___setitem__(self, i, v)

    def append(self, x: "cblock_pos_t") -> "void":
        r"""
        append(self, x)

        @param x: cblock_pos_t const &
        """
        return _ida_hexrays.cblock_posvec_t_append(self, x)

    def extend(self, x: "cblock_posvec_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< cblock_pos_t > const &
        """
        return _ida_hexrays.cblock_posvec_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register cblock_posvec_t in _ida_hexrays:
_ida_hexrays.cblock_posvec_t_swigregister(cblock_posvec_t)
class lvar_saved_infos_t(object):
    r"""
    Proxy of C++ qvector< lvar_saved_info_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> lvar_saved_infos_t
        __init__(self, x) -> lvar_saved_infos_t

        @param x: qvector< lvar_saved_info_t > const &
        """
        _ida_hexrays.lvar_saved_infos_t_swiginit(self, _ida_hexrays.new_lvar_saved_infos_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_lvar_saved_infos_t

    def push_back(self, *args) -> "lvar_saved_info_t &":
        r"""
        push_back(self, x)

        @param x: lvar_saved_info_t const &

        push_back(self) -> lvar_saved_info_t
        """
        return _ida_hexrays.lvar_saved_infos_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.lvar_saved_infos_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.lvar_saved_infos_t_empty(self)

    def at(self, _idx: "size_t") -> "lvar_saved_info_t const &":
        r"""
        at(self, _idx) -> lvar_saved_info_t

        @param _idx: size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.lvar_saved_infos_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.lvar_saved_infos_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: lvar_saved_info_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=lvar_saved_info_t())

        @param x: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.lvar_saved_infos_t_truncate(self)

    def swap(self, r: "lvar_saved_infos_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< lvar_saved_info_t > &
        """
        return _ida_hexrays.lvar_saved_infos_t_swap(self, r)

    def extract(self) -> "lvar_saved_info_t *":
        r"""
        extract(self) -> lvar_saved_info_t
        """
        return _ida_hexrays.lvar_saved_infos_t_extract(self)

    def inject(self, s: "lvar_saved_info_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: lvar_saved_info_t *
        @param len: size_t
        """
        return _ida_hexrays.lvar_saved_infos_t_inject(self, s, len)

    def __eq__(self, r: "lvar_saved_infos_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< lvar_saved_info_t > const &
        """
        return _ida_hexrays.lvar_saved_infos_t___eq__(self, r)

    def __ne__(self, r: "lvar_saved_infos_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< lvar_saved_info_t > const &
        """
        return _ida_hexrays.lvar_saved_infos_t___ne__(self, r)

    def begin(self, *args) -> "qvector< lvar_saved_info_t >::const_iterator":
        r"""
        begin(self) -> lvar_saved_info_t
        """
        return _ida_hexrays.lvar_saved_infos_t_begin(self, *args)

    def end(self, *args) -> "qvector< lvar_saved_info_t >::const_iterator":
        r"""
        end(self) -> lvar_saved_info_t
        """
        return _ida_hexrays.lvar_saved_infos_t_end(self, *args)

    def insert(self, it: "lvar_saved_info_t", x: "lvar_saved_info_t") -> "qvector< lvar_saved_info_t >::iterator":
        r"""
        insert(self, it, x) -> lvar_saved_info_t

        @param it: qvector< lvar_saved_info_t >::iterator
        @param x: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< lvar_saved_info_t >::iterator":
        r"""
        erase(self, it) -> lvar_saved_info_t

        @param it: qvector< lvar_saved_info_t >::iterator

        erase(self, first, last) -> lvar_saved_info_t

        @param first: qvector< lvar_saved_info_t >::iterator
        @param last: qvector< lvar_saved_info_t >::iterator
        """
        return _ida_hexrays.lvar_saved_infos_t_erase(self, *args)

    def find(self, *args) -> "qvector< lvar_saved_info_t >::const_iterator":
        r"""
        find(self, x) -> lvar_saved_info_t

        @param x: lvar_saved_info_t const &

        """
        return _ida_hexrays.lvar_saved_infos_t_find(self, *args)

    def has(self, x: "lvar_saved_info_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t_has(self, x)

    def add_unique(self, x: "lvar_saved_info_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t_add_unique(self, x)

    def _del(self, x: "lvar_saved_info_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: lvar_saved_info_t const &

        """
        return _ida_hexrays.lvar_saved_infos_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.lvar_saved_infos_t___len__(self)

    def __getitem__(self, i: "size_t") -> "lvar_saved_info_t const &":
        r"""
        __getitem__(self, i) -> lvar_saved_info_t

        @param i: size_t
        """
        return _ida_hexrays.lvar_saved_infos_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "lvar_saved_info_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t___setitem__(self, i, v)

    def append(self, x: "lvar_saved_info_t") -> "void":
        r"""
        append(self, x)

        @param x: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_infos_t_append(self, x)

    def extend(self, x: "lvar_saved_infos_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< lvar_saved_info_t > const &
        """
        return _ida_hexrays.lvar_saved_infos_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register lvar_saved_infos_t in _ida_hexrays:
_ida_hexrays.lvar_saved_infos_t_swigregister(lvar_saved_infos_t)
class ui_stroff_ops_t(object):
    r"""
    Proxy of C++ qvector< ui_stroff_op_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> ui_stroff_ops_t
        __init__(self, x) -> ui_stroff_ops_t

        @param x: qvector< ui_stroff_op_t > const &
        """
        _ida_hexrays.ui_stroff_ops_t_swiginit(self, _ida_hexrays.new_ui_stroff_ops_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_ui_stroff_ops_t

    def push_back(self, *args) -> "ui_stroff_op_t &":
        r"""
        push_back(self, x)

        @param x: ui_stroff_op_t const &

        push_back(self) -> ui_stroff_op_t
        """
        return _ida_hexrays.ui_stroff_ops_t_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.ui_stroff_ops_t_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.ui_stroff_ops_t_empty(self)

    def at(self, _idx: "size_t") -> "ui_stroff_op_t const &":
        r"""
        at(self, _idx) -> ui_stroff_op_t

        @param _idx: size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.ui_stroff_ops_t_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.ui_stroff_ops_t_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: ui_stroff_op_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=ui_stroff_op_t())

        @param x: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.ui_stroff_ops_t_truncate(self)

    def swap(self, r: "ui_stroff_ops_t") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< ui_stroff_op_t > &
        """
        return _ida_hexrays.ui_stroff_ops_t_swap(self, r)

    def extract(self) -> "ui_stroff_op_t *":
        r"""
        extract(self) -> ui_stroff_op_t
        """
        return _ida_hexrays.ui_stroff_ops_t_extract(self)

    def inject(self, s: "ui_stroff_op_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: ui_stroff_op_t *
        @param len: size_t
        """
        return _ida_hexrays.ui_stroff_ops_t_inject(self, s, len)

    def __eq__(self, r: "ui_stroff_ops_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< ui_stroff_op_t > const &
        """
        return _ida_hexrays.ui_stroff_ops_t___eq__(self, r)

    def __ne__(self, r: "ui_stroff_ops_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< ui_stroff_op_t > const &
        """
        return _ida_hexrays.ui_stroff_ops_t___ne__(self, r)

    def begin(self, *args) -> "qvector< ui_stroff_op_t >::const_iterator":
        r"""
        begin(self) -> ui_stroff_op_t
        """
        return _ida_hexrays.ui_stroff_ops_t_begin(self, *args)

    def end(self, *args) -> "qvector< ui_stroff_op_t >::const_iterator":
        r"""
        end(self) -> ui_stroff_op_t
        """
        return _ida_hexrays.ui_stroff_ops_t_end(self, *args)

    def insert(self, it: "ui_stroff_op_t", x: "ui_stroff_op_t") -> "qvector< ui_stroff_op_t >::iterator":
        r"""
        insert(self, it, x) -> ui_stroff_op_t

        @param it: qvector< ui_stroff_op_t >::iterator
        @param x: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t_insert(self, it, x)

    def erase(self, *args) -> "qvector< ui_stroff_op_t >::iterator":
        r"""
        erase(self, it) -> ui_stroff_op_t

        @param it: qvector< ui_stroff_op_t >::iterator

        erase(self, first, last) -> ui_stroff_op_t

        @param first: qvector< ui_stroff_op_t >::iterator
        @param last: qvector< ui_stroff_op_t >::iterator
        """
        return _ida_hexrays.ui_stroff_ops_t_erase(self, *args)

    def find(self, *args) -> "qvector< ui_stroff_op_t >::const_iterator":
        r"""
        find(self, x) -> ui_stroff_op_t

        @param x: ui_stroff_op_t const &

        """
        return _ida_hexrays.ui_stroff_ops_t_find(self, *args)

    def has(self, x: "ui_stroff_op_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t_has(self, x)

    def add_unique(self, x: "ui_stroff_op_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t_add_unique(self, x)

    def _del(self, x: "ui_stroff_op_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: ui_stroff_op_t const &

        """
        return _ida_hexrays.ui_stroff_ops_t__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.ui_stroff_ops_t___len__(self)

    def __getitem__(self, i: "size_t") -> "ui_stroff_op_t const &":
        r"""
        __getitem__(self, i) -> ui_stroff_op_t

        @param i: size_t
        """
        return _ida_hexrays.ui_stroff_ops_t___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "ui_stroff_op_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t___setitem__(self, i, v)

    def append(self, x: "ui_stroff_op_t") -> "void":
        r"""
        append(self, x)

        @param x: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_ops_t_append(self, x)

    def extend(self, x: "ui_stroff_ops_t") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< ui_stroff_op_t > const &
        """
        return _ida_hexrays.ui_stroff_ops_t_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register ui_stroff_ops_t in _ida_hexrays:
_ida_hexrays.ui_stroff_ops_t_swigregister(ui_stroff_ops_t)

def qswap(a: "cinsn_t", b: "cinsn_t") -> "void":
    r"""
    qswap(a, b)

    @param a: cinsn_t &
    @param b: cinsn_t &
    """
    return _ida_hexrays.qswap(a, b)

def debug_hexrays_ctree(level: "int", msg: "char const *") -> "void":
    r"""
    debug_hexrays_ctree(level, msg)

    @param level: int
    @param msg: char const *
    """
    return _ida_hexrays.debug_hexrays_ctree(level, msg)

def init_hexrays_plugin(flags: "int"=0) -> "bool":
    r"""
    init_hexrays_plugin(flags=0) -> bool
    Check that your plugin is compatible with hex-rays decompiler. This function
    must be called before calling any other decompiler function.

    @param flags: (C++: int) reserved, must be 0
    @return: true if the decompiler exists and is compatible with your plugin
    """
    return _ida_hexrays.init_hexrays_plugin(flags)

def get_widget_vdui(f: "TWidget *") -> "vdui_t *":
    r"""
    get_widget_vdui(f) -> vdui_t
    Get the vdui_t instance associated to the TWidget

    @param f: (C++: TWidget *) pointer to window
    @return: a vdui_t *, or nullptr
    """
    return _ida_hexrays.get_widget_vdui(f)

def boundaries_find(map: "boundaries_t", key: "cinsn_t") -> "boundaries_iterator_t":
    r"""
    boundaries_find(map, key) -> boundaries_iterator_t
    Find the specified key in boundaries_t.

    @param map: (C++: const boundaries_t *) boundaries_t const *
    @param key: (C++: const cinsn_t *&) cinsn_t const *
    """
    return _ida_hexrays.boundaries_find(map, key)

def boundaries_insert(map: "boundaries_t", key: "cinsn_t", val: "rangeset_t") -> "boundaries_iterator_t":
    r"""
    boundaries_insert(map, key, val) -> boundaries_iterator_t
    Insert new (cinsn_t *, rangeset_t) pair into boundaries_t.

    @param map: (C++: boundaries_t *)
    @param key: (C++: const cinsn_t *&) cinsn_t const *
    @param val: (C++: const rangeset_t &) rangeset_t const &
    """
    return _ida_hexrays.boundaries_insert(map, key, val)

def term_hexrays_plugin() -> "void":
    r"""
    term_hexrays_plugin()
    Stop working with hex-rays decompiler.
    """
    return _ida_hexrays.term_hexrays_plugin()
class Hexrays_Hooks(object):
    r"""
    Proxy of C++ Hexrays_Hooks class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _flags: "uint32"=0, _hkcb_flags: "uint32"=0x0001):
        r"""
        __init__(self, _flags=0, _hkcb_flags=0x0001) -> Hexrays_Hooks

        @param _flags: uint32
        @param _hkcb_flags: uint32
        """
        if self.__class__ == Hexrays_Hooks:
            _self = None
        else:
            _self = self
        _ida_hexrays.Hexrays_Hooks_swiginit(self, _ida_hexrays.new_Hexrays_Hooks(_self, _flags, _hkcb_flags))
    __swig_destroy__ = _ida_hexrays.delete_Hexrays_Hooks

    def hook(self) -> "bool":
        r"""
        hook(self) -> bool
        """
        return _ida_hexrays.Hexrays_Hooks_hook(self)

    def unhook(self) -> "bool":
        r"""
        unhook(self) -> bool
        """
        return _ida_hexrays.Hexrays_Hooks_unhook(self)

    def flowchart(self, fc: "qflow_chart_t", mba: "mba_t") -> "int":
        r"""
        flowchart(self, fc, mba) -> int
        Flowchart has been generated.

        @param fc: (qflow_chart_t *)
        @param mba: (mba_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_flowchart(self, fc, mba)

    def stkpnts(self, mba: "mba_t", _sps: "stkpnts_t *") -> "int":
        r"""
        stkpnts(self, mba, _sps) -> int
        SP change points have been calculated.

        @param mba: (mba_t *)
        @param _sps: stkpnts_t *
        @return: Microcode error codes code This event is generated for each inlined
                 range as well.
        """
        return _ida_hexrays.Hexrays_Hooks_stkpnts(self, mba, _sps)

    def prolog(self, mba: "mba_t", fc: "qflow_chart_t", reachable_blocks: "bitset_t", decomp_flags: "int") -> "int":
        r"""
        prolog(self, mba, fc, reachable_blocks, decomp_flags) -> int
        Prolog analysis has been finished.

        @param mba: (mba_t *)
        @param fc: (qflow_chart_t *)
        @param reachable_blocks: (bitset_t *)
        @param decomp_flags: (int)
        @return: Microcode error codes code This event is generated for each inlined
                 range as well.
        """
        return _ida_hexrays.Hexrays_Hooks_prolog(self, mba, fc, reachable_blocks, decomp_flags)

    def microcode(self, mba: "mba_t") -> "int":
        r"""
        microcode(self, mba) -> int
        Microcode has been generated.

        @param mba: (mba_t *)
        @return: Microcode error codes code
        """
        return _ida_hexrays.Hexrays_Hooks_microcode(self, mba)

    def preoptimized(self, mba: "mba_t") -> "int":
        r"""
        preoptimized(self, mba) -> int
        Microcode has been preoptimized.

        @param mba: (mba_t *)
        @return: Microcode error codes code
        """
        return _ida_hexrays.Hexrays_Hooks_preoptimized(self, mba)

    def locopt(self, mba: "mba_t") -> "int":
        r"""
        locopt(self, mba) -> int
        Basic block level optimization has been finished.

        @param mba: (mba_t *)
        @return: Microcode error codes code
        """
        return _ida_hexrays.Hexrays_Hooks_locopt(self, mba)

    def prealloc(self, mba: "mba_t") -> "int":
        r"""
        prealloc(self, mba) -> int
        Local variables: preallocation step begins.

        @param mba: (mba_t *) This event may occur several times. Should return: 1 if
                    modified microcode Negative values are Microcode error codes error
                    codes
        """
        return _ida_hexrays.Hexrays_Hooks_prealloc(self, mba)

    def glbopt(self, mba: "mba_t") -> "int":
        r"""
        glbopt(self, mba) -> int
        Global optimization has been finished. If microcode is modified, MERR_LOOP must
        be returned. It will cause a complete restart of the optimization.

        @param mba: (mba_t *)
        @return: Microcode error codes code
        """
        return _ida_hexrays.Hexrays_Hooks_glbopt(self, mba)

    def pre_structural(self, ct: "control_graph_t *", cfunc: "cfunc_t", g: "simple_graph_t") -> "int":
        r"""
        pre_structural(self, ct, cfunc, g) -> int
        Structure analysis is starting.

        @param ct: (control_graph_t *) in/out: control graph
        @param cfunc: (cfunc_t *) in: the current function
        @param g: (const simple_graph_t *) in: control flow graph
        @return: Microcode error codes code; MERR_BLOCK means that the analysis has been
                 performed by a plugin
        """
        return _ida_hexrays.Hexrays_Hooks_pre_structural(self, ct, cfunc, g)

    def structural(self, ct: "control_graph_t *") -> "int":
        r"""
        structural(self, ct) -> int
        Structural analysis has been finished.

        @param ct: (control_graph_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_structural(self, ct)

    def maturity(self, cfunc: "cfunc_t", new_maturity: "ctree_maturity_t") -> "int":
        r"""
        maturity(self, cfunc, new_maturity) -> int
        Ctree maturity level is being changed.

        @param cfunc: (cfunc_t *)
        @param new_maturity: (ctree_maturity_t)
        """
        return _ida_hexrays.Hexrays_Hooks_maturity(self, cfunc, new_maturity)

    def interr(self, errcode: "int") -> "int":
        r"""
        interr(self, errcode) -> int
        Internal error has occurred.

        @param errcode: (int )
        """
        return _ida_hexrays.Hexrays_Hooks_interr(self, errcode)

    def combine(self, blk: "mblock_t", insn: "minsn_t") -> "int":
        r"""
        combine(self, blk, insn) -> int
        Trying to combine instructions of basic block.

        @param blk: (mblock_t *)
        @param insn: (minsn_t *) Should return: 1 if combined the current instruction
                     with a preceding one -1 if the instruction should not be combined 0
                     else
        """
        return _ida_hexrays.Hexrays_Hooks_combine(self, blk, insn)

    def print_func(self, cfunc: "cfunc_t", vp: "vc_printer_t") -> "int":
        r"""
        print_func(self, cfunc, vp) -> int
        Printing ctree and generating text.

        @param cfunc: (cfunc_t *)
        @param vp: (vc_printer_t *) Returns: 1 if text has been generated by the plugin
                   It is forbidden to modify ctree at this event.
        """
        return _ida_hexrays.Hexrays_Hooks_print_func(self, cfunc, vp)

    def func_printed(self, cfunc: "cfunc_t") -> "int":
        r"""
        func_printed(self, cfunc) -> int
        Function text has been generated. Plugins may modify the text in cfunc_t::sv.
        The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store
        pointers to ctree items.

        @param cfunc: (cfunc_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_func_printed(self, cfunc)

    def resolve_stkaddrs(self, mba: "mba_t") -> "int":
        r"""
        resolve_stkaddrs(self, mba) -> int
        The optimizer is about to resolve stack addresses.

        @param mba: (mba_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_resolve_stkaddrs(self, mba)

    def build_callinfo(self, blk: "mblock_t", type: "tinfo_t") -> "PyObject *":
        r"""
        build_callinfo(self, blk, type) -> PyObject *
        Analyzing a call instruction.

        @param blk: (mblock_t *) blk->tail is the call.
        @param type: (tinfo_t *) buffer for the output type.
        """
        return _ida_hexrays.Hexrays_Hooks_build_callinfo(self, blk, type)

    def callinfo_built(self, blk: "mblock_t") -> "int":
        r"""
        callinfo_built(self, blk) -> int
        A call instruction has been anallyzed.

        @param blk: (mblock_t *) blk->tail is the call.
        """
        return _ida_hexrays.Hexrays_Hooks_callinfo_built(self, blk)

    def calls_done(self, mba: "mba_t") -> "int":
        r"""
        calls_done(self, mba) -> int
        All calls have been analyzed.

        @param mba: (mba_t *) This event is generated immediately after analyzing all
                    calls, before any optimizitions, call unmerging and block merging.
        """
        return _ida_hexrays.Hexrays_Hooks_calls_done(self, mba)

    def begin_inlining(self, cdg: "codegen_t", decomp_flags: "int") -> "int":
        r"""
        begin_inlining(self, cdg, decomp_flags) -> int
        Starting to inline outlined functions.

        @param cdg: (codegen_t *)
        @param decomp_flags: (int)
        @return: Microcode error codes code This is an opportunity to inline other
                 ranges.
        """
        return _ida_hexrays.Hexrays_Hooks_begin_inlining(self, cdg, decomp_flags)

    def inlining_func(self, cdg: "codegen_t", blk: "int", mbr: "mba_ranges_t") -> "int":
        r"""
        inlining_func(self, cdg, blk, mbr) -> int
        A set of ranges is going to be inlined.

        @param cdg: (codegen_t *)
        @param blk: (int) the block containing call/jump to inline
        @param mbr: (mba_ranges_t *) the range to inline
        """
        return _ida_hexrays.Hexrays_Hooks_inlining_func(self, cdg, blk, mbr)

    def inlined_func(self, cdg: "codegen_t", blk: "int", mbr: "mba_ranges_t", i1: "int", i2: "int") -> "int":
        r"""
        inlined_func(self, cdg, blk, mbr, i1, i2) -> int
        A set of ranges got inlined.

        @param cdg: (codegen_t *)
        @param blk: (int) the block containing call/jump to inline
        @param mbr: (mba_ranges_t *) the range to inline
        @param i1: (int) blknum of the first inlined block
        @param i2: (int) blknum of the last inlined block (excluded)
        """
        return _ida_hexrays.Hexrays_Hooks_inlined_func(self, cdg, blk, mbr, i1, i2)

    def collect_warnings(self, cfunc: "cfunc_t") -> "int":
        r"""
        collect_warnings(self, cfunc) -> int
        Collect warning messages from plugins. These warnings will be displayed at the
        function header, after the user-defined comments.

        @param cfunc: (cfunc_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_collect_warnings(self, cfunc)

    def open_pseudocode(self, vu: "vdui_t") -> "int":
        r"""
        open_pseudocode(self, vu) -> int
        New pseudocode view has been opened.

        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_open_pseudocode(self, vu)

    def switch_pseudocode(self, vu: "vdui_t") -> "int":
        r"""
        switch_pseudocode(self, vu) -> int
        Existing pseudocode view has been reloaded with a new function. Its text has not
        been refreshed yet, only cfunc and mba pointers are ready.

        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_switch_pseudocode(self, vu)

    def refresh_pseudocode(self, vu: "vdui_t") -> "int":
        r"""
        refresh_pseudocode(self, vu) -> int
        Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is
        forbidden in this event.

        @param vu: (vdui_t *) See also hxe_text_ready, which happens earlier
        """
        return _ida_hexrays.Hexrays_Hooks_refresh_pseudocode(self, vu)

    def close_pseudocode(self, vu: "vdui_t") -> "int":
        r"""
        close_pseudocode(self, vu) -> int
        Pseudocode view is being closed.

        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_close_pseudocode(self, vu)

    def keyboard(self, vu: "vdui_t", key_code: "int", shift_state: "int") -> "int":
        r"""
        keyboard(self, vu, key_code, shift_state) -> int
        Keyboard has been hit.

        @param vu: (vdui_t *)
        @param key_code: (int) VK_...
        @param shift_state: (int) Should return: 1 if the event has been handled
        """
        return _ida_hexrays.Hexrays_Hooks_keyboard(self, vu, key_code, shift_state)

    def right_click(self, vu: "vdui_t") -> "int":
        r"""
        right_click(self, vu) -> int
        Mouse right click. Use hxe_populating_popup instead, in case you want to add
        items in the popup menu.

        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_right_click(self, vu)

    def double_click(self, vu: "vdui_t", shift_state: "int") -> "int":
        r"""
        double_click(self, vu, shift_state) -> int
        Mouse double click.

        @param vu: (vdui_t *)
        @param shift_state: (int) Should return: 1 if the event has been handled
        """
        return _ida_hexrays.Hexrays_Hooks_double_click(self, vu, shift_state)

    def curpos(self, vu: "vdui_t") -> "int":
        r"""
        curpos(self, vu) -> int
        Current cursor position has been changed. (for example, by left-clicking or
        using keyboard)

        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_curpos(self, vu)

    def create_hint(self, vu: "vdui_t") -> "PyObject *":
        r"""
        create_hint(self, vu) -> PyObject *
        Create a hint for the current item.
        @see: ui_get_custom_viewer_hint

        @param vu: (vdui_t *)
        @retval 0: continue collecting hints with other subscribers
        @retval 1: stop collecting hints
        """
        return _ida_hexrays.Hexrays_Hooks_create_hint(self, vu)

    def text_ready(self, vu: "vdui_t") -> "int":
        r"""
        text_ready(self, vu) -> int
        Decompiled text is ready.

        @param vu: (vdui_t *) This event can be used to modify the output text (sv).
                   Obsolete. Please use hxe_func_printed instead.
        """
        return _ida_hexrays.Hexrays_Hooks_text_ready(self, vu)

    def populating_popup(self, widget: "TWidget *", popup_handle: "TPopupMenu *", vu: "vdui_t") -> "int":
        r"""
        populating_popup(self, widget, popup_handle, vu) -> int
        Populating popup menu. We can add menu items now.

        @param widget: (TWidget *)
        @param popup_handle: (TPopupMenu *)
        @param vu: (vdui_t *)
        """
        return _ida_hexrays.Hexrays_Hooks_populating_popup(self, widget, popup_handle, vu)

    def lvar_name_changed(self, vu: "vdui_t", v: "lvar_t", name: "char const *", is_user_name: "bool") -> "int":
        r"""
        lvar_name_changed(self, vu, v, name, is_user_name) -> int
        Local variable got renamed.

        @param vu: (vdui_t *)
        @param v: (lvar_t *)
        @param name: (const char *)
        @param is_user_name: (bool) Please note that it is possible to read/write user
                             settings for lvars directly from the idb.
        """
        return _ida_hexrays.Hexrays_Hooks_lvar_name_changed(self, vu, v, name, is_user_name)

    def lvar_type_changed(self, vu: "vdui_t", v: "lvar_t", tinfo: "tinfo_t") -> "int":
        r"""
        lvar_type_changed(self, vu, v, tinfo) -> int
        Local variable type got changed.

        @param vu: (vdui_t *)
        @param v: (lvar_t *)
        @param tinfo: (const tinfo_t *) Please note that it is possible to read/write
                      user settings for lvars directly from the idb.
        """
        return _ida_hexrays.Hexrays_Hooks_lvar_type_changed(self, vu, v, tinfo)

    def lvar_cmt_changed(self, vu: "vdui_t", v: "lvar_t", cmt: "char const *") -> "int":
        r"""
        lvar_cmt_changed(self, vu, v, cmt) -> int
        Local variable comment got changed.

        @param vu: (vdui_t *)
        @param v: (lvar_t *)
        @param cmt: (const char *) Please note that it is possible to read/write user
                    settings for lvars directly from the idb.
        """
        return _ida_hexrays.Hexrays_Hooks_lvar_cmt_changed(self, vu, v, cmt)

    def lvar_mapping_changed(self, vu: "vdui_t", frm: "lvar_t", to: "lvar_t") -> "int":
        r"""
        lvar_mapping_changed(self, vu, frm, to) -> int
        Local variable mapping got changed.

        @param vu: (vdui_t *)
        @param from: lvar_t *
        @param to: (lvar_t *) Please note that it is possible to read/write user
                   settings for lvars directly from the idb.
        """
        return _ida_hexrays.Hexrays_Hooks_lvar_mapping_changed(self, vu, frm, to)

    def cmt_changed(self, cfunc: "cfunc_t", loc: "treeloc_t", cmt: "char const *") -> "int":
        r"""
        cmt_changed(self, cfunc, loc, cmt) -> int
        Comment got changed.

        @param cfunc: (cfunc_t *)
        @param loc: (const treeloc_t *)
        @param cmt: (const char *)
        """
        return _ida_hexrays.Hexrays_Hooks_cmt_changed(self, cfunc, loc, cmt)
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_Hexrays_Hooks(self)
        return weakref.proxy(self)

# Register Hexrays_Hooks in _ida_hexrays:
_ida_hexrays.Hexrays_Hooks_swigregister(Hexrays_Hooks)
class uval_ivl_t(object):
    r"""
    Proxy of C++ ivl_tpl< uval_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    off: "unsigned long long" = property(_ida_hexrays.uval_ivl_t_off_get, _ida_hexrays.uval_ivl_t_off_set, doc=r"""off""")
    size: "unsigned long long" = property(_ida_hexrays.uval_ivl_t_size_get, _ida_hexrays.uval_ivl_t_size_set, doc=r"""size""")

    def __init__(self, _off: "unsigned long long", _size: "unsigned long long"):
        r"""
        __init__(self, _off, _size) -> uval_ivl_t

        @param _off: unsigned long long
        @param _size: unsigned long long
        """
        _ida_hexrays.uval_ivl_t_swiginit(self, _ida_hexrays.new_uval_ivl_t(_off, _size))

    def valid(self) -> "bool":
        r"""
        valid(self) -> bool
        """
        return _ida_hexrays.uval_ivl_t_valid(self)

    def end(self) -> "unsigned long long":
        r"""
        end(self) -> unsigned long long
        """
        return _ida_hexrays.uval_ivl_t_end(self)

    def last(self) -> "unsigned long long":
        r"""
        last(self) -> unsigned long long
        """
        return _ida_hexrays.uval_ivl_t_last(self)
    __swig_destroy__ = _ida_hexrays.delete_uval_ivl_t

# Register uval_ivl_t in _ida_hexrays:
_ida_hexrays.uval_ivl_t_swigregister(uval_ivl_t)
class uval_ivl_ivlset_t(object):
    r"""
    Proxy of C++ ivlset_tpl< ivl_t,uval_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> uval_ivl_ivlset_t
        __init__(self, ivl) -> uval_ivl_ivlset_t

        @param ivl: ivl_t const &
        """
        _ida_hexrays.uval_ivl_ivlset_t_swiginit(self, _ida_hexrays.new_uval_ivl_ivlset_t(*args))

    def swap(self, r: "uval_ivl_ivlset_t") -> "void":
        r"""
        swap(self, r)

        @param r: ivlset_tpl< ivl_t,uval_t > &
        """
        return _ida_hexrays.uval_ivl_ivlset_t_swap(self, r)

    def getivl(self, idx: "int") -> "ivl_t const &":
        r"""
        getivl(self, idx) -> ivl_t

        @param idx: int
        """
        return _ida_hexrays.uval_ivl_ivlset_t_getivl(self, idx)

    def lastivl(self) -> "ivl_t const &":
        r"""
        lastivl(self) -> ivl_t
        """
        return _ida_hexrays.uval_ivl_ivlset_t_lastivl(self)

    def nivls(self) -> "size_t":
        r"""
        nivls(self) -> size_t
        """
        return _ida_hexrays.uval_ivl_ivlset_t_nivls(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.uval_ivl_ivlset_t_empty(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.uval_ivl_ivlset_t_clear(self)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.uval_ivl_ivlset_t_qclear(self)

    def all_values(self) -> "bool":
        r"""
        all_values(self) -> bool
        """
        return _ida_hexrays.uval_ivl_ivlset_t_all_values(self)

    def set_all_values(self) -> "void":
        r"""
        set_all_values(self)
        """
        return _ida_hexrays.uval_ivl_ivlset_t_set_all_values(self)

    def single_value(self, *args) -> "bool":
        r"""
        single_value(self) -> bool
        single_value(self, v) -> bool

        @param v: unsigned long long
        """
        return _ida_hexrays.uval_ivl_ivlset_t_single_value(self, *args)

    def __eq__(self, v: "ivl_t") -> "bool":
        r"""
        __eq__(self, v) -> bool

        @param v: ivl_t const &
        """
        return _ida_hexrays.uval_ivl_ivlset_t___eq__(self, v)

    def __ne__(self, v: "ivl_t") -> "bool":
        r"""
        __ne__(self, v) -> bool

        @param v: ivl_t const &
        """
        return _ida_hexrays.uval_ivl_ivlset_t___ne__(self, v)

    def begin(self, *args) -> "ivlset_tpl< ivl_t,unsigned long long >::iterator":
        r"""
        begin(self) -> ivlset_tpl< ivl_t,unsigned long long >::const_iterator
        begin(self) -> ivlset_tpl< ivl_t,unsigned long long >::iterator
        """
        return _ida_hexrays.uval_ivl_ivlset_t_begin(self, *args)

    def end(self, *args) -> "ivlset_tpl< ivl_t,unsigned long long >::iterator":
        r"""
        end(self) -> ivlset_tpl< ivl_t,unsigned long long >::const_iterator
        end(self) -> ivlset_tpl< ivl_t,unsigned long long >::iterator
        """
        return _ida_hexrays.uval_ivl_ivlset_t_end(self, *args)
    __swig_destroy__ = _ida_hexrays.delete_uval_ivl_ivlset_t

# Register uval_ivl_ivlset_t in _ida_hexrays:
_ida_hexrays.uval_ivl_ivlset_t_swigregister(uval_ivl_ivlset_t)
class array_of_ivlsets(object):
    r"""
    Proxy of C++ qvector< ivlset_t > class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> array_of_ivlsets
        __init__(self, x) -> array_of_ivlsets

        @param x: qvector< ivlset_t > const &
        """
        _ida_hexrays.array_of_ivlsets_swiginit(self, _ida_hexrays.new_array_of_ivlsets(*args))
    __swig_destroy__ = _ida_hexrays.delete_array_of_ivlsets

    def push_back(self, *args) -> "ivlset_t &":
        r"""
        push_back(self, x)

        @param x: ivlset_t const &

        push_back(self) -> ivlset_t
        """
        return _ida_hexrays.array_of_ivlsets_push_back(self, *args)

    def pop_back(self) -> "void":
        r"""
        pop_back(self)
        """
        return _ida_hexrays.array_of_ivlsets_pop_back(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.array_of_ivlsets_size(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.array_of_ivlsets_empty(self)

    def at(self, _idx: "size_t") -> "ivlset_t const &":
        r"""
        at(self, _idx) -> ivlset_t

        @param _idx: size_t
        """
        return _ida_hexrays.array_of_ivlsets_at(self, _idx)

    def qclear(self) -> "void":
        r"""
        qclear(self)
        """
        return _ida_hexrays.array_of_ivlsets_qclear(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.array_of_ivlsets_clear(self)

    def resize(self, *args) -> "void":
        r"""
        resize(self, _newsize, x)

        @param _newsize: size_t
        @param x: ivlset_t const &

        resize(self, _newsize)

        @param _newsize: size_t
        """
        return _ida_hexrays.array_of_ivlsets_resize(self, *args)

    def grow(self, *args) -> "void":
        r"""
        grow(self, x=ivlset_t())

        @param x: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets_grow(self, *args)

    def capacity(self) -> "size_t":
        r"""
        capacity(self) -> size_t
        """
        return _ida_hexrays.array_of_ivlsets_capacity(self)

    def reserve(self, cnt: "size_t") -> "void":
        r"""
        reserve(self, cnt)

        @param cnt: size_t
        """
        return _ida_hexrays.array_of_ivlsets_reserve(self, cnt)

    def truncate(self) -> "void":
        r"""
        truncate(self)
        """
        return _ida_hexrays.array_of_ivlsets_truncate(self)

    def swap(self, r: "array_of_ivlsets") -> "void":
        r"""
        swap(self, r)

        @param r: qvector< ivlset_t > &
        """
        return _ida_hexrays.array_of_ivlsets_swap(self, r)

    def extract(self) -> "ivlset_t *":
        r"""
        extract(self) -> ivlset_t
        """
        return _ida_hexrays.array_of_ivlsets_extract(self)

    def inject(self, s: "ivlset_t", len: "size_t") -> "void":
        r"""
        inject(self, s, len)

        @param s: ivlset_t *
        @param len: size_t
        """
        return _ida_hexrays.array_of_ivlsets_inject(self, s, len)

    def __eq__(self, r: "array_of_ivlsets") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: qvector< ivlset_t > const &
        """
        return _ida_hexrays.array_of_ivlsets___eq__(self, r)

    def __ne__(self, r: "array_of_ivlsets") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: qvector< ivlset_t > const &
        """
        return _ida_hexrays.array_of_ivlsets___ne__(self, r)

    def begin(self, *args) -> "qvector< ivlset_t >::const_iterator":
        r"""
        begin(self) -> ivlset_t
        """
        return _ida_hexrays.array_of_ivlsets_begin(self, *args)

    def end(self, *args) -> "qvector< ivlset_t >::const_iterator":
        r"""
        end(self) -> ivlset_t
        """
        return _ida_hexrays.array_of_ivlsets_end(self, *args)

    def insert(self, it: "ivlset_t", x: "ivlset_t") -> "qvector< ivlset_t >::iterator":
        r"""
        insert(self, it, x) -> ivlset_t

        @param it: qvector< ivlset_t >::iterator
        @param x: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets_insert(self, it, x)

    def erase(self, *args) -> "qvector< ivlset_t >::iterator":
        r"""
        erase(self, it) -> ivlset_t

        @param it: qvector< ivlset_t >::iterator

        erase(self, first, last) -> ivlset_t

        @param first: qvector< ivlset_t >::iterator
        @param last: qvector< ivlset_t >::iterator
        """
        return _ida_hexrays.array_of_ivlsets_erase(self, *args)

    def find(self, *args) -> "qvector< ivlset_t >::const_iterator":
        r"""
        find(self, x) -> ivlset_t

        @param x: ivlset_t const &

        """
        return _ida_hexrays.array_of_ivlsets_find(self, *args)

    def has(self, x: "ivlset_t") -> "bool":
        r"""
        has(self, x) -> bool

        @param x: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets_has(self, x)

    def add_unique(self, x: "ivlset_t") -> "bool":
        r"""
        add_unique(self, x) -> bool

        @param x: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets_add_unique(self, x)

    def _del(self, x: "ivlset_t") -> "bool":
        r"""
        _del(self, x) -> bool

        Parameters
        ----------
        x: ivlset_t const &

        """
        return _ida_hexrays.array_of_ivlsets__del(self, x)

    def __len__(self) -> "size_t":
        r"""
        __len__(self) -> size_t
        """
        return _ida_hexrays.array_of_ivlsets___len__(self)

    def __getitem__(self, i: "size_t") -> "ivlset_t const &":
        r"""
        __getitem__(self, i) -> ivlset_t

        @param i: size_t
        """
        return _ida_hexrays.array_of_ivlsets___getitem__(self, i)

    def __setitem__(self, i: "size_t", v: "ivlset_t") -> "void":
        r"""
        __setitem__(self, i, v)

        @param i: size_t
        @param v: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets___setitem__(self, i, v)

    def append(self, x: "ivlset_t") -> "void":
        r"""
        append(self, x)

        @param x: ivlset_t const &
        """
        return _ida_hexrays.array_of_ivlsets_append(self, x)

    def extend(self, x: "array_of_ivlsets") -> "void":
        r"""
        extend(self, x)

        @param x: qvector< ivlset_t > const &
        """
        return _ida_hexrays.array_of_ivlsets_extend(self, x)

    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


# Register array_of_ivlsets in _ida_hexrays:
_ida_hexrays.array_of_ivlsets_swigregister(array_of_ivlsets)
MAX_SUPPORTED_STACK_SIZE = _ida_hexrays.MAX_SUPPORTED_STACK_SIZE


def hexrays_alloc(size: "size_t") -> "void *":
    r"""
    hexrays_alloc(size) -> void *

    @param size: size_t
    """
    return _ida_hexrays.hexrays_alloc(size)

def hexrays_free(ptr: "void *") -> "void":
    r"""
    hexrays_free(ptr)

    @param ptr: void *
    """
    return _ida_hexrays.hexrays_free(ptr)
MAX_VLR_SIZE = _ida_hexrays.MAX_VLR_SIZE


def max_vlr_value(size: "int") -> "uvlr_t":
    r"""
    max_vlr_value(size) -> uvlr_t

    @param size: int
    """
    return _ida_hexrays.max_vlr_value(size)

def min_vlr_svalue(size: "int") -> "uvlr_t":
    r"""
    min_vlr_svalue(size) -> uvlr_t

    @param size: int
    """
    return _ida_hexrays.min_vlr_svalue(size)

def max_vlr_svalue(size: "int") -> "uvlr_t":
    r"""
    max_vlr_svalue(size) -> uvlr_t

    @param size: int
    """
    return _ida_hexrays.max_vlr_svalue(size)
CMP_NZ = _ida_hexrays.CMP_NZ

CMP_Z = _ida_hexrays.CMP_Z

CMP_AE = _ida_hexrays.CMP_AE

CMP_B = _ida_hexrays.CMP_B

CMP_A = _ida_hexrays.CMP_A

CMP_BE = _ida_hexrays.CMP_BE

CMP_GT = _ida_hexrays.CMP_GT

CMP_GE = _ida_hexrays.CMP_GE

CMP_LT = _ida_hexrays.CMP_LT

CMP_LE = _ida_hexrays.CMP_LE


def is_unsigned_cmpop(cmpop: "cmpop_t") -> "bool":
    r"""
    is_unsigned_cmpop(cmpop) -> bool

    @param cmpop: enum cmpop_t
    """
    return _ida_hexrays.is_unsigned_cmpop(cmpop)

def is_signed_cmpop(cmpop: "cmpop_t") -> "bool":
    r"""
    is_signed_cmpop(cmpop) -> bool

    @param cmpop: enum cmpop_t
    """
    return _ida_hexrays.is_signed_cmpop(cmpop)

def is_cmpop_with_eq(cmpop: "cmpop_t") -> "bool":
    r"""
    is_cmpop_with_eq(cmpop) -> bool

    @param cmpop: enum cmpop_t
    """
    return _ida_hexrays.is_cmpop_with_eq(cmpop)

def is_cmpop_without_eq(cmpop: "cmpop_t") -> "bool":
    r"""
    is_cmpop_without_eq(cmpop) -> bool

    @param cmpop: enum cmpop_t
    """
    return _ida_hexrays.is_cmpop_without_eq(cmpop)
class valrng_t(object):
    r"""
    Proxy of C++ valrng_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self, size_=MAX_VLR_SIZE) -> valrng_t

        @param size_: int

        __init__(self, r) -> valrng_t

        @param r: valrng_t const &
        """
        _ida_hexrays.valrng_t_swiginit(self, _ida_hexrays.new_valrng_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_valrng_t

    def swap(self, r: "valrng_t") -> "void":
        r"""
        swap(self, r)

        @param r: valrng_t &
        """
        return _ida_hexrays.valrng_t_swap(self, r)

    def __eq__(self, r: "valrng_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___eq__(self, r)

    def __ne__(self, r: "valrng_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___ne__(self, r)

    def __lt__(self, r: "valrng_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___lt__(self, r)

    def __gt__(self, r: "valrng_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___gt__(self, r)

    def __le__(self, r: "valrng_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___le__(self, r)

    def __ge__(self, r: "valrng_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t___ge__(self, r)

    def compare(self, r: "valrng_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t_compare(self, r)

    def set_none(self) -> "void":
        r"""
        set_none(self)
        """
        return _ida_hexrays.valrng_t_set_none(self)

    def set_all(self) -> "void":
        r"""
        set_all(self)
        """
        return _ida_hexrays.valrng_t_set_all(self)

    def set_unk(self) -> "void":
        r"""
        set_unk(self)
        """
        return _ida_hexrays.valrng_t_set_unk(self)

    def set_eq(self, v: "uvlr_t") -> "void":
        r"""
        set_eq(self, v)

        @param v: uvlr_t
        """
        return _ida_hexrays.valrng_t_set_eq(self, v)

    def set_cmp(self, cmp: "cmpop_t", _value: "uvlr_t") -> "void":
        r"""
        set_cmp(self, cmp, _value)

        @param cmp: enum cmpop_t
        @param _value: uvlr_t
        """
        return _ida_hexrays.valrng_t_set_cmp(self, cmp, _value)

    def reduce_size(self, new_size: "int") -> "bool":
        r"""
        reduce_size(self, new_size) -> bool

        @param new_size: int
        """
        return _ida_hexrays.valrng_t_reduce_size(self, new_size)

    def intersect_with(self, r: "valrng_t") -> "bool":
        r"""
        intersect_with(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t_intersect_with(self, r)

    def unite_with(self, r: "valrng_t") -> "bool":
        r"""
        unite_with(self, r) -> bool

        @param r: valrng_t const &
        """
        return _ida_hexrays.valrng_t_unite_with(self, r)

    def inverse(self) -> "void":
        r"""
        inverse(self)
        """
        return _ida_hexrays.valrng_t_inverse(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.valrng_t_empty(self)

    def all_values(self) -> "bool":
        r"""
        all_values(self) -> bool
        """
        return _ida_hexrays.valrng_t_all_values(self)

    def is_unknown(self) -> "bool":
        r"""
        is_unknown(self) -> bool
        """
        return _ida_hexrays.valrng_t_is_unknown(self)

    def has(self, v: "uvlr_t") -> "bool":
        r"""
        has(self, v) -> bool

        @param v: uvlr_t
        """
        return _ida_hexrays.valrng_t_has(self, v)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.valrng_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.valrng_t_dstr(self)

    def cvt_to_single_value(self) -> "bool":
        r"""
        cvt_to_single_value(self) -> bool
        """
        return _ida_hexrays.valrng_t_cvt_to_single_value(self)

    def cvt_to_cmp(self) -> "bool":
        r"""
        cvt_to_cmp(self) -> bool
        """
        return _ida_hexrays.valrng_t_cvt_to_cmp(self)

    def get_size(self) -> "int":
        r"""
        get_size(self) -> int
        """
        return _ida_hexrays.valrng_t_get_size(self)

    def max_value(self) -> "uvlr_t":
        r"""
        max_value(self) -> uvlr_t
        """
        return _ida_hexrays.valrng_t_max_value(self)

    def min_svalue(self) -> "uvlr_t":
        r"""
        min_svalue(self) -> uvlr_t
        """
        return _ida_hexrays.valrng_t_min_svalue(self)

    def max_svalue(self) -> "uvlr_t":
        r"""
        max_svalue(self) -> uvlr_t
        """
        return _ida_hexrays.valrng_t_max_svalue(self)

    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.valrng_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.valrng_t__deregister(self)

# Register valrng_t in _ida_hexrays:
_ida_hexrays.valrng_t_swigregister(valrng_t)
cvar = _ida_hexrays.cvar
MAX_VLR_VALUE = cvar.MAX_VLR_VALUE
MAX_VLR_SVALUE = cvar.MAX_VLR_SVALUE
MIN_VLR_SVALUE = cvar.MIN_VLR_SVALUE


def is_may_access(maymust: "maymust_t") -> "bool":
    r"""
    is_may_access(maymust) -> bool

    @param maymust: maymust_t
    """
    return _ida_hexrays.is_may_access(maymust)
MERR_OK = _ida_hexrays.MERR_OK
r"""
ok
"""

MERR_BLOCK = _ida_hexrays.MERR_BLOCK
r"""
no error, switch to new block
"""

MERR_INTERR = _ida_hexrays.MERR_INTERR
r"""
internal error
"""

MERR_INSN = _ida_hexrays.MERR_INSN
r"""
cannot convert to microcode
"""

MERR_MEM = _ida_hexrays.MERR_MEM
r"""
not enough memory
"""

MERR_BADBLK = _ida_hexrays.MERR_BADBLK
r"""
bad block found
"""

MERR_BADSP = _ida_hexrays.MERR_BADSP
r"""
positive sp value has been found
"""

MERR_PROLOG = _ida_hexrays.MERR_PROLOG
r"""
prolog analysis failed
"""

MERR_SWITCH = _ida_hexrays.MERR_SWITCH
r"""
wrong switch idiom
"""

MERR_EXCEPTION = _ida_hexrays.MERR_EXCEPTION
r"""
exception analysis failed
"""

MERR_HUGESTACK = _ida_hexrays.MERR_HUGESTACK
r"""
stack frame is too big
"""

MERR_LVARS = _ida_hexrays.MERR_LVARS
r"""
local variable allocation failed
"""

MERR_BITNESS = _ida_hexrays.MERR_BITNESS
r"""
16-bit functions cannot be decompiled
"""

MERR_BADCALL = _ida_hexrays.MERR_BADCALL
r"""
could not determine call arguments
"""

MERR_BADFRAME = _ida_hexrays.MERR_BADFRAME
r"""
function frame is wrong
"""

MERR_UNKTYPE = _ida_hexrays.MERR_UNKTYPE
r"""
undefined type s (currently unused error code)
"""

MERR_BADIDB = _ida_hexrays.MERR_BADIDB
r"""
inconsistent database information
"""

MERR_SIZEOF = _ida_hexrays.MERR_SIZEOF
r"""
wrong basic type sizes in compiler settings
"""

MERR_REDO = _ida_hexrays.MERR_REDO
r"""
redecompilation has been requested
"""

MERR_CANCELED = _ida_hexrays.MERR_CANCELED
r"""
decompilation has been cancelled
"""

MERR_RECDEPTH = _ida_hexrays.MERR_RECDEPTH
r"""
max recursion depth reached during lvar allocation
"""

MERR_OVERLAP = _ida_hexrays.MERR_OVERLAP
r"""
variables would overlap: s
"""

MERR_PARTINIT = _ida_hexrays.MERR_PARTINIT
r"""
partially initialized variable s
"""

MERR_COMPLEX = _ida_hexrays.MERR_COMPLEX
r"""
too complex function
"""

MERR_LICENSE = _ida_hexrays.MERR_LICENSE
r"""
no license available
"""

MERR_ONLY32 = _ida_hexrays.MERR_ONLY32
r"""
only 32-bit functions can be decompiled for the current database
"""

MERR_ONLY64 = _ida_hexrays.MERR_ONLY64
r"""
only 64-bit functions can be decompiled for the current database
"""

MERR_BUSY = _ida_hexrays.MERR_BUSY
r"""
already decompiling a function
"""

MERR_FARPTR = _ida_hexrays.MERR_FARPTR
r"""
far memory model is supported only for pc
"""

MERR_EXTERN = _ida_hexrays.MERR_EXTERN
r"""
special segments cannot be decompiled
"""

MERR_FUNCSIZE = _ida_hexrays.MERR_FUNCSIZE
r"""
too big function
"""

MERR_BADRANGES = _ida_hexrays.MERR_BADRANGES
r"""
bad input ranges
"""

MERR_BADARCH = _ida_hexrays.MERR_BADARCH
r"""
current architecture is not supported
"""

MERR_DSLOT = _ida_hexrays.MERR_DSLOT
r"""
bad instruction in the delay slot
"""

MERR_STOP = _ida_hexrays.MERR_STOP
r"""
no error, stop the analysis
"""

MERR_CLOUD = _ida_hexrays.MERR_CLOUD
r"""
cloud: s
"""

MERR_MAX_ERR = _ida_hexrays.MERR_MAX_ERR

MERR_LOOP = _ida_hexrays.MERR_LOOP
r"""
internal code: redo last loop (never reported)
"""


def get_merror_desc(code: "merror_t", mba: "mba_t") -> "qstring *":
    r"""
    get_merror_desc(code, mba) -> str
    Get textual description of an error code

    @param code: (C++: merror_t) Microcode error codes
    @param mba: (C++: mba_t *) the microcode array
    @return: the error address
    """
    return _ida_hexrays.get_merror_desc(code, mba)
m_nop = _ida_hexrays.m_nop

m_stx = _ida_hexrays.m_stx

m_ldx = _ida_hexrays.m_ldx

m_ldc = _ida_hexrays.m_ldc

m_mov = _ida_hexrays.m_mov

m_neg = _ida_hexrays.m_neg

m_lnot = _ida_hexrays.m_lnot

m_bnot = _ida_hexrays.m_bnot

m_xds = _ida_hexrays.m_xds

m_xdu = _ida_hexrays.m_xdu

m_low = _ida_hexrays.m_low

m_high = _ida_hexrays.m_high

m_add = _ida_hexrays.m_add

m_sub = _ida_hexrays.m_sub

m_mul = _ida_hexrays.m_mul

m_udiv = _ida_hexrays.m_udiv

m_sdiv = _ida_hexrays.m_sdiv

m_umod = _ida_hexrays.m_umod

m_smod = _ida_hexrays.m_smod

m_or = _ida_hexrays.m_or

m_and = _ida_hexrays.m_and

m_xor = _ida_hexrays.m_xor

m_shl = _ida_hexrays.m_shl

m_shr = _ida_hexrays.m_shr

m_sar = _ida_hexrays.m_sar

m_cfadd = _ida_hexrays.m_cfadd

m_ofadd = _ida_hexrays.m_ofadd

m_cfshl = _ida_hexrays.m_cfshl

m_cfshr = _ida_hexrays.m_cfshr

m_sets = _ida_hexrays.m_sets

m_seto = _ida_hexrays.m_seto

m_setp = _ida_hexrays.m_setp

m_setnz = _ida_hexrays.m_setnz

m_setz = _ida_hexrays.m_setz

m_setae = _ida_hexrays.m_setae

m_setb = _ida_hexrays.m_setb

m_seta = _ida_hexrays.m_seta

m_setbe = _ida_hexrays.m_setbe

m_setg = _ida_hexrays.m_setg

m_setge = _ida_hexrays.m_setge

m_setl = _ida_hexrays.m_setl

m_setle = _ida_hexrays.m_setle

m_jcnd = _ida_hexrays.m_jcnd

m_jnz = _ida_hexrays.m_jnz

m_jz = _ida_hexrays.m_jz

m_jae = _ida_hexrays.m_jae

m_jb = _ida_hexrays.m_jb

m_ja = _ida_hexrays.m_ja

m_jbe = _ida_hexrays.m_jbe

m_jg = _ida_hexrays.m_jg

m_jge = _ida_hexrays.m_jge

m_jl = _ida_hexrays.m_jl

m_jle = _ida_hexrays.m_jle

m_jtbl = _ida_hexrays.m_jtbl

m_ijmp = _ida_hexrays.m_ijmp

m_goto = _ida_hexrays.m_goto

m_call = _ida_hexrays.m_call

m_icall = _ida_hexrays.m_icall

m_ret = _ida_hexrays.m_ret

m_push = _ida_hexrays.m_push

m_pop = _ida_hexrays.m_pop

m_und = _ida_hexrays.m_und

m_ext = _ida_hexrays.m_ext

m_f2i = _ida_hexrays.m_f2i

m_f2u = _ida_hexrays.m_f2u

m_i2f = _ida_hexrays.m_i2f

m_u2f = _ida_hexrays.m_u2f

m_f2f = _ida_hexrays.m_f2f

m_fneg = _ida_hexrays.m_fneg

m_fadd = _ida_hexrays.m_fadd

m_fsub = _ida_hexrays.m_fsub

m_fmul = _ida_hexrays.m_fmul

m_fdiv = _ida_hexrays.m_fdiv


def must_mcode_close_block(mcode: "mcode_t", including_calls: "bool") -> "bool":
    r"""
    must_mcode_close_block(mcode, including_calls) -> bool
    Must an instruction with the given opcode be the last one in a block? Such
    opcodes are called closing opcodes.

    @param mcode: (C++: mcode_t) instruction opcode
    @param including_calls: (C++: bool) should m_call/m_icall be considered as the closing
                            opcodes? If this function returns true, the opcode
                            cannot appear in the middle of a block. Calls are a
                            special case: unknown calls (is_unknown_call) are
                            considered as closing opcodes.
    """
    return _ida_hexrays.must_mcode_close_block(mcode, including_calls)

def is_mcode_propagatable(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_propagatable(mcode) -> bool
    May opcode be propagated? Such opcodes can be used in sub-instructions (nested
    instructions) There is a handful of non-propagatable opcodes, like jumps, ret,
    nop, etc All other regular opcodes are propagatable and may appear in a nested
    instruction.

    @param mcode: (C++: mcode_t) enum mcode_t
    """
    return _ida_hexrays.is_mcode_propagatable(mcode)

def is_mcode_addsub(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_addsub(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_addsub(mcode)

def is_mcode_xdsu(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_xdsu(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_xdsu(mcode)

def is_mcode_set(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_set(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_set(mcode)

def is_mcode_set1(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_set1(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_set1(mcode)

def is_mcode_j1(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_j1(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_j1(mcode)

def is_mcode_jcond(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_jcond(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_jcond(mcode)

def is_mcode_convertible_to_jmp(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_convertible_to_jmp(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_convertible_to_jmp(mcode)

def is_mcode_convertible_to_set(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_convertible_to_set(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_convertible_to_set(mcode)

def is_mcode_call(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_call(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_call(mcode)

def is_mcode_fpu(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_fpu(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_fpu(mcode)

def is_mcode_commutative(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_commutative(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_commutative(mcode)

def is_mcode_shift(mcode: "mcode_t") -> "bool":
    r"""
    is_mcode_shift(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.is_mcode_shift(mcode)

def is_mcode_divmod(op: "mcode_t") -> "bool":
    r"""
    is_mcode_divmod(op) -> bool

    @param op: enum mcode_t
    """
    return _ida_hexrays.is_mcode_divmod(op)

def has_mcode_seloff(op: "mcode_t") -> "bool":
    r"""
    has_mcode_seloff(op) -> bool

    @param op: enum mcode_t
    """
    return _ida_hexrays.has_mcode_seloff(op)

def set2jcnd(code: "mcode_t") -> "mcode_t":
    r"""
    set2jcnd(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.set2jcnd(code)

def jcnd2set(code: "mcode_t") -> "mcode_t":
    r"""
    jcnd2set(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.jcnd2set(code)

def negate_mcode_relation(code: "mcode_t") -> "mcode_t":
    r"""
    negate_mcode_relation(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.negate_mcode_relation(code)

def swap_mcode_relation(code: "mcode_t") -> "mcode_t":
    r"""
    swap_mcode_relation(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.swap_mcode_relation(code)

def get_signed_mcode(code: "mcode_t") -> "mcode_t":
    r"""
    get_signed_mcode(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.get_signed_mcode(code)

def get_unsigned_mcode(code: "mcode_t") -> "mcode_t":
    r"""
    get_unsigned_mcode(code) -> mcode_t

    @param code: enum mcode_t
    """
    return _ida_hexrays.get_unsigned_mcode(code)

def is_signed_mcode(code: "mcode_t") -> "bool":
    r"""
    is_signed_mcode(code) -> bool

    @param code: enum mcode_t
    """
    return _ida_hexrays.is_signed_mcode(code)

def is_unsigned_mcode(code: "mcode_t") -> "bool":
    r"""
    is_unsigned_mcode(code) -> bool

    @param code: enum mcode_t
    """
    return _ida_hexrays.is_unsigned_mcode(code)

def mcode_modifies_d(mcode: "mcode_t") -> "bool":
    r"""
    mcode_modifies_d(mcode) -> bool

    @param mcode: enum mcode_t
    """
    return _ida_hexrays.mcode_modifies_d(mcode)
class operand_locator_t(object):
    r"""
    Proxy of C++ operand_locator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.operand_locator_t_ea_get, _ida_hexrays.operand_locator_t_ea_set, doc=r"""ea""")
    r"""
    address of the original processor instruction
    """
    opnum: "int" = property(_ida_hexrays.operand_locator_t_opnum_get, _ida_hexrays.operand_locator_t_opnum_set, doc=r"""opnum""")
    r"""
    operand number in the instruction
    """

    def __init__(self, _ea: "ea_t", _opnum: "int"):
        r"""
        __init__(self, _ea, _opnum) -> operand_locator_t

        @param _ea: ea_t
        @param _opnum: int
        """
        _ida_hexrays.operand_locator_t_swiginit(self, _ida_hexrays.new_operand_locator_t(_ea, _opnum))

    def __eq__(self, r: "operand_locator_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___eq__(self, r)

    def __ne__(self, r: "operand_locator_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___ne__(self, r)

    def __lt__(self, r: "operand_locator_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___lt__(self, r)

    def __gt__(self, r: "operand_locator_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___gt__(self, r)

    def __le__(self, r: "operand_locator_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___le__(self, r)

    def __ge__(self, r: "operand_locator_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t___ge__(self, r)

    def compare(self, r: "operand_locator_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: operand_locator_t const &
        """
        return _ida_hexrays.operand_locator_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_operand_locator_t

# Register operand_locator_t in _ida_hexrays:
_ida_hexrays.operand_locator_t_swigregister(operand_locator_t)
MUST_ACCESS = cvar.MUST_ACCESS
MAY_ACCESS = cvar.MAY_ACCESS
MAYMUST_ACCESS_MASK = cvar.MAYMUST_ACCESS_MASK
ONE_ACCESS_TYPE = cvar.ONE_ACCESS_TYPE
INCLUDE_SPOILED_REGS = cvar.INCLUDE_SPOILED_REGS
EXCLUDE_PASS_REGS = cvar.EXCLUDE_PASS_REGS
FULL_XDSU = cvar.FULL_XDSU
WITH_ASSERTS = cvar.WITH_ASSERTS
EXCLUDE_VOLATILE = cvar.EXCLUDE_VOLATILE
INCLUDE_UNUSED_SRC = cvar.INCLUDE_UNUSED_SRC
INCLUDE_DEAD_RETREGS = cvar.INCLUDE_DEAD_RETREGS
INCLUDE_RESTRICTED = cvar.INCLUDE_RESTRICTED
CALL_SPOILS_ONLY_ARGS = cvar.CALL_SPOILS_ONLY_ARGS
mr_none = cvar.mr_none
mr_cf = cvar.mr_cf
mr_zf = cvar.mr_zf
mr_sf = cvar.mr_sf
mr_of = cvar.mr_of
mr_pf = cvar.mr_pf
cc_count = cvar.cc_count
mr_cc = cvar.mr_cc
mr_first = cvar.mr_first

class number_format_t(object):
    r"""
    Proxy of C++ number_format_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    flags32: "flags_t" = property(_ida_hexrays.number_format_t_flags32_get, _ida_hexrays.number_format_t_flags32_set, doc=r"""flags32""")
    r"""
    low 32bit of flags (for compatibility)
    """
    opnum: "char" = property(_ida_hexrays.number_format_t_opnum_get, _ida_hexrays.number_format_t_opnum_set, doc=r"""opnum""")
    r"""
    operand number: 0..UA_MAXOP
    """
    props: "char" = property(_ida_hexrays.number_format_t_props_get, _ida_hexrays.number_format_t_props_set, doc=r"""props""")
    r"""
    properties: combination of NF_ bits (Number format property bits)
    """
    serial: "uchar" = property(_ida_hexrays.number_format_t_serial_get, _ida_hexrays.number_format_t_serial_set, doc=r"""serial""")
    r"""
    for enums: constant serial number
    """
    org_nbytes: "char" = property(_ida_hexrays.number_format_t_org_nbytes_get, _ida_hexrays.number_format_t_org_nbytes_set, doc=r"""org_nbytes""")
    r"""
    original number size in bytes
    """
    type_name: "qstring" = property(_ida_hexrays.number_format_t_type_name_get, _ida_hexrays.number_format_t_type_name_set, doc=r"""type_name""")
    r"""
    for stroffs: structure for offsetof()
    for enums: enum name
    """
    flags: "flags64_t" = property(_ida_hexrays.number_format_t_flags_get, _ida_hexrays.number_format_t_flags_set, doc=r"""flags""")
    r"""
    ida flags, which describe number radix, enum, etc
    """

    def __init__(self, _opnum: "int"=0):
        r"""
        __init__(self, _opnum=0) -> number_format_t

        @param _opnum: int
        """
        _ida_hexrays.number_format_t_swiginit(self, _ida_hexrays.new_number_format_t(_opnum))

    def get_radix(self) -> "int":
        r"""
        get_radix(self) -> int
        Get number radix

        @return: 2,8,10, or 16
        """
        return _ida_hexrays.number_format_t_get_radix(self)

    def is_fixed(self) -> "bool":
        r"""
        is_fixed(self) -> bool
        Is number representation fixed? Fixed representation cannot be modified by the
        decompiler
        """
        return _ida_hexrays.number_format_t_is_fixed(self)

    def is_hex(self) -> "bool":
        r"""
        is_hex(self) -> bool
        Is a hexadecimal number?
        """
        return _ida_hexrays.number_format_t_is_hex(self)

    def is_dec(self) -> "bool":
        r"""
        is_dec(self) -> bool
        Is a decimal number?
        """
        return _ida_hexrays.number_format_t_is_dec(self)

    def is_oct(self) -> "bool":
        r"""
        is_oct(self) -> bool
        Is a octal number?
        """
        return _ida_hexrays.number_format_t_is_oct(self)

    def is_enum(self) -> "bool":
        r"""
        is_enum(self) -> bool
        Is a symbolic constant?
        """
        return _ida_hexrays.number_format_t_is_enum(self)

    def is_char(self) -> "bool":
        r"""
        is_char(self) -> bool
        Is a character constant?
        """
        return _ida_hexrays.number_format_t_is_char(self)

    def is_stroff(self) -> "bool":
        r"""
        is_stroff(self) -> bool
        Is a structure field offset?
        """
        return _ida_hexrays.number_format_t_is_stroff(self)

    def is_numop(self) -> "bool":
        r"""
        is_numop(self) -> bool
        Is a number?
        """
        return _ida_hexrays.number_format_t_is_numop(self)

    def needs_to_be_inverted(self) -> "bool":
        r"""
        needs_to_be_inverted(self) -> bool
        Does the number need to be negated or bitwise negated? Returns true if the user
        requested a negation but it is not done yet
        """
        return _ida_hexrays.number_format_t_needs_to_be_inverted(self)

    def has_unmutable_type(self) -> "bool":
        r"""
        has_unmutable_type(self) -> bool
        """
        return _ida_hexrays.number_format_t_has_unmutable_type(self)
    __swig_destroy__ = _ida_hexrays.delete_number_format_t

# Register number_format_t in _ida_hexrays:
_ida_hexrays.number_format_t_swigregister(number_format_t)
NF_FIXED = _ida_hexrays.NF_FIXED
r"""
number format has been defined by the user
"""

NF_NEGDONE = _ida_hexrays.NF_NEGDONE
r"""
temporary internal bit: negation has been performed
"""

NF_BINVDONE = _ida_hexrays.NF_BINVDONE
r"""
temporary internal bit: inverting bits is done
"""

NF_NEGATE = _ida_hexrays.NF_NEGATE
r"""
The user asked to negate the constant.
"""

NF_BITNOT = _ida_hexrays.NF_BITNOT
r"""
The user asked to invert bits of the constant.
"""

NF_VALID = _ida_hexrays.NF_VALID
r"""
internal bit: stroff or enum is valid for enums: this bit is set immediately for
stroffs: this bit is set at the end of decompilation
"""


class vd_printer_t(object):
    r"""
    Proxy of C++ vd_printer_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    tmpbuf: "qstring" = property(_ida_hexrays.vd_printer_t_tmpbuf_get, _ida_hexrays.vd_printer_t_tmpbuf_set, doc=r"""tmpbuf""")
    hdrlines: "int" = property(_ida_hexrays.vd_printer_t_hdrlines_get, _ida_hexrays.vd_printer_t_hdrlines_set, doc=r"""hdrlines""")
    r"""
    number of header lines (prototype+typedef+lvars) valid at the end of print
    process
    """

    def _print(self, indent: "int", format: "char const *") -> "int":
        r"""
        _print(self, indent, format) -> int

        Parameters
        ----------
        indent: int
        format: char const *

        """
        return _ida_hexrays.vd_printer_t__print(self, indent, format)

    def __init__(self):
        r"""
        __init__(self) -> vd_printer_t

        @param self: PyObject *
        """
        if self.__class__ == vd_printer_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.vd_printer_t_swiginit(self, _ida_hexrays.new_vd_printer_t(_self, ))
    __swig_destroy__ = _ida_hexrays.delete_vd_printer_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_vd_printer_t(self)
        return weakref.proxy(self)

# Register vd_printer_t in _ida_hexrays:
_ida_hexrays.vd_printer_t_swigregister(vd_printer_t)
class vc_printer_t(vd_printer_t):
    r"""
    Proxy of C++ vc_printer_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    func: "cfunc_t const *" = property(_ida_hexrays.vc_printer_t_func_get, _ida_hexrays.vc_printer_t_func_set, doc=r"""func""")
    r"""
    cfunc_t to generate text for
    """
    lastchar: "char" = property(_ida_hexrays.vc_printer_t_lastchar_get, _ida_hexrays.vc_printer_t_lastchar_set, doc=r"""lastchar""")
    r"""
    internal: last printed character
    """

    def __init__(self, f: "cfunc_t"):
        r"""
        __init__(self, f) -> vc_printer_t

        @param f: cfunc_t const *
        """
        if self.__class__ == vc_printer_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.vc_printer_t_swiginit(self, _ida_hexrays.new_vc_printer_t(_self, f))

    def oneliner(self) -> "bool":
        r"""
        oneliner(self) -> bool
        Are we generating one-line text representation?

        @return: true if the output will occupy one line without line breaks
        """
        return _ida_hexrays.vc_printer_t_oneliner(self)
    __swig_destroy__ = _ida_hexrays.delete_vc_printer_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_vc_printer_t(self)
        return weakref.proxy(self)

# Register vc_printer_t in _ida_hexrays:
_ida_hexrays.vc_printer_t_swigregister(vc_printer_t)
class qstring_printer_t(vc_printer_t):
    r"""
    Proxy of C++ qstring_printer_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    with_tags: "bool" = property(_ida_hexrays.qstring_printer_t_with_tags_get, _ida_hexrays.qstring_printer_t_with_tags_set, doc=r"""with_tags""")
    r"""
    Generate output with color tags.
    """
    s: "qstring &" = property(_ida_hexrays.qstring_printer_t_s_get, _ida_hexrays.qstring_printer_t_s_set, doc=r"""s""")
    r"""
    Reference to the output string
    """

    def _print(self, indent: "int", format: "char const *") -> "int":
        r"""
        _print(self, indent, format) -> int

        Parameters
        ----------
        indent: int
        format: char const *

        """
        return _ida_hexrays.qstring_printer_t__print(self, indent, format)

    def __init__(self, f: "cfunc_t", tags: "bool"):
        r"""
        __init__(self, f, tags) -> qstring_printer_t

        @param f: cfunc_t const *
        @param tags: bool
        """
        _ida_hexrays.qstring_printer_t_swiginit(self, _ida_hexrays.new_qstring_printer_t(f, tags))

    def get_s(self) -> "qstring":
        r"""
        get_s(self) -> qstring
        """
        return _ida_hexrays.qstring_printer_t_get_s(self)

    s = property(lambda self: self.get_s())


# Register qstring_printer_t in _ida_hexrays:
_ida_hexrays.qstring_printer_t_swigregister(qstring_printer_t)

def dstr(tif: "tinfo_t") -> "char const *":
    r"""
    dstr(tif) -> char const *
    Print the specified type info. This function can be used from a debugger by
    typing "tif->dstr()"

    @param tif: (C++: const tinfo_t *) tinfo_t const *
    """
    return _ida_hexrays.dstr(tif)

def is_type_correct(ptr: "type_t const *") -> "bool":
    r"""
    is_type_correct(ptr) -> bool
    Verify a type string.

    @param ptr: (C++: const type_t *) type_t const *
    @return: true if type string is correct
    """
    return _ida_hexrays.is_type_correct(ptr)

def is_small_udt(tif: "tinfo_t") -> "bool":
    r"""
    is_small_udt(tif) -> bool
    Is a small structure or union?

    @param tif: (C++: const tinfo_t &) tinfo_t const &
    @return: true if the type is a small UDT (user defined type). Small UDTs fit
             into a register (or pair or registers) as a rule.
    """
    return _ida_hexrays.is_small_udt(tif)

def is_nonbool_type(type: "tinfo_t") -> "bool":
    r"""
    is_nonbool_type(type) -> bool
    Is definitely a non-boolean type?

    @param type: (C++: const tinfo_t &) tinfo_t const &
    @return: true if the type is a non-boolean type (non bool and well defined)
    """
    return _ida_hexrays.is_nonbool_type(type)

def is_bool_type(type: "tinfo_t") -> "bool":
    r"""
    is_bool_type(type) -> bool
    Is a boolean type?

    @param type: (C++: const tinfo_t &) tinfo_t const &
    @return: true if the type is a boolean type
    """
    return _ida_hexrays.is_bool_type(type)

def is_ptr_or_array(t: "type_t") -> "bool":
    r"""
    is_ptr_or_array(t) -> bool
    Is a pointer or array type?

    @param t: (C++: type_t)
    """
    return _ida_hexrays.is_ptr_or_array(t)

def is_paf(t: "type_t") -> "bool":
    r"""
    is_paf(t) -> bool
    Is a pointer, array, or function type?

    @param t: (C++: type_t)
    """
    return _ida_hexrays.is_paf(t)

def is_inplace_def(type: "tinfo_t") -> "bool":
    r"""
    is_inplace_def(type) -> bool
    Is struct/union/enum definition (not declaration)?

    @param type: (C++: const tinfo_t &) tinfo_t const &
    """
    return _ida_hexrays.is_inplace_def(type)

def partial_type_num(type: "tinfo_t") -> "int":
    r"""
    partial_type_num(type) -> int
    Calculate number of partial subtypes.

    @param type: (C++: const tinfo_t &) tinfo_t const &
    @return: number of partial subtypes. The bigger is this number, the uglier is
             the type.
    """
    return _ida_hexrays.partial_type_num(type)

def get_float_type(width: "int") -> "tinfo_t":
    r"""
    get_float_type(width) -> tinfo_t
    Get a type of a floating point value with the specified width

    @param width: (C++: int) width of the desired type
    @return: type info object
    """
    return _ida_hexrays.get_float_type(width)

def get_int_type_by_width_and_sign(srcwidth: "int", sign: "type_sign_t") -> "tinfo_t":
    r"""
    get_int_type_by_width_and_sign(srcwidth, sign) -> tinfo_t
    Create a type info by width and sign. Returns a simple type (examples: int,
    short) with the given width and sign.

    @param srcwidth: (C++: int) size of the type in bytes
    @param sign: (C++: type_sign_t) sign of the type
    """
    return _ida_hexrays.get_int_type_by_width_and_sign(srcwidth, sign)

def get_unk_type(size: "int") -> "tinfo_t":
    r"""
    get_unk_type(size) -> tinfo_t
    Create a partial type info by width. Returns a partially defined type (examples:
    _DWORD, _BYTE) with the given width.

    @param size: (C++: int) size of the type in bytes
    """
    return _ida_hexrays.get_unk_type(size)

def dummy_ptrtype(ptrsize: "int", isfp: "bool") -> "tinfo_t":
    r"""
    dummy_ptrtype(ptrsize, isfp) -> tinfo_t
    Generate a dummy pointer type

    @param ptrsize: (C++: int) size of pointed object
    @param isfp: (C++: bool) is floating point object?
    """
    return _ida_hexrays.dummy_ptrtype(ptrsize, isfp)

def make_pointer(type: "tinfo_t") -> "tinfo_t":
    r"""
    make_pointer(type) -> tinfo_t
    Create a pointer type. This function performs the following conversion: "type"
    -> "type*"

    @param type: (C++: const tinfo_t &) object type.
    @return: "type*". for example, if 'char' is passed as the argument,
    """
    return _ida_hexrays.make_pointer(type)

def create_typedef(*args) -> "tinfo_t":
    r"""
    create_typedef(name) -> tinfo_t
    Create a reference to an ordinal type.

    @param name: char const *

    @return: type which refers to the specified ordinal. For example, if n is 1, the
             type info which refers to ordinal type 1 is created.
    create_typedef(n) -> tinfo_t

    @param n: int
    """
    return _ida_hexrays.create_typedef(*args)
GUESSED_NONE = _ida_hexrays.GUESSED_NONE

GUESSED_WEAK = _ida_hexrays.GUESSED_WEAK

GUESSED_FUNC = _ida_hexrays.GUESSED_FUNC

GUESSED_DATA = _ida_hexrays.GUESSED_DATA

TS_NOELL = _ida_hexrays.TS_NOELL

TS_SHRINK = _ida_hexrays.TS_SHRINK

TS_DONTREF = _ida_hexrays.TS_DONTREF

TS_MASK = _ida_hexrays.TS_MASK


def get_type(id: "uval_t", tif: "tinfo_t", guess: "type_source_t") -> "bool":
    r"""
    get_type(id, tif, guess) -> bool
    Get a global type. Global types are types of addressable objects and
    struct/union/enum types

    @param id: (C++: uval_t) address or id of the object
    @param tif: (C++: tinfo_t *) buffer for the answer
    @param guess: (C++: type_source_t) what kind of types to consider
    @return: success
    """
    return _ida_hexrays.get_type(id, tif, guess)

def set_type(id: "uval_t", tif: "tinfo_t", source: "type_source_t", force: "bool"=False) -> "bool":
    r"""
    set_type(id, tif, source, force=False) -> bool
    Set a global type.

    @param id: (C++: uval_t) address or id of the object
    @param tif: (C++: const tinfo_t &) new type info
    @param source: (C++: type_source_t) where the type comes from
    @param force: (C++: bool) true means to set the type as is, false means to merge the new
                  type with the possibly existing old type info.
    @return: success
    """
    return _ida_hexrays.set_type(id, tif, source, force)
class vdloc_t(ida_typeinf.argloc_t):
    r"""
    Proxy of C++ vdloc_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def reg1(self) -> "int":
        r"""
        reg1(self) -> int
        """
        return _ida_hexrays.vdloc_t_reg1(self)

    def _set_reg1(self, r1: "int") -> "void":
        r"""
        _set_reg1(self, r1)

        Parameters
        ----------
        r1: int

        """
        return _ida_hexrays.vdloc_t__set_reg1(self, r1)

    def set_reg1(self, r1: "int") -> "void":
        r"""
        set_reg1(self, r1)

        @param r1: int
        """
        return _ida_hexrays.vdloc_t_set_reg1(self, r1)

    def __eq__(self, r: "vdloc_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___eq__(self, r)

    def __ne__(self, r: "vdloc_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___ne__(self, r)

    def __lt__(self, r: "vdloc_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___lt__(self, r)

    def __gt__(self, r: "vdloc_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___gt__(self, r)

    def __le__(self, r: "vdloc_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___le__(self, r)

    def __ge__(self, r: "vdloc_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t___ge__(self, r)

    def compare(self, r: "vdloc_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: vdloc_t const &
        """
        return _ida_hexrays.vdloc_t_compare(self, r)

    def is_aliasable(self, mb: "mba_t", size: "int") -> "bool":
        r"""
        is_aliasable(self, mb, size) -> bool

        @param mb: mba_t const *
        @param size: int
        """
        return _ida_hexrays.vdloc_t_is_aliasable(self, mb, size)

    def __init__(self):
        r"""
        __init__(self) -> vdloc_t
        """
        _ida_hexrays.vdloc_t_swiginit(self, _ida_hexrays.new_vdloc_t())
    __swig_destroy__ = _ida_hexrays.delete_vdloc_t

# Register vdloc_t in _ida_hexrays:
_ida_hexrays.vdloc_t_swigregister(vdloc_t)

def print_vdloc(loc: "vdloc_t", nbytes: "int") -> "qstring *":
    r"""
    print_vdloc(loc, nbytes) -> str
    Print vdloc. Since vdloc does not always carry the size info, we pass it as
    NBYTES..

    @param loc: (C++: const vdloc_t &) vdloc_t const &
    @param nbytes: (C++: int)
    """
    return _ida_hexrays.print_vdloc(loc, nbytes)

def arglocs_overlap(loc1: "vdloc_t", w1: "size_t", loc2: "vdloc_t", w2: "size_t") -> "bool":
    r"""
    arglocs_overlap(loc1, w1, loc2, w2) -> bool
    Do two arglocs overlap?

    @param loc1: (C++: const vdloc_t &) vdloc_t const &
    @param w1: (C++: size_t)
    @param loc2: (C++: const vdloc_t &) vdloc_t const &
    @param w2: (C++: size_t)
    """
    return _ida_hexrays.arglocs_overlap(loc1, w1, loc2, w2)
class lvar_locator_t(object):
    r"""
    Proxy of C++ lvar_locator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    location: "vdloc_t" = property(_ida_hexrays.lvar_locator_t_location_get, _ida_hexrays.lvar_locator_t_location_set, doc=r"""location""")
    r"""
    Variable location.
    """
    defea: "ea_t" = property(_ida_hexrays.lvar_locator_t_defea_get, _ida_hexrays.lvar_locator_t_defea_set, doc=r"""defea""")
    r"""
    Definition address. Usually, this is the address of the instruction that
    initializes the variable. In some cases it can be a fictional address.
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> lvar_locator_t
        __init__(self, loc, ea) -> lvar_locator_t

        @param loc: vdloc_t const &
        @param ea: ea_t
        """
        _ida_hexrays.lvar_locator_t_swiginit(self, _ida_hexrays.new_lvar_locator_t(*args))

    def get_stkoff(self) -> "sval_t":
        r"""
        get_stkoff(self) -> sval_t
        Get offset of the varialbe in the stack frame.

        @return: a non-negative value for stack variables. The value is an offset from
                 the bottom of the stack frame in terms of vd-offsets. negative values
                 mean error (not a stack variable)
        """
        return _ida_hexrays.lvar_locator_t_get_stkoff(self)

    def is_reg1(self) -> "bool":
        r"""
        is_reg1(self) -> bool
        Is variable located on one register?
        """
        return _ida_hexrays.lvar_locator_t_is_reg1(self)

    def is_reg2(self) -> "bool":
        r"""
        is_reg2(self) -> bool
        Is variable located on two registers?
        """
        return _ida_hexrays.lvar_locator_t_is_reg2(self)

    def is_reg_var(self) -> "bool":
        r"""
        is_reg_var(self) -> bool
        Is variable located on register(s)?
        """
        return _ida_hexrays.lvar_locator_t_is_reg_var(self)

    def is_stk_var(self) -> "bool":
        r"""
        is_stk_var(self) -> bool
        Is variable located on the stack?
        """
        return _ida_hexrays.lvar_locator_t_is_stk_var(self)

    def is_scattered(self) -> "bool":
        r"""
        is_scattered(self) -> bool
        Is variable scattered?
        """
        return _ida_hexrays.lvar_locator_t_is_scattered(self)

    def get_reg1(self) -> "mreg_t":
        r"""
        get_reg1(self) -> mreg_t
        Get the register number of the variable.
        """
        return _ida_hexrays.lvar_locator_t_get_reg1(self)

    def get_reg2(self) -> "mreg_t":
        r"""
        get_reg2(self) -> mreg_t
        Get the number of the second register (works only for ALOC_REG2 lvars)
        """
        return _ida_hexrays.lvar_locator_t_get_reg2(self)

    def get_scattered(self, *args) -> "scattered_aloc_t &":
        r"""
        get_scattered(self) -> scattered_aloc_t
        """
        return _ida_hexrays.lvar_locator_t_get_scattered(self, *args)

    def __eq__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___eq__(self, r)

    def __ne__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___ne__(self, r)

    def __lt__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___lt__(self, r)

    def __gt__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___gt__(self, r)

    def __le__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___le__(self, r)

    def __ge__(self, r: "lvar_locator_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t___ge__(self, r)

    def compare(self, r: "lvar_locator_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: lvar_locator_t const &
        """
        return _ida_hexrays.lvar_locator_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_lvar_locator_t

# Register lvar_locator_t in _ida_hexrays:
_ida_hexrays.lvar_locator_t_swigregister(lvar_locator_t)
class lvar_t(lvar_locator_t):
    r"""
    Proxy of C++ lvar_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_hexrays.lvar_t_name_get, _ida_hexrays.lvar_t_name_set, doc=r"""name""")
    r"""
    variable name. use mba_t::set_nice_lvar_name() and mba_t::set_user_lvar_name()
    to modify it
    """
    cmt: "qstring" = property(_ida_hexrays.lvar_t_cmt_get, _ida_hexrays.lvar_t_cmt_set, doc=r"""cmt""")
    r"""
    variable comment string
    """
    tif: "tinfo_t" = property(_ida_hexrays.lvar_t_tif_get, _ida_hexrays.lvar_t_tif_set, doc=r"""tif""")
    r"""
    variable type
    """
    width: "int" = property(_ida_hexrays.lvar_t_width_get, _ida_hexrays.lvar_t_width_set, doc=r"""width""")
    r"""
    variable size in bytes
    """
    defblk: "int" = property(_ida_hexrays.lvar_t_defblk_get, _ida_hexrays.lvar_t_defblk_set, doc=r"""defblk""")
    r"""
    first block defining the variable. 0 for args, -1 if unknown
    """
    divisor: "uint64" = property(_ida_hexrays.lvar_t_divisor_get, _ida_hexrays.lvar_t_divisor_set, doc=r"""divisor""")
    r"""
    max known divisor of the variable
    """

    def used(self) -> "bool":
        r"""
        used(self) -> bool
        Is the variable used in the code?
        """
        return _ida_hexrays.lvar_t_used(self)

    def typed(self) -> "bool":
        r"""
        typed(self) -> bool
        Has the variable a type?
        """
        return _ida_hexrays.lvar_t_typed(self)

    def mreg_done(self) -> "bool":
        r"""
        mreg_done(self) -> bool
        Have corresponding microregs been replaced by references to this variable?
        """
        return _ida_hexrays.lvar_t_mreg_done(self)

    def has_nice_name(self) -> "bool":
        r"""
        has_nice_name(self) -> bool
        Does the variable have a nice name?
        """
        return _ida_hexrays.lvar_t_has_nice_name(self)

    def is_unknown_width(self) -> "bool":
        r"""
        is_unknown_width(self) -> bool
        Do we know the width of the variable?
        """
        return _ida_hexrays.lvar_t_is_unknown_width(self)

    def has_user_info(self) -> "bool":
        r"""
        has_user_info(self) -> bool
        Has any user-defined information?
        """
        return _ida_hexrays.lvar_t_has_user_info(self)

    def has_user_name(self) -> "bool":
        r"""
        has_user_name(self) -> bool
        Has user-defined name?
        """
        return _ida_hexrays.lvar_t_has_user_name(self)

    def has_user_type(self) -> "bool":
        r"""
        has_user_type(self) -> bool
        Has user-defined type?
        """
        return _ida_hexrays.lvar_t_has_user_type(self)

    def is_result_var(self) -> "bool":
        r"""
        is_result_var(self) -> bool
        Is the function result?
        """
        return _ida_hexrays.lvar_t_is_result_var(self)

    def is_arg_var(self) -> "bool":
        r"""
        is_arg_var(self) -> bool
        Is the function argument?
        """
        return _ida_hexrays.lvar_t_is_arg_var(self)

    def is_fake_var(self) -> "bool":
        r"""
        is_fake_var(self) -> bool
        Is fake return variable?
        """
        return _ida_hexrays.lvar_t_is_fake_var(self)

    def is_overlapped_var(self) -> "bool":
        r"""
        is_overlapped_var(self) -> bool
        Is overlapped variable?
        """
        return _ida_hexrays.lvar_t_is_overlapped_var(self)

    def is_floating_var(self) -> "bool":
        r"""
        is_floating_var(self) -> bool
        Used by a fpu insn?
        """
        return _ida_hexrays.lvar_t_is_floating_var(self)

    def is_spoiled_var(self) -> "bool":
        r"""
        is_spoiled_var(self) -> bool
        Is spoiled var? (meaningful only during lvar allocation)
        """
        return _ida_hexrays.lvar_t_is_spoiled_var(self)

    def is_noptr_var(self) -> "bool":
        r"""
        is_noptr_var(self) -> bool
        Variable type should not be a pointer.
        """
        return _ida_hexrays.lvar_t_is_noptr_var(self)

    def is_mapdst_var(self) -> "bool":
        r"""
        is_mapdst_var(self) -> bool
        Other variable(s) map to this var?
        """
        return _ida_hexrays.lvar_t_is_mapdst_var(self)

    def is_thisarg(self) -> "bool":
        r"""
        is_thisarg(self) -> bool
        Is 'this' argument of a C++ member function?
        """
        return _ida_hexrays.lvar_t_is_thisarg(self)

    def is_split_var(self) -> "bool":
        r"""
        is_split_var(self) -> bool
        Is a split variable?
        """
        return _ida_hexrays.lvar_t_is_split_var(self)

    def has_regname(self) -> "bool":
        r"""
        has_regname(self) -> bool
        Has a register name? (like _RAX)
        """
        return _ida_hexrays.lvar_t_has_regname(self)

    def in_asm(self) -> "bool":
        r"""
        in_asm(self) -> bool
        Is variable used in an instruction translated into __asm?
        """
        return _ida_hexrays.lvar_t_in_asm(self)

    def is_dummy_arg(self) -> "bool":
        r"""
        is_dummy_arg(self) -> bool
        Is a dummy argument (added to fill a hole in the argument list)
        """
        return _ida_hexrays.lvar_t_is_dummy_arg(self)

    def is_notarg(self) -> "bool":
        r"""
        is_notarg(self) -> bool
        Is a local variable? (local variable cannot be an input argument)
        """
        return _ida_hexrays.lvar_t_is_notarg(self)

    def is_automapped(self) -> "bool":
        r"""
        is_automapped(self) -> bool
        Was the variable automatically mapped to another variable?
        """
        return _ida_hexrays.lvar_t_is_automapped(self)

    def is_used_byref(self) -> "bool":
        r"""
        is_used_byref(self) -> bool
        Was the address of the variable taken?
        """
        return _ida_hexrays.lvar_t_is_used_byref(self)

    def is_decl_unused(self) -> "bool":
        r"""
        is_decl_unused(self) -> bool
        Was declared as __unused by the user? See CVAR_UNUSED.
        """
        return _ida_hexrays.lvar_t_is_decl_unused(self)

    def is_shared(self) -> "bool":
        r"""
        is_shared(self) -> bool
        Is lvar mapped to several chains.
        """
        return _ida_hexrays.lvar_t_is_shared(self)

    def was_scattered_arg(self) -> "bool":
        r"""
        was_scattered_arg(self) -> bool
        Was lvar transformed from a scattered argument?
        """
        return _ida_hexrays.lvar_t_was_scattered_arg(self)

    def set_used(self) -> "void":
        r"""
        set_used(self)
        """
        return _ida_hexrays.lvar_t_set_used(self)

    def clear_used(self) -> "void":
        r"""
        clear_used(self)
        """
        return _ida_hexrays.lvar_t_clear_used(self)

    def set_typed(self) -> "void":
        r"""
        set_typed(self)
        """
        return _ida_hexrays.lvar_t_set_typed(self)

    def set_non_typed(self) -> "void":
        r"""
        set_non_typed(self)
        """
        return _ida_hexrays.lvar_t_set_non_typed(self)

    def clr_user_info(self) -> "void":
        r"""
        clr_user_info(self)
        """
        return _ida_hexrays.lvar_t_clr_user_info(self)

    def set_user_name(self) -> "void":
        r"""
        set_user_name(self)
        """
        return _ida_hexrays.lvar_t_set_user_name(self)

    def set_user_type(self) -> "void":
        r"""
        set_user_type(self)
        """
        return _ida_hexrays.lvar_t_set_user_type(self)

    def clr_user_type(self) -> "void":
        r"""
        clr_user_type(self)
        """
        return _ida_hexrays.lvar_t_clr_user_type(self)

    def clr_user_name(self) -> "void":
        r"""
        clr_user_name(self)
        """
        return _ida_hexrays.lvar_t_clr_user_name(self)

    def set_mreg_done(self) -> "void":
        r"""
        set_mreg_done(self)
        """
        return _ida_hexrays.lvar_t_set_mreg_done(self)

    def clr_mreg_done(self) -> "void":
        r"""
        clr_mreg_done(self)
        """
        return _ida_hexrays.lvar_t_clr_mreg_done(self)

    def set_unknown_width(self) -> "void":
        r"""
        set_unknown_width(self)
        """
        return _ida_hexrays.lvar_t_set_unknown_width(self)

    def clr_unknown_width(self) -> "void":
        r"""
        clr_unknown_width(self)
        """
        return _ida_hexrays.lvar_t_clr_unknown_width(self)

    def set_arg_var(self) -> "void":
        r"""
        set_arg_var(self)
        """
        return _ida_hexrays.lvar_t_set_arg_var(self)

    def clr_arg_var(self) -> "void":
        r"""
        clr_arg_var(self)
        """
        return _ida_hexrays.lvar_t_clr_arg_var(self)

    def set_fake_var(self) -> "void":
        r"""
        set_fake_var(self)
        """
        return _ida_hexrays.lvar_t_set_fake_var(self)

    def clr_fake_var(self) -> "void":
        r"""
        clr_fake_var(self)
        """
        return _ida_hexrays.lvar_t_clr_fake_var(self)

    def set_overlapped_var(self) -> "void":
        r"""
        set_overlapped_var(self)
        """
        return _ida_hexrays.lvar_t_set_overlapped_var(self)

    def clr_overlapped_var(self) -> "void":
        r"""
        clr_overlapped_var(self)
        """
        return _ida_hexrays.lvar_t_clr_overlapped_var(self)

    def set_floating_var(self) -> "void":
        r"""
        set_floating_var(self)
        """
        return _ida_hexrays.lvar_t_set_floating_var(self)

    def clr_floating_var(self) -> "void":
        r"""
        clr_floating_var(self)
        """
        return _ida_hexrays.lvar_t_clr_floating_var(self)

    def set_spoiled_var(self) -> "void":
        r"""
        set_spoiled_var(self)
        """
        return _ida_hexrays.lvar_t_set_spoiled_var(self)

    def clr_spoiled_var(self) -> "void":
        r"""
        clr_spoiled_var(self)
        """
        return _ida_hexrays.lvar_t_clr_spoiled_var(self)

    def set_mapdst_var(self) -> "void":
        r"""
        set_mapdst_var(self)
        """
        return _ida_hexrays.lvar_t_set_mapdst_var(self)

    def clr_mapdst_var(self) -> "void":
        r"""
        clr_mapdst_var(self)
        """
        return _ida_hexrays.lvar_t_clr_mapdst_var(self)

    def set_noptr_var(self) -> "void":
        r"""
        set_noptr_var(self)
        """
        return _ida_hexrays.lvar_t_set_noptr_var(self)

    def clr_noptr_var(self) -> "void":
        r"""
        clr_noptr_var(self)
        """
        return _ida_hexrays.lvar_t_clr_noptr_var(self)

    def set_thisarg(self) -> "void":
        r"""
        set_thisarg(self)
        """
        return _ida_hexrays.lvar_t_set_thisarg(self)

    def clr_thisarg(self) -> "void":
        r"""
        clr_thisarg(self)
        """
        return _ida_hexrays.lvar_t_clr_thisarg(self)

    def set_split_var(self) -> "void":
        r"""
        set_split_var(self)
        """
        return _ida_hexrays.lvar_t_set_split_var(self)

    def clr_split_var(self) -> "void":
        r"""
        clr_split_var(self)
        """
        return _ida_hexrays.lvar_t_clr_split_var(self)

    def set_dummy_arg(self) -> "void":
        r"""
        set_dummy_arg(self)
        """
        return _ida_hexrays.lvar_t_set_dummy_arg(self)

    def clr_dummy_arg(self) -> "void":
        r"""
        clr_dummy_arg(self)
        """
        return _ida_hexrays.lvar_t_clr_dummy_arg(self)

    def set_notarg(self) -> "void":
        r"""
        set_notarg(self)
        """
        return _ida_hexrays.lvar_t_set_notarg(self)

    def clr_notarg(self) -> "void":
        r"""
        clr_notarg(self)
        """
        return _ida_hexrays.lvar_t_clr_notarg(self)

    def set_automapped(self) -> "void":
        r"""
        set_automapped(self)
        """
        return _ida_hexrays.lvar_t_set_automapped(self)

    def clr_automapped(self) -> "void":
        r"""
        clr_automapped(self)
        """
        return _ida_hexrays.lvar_t_clr_automapped(self)

    def set_used_byref(self) -> "void":
        r"""
        set_used_byref(self)
        """
        return _ida_hexrays.lvar_t_set_used_byref(self)

    def clr_used_byref(self) -> "void":
        r"""
        clr_used_byref(self)
        """
        return _ida_hexrays.lvar_t_clr_used_byref(self)

    def set_decl_unused(self) -> "void":
        r"""
        set_decl_unused(self)
        """
        return _ida_hexrays.lvar_t_set_decl_unused(self)

    def clr_decl_unused(self) -> "void":
        r"""
        clr_decl_unused(self)
        """
        return _ida_hexrays.lvar_t_clr_decl_unused(self)

    def set_shared(self) -> "void":
        r"""
        set_shared(self)
        """
        return _ida_hexrays.lvar_t_set_shared(self)

    def clr_shared(self) -> "void":
        r"""
        clr_shared(self)
        """
        return _ida_hexrays.lvar_t_clr_shared(self)

    def set_scattered_arg(self) -> "void":
        r"""
        set_scattered_arg(self)
        """
        return _ida_hexrays.lvar_t_set_scattered_arg(self)

    def clr_scattered_arg(self) -> "void":
        r"""
        clr_scattered_arg(self)
        """
        return _ida_hexrays.lvar_t_clr_scattered_arg(self)

    def has_common(self, v: "lvar_t") -> "bool":
        r"""
        has_common(self, v) -> bool
        Do variables overlap?

        @param v: (C++: const lvar_t &) lvar_t const &
        """
        return _ida_hexrays.lvar_t_has_common(self, v)

    def has_common_bit(self, loc: "vdloc_t", width2: "asize_t") -> "bool":
        r"""
        has_common_bit(self, loc, width2) -> bool
        Does the variable overlap with the specified location?

        @param loc: (C++: const vdloc_t &) vdloc_t const &
        @param width2: (C++: asize_t)
        """
        return _ida_hexrays.lvar_t_has_common_bit(self, loc, width2)

    def type(self, *args) -> "tinfo_t &":
        r"""
        type(self) -> tinfo_t
        """
        return _ida_hexrays.lvar_t_type(self, *args)

    def accepts_type(self, t: "tinfo_t", may_change_thisarg: "bool"=False) -> "bool":
        r"""
        accepts_type(self, t, may_change_thisarg=False) -> bool
        Check if the variable accept the specified type. Some types are forbidden (void,
        function types, wrong arrays, etc)

        @param t: (C++: const tinfo_t &) tinfo_t const &
        @param may_change_thisarg: (C++: bool)
        """
        return _ida_hexrays.lvar_t_accepts_type(self, t, may_change_thisarg)

    def set_lvar_type(self, t: "tinfo_t", may_fail: "bool"=False) -> "bool":
        r"""
        set_lvar_type(self, t, may_fail=False) -> bool
        Set variable type Note: this function does not modify the idb, only the lvar
        instance in the memory. For permanent changes see modify_user_lvars() Also, the
        variable type is not considered as final by the decompiler and may be modified
        later by the type derivation. In some cases set_final_var_type() may work
        better, but it does not do persistent changes to the database neither.

        @param t: (C++: const tinfo_t &) new type
        @param may_fail: (C++: bool) if false and type is bad, interr
        @return: success
        """
        return _ida_hexrays.lvar_t_set_lvar_type(self, t, may_fail)

    def set_final_lvar_type(self, t: "tinfo_t") -> "void":
        r"""
        set_final_lvar_type(self, t)
        Set final variable type.

        @param t: (C++: const tinfo_t &) tinfo_t const &
        """
        return _ida_hexrays.lvar_t_set_final_lvar_type(self, t)

    def set_width(self, w: "int", svw_flags: "int"=0) -> "bool":
        r"""
        set_width(self, w, svw_flags=0) -> bool
        Change the variable width. We call the variable size 'width', it is represents
        the number of bytes. This function may change the variable type using
        set_lvar_type().

        @param w: (C++: int) new width
        @param svw_flags: (C++: int) combination of SVW_... bits
        @return: success
        """
        return _ida_hexrays.lvar_t_set_width(self, w, svw_flags)

    def append_list(self, mba: "mba_t", lst: "mlist_t", pad_if_scattered: "bool"=False) -> "void":
        r"""
        append_list(self, mba, lst, pad_if_scattered=False)
        Append local variable to mlist.

        @param mba: (C++: const mba_t *) ptr to the current mba_t
        @param lst: (C++: mlist_t *) list to append to
        @param pad_if_scattered: (C++: bool) if true, append padding bytes in case of scattered lvar
        """
        return _ida_hexrays.lvar_t_append_list(self, mba, lst, pad_if_scattered)

    def is_aliasable(self, mba: "mba_t") -> "bool":
        r"""
        is_aliasable(self, mba) -> bool
        Is the variable aliasable?

        @param mba: (C++: const mba_t *) ptr to the current mba_t Aliasable variables may be modified
                    indirectly (through a pointer)
        """
        return _ida_hexrays.lvar_t_is_aliasable(self, mba)
    __swig_destroy__ = _ida_hexrays.delete_lvar_t

# Register lvar_t in _ida_hexrays:
_ida_hexrays.lvar_t_swigregister(lvar_t)
SVW_INT = _ida_hexrays.SVW_INT

SVW_FLOAT = _ida_hexrays.SVW_FLOAT

SVW_SOFT = _ida_hexrays.SVW_SOFT


class lvars_t(qvector_lvar_t):
    r"""
    Proxy of C++ lvars_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def find_input_lvar(self, argloc: "vdloc_t", _size: "int") -> "int":
        r"""
        find_input_lvar(self, argloc, _size) -> int
        Find an input variable at the specified location.

        @param argloc: (C++: const vdloc_t &) variable location
        @param _size: (C++: int) variable size in bytes
        @return: -1 if failed, otherwise an index into 'vars'
        """
        return _ida_hexrays.lvars_t_find_input_lvar(self, argloc, _size)

    def find_input_reg(self, reg: "int", _size: "int"=1) -> "int":
        r"""
        find_input_reg(self, reg, _size=1) -> int
        Find an input register variable.

        @param reg: (C++: int) register to find
        @param _size: (C++: int) variable size in bytes
        @return: -1 if failed, otherwise an index into 'vars'
        """
        return _ida_hexrays.lvars_t_find_input_reg(self, reg, _size)

    def find_stkvar(self, spoff: "sval_t", width: "int") -> "int":
        r"""
        find_stkvar(self, spoff, width) -> int
        Find a stack variable at the specified location.

        @param spoff: (C++: sval_t) offset from the minimal sp
        @param width: (C++: int) variable size in bytes
        @return: -1 if failed, otherwise an index into 'vars'
        """
        return _ida_hexrays.lvars_t_find_stkvar(self, spoff, width)

    def find(self, ll: "lvar_locator_t") -> "lvar_t *":
        r"""
        find(self, ll) -> lvar_t
        Find a variable at the specified location.

        @param ll: (C++: const lvar_locator_t &) variable location
        @return: pointer to variable or nullptr
        """
        return _ida_hexrays.lvars_t_find(self, ll)

    def find_lvar(self, location: "vdloc_t", width: "int", defblk: "int"=-1) -> "int":
        r"""
        find_lvar(self, location, width, defblk=-1) -> int
        Find a variable at the specified location.

        @param location: (C++: const vdloc_t &) variable location
        @param width: (C++: int) variable size in bytes
        @param defblk: (C++: int) definition block of the lvar. -1 means any block
        @return: -1 if failed, otherwise an index into 'vars'
        """
        return _ida_hexrays.lvars_t_find_lvar(self, location, width, defblk)

    def __init__(self):
        r"""
        __init__(self) -> lvars_t
        """
        _ida_hexrays.lvars_t_swiginit(self, _ida_hexrays.new_lvars_t())
    __swig_destroy__ = _ida_hexrays.delete_lvars_t

# Register lvars_t in _ida_hexrays:
_ida_hexrays.lvars_t_swigregister(lvars_t)
class lvar_saved_info_t(object):
    r"""
    Proxy of C++ lvar_saved_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ll: "lvar_locator_t" = property(_ida_hexrays.lvar_saved_info_t_ll_get, _ida_hexrays.lvar_saved_info_t_ll_set, doc=r"""ll""")
    r"""
    Variable locator.
    """
    name: "qstring" = property(_ida_hexrays.lvar_saved_info_t_name_get, _ida_hexrays.lvar_saved_info_t_name_set, doc=r"""name""")
    r"""
    Name.
    """
    type: "tinfo_t" = property(_ida_hexrays.lvar_saved_info_t_type_get, _ida_hexrays.lvar_saved_info_t_type_set, doc=r"""type""")
    r"""
    Type.
    """
    cmt: "qstring" = property(_ida_hexrays.lvar_saved_info_t_cmt_get, _ida_hexrays.lvar_saved_info_t_cmt_set, doc=r"""cmt""")
    r"""
    Comment.
    """
    size: "ssize_t" = property(_ida_hexrays.lvar_saved_info_t_size_get, _ida_hexrays.lvar_saved_info_t_size_set, doc=r"""size""")
    r"""
    Type size (if not initialized then -1)
    """
    flags: "int" = property(_ida_hexrays.lvar_saved_info_t_flags_get, _ida_hexrays.lvar_saved_info_t_flags_set, doc=r"""flags""")
    r"""
    saved user lvar info property bits
    """

    def has_info(self) -> "bool":
        r"""
        has_info(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_has_info(self)

    def __eq__(self, r: "lvar_saved_info_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_info_t___eq__(self, r)

    def __ne__(self, r: "lvar_saved_info_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: lvar_saved_info_t const &
        """
        return _ida_hexrays.lvar_saved_info_t___ne__(self, r)

    def is_kept(self) -> "bool":
        r"""
        is_kept(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_is_kept(self)

    def clear_keep(self) -> "void":
        r"""
        clear_keep(self)
        """
        return _ida_hexrays.lvar_saved_info_t_clear_keep(self)

    def set_keep(self) -> "void":
        r"""
        set_keep(self)
        """
        return _ida_hexrays.lvar_saved_info_t_set_keep(self)

    def is_split_lvar(self) -> "bool":
        r"""
        is_split_lvar(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_is_split_lvar(self)

    def set_split_lvar(self) -> "void":
        r"""
        set_split_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_set_split_lvar(self)

    def clr_split_lvar(self) -> "void":
        r"""
        clr_split_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_clr_split_lvar(self)

    def is_noptr_lvar(self) -> "bool":
        r"""
        is_noptr_lvar(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_is_noptr_lvar(self)

    def set_noptr_lvar(self) -> "void":
        r"""
        set_noptr_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_set_noptr_lvar(self)

    def clr_noptr_lvar(self) -> "void":
        r"""
        clr_noptr_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_clr_noptr_lvar(self)

    def is_nomap_lvar(self) -> "bool":
        r"""
        is_nomap_lvar(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_is_nomap_lvar(self)

    def set_nomap_lvar(self) -> "void":
        r"""
        set_nomap_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_set_nomap_lvar(self)

    def clr_nomap_lvar(self) -> "void":
        r"""
        clr_nomap_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_clr_nomap_lvar(self)

    def is_unused_lvar(self) -> "bool":
        r"""
        is_unused_lvar(self) -> bool
        """
        return _ida_hexrays.lvar_saved_info_t_is_unused_lvar(self)

    def set_unused_lvar(self) -> "void":
        r"""
        set_unused_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_set_unused_lvar(self)

    def clr_unused_lvar(self) -> "void":
        r"""
        clr_unused_lvar(self)
        """
        return _ida_hexrays.lvar_saved_info_t_clr_unused_lvar(self)

    def __init__(self):
        r"""
        __init__(self) -> lvar_saved_info_t
        """
        _ida_hexrays.lvar_saved_info_t_swiginit(self, _ida_hexrays.new_lvar_saved_info_t())
    __swig_destroy__ = _ida_hexrays.delete_lvar_saved_info_t

# Register lvar_saved_info_t in _ida_hexrays:
_ida_hexrays.lvar_saved_info_t_swigregister(lvar_saved_info_t)
LVINF_KEEP = _ida_hexrays.LVINF_KEEP
r"""
preserve saved user settings regardless of vars for example, if a var loses all
its user-defined attributes or even gets destroyed, keep its lvar_saved_info_t.
this is used for ephemeral variables that get destroyed by macro recognition.
"""

LVINF_SPLIT = _ida_hexrays.LVINF_SPLIT
r"""
split allocation of a new variable. forces the decompiler to create a new
variable at ll.defea
"""

LVINF_NOPTR = _ida_hexrays.LVINF_NOPTR
r"""
variable type should not be a pointer
"""

LVINF_NOMAP = _ida_hexrays.LVINF_NOMAP
r"""
forbid automatic mapping of the variable
"""

LVINF_UNUSED = _ida_hexrays.LVINF_UNUSED
r"""
unused argument, corresponds to CVAR_UNUSED
"""


class lvar_uservec_t(object):
    r"""
    Proxy of C++ lvar_uservec_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    lvvec: "lvar_saved_infos_t" = property(_ida_hexrays.lvar_uservec_t_lvvec_get, _ida_hexrays.lvar_uservec_t_lvvec_set, doc=r"""lvvec""")
    r"""
    User-specified names, types, comments for lvars. Variables without user-
    specified info are not present in this vector.
    """
    lmaps: "lvar_mapping_t" = property(_ida_hexrays.lvar_uservec_t_lmaps_get, _ida_hexrays.lvar_uservec_t_lmaps_set, doc=r"""lmaps""")
    r"""
    Local variable mapping (used for merging variables)
    """
    stkoff_delta: "uval_t" = property(_ida_hexrays.lvar_uservec_t_stkoff_delta_get, _ida_hexrays.lvar_uservec_t_stkoff_delta_set, doc=r"""stkoff_delta""")
    r"""
    Delta to add to IDA stack offset to calculate Hex-Rays stack offsets. Should be
    set by the caller before calling save_user_lvar_settings();
    """
    ulv_flags: "int" = property(_ida_hexrays.lvar_uservec_t_ulv_flags_get, _ida_hexrays.lvar_uservec_t_ulv_flags_set, doc=r"""ulv_flags""")
    r"""
    Various flags. Possible values are from lvar_uservec_t property bits.
    """

    def swap(self, r: "lvar_uservec_t") -> "void":
        r"""
        swap(self, r)

        @param r: lvar_uservec_t &
        """
        return _ida_hexrays.lvar_uservec_t_swap(self, r)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.lvar_uservec_t_clear(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.lvar_uservec_t_empty(self)

    def find_info(self, vloc: "lvar_locator_t") -> "lvar_saved_info_t *":
        r"""
        find_info(self, vloc) -> lvar_saved_info_t
        find saved user settings for given var

        @param vloc: (C++: const lvar_locator_t &) lvar_locator_t const &
        """
        return _ida_hexrays.lvar_uservec_t_find_info(self, vloc)

    def keep_info(self, v: "lvar_t") -> "void":
        r"""
        keep_info(self, v)
        Preserve user settings for given var.

        @param v: (C++: const lvar_t &) lvar_t const &
        """
        return _ida_hexrays.lvar_uservec_t_keep_info(self, v)

    def __init__(self):
        r"""
        __init__(self) -> lvar_uservec_t
        """
        _ida_hexrays.lvar_uservec_t_swiginit(self, _ida_hexrays.new_lvar_uservec_t())
    __swig_destroy__ = _ida_hexrays.delete_lvar_uservec_t

# Register lvar_uservec_t in _ida_hexrays:
_ida_hexrays.lvar_uservec_t_swigregister(lvar_uservec_t)
ULV_PRECISE_DEFEA = _ida_hexrays.ULV_PRECISE_DEFEA
r"""
Use precise defea's for lvar locations.
"""



def restore_user_lvar_settings(lvinf: "lvar_uservec_t", func_ea: "ea_t") -> "bool":
    r"""
    restore_user_lvar_settings(lvinf, func_ea) -> bool
    Restore user defined local variable settings in the database.

    @param lvinf: (C++: lvar_uservec_t *) ptr to output buffer
    @param func_ea: (C++: ea_t) entry address of the function
    @return: success
    """
    return _ida_hexrays.restore_user_lvar_settings(lvinf, func_ea)

def save_user_lvar_settings(func_ea: "ea_t", lvinf: "lvar_uservec_t") -> "void":
    r"""
    save_user_lvar_settings(func_ea, lvinf)
    Save user defined local variable settings into the database.

    @param func_ea: (C++: ea_t) entry address of the function
    @param lvinf: (C++: const lvar_uservec_t &) user-specified info about local variables
    """
    return _ida_hexrays.save_user_lvar_settings(func_ea, lvinf)
class user_lvar_modifier_t(object):
    r"""
    Proxy of C++ user_lvar_modifier_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_hexrays.delete_user_lvar_modifier_t

    def modify_lvars(self, lvinf: "lvar_uservec_t") -> "bool":
        r"""
        modify_lvars(self, lvinf) -> bool
        Modify lvar settings. Returns: true-modified

        @param lvinf: (C++: lvar_uservec_t *)
        """
        return _ida_hexrays.user_lvar_modifier_t_modify_lvars(self, lvinf)

    def __init__(self):
        r"""
        __init__(self) -> user_lvar_modifier_t

        @param self: PyObject *
        """
        if self.__class__ == user_lvar_modifier_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.user_lvar_modifier_t_swiginit(self, _ida_hexrays.new_user_lvar_modifier_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_user_lvar_modifier_t(self)
        return weakref.proxy(self)

# Register user_lvar_modifier_t in _ida_hexrays:
_ida_hexrays.user_lvar_modifier_t_swigregister(user_lvar_modifier_t)

def modify_user_lvars(entry_ea: "ea_t", mlv: "user_lvar_modifier_t") -> "bool":
    r"""
    modify_user_lvars(entry_ea, mlv) -> bool
    Modify saved local variable settings.

    @param entry_ea: (C++: ea_t) function start address
    @param mlv: (C++: user_lvar_modifier_t &) local variable modifier
    @return: true if modified variables
    """
    return _ida_hexrays.modify_user_lvars(entry_ea, mlv)

def modify_user_lvar_info(func_ea: "ea_t", mli_flags: "uint", info: "lvar_saved_info_t") -> "bool":
    r"""
    modify_user_lvar_info(func_ea, mli_flags, info) -> bool
    Modify saved local variable settings of one variable.

    @param func_ea: (C++: ea_t) function start address
    @param mli_flags: (C++: uint) bits that specify which attrs defined by INFO are to be set
    @param info: (C++: const lvar_saved_info_t &) local variable info attrs
    @return: true if modified, false if invalid MLI_FLAGS passed
    """
    return _ida_hexrays.modify_user_lvar_info(func_ea, mli_flags, info)
MLI_NAME = _ida_hexrays.MLI_NAME
r"""
apply lvar name
"""

MLI_TYPE = _ida_hexrays.MLI_TYPE
r"""
apply lvar type
"""

MLI_CMT = _ida_hexrays.MLI_CMT
r"""
apply lvar comment
"""

MLI_SET_FLAGS = _ida_hexrays.MLI_SET_FLAGS
r"""
set LVINF_... bits
"""

MLI_CLR_FLAGS = _ida_hexrays.MLI_CLR_FLAGS
r"""
clear LVINF_... bits
"""


def locate_lvar(out: "lvar_locator_t", func_ea: "ea_t", varname: "char const *") -> "bool":
    r"""
    locate_lvar(out, func_ea, varname) -> bool
    Find a variable by name.

    @param out: (C++: lvar_locator_t *) output buffer for the variable locator
    @param func_ea: (C++: ea_t) function start address
    @param varname: (C++: const char *) variable name
    @return: success Since VARNAME is not always enough to find the variable, it may
             decompile the function.
    """
    return _ida_hexrays.locate_lvar(out, func_ea, varname)

def rename_lvar(func_ea: "ea_t", oldname: "char const *", newname: "char const *") -> "bool":
    r"""
    rename_lvar(func_ea, oldname, newname) -> bool
    Rename a local variable.

    @param func_ea: (C++: ea_t) function start address
    @param oldname: (C++: const char *) old name of the variable
    @param newname: (C++: const char *) new name of the variable
    @return: success This is a convenience function. For bulk renaming consider
             using modify_user_lvars.
    """
    return _ida_hexrays.rename_lvar(func_ea, oldname, newname)
class udcall_t(object):
    r"""
    Proxy of C++ udcall_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_hexrays.udcall_t_name_get, _ida_hexrays.udcall_t_name_set, doc=r"""name""")
    tif: "tinfo_t" = property(_ida_hexrays.udcall_t_tif_get, _ida_hexrays.udcall_t_tif_set, doc=r"""tif""")

    def __eq__(self, r: "udcall_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___eq__(self, r)

    def __ne__(self, r: "udcall_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___ne__(self, r)

    def __lt__(self, r: "udcall_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___lt__(self, r)

    def __gt__(self, r: "udcall_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___gt__(self, r)

    def __le__(self, r: "udcall_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___le__(self, r)

    def __ge__(self, r: "udcall_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t___ge__(self, r)

    def compare(self, r: "udcall_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: udcall_t const &
        """
        return _ida_hexrays.udcall_t_compare(self, r)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.udcall_t_empty(self)

    def __init__(self):
        r"""
        __init__(self) -> udcall_t
        """
        _ida_hexrays.udcall_t_swiginit(self, _ida_hexrays.new_udcall_t())
    __swig_destroy__ = _ida_hexrays.delete_udcall_t

# Register udcall_t in _ida_hexrays:
_ida_hexrays.udcall_t_swigregister(udcall_t)

def restore_user_defined_calls(udcalls: "udcall_map_t *", func_ea: "ea_t") -> "bool":
    r"""
    restore_user_defined_calls(udcalls, func_ea) -> bool
    Restore user defined function calls from the database.

    @param udcalls: (C++: udcall_map_t *) ptr to output buffer
    @param func_ea: (C++: ea_t) entry address of the function
    @return: success
    """
    return _ida_hexrays.restore_user_defined_calls(udcalls, func_ea)

def save_user_defined_calls(func_ea: "ea_t", udcalls: "udcall_map_t const &") -> "void":
    r"""
    save_user_defined_calls(func_ea, udcalls)
    Save user defined local function calls into the database.

    @param func_ea: (C++: ea_t) entry address of the function
    @param udcalls: (C++: const udcall_map_t &) user-specified info about user defined function calls
    """
    return _ida_hexrays.save_user_defined_calls(func_ea, udcalls)

def parse_user_call(udc: "udcall_t", decl: "char const *", silent: "bool") -> "bool":
    r"""
    parse_user_call(udc, decl, silent) -> bool
    Convert function type declaration into internal structure

    @param udc: (C++: udcall_t *) - pointer to output structure
    @param decl: (C++: const char *) - function type declaration
    @param silent: (C++: bool) - if TRUE: do not show warning in case of incorrect type
    @return: success
    """
    return _ida_hexrays.parse_user_call(udc, decl, silent)

def convert_to_user_call(udc: "udcall_t", cdg: "codegen_t") -> "merror_t":
    r"""
    convert_to_user_call(udc, cdg) -> merror_t
    try to generate user-defined call for an instruction

    @param udc: (C++: const udcall_t &) udcall_t const &
    @param cdg: (C++: codegen_t &)
    @return: Microcode error codes code: MERR_OK - user-defined call generated else
             - error (MERR_INSN == inacceptable udc.tif)
    """
    return _ida_hexrays.convert_to_user_call(udc, cdg)
class microcode_filter_t(object):
    r"""
    Proxy of C++ microcode_filter_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_hexrays.delete_microcode_filter_t

    def match(self, cdg: "codegen_t") -> "bool":
        r"""
        match(self, cdg) -> bool
        check if the filter object is to be applied

        @param cdg: (C++: codegen_t &)
        @return: success
        """
        return _ida_hexrays.microcode_filter_t_match(self, cdg)

    def apply(self, cdg: "codegen_t") -> "merror_t":
        r"""
        apply(self, cdg) -> merror_t
        generate microcode for an instruction

        @param cdg: (C++: codegen_t &)
        @return: MERR_... code: MERR_OK - user-defined microcode generated, go to the
                 next instruction MERR_INSN - not generated - the caller should try the
                 standard way else - error
        """
        return _ida_hexrays.microcode_filter_t_apply(self, cdg)

    def __init__(self):
        r"""
        __init__(self) -> microcode_filter_t

        @param self: PyObject *
        """
        if self.__class__ == microcode_filter_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.microcode_filter_t_swiginit(self, _ida_hexrays.new_microcode_filter_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_microcode_filter_t(self)
        return weakref.proxy(self)

# Register microcode_filter_t in _ida_hexrays:
_ida_hexrays.microcode_filter_t_swigregister(microcode_filter_t)

def install_microcode_filter(filter: "microcode_filter_t", install: "bool"=True) -> "bool":
    r"""
    install_microcode_filter(filter, install=True) -> bool
    register/unregister non-standard microcode generator

    @param filter: (C++: microcode_filter_t *) - microcode generator object
    @param install: (C++: bool) - TRUE - register the object, FALSE - unregister
    @return: success
    """
    return _ida_hexrays.install_microcode_filter(filter, install)
class udc_filter_t(microcode_filter_t):
    r"""
    Proxy of C++ udc_filter_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def cleanup(self) -> "void":
        r"""
        cleanup(self)
        Cleanup the filter This function properly clears type information associated to
        this filter.
        """
        return _ida_hexrays.udc_filter_t_cleanup(self)

    def match(self, cdg: "codegen_t") -> "bool":
        r"""
        match(self, cdg) -> bool
        return true if the filter object should be applied to given instruction

        @param cdg: (C++: codegen_t &)
        """
        return _ida_hexrays.udc_filter_t_match(self, cdg)

    def apply(self, cdg: "codegen_t") -> "merror_t":
        r"""
        apply(self, cdg) -> merror_t
        generate microcode for an instruction

        @param cdg: (C++: codegen_t &)
        @return: MERR_... code: MERR_OK - user-defined microcode generated, go to the
                 next instruction MERR_INSN - not generated - the caller should try the
                 standard way else - error
        """
        return _ida_hexrays.udc_filter_t_apply(self, cdg)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.udc_filter_t_empty(self)

    def install(self) -> "void":
        r"""
        install(self)
        """
        return _ida_hexrays.udc_filter_t_install(self)

    def remove(self) -> "bool":
        r"""
        remove(self) -> bool
        """
        return _ida_hexrays.udc_filter_t_remove(self)
    __swig_destroy__ = _ida_hexrays.delete_udc_filter_t

    def init(self, decl: "char const *") -> "bool":
        r"""
        init(self, decl) -> bool

        @param decl: char const *
        """
        return _ida_hexrays.udc_filter_t_init(self, decl)

    def __init__(self):
        r"""
        __init__(self) -> udc_filter_t

        @param self: PyObject *
        """
        if self.__class__ == udc_filter_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.udc_filter_t_swiginit(self, _ida_hexrays.new_udc_filter_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_udc_filter_t(self)
        return weakref.proxy(self)

# Register udc_filter_t in _ida_hexrays:
_ida_hexrays.udc_filter_t_swigregister(udc_filter_t)
class bitset_t(object):
    r"""
    Proxy of C++ bitset_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> bitset_t
        __init__(self, m) -> bitset_t

        @param m: bitset_t const &
        """
        _ida_hexrays.bitset_t_swiginit(self, _ida_hexrays.new_bitset_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_bitset_t

    def swap(self, r: "bitset_t") -> "void":
        r"""
        swap(self, r)

        @param r: bitset_t &
        """
        return _ida_hexrays.bitset_t_swap(self, r)

    def copy(self, m: "bitset_t") -> "bitset_t &":
        r"""
        copy(self, m) -> bitset_t

        @param m: bitset_t const &
        """
        return _ida_hexrays.bitset_t_copy(self, m)

    def add(self, *args) -> "bool":
        r"""
        add(self, bit) -> bool

        @param bit: int

        add(self, bit, width) -> bool

        @param bit: int
        @param width: int

        add(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_add(self, *args)

    def sub(self, *args) -> "bool":
        r"""
        sub(self, bit) -> bool

        @param bit: int

        sub(self, bit, width) -> bool

        @param bit: int
        @param width: int

        sub(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_sub(self, *args)

    def cut_at(self, maxbit: "int") -> "bool":
        r"""
        cut_at(self, maxbit) -> bool

        @param maxbit: int
        """
        return _ida_hexrays.bitset_t_cut_at(self, maxbit)

    def shift_down(self, shift: "int") -> "void":
        r"""
        shift_down(self, shift)

        @param shift: int
        """
        return _ida_hexrays.bitset_t_shift_down(self, shift)

    def has(self, bit: "int") -> "bool":
        r"""
        has(self, bit) -> bool

        @param bit: int
        """
        return _ida_hexrays.bitset_t_has(self, bit)

    def has_all(self, bit: "int", width: "int") -> "bool":
        r"""
        has_all(self, bit, width) -> bool

        @param bit: int
        @param width: int
        """
        return _ida_hexrays.bitset_t_has_all(self, bit, width)

    def has_any(self, bit: "int", width: "int") -> "bool":
        r"""
        has_any(self, bit, width) -> bool

        @param bit: int
        @param width: int
        """
        return _ida_hexrays.bitset_t_has_any(self, bit, width)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.bitset_t_dstr(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.bitset_t_empty(self)

    def count(self, *args) -> "int":
        r"""
        count(self) -> int
        count(self, bit) -> int

        @param bit: int
        """
        return _ida_hexrays.bitset_t_count(self, *args)

    def last(self) -> "int":
        r"""
        last(self) -> int
        """
        return _ida_hexrays.bitset_t_last(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.bitset_t_clear(self)

    def fill_with_ones(self, maxbit: "int") -> "void":
        r"""
        fill_with_ones(self, maxbit)

        @param maxbit: int
        """
        return _ida_hexrays.bitset_t_fill_with_ones(self, maxbit)

    def has_common(self, ml: "bitset_t") -> "bool":
        r"""
        has_common(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_has_common(self, ml)

    def intersect(self, ml: "bitset_t") -> "bool":
        r"""
        intersect(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_intersect(self, ml)

    def is_subset_of(self, ml: "bitset_t") -> "bool":
        r"""
        is_subset_of(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_is_subset_of(self, ml)

    def includes(self, ml: "bitset_t") -> "bool":
        r"""
        includes(self, ml) -> bool

        @param ml: bitset_t const &
        """
        return _ida_hexrays.bitset_t_includes(self, ml)

    def __eq__(self, r: "bitset_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___eq__(self, r)

    def __ne__(self, r: "bitset_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___ne__(self, r)

    def __lt__(self, r: "bitset_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___lt__(self, r)

    def __gt__(self, r: "bitset_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___gt__(self, r)

    def __le__(self, r: "bitset_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___le__(self, r)

    def __ge__(self, r: "bitset_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t___ge__(self, r)

    def compare(self, r: "bitset_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: bitset_t const &
        """
        return _ida_hexrays.bitset_t_compare(self, r)

    def itat(self, n: "int") -> "bitset_t::iterator":
        r"""
        itat(self, n) -> iterator

        @param n: int
        """
        return _ida_hexrays.bitset_t_itat(self, n)

    def begin(self) -> "bitset_t::iterator":
        r"""
        begin(self) -> iterator
        """
        return _ida_hexrays.bitset_t_begin(self)

    def end(self) -> "bitset_t::iterator":
        r"""
        end(self) -> iterator
        """
        return _ida_hexrays.bitset_t_end(self)

    def front(self) -> "int":
        r"""
        front(self) -> int
        """
        return _ida_hexrays.bitset_t_front(self)

    def back(self) -> "int":
        r"""
        back(self) -> int
        """
        return _ida_hexrays.bitset_t_back(self)

    def inc(self, p: "iterator", n: "int"=1) -> "void":
        r"""
        inc(self, p, n=1)

        @param p: bitset_t::iterator &
        @param n: int
        """
        return _ida_hexrays.bitset_t_inc(self, p, n)

    def itv(self, it: "iterator") -> "int":
        r"""
        itv(self, it) -> int

        @param it: bitset_t::const_iterator
        """
        return _ida_hexrays.bitset_t_itv(self, it)

    __len__ = count
    def __iter__(self):
        it = self.begin()
        for i in range(self.count()):
            yield self.itv(it)
            self.inc(it)


# Register bitset_t in _ida_hexrays:
_ida_hexrays.bitset_t_swigregister(bitset_t)
bitset_width = cvar.bitset_width
bitset_align = cvar.bitset_align
bitset_shift = cvar.bitset_shift

class iterator(object):
    r"""
    Proxy of C++ bitset_t::iterator class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, n: "int"=-1):
        r"""
        __init__(self, n=-1) -> iterator

        @param n: int
        """
        _ida_hexrays.iterator_swiginit(self, _ida_hexrays.new_iterator(n))

    def __eq__(self, n: "iterator") -> "bool":
        r"""
        __eq__(self, n) -> bool

        @param n: bitset_t::iterator const &
        """
        return _ida_hexrays.iterator___eq__(self, n)

    def __ne__(self, n: "iterator") -> "bool":
        r"""
        __ne__(self, n) -> bool

        @param n: bitset_t::iterator const &
        """
        return _ida_hexrays.iterator___ne__(self, n)

    def __ref__(self) -> "int":
        r"""
        __ref__(self) -> int
        """
        return _ida_hexrays.iterator___ref__(self)
    __swig_destroy__ = _ida_hexrays.delete_iterator

# Register iterator in _ida_hexrays:
_ida_hexrays.iterator_swigregister(iterator)
class ivl_t(uval_ivl_t):
    r"""
    Proxy of C++ ivl_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _off: "uval_t"=0, _size: "uval_t"=0):
        r"""
        __init__(self, _off=0, _size=0) -> ivl_t

        @param _off: uval_t
        @param _size: uval_t
        """
        _ida_hexrays.ivl_t_swiginit(self, _ida_hexrays.new_ivl_t(_off, _size))

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.ivl_t_empty(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.ivl_t_clear(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.ivl_t_dstr(self)

    def extend_to_cover(self, r: "ivl_t") -> "bool":
        r"""
        extend_to_cover(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t_extend_to_cover(self, r)

    def intersect(self, r: "ivl_t") -> "void":
        r"""
        intersect(self, r)

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t_intersect(self, r)

    def overlap(self, ivl: "ivl_t") -> "bool":
        r"""
        overlap(self, ivl) -> bool

        @param ivl: ivl_t const &
        """
        return _ida_hexrays.ivl_t_overlap(self, ivl)

    def includes(self, ivl: "ivl_t") -> "bool":
        r"""
        includes(self, ivl) -> bool

        @param ivl: ivl_t const &
        """
        return _ida_hexrays.ivl_t_includes(self, ivl)

    def contains(self, off2: "uval_t") -> "bool":
        r"""
        contains(self, off2) -> bool

        @param off2: uval_t
        """
        return _ida_hexrays.ivl_t_contains(self, off2)

    def __eq__(self, r: "ivl_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___eq__(self, r)

    def __ne__(self, r: "ivl_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___ne__(self, r)

    def __lt__(self, r: "ivl_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___lt__(self, r)

    def __gt__(self, r: "ivl_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___gt__(self, r)

    def __le__(self, r: "ivl_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___le__(self, r)

    def __ge__(self, r: "ivl_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t___ge__(self, r)

    def compare(self, r: "ivl_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ivl_t const &
        """
        return _ida_hexrays.ivl_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_ivl_t

# Register ivl_t in _ida_hexrays:
_ida_hexrays.ivl_t_swigregister(ivl_t)
class ivl_with_name_t(object):
    r"""
    Proxy of C++ ivl_with_name_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ivl: "ivl_t" = property(_ida_hexrays.ivl_with_name_t_ivl_get, _ida_hexrays.ivl_with_name_t_ivl_set, doc=r"""ivl""")
    whole: "char const *" = property(_ida_hexrays.ivl_with_name_t_whole_get, _ida_hexrays.ivl_with_name_t_whole_set, doc=r"""whole""")
    part: "char const *" = property(_ida_hexrays.ivl_with_name_t_part_get, _ida_hexrays.ivl_with_name_t_part_set, doc=r"""part""")

    def __init__(self):
        r"""
        __init__(self) -> ivl_with_name_t
        """
        _ida_hexrays.ivl_with_name_t_swiginit(self, _ida_hexrays.new_ivl_with_name_t())
    __swig_destroy__ = _ida_hexrays.delete_ivl_with_name_t

# Register ivl_with_name_t in _ida_hexrays:
_ida_hexrays.ivl_with_name_t_swigregister(ivl_with_name_t)
class ivlset_t(uval_ivl_ivlset_t):
    r"""
    Proxy of C++ ivlset_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> ivlset_t
        __init__(self, ivl) -> ivlset_t

        @param ivl: ivl_t const &
        """
        _ida_hexrays.ivlset_t_swiginit(self, _ida_hexrays.new_ivlset_t(*args))

    def add(self, *args) -> "bool":
        r"""
        add(self, ivl) -> bool

        @param ivl: ivl_t const &

        add(self, ea, size) -> bool

        @param ea: ea_t
        @param size: asize_t

        add(self, ivs) -> bool

        @param ivs: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_add(self, *args)

    def addmasked(self, ivs: "ivlset_t", mask: "ivl_t") -> "bool":
        r"""
        addmasked(self, ivs, mask) -> bool

        @param ivs: ivlset_t const &
        @param mask: ivl_t const &
        """
        return _ida_hexrays.ivlset_t_addmasked(self, ivs, mask)

    def sub(self, *args) -> "bool":
        r"""
        sub(self, ivl) -> bool

        @param ivl: ivl_t const &

        sub(self, ea, size) -> bool

        @param ea: ea_t
        @param size: asize_t

        sub(self, ivs) -> bool

        @param ivs: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_sub(self, *args)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.ivlset_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.ivlset_t_dstr(self)

    def count(self) -> "asize_t":
        r"""
        count(self) -> asize_t
        """
        return _ida_hexrays.ivlset_t_count(self)

    def has_common(self, *args) -> "bool":
        r"""
        has_common(self, ivl, strict=False) -> bool

        @param ivl: ivl_t const &
        @param strict: bool

        has_common(self, ivs) -> bool

        @param ivs: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_has_common(self, *args)

    def contains(self, off: "uval_t") -> "bool":
        r"""
        contains(self, off) -> bool

        @param off: uval_t
        """
        return _ida_hexrays.ivlset_t_contains(self, off)

    def includes(self, ivs: "ivlset_t") -> "bool":
        r"""
        includes(self, ivs) -> bool

        @param ivs: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_includes(self, ivs)

    def intersect(self, ivs: "ivlset_t") -> "bool":
        r"""
        intersect(self, ivs) -> bool

        @param ivs: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_intersect(self, ivs)

    def __eq__(self, r: "ivlset_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___eq__(self, r)

    def __ne__(self, r: "ivlset_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___ne__(self, r)

    def __lt__(self, r: "ivlset_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___lt__(self, r)

    def __gt__(self, r: "ivlset_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___gt__(self, r)

    def __le__(self, r: "ivlset_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___le__(self, r)

    def __ge__(self, r: "ivlset_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t___ge__(self, r)

    def compare(self, r: "ivlset_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ivlset_t const &
        """
        return _ida_hexrays.ivlset_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_ivlset_t

# Register ivlset_t in _ida_hexrays:
_ida_hexrays.ivlset_t_swigregister(ivlset_t)
class rlist_t(bitset_t):
    r"""
    Proxy of C++ rlist_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self) -> rlist_t
        __init__(self, m) -> rlist_t

        @param m: rlist_t const &

        __init__(self, reg, width) -> rlist_t

        @param reg: mreg_t
        @param width: int
        """
        _ida_hexrays.rlist_t_swiginit(self, _ida_hexrays.new_rlist_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_rlist_t

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.rlist_t_dstr(self)

# Register rlist_t in _ida_hexrays:
_ida_hexrays.rlist_t_swigregister(rlist_t)
class mlist_t(object):
    r"""
    Proxy of C++ mlist_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    reg: "rlist_t" = property(_ida_hexrays.mlist_t_reg_get, _ida_hexrays.mlist_t_reg_set, doc=r"""reg""")
    mem: "ivlset_t" = property(_ida_hexrays.mlist_t_mem_get, _ida_hexrays.mlist_t_mem_set, doc=r"""mem""")

    def __init__(self, *args):
        r"""
        __init__(self) -> mlist_t
        __init__(self, ivl) -> mlist_t

        @param ivl: ivl_t const &

        __init__(self, r, size) -> mlist_t

        @param r: mreg_t
        @param size: int
        """
        _ida_hexrays.mlist_t_swiginit(self, _ida_hexrays.new_mlist_t(*args))

    def swap(self, r: "mlist_t") -> "void":
        r"""
        swap(self, r)

        @param r: mlist_t &
        """
        return _ida_hexrays.mlist_t_swap(self, r)

    def addmem(self, ea: "ea_t", size: "asize_t") -> "bool":
        r"""
        addmem(self, ea, size) -> bool

        @param ea: ea_t
        @param size: asize_t
        """
        return _ida_hexrays.mlist_t_addmem(self, ea, size)

    def add(self, *args) -> "bool":
        r"""
        add(self, r, size) -> bool

        @param r: mreg_t
        @param size: int

        add(self, r) -> bool

        @param r: rlist_t const &

        add(self, ivl) -> bool

        @param ivl: ivl_t const &

        add(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_add(self, *args)

    def sub(self, *args) -> "bool":
        r"""
        sub(self, r, size) -> bool

        @param r: mreg_t
        @param size: int

        sub(self, ivl) -> bool

        @param ivl: ivl_t const &

        sub(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_sub(self, *args)

    def count(self) -> "asize_t":
        r"""
        count(self) -> asize_t
        """
        return _ida_hexrays.mlist_t_count(self)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.mlist_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.mlist_t_dstr(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mlist_t_empty(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.mlist_t_clear(self)

    def has(self, r: "mreg_t") -> "bool":
        r"""
        has(self, r) -> bool

        @param r: mreg_t
        """
        return _ida_hexrays.mlist_t_has(self, r)

    def has_all(self, r: "mreg_t", size: "int") -> "bool":
        r"""
        has_all(self, r, size) -> bool

        @param r: mreg_t
        @param size: int
        """
        return _ida_hexrays.mlist_t_has_all(self, r, size)

    def has_any(self, r: "mreg_t", size: "int") -> "bool":
        r"""
        has_any(self, r, size) -> bool

        @param r: mreg_t
        @param size: int
        """
        return _ida_hexrays.mlist_t_has_any(self, r, size)

    def has_memory(self) -> "bool":
        r"""
        has_memory(self) -> bool
        """
        return _ida_hexrays.mlist_t_has_memory(self)

    def has_common(self, lst: "mlist_t") -> "bool":
        r"""
        has_common(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_has_common(self, lst)

    def includes(self, lst: "mlist_t") -> "bool":
        r"""
        includes(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_includes(self, lst)

    def intersect(self, lst: "mlist_t") -> "bool":
        r"""
        intersect(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_intersect(self, lst)

    def is_subset_of(self, lst: "mlist_t") -> "bool":
        r"""
        is_subset_of(self, lst) -> bool

        @param lst: mlist_t const &
        """
        return _ida_hexrays.mlist_t_is_subset_of(self, lst)

    def __eq__(self, r: "mlist_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___eq__(self, r)

    def __ne__(self, r: "mlist_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___ne__(self, r)

    def __lt__(self, r: "mlist_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___lt__(self, r)

    def __gt__(self, r: "mlist_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___gt__(self, r)

    def __le__(self, r: "mlist_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___le__(self, r)

    def __ge__(self, r: "mlist_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t___ge__(self, r)

    def compare(self, r: "mlist_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: mlist_t const &
        """
        return _ida_hexrays.mlist_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_mlist_t

# Register mlist_t in _ida_hexrays:
_ida_hexrays.mlist_t_swigregister(mlist_t)

def get_temp_regs() -> "mlist_t const &":
    r"""
    get_temp_regs() -> mlist_t
    Get list of temporary registers. Tempregs are temporary registers that are used
    during code generation. They do not map to regular processor registers. They are
    used only to store temporary values during execution of one instruction.
    Tempregs may not be used to pass a value from one block to another. In other
    words, at the end of a block all tempregs must be dead.
    """
    return _ida_hexrays.get_temp_regs()

def is_kreg(r: "mreg_t") -> "bool":
    r"""
    is_kreg(r) -> bool
    Is a kernel register? Kernel registers are temporary registers that can be used
    freely. They may be used to store values that cross instruction or basic block
    boundaries. Kernel registers do not map to regular processor registers. See also
    mba_t::alloc_kreg()

    @param r: (C++: mreg_t)
    """
    return _ida_hexrays.is_kreg(r)

def reg2mreg(reg: "int") -> "mreg_t":
    r"""
    reg2mreg(reg) -> mreg_t
    Map a processor register to a microregister.

    @param reg: (C++: int) processor register number
    @return: microregister register id or mr_none
    """
    return _ida_hexrays.reg2mreg(reg)

def mreg2reg(reg: "mreg_t", width: "int") -> "int":
    r"""
    mreg2reg(reg, width) -> int
    Map a microregister to a processor register.

    @param reg: (C++: mreg_t) microregister number
    @param width: (C++: int) size of microregister in bytes
    @return: processor register id or -1
    """
    return _ida_hexrays.mreg2reg(reg, width)

def get_mreg_name(reg: "mreg_t", width: "int", ud: "void *"=None) -> "qstring *":
    r"""
    get_mreg_name(reg, width, ud=None) -> int
    Get the microregister name.

    @param reg: (C++: mreg_t) microregister number
    @param width: (C++: int) size of microregister in bytes. may be bigger than the real
                  register size.
    @param ud: (C++: void *) reserved, must be nullptr
    @return: width of the printed register. this value may be less than the WIDTH
             argument.
    """
    return _ida_hexrays.get_mreg_name(reg, width, ud)
class optinsn_t(object):
    r"""
    Proxy of C++ optinsn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def func(self, blk: "mblock_t", ins: "minsn_t", optflags: "int") -> "int":
        r"""
        func(self, blk, ins, optflags) -> int
        Optimize an instruction.

        @param blk: (C++: mblock_t *) current basic block. maybe nullptr, which means that the instruction
                    must be optimized without context
        @param ins: (C++: minsn_t *) instruction to optimize; it is always a top-level instruction. the
                    callback may not delete the instruction but may convert it into nop
                    (see mblock_t::make_nop). to optimize sub-instructions, visit them
                    using minsn_visitor_t. sub-instructions may not be converted into
                    nop but can be converted to "mov x,x". for example: add x,0,x => mov
                    x,x this callback may change other instructions in the block, but
                    should do this with care, e.g. to no break the propagation algorithm
                    if called with OPTI_NO_LDXOPT.
        @param optflags: (C++: int) combination of optimization flags bits
        @return: number of changes made to the instruction. if after this call the
                 instruction's use/def lists have changed, you must mark the block level
                 lists as dirty (see mark_lists_dirty)
        """
        return _ida_hexrays.optinsn_t_func(self, blk, ins, optflags)

    def install(self) -> "void":
        r"""
        install(self)
        """
        return _ida_hexrays.optinsn_t_install(self)

    def remove(self) -> "bool":
        r"""
        remove(self) -> bool
        """
        return _ida_hexrays.optinsn_t_remove(self)
    __swig_destroy__ = _ida_hexrays.delete_optinsn_t

    def __init__(self):
        r"""
        __init__(self) -> optinsn_t

        @param self: PyObject *
        """
        if self.__class__ == optinsn_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.optinsn_t_swiginit(self, _ida_hexrays.new_optinsn_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_optinsn_t(self)
        return weakref.proxy(self)

# Register optinsn_t in _ida_hexrays:
_ida_hexrays.optinsn_t_swigregister(optinsn_t)
class optblock_t(object):
    r"""
    Proxy of C++ optblock_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def func(self, blk: "mblock_t") -> "int":
        r"""
        func(self, blk) -> int
        Optimize a block. This function usually performs the optimizations that require
        analyzing the entire block and/or its neighbors. For example it can recognize
        patterns and perform conversions like: b0: b0: ... ... jnz x, 0, @b2 => jnz x,
        0, @b2 b1: b1: add x, 0, y mov x, y ... ...

        @param blk: (C++: mblock_t *) Basic block to optimize as a whole.
        @return: number of changes made to the block. See also mark_lists_dirty.
        """
        return _ida_hexrays.optblock_t_func(self, blk)

    def install(self) -> "void":
        r"""
        install(self)
        """
        return _ida_hexrays.optblock_t_install(self)

    def remove(self) -> "bool":
        r"""
        remove(self) -> bool
        """
        return _ida_hexrays.optblock_t_remove(self)
    __swig_destroy__ = _ida_hexrays.delete_optblock_t

    def __init__(self):
        r"""
        __init__(self) -> optblock_t

        @param self: PyObject *
        """
        if self.__class__ == optblock_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.optblock_t_swiginit(self, _ida_hexrays.new_optblock_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_optblock_t(self)
        return weakref.proxy(self)

# Register optblock_t in _ida_hexrays:
_ida_hexrays.optblock_t_swigregister(optblock_t)
class simple_graph_t(ida_gdl.gdl_graph_t):
    r"""
    Proxy of C++ simple_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    title: "qstring" = property(_ida_hexrays.simple_graph_t_title_get, _ida_hexrays.simple_graph_t_title_set, doc=r"""title""")
    colored_gdl_edges: "bool" = property(_ida_hexrays.simple_graph_t_colored_gdl_edges_get, _ida_hexrays.simple_graph_t_colored_gdl_edges_set, doc=r"""colored_gdl_edges""")

    def compute_dominators(self, domin: "array_of_node_bitset_t &", post: "bool"=False) -> "void":
        r"""
        compute_dominators(self, domin, post=False)

        @param domin: array_of_node_bitset_t &
        @param post: bool
        """
        return _ida_hexrays.simple_graph_t_compute_dominators(self, domin, post)

    def compute_immediate_dominators(self, domin: "array_of_node_bitset_t const &", idomin: "intvec_t", post: "bool"=False) -> "void":
        r"""
        compute_immediate_dominators(self, domin, idomin, post=False)

        @param domin: array_of_node_bitset_t const &
        @param idomin: intvec_t &
        @param post: bool
        """
        return _ida_hexrays.simple_graph_t_compute_immediate_dominators(self, domin, idomin, post)

    def depth_first_preorder(self, pre: "node_ordering_t") -> "int":
        r"""
        depth_first_preorder(self, pre) -> int

        @param pre: node_ordering_t *
        """
        return _ida_hexrays.simple_graph_t_depth_first_preorder(self, pre)

    def depth_first_postorder(self, post: "node_ordering_t") -> "int":
        r"""
        depth_first_postorder(self, post) -> int

        @param post: node_ordering_t *
        """
        return _ida_hexrays.simple_graph_t_depth_first_postorder(self, post)

    def begin(self) -> "simple_graph_t::iterator":
        r"""
        begin(self) -> simple_graph_t::iterator
        """
        return _ida_hexrays.simple_graph_t_begin(self)

    def end(self) -> "simple_graph_t::iterator":
        r"""
        end(self) -> simple_graph_t::iterator
        """
        return _ida_hexrays.simple_graph_t_end(self)

    def front(self) -> "int":
        r"""
        front(self) -> int
        """
        return _ida_hexrays.simple_graph_t_front(self)

    def inc(self, p: "simple_graph_t::iterator &", n: "int"=1) -> "void":
        r"""
        inc(self, p, n=1)

        @param p: simple_graph_t::iterator &
        @param n: int
        """
        return _ida_hexrays.simple_graph_t_inc(self, p, n)

    def goup(self, node: "int") -> "int":
        r"""
        goup(self, node) -> int

        @param node: int
        """
        return _ida_hexrays.simple_graph_t_goup(self, node)

# Register simple_graph_t in _ida_hexrays:
_ida_hexrays.simple_graph_t_swigregister(simple_graph_t)
class op_parent_info_t(object):
    r"""
    Proxy of C++ op_parent_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t *" = property(_ida_hexrays.op_parent_info_t_mba_get, _ida_hexrays.op_parent_info_t_mba_set, doc=r"""mba""")
    blk: "mblock_t *" = property(_ida_hexrays.op_parent_info_t_blk_get, _ida_hexrays.op_parent_info_t_blk_set, doc=r"""blk""")
    topins: "minsn_t *" = property(_ida_hexrays.op_parent_info_t_topins_get, _ida_hexrays.op_parent_info_t_topins_set, doc=r"""topins""")
    curins: "minsn_t *" = property(_ida_hexrays.op_parent_info_t_curins_get, _ida_hexrays.op_parent_info_t_curins_set, doc=r"""curins""")

    def __init__(self, _mba: "mba_t"=None, _blk: "mblock_t"=None, _topins: "minsn_t"=None):
        r"""
        __init__(self, _mba=None, _blk=None, _topins=None) -> op_parent_info_t

        @param _mba: mba_t *
        @param _blk: mblock_t *
        @param _topins: minsn_t *
        """
        if self.__class__ == op_parent_info_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.op_parent_info_t_swiginit(self, _ida_hexrays.new_op_parent_info_t(_self, _mba, _blk, _topins))
    __swig_destroy__ = _ida_hexrays.delete_op_parent_info_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_op_parent_info_t(self)
        return weakref.proxy(self)

# Register op_parent_info_t in _ida_hexrays:
_ida_hexrays.op_parent_info_t_swigregister(op_parent_info_t)
class minsn_visitor_t(op_parent_info_t):
    r"""
    Proxy of C++ minsn_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _mba: "mba_t"=None, _blk: "mblock_t"=None, _topins: "minsn_t"=None):
        r"""
        __init__(self, _mba=None, _blk=None, _topins=None) -> minsn_visitor_t

        @param _mba: mba_t *
        @param _blk: mblock_t *
        @param _topins: minsn_t *
        """
        if self.__class__ == minsn_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.minsn_visitor_t_swiginit(self, _ida_hexrays.new_minsn_visitor_t(_self, _mba, _blk, _topins))

    def visit_minsn(self) -> "int":
        r"""
        visit_minsn(self) -> int
        """
        return _ida_hexrays.minsn_visitor_t_visit_minsn(self)
    __swig_destroy__ = _ida_hexrays.delete_minsn_visitor_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_minsn_visitor_t(self)
        return weakref.proxy(self)

# Register minsn_visitor_t in _ida_hexrays:
_ida_hexrays.minsn_visitor_t_swigregister(minsn_visitor_t)
class mop_visitor_t(op_parent_info_t):
    r"""
    Proxy of C++ mop_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    prune: "bool" = property(_ida_hexrays.mop_visitor_t_prune_get, _ida_hexrays.mop_visitor_t_prune_set, doc=r"""prune""")
    r"""
    Should skip sub-operands of the current operand? visit_mop() may set
    'prune=true' for that.
    """

    def __init__(self, _mba: "mba_t"=None, _blk: "mblock_t"=None, _topins: "minsn_t"=None):
        r"""
        __init__(self, _mba=None, _blk=None, _topins=None) -> mop_visitor_t

        @param _mba: mba_t *
        @param _blk: mblock_t *
        @param _topins: minsn_t *
        """
        if self.__class__ == mop_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.mop_visitor_t_swiginit(self, _ida_hexrays.new_mop_visitor_t(_self, _mba, _blk, _topins))

    def visit_mop(self, op: "mop_t", type: "tinfo_t", is_target: "bool") -> "int":
        r"""
        visit_mop(self, op, type, is_target) -> int

        @param op: mop_t *
        @param type: tinfo_t const *
        @param is_target: bool
        """
        return _ida_hexrays.mop_visitor_t_visit_mop(self, op, type, is_target)
    __swig_destroy__ = _ida_hexrays.delete_mop_visitor_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_mop_visitor_t(self)
        return weakref.proxy(self)

# Register mop_visitor_t in _ida_hexrays:
_ida_hexrays.mop_visitor_t_swigregister(mop_visitor_t)
class scif_visitor_t(object):
    r"""
    Proxy of C++ scif_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_hexrays.delete_scif_visitor_t

    def visit_scif_mop(self, r: "mop_t", off: "int") -> "int":
        r"""
        visit_scif_mop(self, r, off) -> int

        @param r: mop_t const &
        @param off: int
        """
        return _ida_hexrays.scif_visitor_t_visit_scif_mop(self, r, off)

    def __init__(self):
        r"""
        __init__(self) -> scif_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == scif_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.scif_visitor_t_swiginit(self, _ida_hexrays.new_scif_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_scif_visitor_t(self)
        return weakref.proxy(self)

# Register scif_visitor_t in _ida_hexrays:
_ida_hexrays.scif_visitor_t_swigregister(scif_visitor_t)
class mlist_mop_visitor_t(object):
    r"""
    Proxy of C++ mlist_mop_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    topins: "minsn_t *" = property(_ida_hexrays.mlist_mop_visitor_t_topins_get, _ida_hexrays.mlist_mop_visitor_t_topins_set, doc=r"""topins""")
    curins: "minsn_t *" = property(_ida_hexrays.mlist_mop_visitor_t_curins_get, _ida_hexrays.mlist_mop_visitor_t_curins_set, doc=r"""curins""")
    changed: "bool" = property(_ida_hexrays.mlist_mop_visitor_t_changed_get, _ida_hexrays.mlist_mop_visitor_t_changed_set, doc=r"""changed""")
    list: "mlist_t *" = property(_ida_hexrays.mlist_mop_visitor_t_list_get, _ida_hexrays.mlist_mop_visitor_t_list_set, doc=r"""list""")
    prune: "bool" = property(_ida_hexrays.mlist_mop_visitor_t_prune_get, _ida_hexrays.mlist_mop_visitor_t_prune_set, doc=r"""prune""")
    r"""
    Should skip sub-operands of the current operand? visit_mop() may set
    'prune=true' for that.
    """
    __swig_destroy__ = _ida_hexrays.delete_mlist_mop_visitor_t

    def visit_mop(self, op: "mop_t") -> "int":
        r"""
        visit_mop(self, op) -> int

        @param op: mop_t *
        """
        return _ida_hexrays.mlist_mop_visitor_t_visit_mop(self, op)

    def __init__(self):
        r"""
        __init__(self) -> mlist_mop_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == mlist_mop_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.mlist_mop_visitor_t_swiginit(self, _ida_hexrays.new_mlist_mop_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_mlist_mop_visitor_t(self)
        return weakref.proxy(self)

# Register mlist_mop_visitor_t in _ida_hexrays:
_ida_hexrays.mlist_mop_visitor_t_swigregister(mlist_mop_visitor_t)
class lvar_ref_t(object):
    r"""
    Proxy of C++ lvar_ref_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t *const" = property(_ida_hexrays.lvar_ref_t_mba_get, doc=r"""mba""")
    r"""
    Pointer to the parent mba_t object. Since we need to access the 'mba->vars'
    array in order to retrieve the referenced variable, we keep a pointer to mba_t
    here. Note: this means this class and consequently mop_t, minsn_t, mblock_t are
    specific to a mba_t object and cannot migrate between them. fortunately this is
    not something we need to do. second, lvar_ref_t's appear only after MMAT_LVARS.
    """
    off: "sval_t" = property(_ida_hexrays.lvar_ref_t_off_get, _ida_hexrays.lvar_ref_t_off_set, doc=r"""off""")
    r"""
    offset from the beginning of the variable
    """
    idx: "int" = property(_ida_hexrays.lvar_ref_t_idx_get, _ida_hexrays.lvar_ref_t_idx_set, doc=r"""idx""")
    r"""
    index into mba->vars
    """

    def __init__(self, *args):
        r"""
        __init__(self, m, i, o=0) -> lvar_ref_t

        @param m: mba_t *
        @param i: int
        @param o: sval_t

        __init__(self, r) -> lvar_ref_t

        @param r: lvar_ref_t const &
        """
        _ida_hexrays.lvar_ref_t_swiginit(self, _ida_hexrays.new_lvar_ref_t(*args))

    def __eq__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___eq__(self, r)

    def __ne__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___ne__(self, r)

    def __lt__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___lt__(self, r)

    def __gt__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___gt__(self, r)

    def __le__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___le__(self, r)

    def __ge__(self, r: "lvar_ref_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t___ge__(self, r)

    def compare(self, r: "lvar_ref_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: lvar_ref_t const &
        """
        return _ida_hexrays.lvar_ref_t_compare(self, r)

    def swap(self, r: "lvar_ref_t") -> "void":
        r"""
        swap(self, r)

        @param r: lvar_ref_t &
        """
        return _ida_hexrays.lvar_ref_t_swap(self, r)

    def var(self) -> "lvar_t &":
        r"""
        var(self) -> lvar_t
        Retrieve the referenced variable.
        """
        return _ida_hexrays.lvar_ref_t_var(self)
    __swig_destroy__ = _ida_hexrays.delete_lvar_ref_t

# Register lvar_ref_t in _ida_hexrays:
_ida_hexrays.lvar_ref_t_swigregister(lvar_ref_t)
mop_z = cvar.mop_z
r"""
none
"""
mop_r = cvar.mop_r
r"""
register (they exist until MMAT_LVARS)
"""
mop_n = cvar.mop_n
r"""
immediate number constant
"""
mop_str = cvar.mop_str
r"""
immediate string constant (user representation)
"""
mop_d = cvar.mop_d
r"""
result of another instruction
"""
mop_S = cvar.mop_S
r"""
local stack variable (they exist until MMAT_LVARS)
"""
mop_v = cvar.mop_v
r"""
global variable
"""
mop_b = cvar.mop_b
r"""
micro basic block (mblock_t)
"""
mop_f = cvar.mop_f
r"""
list of arguments
"""
mop_l = cvar.mop_l
r"""
local variable
"""
mop_a = cvar.mop_a
r"""
mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
"""
mop_h = cvar.mop_h
r"""
helper function
"""
mop_c = cvar.mop_c
r"""
mcases
"""
mop_fn = cvar.mop_fn
r"""
floating point constant
"""
mop_p = cvar.mop_p
r"""
operand pair
"""
mop_sc = cvar.mop_sc
r"""
scattered
"""
NOSIZE = cvar.NOSIZE
r"""
wrong or unexisting operand size
"""

class stkvar_ref_t(object):
    r"""
    Proxy of C++ stkvar_ref_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t *const" = property(_ida_hexrays.stkvar_ref_t_mba_get, doc=r"""mba""")
    r"""
    Pointer to the parent mba_t object. We need it in order to retrieve the
    referenced stack variable. See notes for lvar_ref_t::mba.
    """
    off: "sval_t" = property(_ida_hexrays.stkvar_ref_t_off_get, _ida_hexrays.stkvar_ref_t_off_set, doc=r"""off""")
    r"""
    Offset to the stack variable from the bottom of the stack frame. It is called
    'decompiler stkoff' and it is different from IDA stkoff. See a note and a
    picture about 'decompiler stkoff' below.
    """

    def __init__(self, m: "mba_t", o: "sval_t"):
        r"""
        __init__(self, m, o) -> stkvar_ref_t

        @param m: mba_t *
        @param o: sval_t
        """
        _ida_hexrays.stkvar_ref_t_swiginit(self, _ida_hexrays.new_stkvar_ref_t(m, o))

    def __eq__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___eq__(self, r)

    def __ne__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___ne__(self, r)

    def __lt__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___lt__(self, r)

    def __gt__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___gt__(self, r)

    def __le__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___le__(self, r)

    def __ge__(self, r: "stkvar_ref_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t___ge__(self, r)

    def compare(self, r: "stkvar_ref_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: stkvar_ref_t const &
        """
        return _ida_hexrays.stkvar_ref_t_compare(self, r)

    def swap(self, r: "stkvar_ref_t") -> "void":
        r"""
        swap(self, r)

        @param r: stkvar_ref_t &
        """
        return _ida_hexrays.stkvar_ref_t_swap(self, r)

    def get_stkvar(self, udm: "udm_t"=None, p_idaoff: "uval_t *"=None) -> "ssize_t":
        r"""
        get_stkvar(self, udm=None, p_idaoff=None) -> ssize_t
        Retrieve the referenced stack variable.

        @param udm: (C++: udm_t *) stkvar, may be nullptr
        @param p_idaoff: (C++: uval_t *) if specified, will hold IDA stkoff after the call.
        @return: index of stkvar in the frame or -1
        """
        return _ida_hexrays.stkvar_ref_t_get_stkvar(self, udm, p_idaoff)
    __swig_destroy__ = _ida_hexrays.delete_stkvar_ref_t

# Register stkvar_ref_t in _ida_hexrays:
_ida_hexrays.stkvar_ref_t_swigregister(stkvar_ref_t)
class scif_t(vdloc_t):
    r"""
    Proxy of C++ scif_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t *" = property(_ida_hexrays.scif_t_mba_get, _ida_hexrays.scif_t_mba_set, doc=r"""mba""")
    r"""
    Pointer to the parent mba_t object. Some operations may convert a scattered
    operand into something simpler, (a stack operand, for example). We will need to
    create stkvar_ref_t at that moment, this is why we need this pointer. See notes
    for lvar_ref_t::mba.
    """
    name: "qstring" = property(_ida_hexrays.scif_t_name_get, _ida_hexrays.scif_t_name_set, doc=r"""name""")
    r"""
    Usually scattered operands are created from a function prototype, which has the
    name information. We preserve it and use it to name the corresponding local
    variable.
    """
    type: "tinfo_t" = property(_ida_hexrays.scif_t_type_get, _ida_hexrays.scif_t_type_set, doc=r"""type""")
    r"""
    Scattered operands always have type info assigned to them because without it we
    won't be able to manipulte them.
    """

    def __init__(self, _mba: "mba_t", tif: "tinfo_t", n: "qstring *"=None):
        r"""
        __init__(self, _mba, tif, n=None) -> scif_t

        @param _mba: mba_t *
        @param tif: tinfo_t *
        @param n: qstring *
        """
        _ida_hexrays.scif_t_swiginit(self, _ida_hexrays.new_scif_t(_mba, tif, n))
    __swig_destroy__ = _ida_hexrays.delete_scif_t

# Register scif_t in _ida_hexrays:
_ida_hexrays.scif_t_swigregister(scif_t)
class mnumber_t(operand_locator_t):
    r"""
    Proxy of C++ mnumber_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    value: "uint64" = property(_ida_hexrays.mnumber_t_value_get, _ida_hexrays.mnumber_t_value_set, doc=r"""value""")
    org_value: "uint64" = property(_ida_hexrays.mnumber_t_org_value_get, _ida_hexrays.mnumber_t_org_value_set, doc=r"""org_value""")

    def __init__(self, *args):
        r"""
        __init__(self, v, _ea=BADADDR, n=0) -> mnumber_t

        @param v: uint64
        @param _ea: ea_t
        @param n: int
        """
        _ida_hexrays.mnumber_t_swiginit(self, _ida_hexrays.new_mnumber_t(*args))

    def __eq__(self, r: "mnumber_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___eq__(self, r)

    def __ne__(self, r: "mnumber_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___ne__(self, r)

    def __lt__(self, r: "mnumber_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___lt__(self, r)

    def __gt__(self, r: "mnumber_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___gt__(self, r)

    def __le__(self, r: "mnumber_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___le__(self, r)

    def __ge__(self, r: "mnumber_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t___ge__(self, r)

    def compare(self, r: "mnumber_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: mnumber_t const &
        """
        return _ida_hexrays.mnumber_t_compare(self, r)

    def update_value(self, val64: "uint64") -> "void":
        r"""
        update_value(self, val64)

        @param val64: uint64
        """
        return _ida_hexrays.mnumber_t_update_value(self, val64)
    __swig_destroy__ = _ida_hexrays.delete_mnumber_t

# Register mnumber_t in _ida_hexrays:
_ida_hexrays.mnumber_t_swigregister(mnumber_t)
class fnumber_t(object):
    r"""
    Proxy of C++ fnumber_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    fnum: "fpvalue_t" = property(_ida_hexrays.fnumber_t_fnum_get, _ida_hexrays.fnumber_t_fnum_set, doc=r"""fnum""")
    r"""
    Internal representation of the number.
    """
    nbytes: "int" = property(_ida_hexrays.fnumber_t_nbytes_get, _ida_hexrays.fnumber_t_nbytes_set, doc=r"""nbytes""")
    r"""
    Original size of the constant in bytes.
    """

    def dereference_uint16(self) -> "uint16 *":
        r"""
        dereference_uint16(self) -> uint16 *
        """
        return _ida_hexrays.fnumber_t_dereference_uint16(self)

    def dereference_const_uint16(self) -> "uint16 const *":
        r"""
        dereference_const_uint16(self) -> uint16 const *
        """
        return _ida_hexrays.fnumber_t_dereference_const_uint16(self)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.fnumber_t__print(self)

    def __eq__(self, r: "fnumber_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___eq__(self, r)

    def __ne__(self, r: "fnumber_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___ne__(self, r)

    def __lt__(self, r: "fnumber_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___lt__(self, r)

    def __gt__(self, r: "fnumber_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___gt__(self, r)

    def __le__(self, r: "fnumber_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___le__(self, r)

    def __ge__(self, r: "fnumber_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t___ge__(self, r)

    def compare(self, r: "fnumber_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: fnumber_t const &
        """
        return _ida_hexrays.fnumber_t_compare(self, r)

    def calc_max_exp(self) -> "int":
        r"""
        calc_max_exp(self) -> int
        """
        return _ida_hexrays.fnumber_t_calc_max_exp(self)

    def is_nan(self) -> "bool":
        r"""
        is_nan(self) -> bool
        """
        return _ida_hexrays.fnumber_t_is_nan(self)

    def __init__(self):
        r"""
        __init__(self) -> fnumber_t
        """
        _ida_hexrays.fnumber_t_swiginit(self, _ida_hexrays.new_fnumber_t())
    __swig_destroy__ = _ida_hexrays.delete_fnumber_t

# Register fnumber_t in _ida_hexrays:
_ida_hexrays.fnumber_t_swigregister(fnumber_t)
SHINS_NUMADDR = _ida_hexrays.SHINS_NUMADDR
r"""
display definition addresses for numbers
"""

SHINS_VALNUM = _ida_hexrays.SHINS_VALNUM
r"""
display value numbers
"""

SHINS_SHORT = _ida_hexrays.SHINS_SHORT
r"""
do not display use-def chains and other attrs
"""

SHINS_LDXEA = _ida_hexrays.SHINS_LDXEA
r"""
display address of ldx expressions (not used)
"""

NO_SIDEFF = _ida_hexrays.NO_SIDEFF
r"""
change operand size but ignore side effects if you decide to keep the changed
operand, handle_new_size() must be called
"""

WITH_SIDEFF = _ida_hexrays.WITH_SIDEFF
r"""
change operand size and handle side effects
"""

ONLY_SIDEFF = _ida_hexrays.ONLY_SIDEFF
r"""
only handle side effects
"""

ANY_REGSIZE = _ida_hexrays.ANY_REGSIZE
r"""
any register size is permitted
"""

ANY_FPSIZE = _ida_hexrays.ANY_FPSIZE
r"""
any size of floating operand is permitted
"""

class mop_t(object):
    r"""
    Proxy of C++ mop_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    t: "mopt_t" = property(_ida_hexrays.mop_t_t_get, _ida_hexrays.mop_t_t_set, doc=r"""t""")
    r"""
    Operand type.
    """
    oprops: "uint8" = property(_ida_hexrays.mop_t_oprops_get, _ida_hexrays.mop_t_oprops_set, doc=r"""oprops""")
    r"""
    Operand properties.
    """
    valnum: "uint16" = property(_ida_hexrays.mop_t_valnum_get, _ida_hexrays.mop_t_valnum_set, doc=r"""valnum""")
    r"""
    Value number. Zero means unknown. Operands with the same value number are equal.
    """
    size: "int" = property(_ida_hexrays.mop_t_size_get, _ida_hexrays.mop_t_size_set, doc=r"""size""")
    r"""
    Operand size. Usually it is 1,2,4,8 or NOSIZE but for UDTs other sizes are
    permitted
    """

    def set_impptr_done(self) -> "void":
        r"""
        set_impptr_done(self)
        """
        return _ida_hexrays.mop_t_set_impptr_done(self)

    def set_udt(self) -> "void":
        r"""
        set_udt(self)
        """
        return _ida_hexrays.mop_t_set_udt(self)

    def set_undef_val(self) -> "void":
        r"""
        set_undef_val(self)
        """
        return _ida_hexrays.mop_t_set_undef_val(self)

    def set_lowaddr(self) -> "void":
        r"""
        set_lowaddr(self)
        """
        return _ida_hexrays.mop_t_set_lowaddr(self)

    def is_impptr_done(self) -> "bool":
        r"""
        is_impptr_done(self) -> bool
        """
        return _ida_hexrays.mop_t_is_impptr_done(self)

    def is_udt(self) -> "bool":
        r"""
        is_udt(self) -> bool
        """
        return _ida_hexrays.mop_t_is_udt(self)

    def probably_floating(self) -> "bool":
        r"""
        probably_floating(self) -> bool
        """
        return _ida_hexrays.mop_t_probably_floating(self)

    def is_undef_val(self) -> "bool":
        r"""
        is_undef_val(self) -> bool
        """
        return _ida_hexrays.mop_t_is_undef_val(self)

    def is_lowaddr(self) -> "bool":
        r"""
        is_lowaddr(self) -> bool
        """
        return _ida_hexrays.mop_t_is_lowaddr(self)

    def is_ccflags(self) -> "bool":
        r"""
        is_ccflags(self) -> bool
        """
        return _ida_hexrays.mop_t_is_ccflags(self)

    def is_pcval(self) -> "bool":
        r"""
        is_pcval(self) -> bool
        """
        return _ida_hexrays.mop_t_is_pcval(self)

    def is_glbaddr_from_fixup(self) -> "bool":
        r"""
        is_glbaddr_from_fixup(self) -> bool
        """
        return _ida_hexrays.mop_t_is_glbaddr_from_fixup(self)

    def __init__(self, *args):
        r"""
        __init__(self) -> mop_t
        __init__(self, rop) -> mop_t

        @param rop: mop_t const &

        __init__(self, _r, _s) -> mop_t

        @param _r: mreg_t
        @param _s: int
        """
        _ida_hexrays.mop_t_swiginit(self, _ida_hexrays.new_mop_t(*args))

    def assign(self, rop: "mop_t") -> "mop_t &":
        r"""
        assign(self, rop) -> mop_t

        @param rop: mop_t const &
        """
        return _ida_hexrays.mop_t_assign(self, rop)
    __swig_destroy__ = _ida_hexrays.delete_mop_t

    def zero(self) -> "void":
        r"""
        zero(self)
        """
        return _ida_hexrays.mop_t_zero(self)

    def swap(self, rop: "mop_t") -> "void":
        r"""
        swap(self, rop)

        @param rop: mop_t &
        """
        return _ida_hexrays.mop_t_swap(self, rop)

    def erase(self) -> "void":
        r"""
        erase(self)
        """
        return _ida_hexrays.mop_t_erase(self)

    def erase_but_keep_size(self) -> "void":
        r"""
        erase_but_keep_size(self)
        """
        return _ida_hexrays.mop_t_erase_but_keep_size(self)

    def _print(self, *args) -> "void":
        r"""
        _print(self, shins_flags=0x04|0x02)

        Parameters
        ----------
        shins_flags: int

        """
        return _ida_hexrays.mop_t__print(self, *args)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.mop_t_dstr(self)

    def create_from_mlist(self, mba: "mba_t", lst: "mlist_t", fullsize: "sval_t") -> "bool":
        r"""
        create_from_mlist(self, mba, lst, fullsize) -> bool
        Create operand from mlist_t. Example: if LST contains 4 bits for R0.4, our
        operand will be (t=mop_r, r=R0, size=4)

        @param mba: (C++: mba_t *) pointer to microcode
        @param lst: (C++: const mlist_t &) list of locations
        @param fullsize: (C++: sval_t) mba->fullsize
        @return: success
        """
        return _ida_hexrays.mop_t_create_from_mlist(self, mba, lst, fullsize)

    def create_from_ivlset(self, mba: "mba_t", ivs: "ivlset_t", fullsize: "sval_t") -> "bool":
        r"""
        create_from_ivlset(self, mba, ivs, fullsize) -> bool
        Create operand from ivlset_t. Example: if IVS contains [glbvar..glbvar+4), our
        operand will be (t=mop_v, g=&glbvar, size=4)

        @param mba: (C++: mba_t *) pointer to microcode
        @param ivs: (C++: const ivlset_t &) set of memory intervals
        @param fullsize: (C++: sval_t) mba->fullsize
        @return: success
        """
        return _ida_hexrays.mop_t_create_from_ivlset(self, mba, ivs, fullsize)

    def create_from_vdloc(self, mba: "mba_t", loc: "vdloc_t", _size: "int") -> "void":
        r"""
        create_from_vdloc(self, mba, loc, _size)
        Create operand from vdloc_t. Example: if LOC contains (type=ALOC_REG1, r=R0),
        our operand will be (t=mop_r, r=R0, size=_SIZE)

        @param mba: (C++: mba_t *) pointer to microcode
        @param loc: (C++: const vdloc_t &) location
        @param _size: (C++: int) operand size Note: this function cannot handle scattered
                      locations.
        @return: success
        """
        return _ida_hexrays.mop_t_create_from_vdloc(self, mba, loc, _size)

    def create_from_scattered_vdloc(self, mba: "mba_t", name: "char const *", type: "tinfo_t", loc: "vdloc_t") -> "void":
        r"""
        create_from_scattered_vdloc(self, mba, name, type, loc)
        Create operand from scattered vdloc_t. Example: if LOC is (ALOC_DIST, {EAX.4,
        EDX.4}) and TYPE is _LARGE_INTEGER, our operand will be (t=mop_sc, scif={EAX.4,
        EDX.4})

        @param mba: (C++: mba_t *) pointer to microcode
        @param name: (C++: const char *) name of the operand, if available
        @param type: (C++: tinfo_t) type of the operand, must be present
        @param loc: (C++: const vdloc_t &) a scattered location
        @return: success
        """
        return _ida_hexrays.mop_t_create_from_scattered_vdloc(self, mba, name, type, loc)

    def create_from_insn(self, m: "minsn_t") -> "void":
        r"""
        create_from_insn(self, m)
        Create operand from an instruction. This function creates a nested instruction
        that can be used as an operand. Example: if m="add x,y,z", our operand will be
        (t=mop_d,d=m). The destination operand of 'add' (z) is lost.

        @param m: (C++: const minsn_t *) instruction to embed into operand. may not be nullptr.
        """
        return _ida_hexrays.mop_t_create_from_insn(self, m)

    def make_number(self, *args) -> "void":
        r"""
        make_number(self, _value, _size, _ea=BADADDR, opnum=0)
        Create an integer constant operand.

        @param _value: (C++: uint64) value to store in the operand
        @param _size: (C++: int) size of the value in bytes (1,2,4,8)
        @param _ea: (C++: ea_t) address of the processor instruction that made the value
        @param opnum: (C++: int) operand number of the processor instruction
        """
        return _ida_hexrays.mop_t_make_number(self, *args)

    def make_fpnum(self, bytes: "void const *") -> "bool":
        r"""
        make_fpnum(self, bytes) -> bool
        Create a floating point constant operand.

        @param bytes: (C++: const void *) pointer to the floating point value as used by the current
                      processor (e.g. for x86 it must be in IEEE 754)
        @return: success
        """
        return _ida_hexrays.mop_t_make_fpnum(self, bytes)

    def _make_reg(self, *args) -> "void":
        r"""
        _make_reg(self, reg)

        Parameters
        ----------
        reg: mreg_t

        _make_reg(self, reg, _size)

        Parameters
        ----------
        reg: mreg_t
        _size: int

        """
        return _ida_hexrays.mop_t__make_reg(self, *args)

    def make_reg(self, *args) -> "void":
        r"""
        make_reg(self, reg)

        @param reg: mreg_t

        make_reg(self, reg, _size)

        @param reg: mreg_t
        @param _size: int
        """
        return _ida_hexrays.mop_t_make_reg(self, *args)

    def _make_lvar(self, mba: "mba_t", idx: "int", off: "sval_t"=0) -> "void":
        r"""
        _make_lvar(self, mba, idx, off=0)

        Parameters
        ----------
        mba: mba_t *
        idx: int
        off: sval_t

        """
        return _ida_hexrays.mop_t__make_lvar(self, mba, idx, off)

    def _make_gvar(self, ea: "ea_t") -> "void":
        r"""
        _make_gvar(self, ea)

        Parameters
        ----------
        ea: ea_t

        """
        return _ida_hexrays.mop_t__make_gvar(self, ea)

    def make_gvar(self, ea: "ea_t") -> "void":
        r"""
        make_gvar(self, ea)
        Create a global variable operand.

        @param ea: (C++: ea_t)
        """
        return _ida_hexrays.mop_t_make_gvar(self, ea)

    def _make_stkvar(self, mba: "mba_t", off: "sval_t") -> "void":
        r"""
        _make_stkvar(self, mba, off)

        Parameters
        ----------
        mba: mba_t *
        off: sval_t

        """
        return _ida_hexrays.mop_t__make_stkvar(self, mba, off)

    def make_stkvar(self, mba: "mba_t", off: "sval_t") -> "void":
        r"""
        make_stkvar(self, mba, off)

        @param mba: mba_t *
        @param off: sval_t
        """
        return _ida_hexrays.mop_t_make_stkvar(self, mba, off)

    def make_reg_pair(self, loreg: "int", hireg: "int", halfsize: "int") -> "void":
        r"""
        make_reg_pair(self, loreg, hireg, halfsize)
        Create pair of registers.

        @param loreg: (C++: int) register holding the low part of the value
        @param hireg: (C++: int) register holding the high part of the value
        @param halfsize: (C++: int) the size of each of loreg/hireg
        """
        return _ida_hexrays.mop_t_make_reg_pair(self, loreg, hireg, halfsize)

    def _make_insn(self, ins: "minsn_t") -> "void":
        r"""
        _make_insn(self, ins)

        Parameters
        ----------
        ins: minsn_t *

        """

        o = ins
        self._ensure_cond(self.t == mop_z, "self.t == mop_z")


        val = _ida_hexrays.mop_t__make_insn(self, ins)

        self._acquire_ownership(o, True)


        return val


    def make_insn(self, ins: "minsn_t") -> "void":
        r"""
        make_insn(self, ins)
        Create a nested instruction.

        @param ins: (C++: minsn_t *)
        """

        o = ins
        self._ensure_cond(self.t == mop_z, "self.t == mop_z")


        val = _ida_hexrays.mop_t_make_insn(self, ins)

        self._acquire_ownership(o, True)


        return val


    def _make_blkref(self, blknum: "int") -> "void":
        r"""
        _make_blkref(self, blknum)

        Parameters
        ----------
        blknum: int

        """
        return _ida_hexrays.mop_t__make_blkref(self, blknum)

    def make_blkref(self, blknum: "int") -> "void":
        r"""
        make_blkref(self, blknum)
        Create a global variable operand.

        @param blknum: (C++: int)
        """
        return _ida_hexrays.mop_t_make_blkref(self, blknum)

    def make_helper(self, name: "char const *") -> "void":
        r"""
        make_helper(self, name)
        Create a helper operand. A helper operand usually keeps a built-in function name
        like "va_start" It is essentially just an arbitrary identifier without any
        additional info.

        @param name: (C++: const char *) char const *
        """
        return _ida_hexrays.mop_t_make_helper(self, name)

    def _make_strlit(self, str: "char const *") -> "void":
        r"""
        _make_strlit(self, str)

        Parameters
        ----------
        str: char const *

        """
        return _ida_hexrays.mop_t__make_strlit(self, str)

    def _make_callinfo(self, fi: "mcallinfo_t") -> "void":
        r"""
        _make_callinfo(self, fi)

        Parameters
        ----------
        fi: mcallinfo_t *

        """

        o = fi
        self._ensure_cond(self.t == mop_z, "self.t == mop_z")


        val = _ida_hexrays.mop_t__make_callinfo(self, fi)

        self._acquire_ownership(o, True)


        return val


    def _make_cases(self, _cases: "mcases_t") -> "void":
        r"""
        _make_cases(self, _cases)

        Parameters
        ----------
        _cases: mcases_t *

        """

        o = _cases
        self._ensure_cond(self.t == mop_z, "self.t == mop_z")


        val = _ida_hexrays.mop_t__make_cases(self, _cases)

        self._acquire_ownership(o, True)


        return val


    def _make_pair(self, _pair: "mop_pair_t") -> "void":
        r"""
        _make_pair(self, _pair)

        Parameters
        ----------
        _pair: mop_pair_t *

        """

        o = _pair
        self._ensure_cond(self.t == mop_z, "self.t == mop_z")


        val = _ida_hexrays.mop_t__make_pair(self, _pair)

        self._acquire_ownership(o, True)


        return val


    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mop_t_empty(self)

    def is_reg(self, *args) -> "bool":
        r"""
        is_reg(self) -> bool
        Is the specified register of the specified size?
        is_reg(self, _r) -> bool

        @param _r: mreg_t

        is_reg(self, _r, _size) -> bool

        @param _r: mreg_t
        @param _size: int
        """
        return _ida_hexrays.mop_t_is_reg(self, *args)

    def is_arglist(self) -> "bool":
        r"""
        is_arglist(self) -> bool
        Is a list of arguments?
        """
        return _ida_hexrays.mop_t_is_arglist(self)

    def is_cc(self) -> "bool":
        r"""
        is_cc(self) -> bool
        Is a condition code?
        """
        return _ida_hexrays.mop_t_is_cc(self)

    def is_bit_reg(self, *args) -> "bool":
        r"""
        is_bit_reg(self, reg) -> bool
        Is a bit register? This includes condition codes and eventually other bit
        registers

        @param reg: (C++: mreg_t)

        is_bit_reg(self) -> bool
        """
        return _ida_hexrays.mop_t_is_bit_reg(self, *args)

    def is_kreg(self) -> "bool":
        r"""
        is_kreg(self) -> bool
        Is a kernel register?
        """
        return _ida_hexrays.mop_t_is_kreg(self)

    def is_mob(self, serial: "int") -> "bool":
        r"""
        is_mob(self, serial) -> bool
        Is a block reference to the specified block?

        @param serial: (C++: int)
        """
        return _ida_hexrays.mop_t_is_mob(self, serial)

    def is_scattered(self) -> "bool":
        r"""
        is_scattered(self) -> bool
        Is a scattered operand?
        """
        return _ida_hexrays.mop_t_is_scattered(self)

    def is_glbaddr(self, *args) -> "bool":
        r"""
        is_glbaddr(self) -> bool
        Is address of the specified global memory cell?
        is_glbaddr(self, ea) -> bool

        @param ea: ea_t
        """
        return _ida_hexrays.mop_t_is_glbaddr(self, *args)

    def is_stkaddr(self) -> "bool":
        r"""
        is_stkaddr(self) -> bool
        Is address of a stack variable?
        """
        return _ida_hexrays.mop_t_is_stkaddr(self)

    def is_insn(self, *args) -> "bool":
        r"""
        is_insn(self) -> bool
        Is a sub-instruction with the specified opcode?
        is_insn(self, code) -> bool

        @param code: enum mcode_t
        """
        return _ida_hexrays.mop_t_is_insn(self, *args)

    def has_side_effects(self, include_ldx_and_divs: "bool"=False) -> "bool":
        r"""
        has_side_effects(self, include_ldx_and_divs=False) -> bool
        Has any side effects?

        @param include_ldx_and_divs: (C++: bool) consider ldx/div/mod as having side effects?
        """
        return _ida_hexrays.mop_t_has_side_effects(self, include_ldx_and_divs)

    def may_use_aliased_memory(self) -> "bool":
        r"""
        may_use_aliased_memory(self) -> bool
        Is it possible for the operand to use aliased memory?
        """
        return _ida_hexrays.mop_t_may_use_aliased_memory(self)

    def is01(self) -> "bool":
        r"""
        is01(self) -> bool
        Are the possible values of the operand only 0 and 1? This function returns true
        for 0/1 constants, bit registers, the result of 'set' insns, etc.
        """
        return _ida_hexrays.mop_t_is01(self)

    def is_sign_extended_from(self, nbytes: "int") -> "bool":
        r"""
        is_sign_extended_from(self, nbytes) -> bool
        Does the high part of the operand consist of the sign bytes?

        @param nbytes: (C++: int) number of bytes that were sign extended. the remaining size-
                       nbytes high bytes must be sign bytes Example:
                       is_sign_extended_from(xds.4(op.1), 1) -> true because the high 3
                       bytes are certainly sign bits
        """
        return _ida_hexrays.mop_t_is_sign_extended_from(self, nbytes)

    def is_zero_extended_from(self, nbytes: "int") -> "bool":
        r"""
        is_zero_extended_from(self, nbytes) -> bool
        Does the high part of the operand consist of zero bytes?

        @param nbytes: (C++: int) number of bytes that were zero extended. the remaining size-
                       nbytes high bytes must be zero Example:
                       is_zero_extended_from(xdu.8(op.1), 2) -> true because the high 6
                       bytes are certainly zero
        """
        return _ida_hexrays.mop_t_is_zero_extended_from(self, nbytes)

    def is_extended_from(self, nbytes: "int", is_signed: "bool") -> "bool":
        r"""
        is_extended_from(self, nbytes, is_signed) -> bool
        Does the high part of the operand consist of zero or sign bytes?

        @param nbytes: (C++: int)
        @param is_signed: (C++: bool)
        """
        return _ida_hexrays.mop_t_is_extended_from(self, nbytes, is_signed)

    def equal_mops(self, rop: "mop_t", eqflags: "int") -> "bool":
        r"""
        equal_mops(self, rop, eqflags) -> bool
        Compare operands. This is the main comparison function for operands.

        @param rop: (C++: const mop_t &) operand to compare with
        @param eqflags: (C++: int) combination of comparison bits bits
        """
        return _ida_hexrays.mop_t_equal_mops(self, rop, eqflags)

    def __eq__(self, rop: "mop_t") -> "bool":
        r"""
        __eq__(self, rop) -> bool

        @param rop: mop_t const &
        """
        return _ida_hexrays.mop_t___eq__(self, rop)

    def __ne__(self, rop: "mop_t") -> "bool":
        r"""
        __ne__(self, rop) -> bool

        @param rop: mop_t const &
        """
        return _ida_hexrays.mop_t___ne__(self, rop)

    def __lt__(self, rop: "mop_t") -> "bool":
        r"""
        __lt__(self, rop) -> bool

        @param rop: mop_t const &
        """
        return _ida_hexrays.mop_t___lt__(self, rop)

    def lexcompare(self, rop: "mop_t") -> "int":
        r"""
        lexcompare(self, rop) -> int

        @param rop: mop_t const &
        """
        return _ida_hexrays.mop_t_lexcompare(self, rop)

    def for_all_ops(self, mv: "mop_visitor_t", type: "tinfo_t"=None, is_target: "bool"=False) -> "int":
        r"""
        for_all_ops(self, mv, type=None, is_target=False) -> int
        Visit the operand and all its sub-operands. This function visits the current
        operand as well.

        @param mv: (C++: mop_visitor_t &) visitor object
        @param type: (C++: const tinfo_t *) operand type
        @param is_target: (C++: bool) is a destination operand?
        """
        return _ida_hexrays.mop_t_for_all_ops(self, mv, type, is_target)

    def for_all_scattered_submops(self, sv: "scif_visitor_t") -> "int":
        r"""
        for_all_scattered_submops(self, sv) -> int
        Visit all sub-operands of a scattered operand. This function does not visit the
        current operand, only its sub-operands. All sub-operands are synthetic and are
        destroyed after the visitor. This function works only with scattered operands.

        @param sv: (C++: scif_visitor_t &) visitor object
        """
        return _ida_hexrays.mop_t_for_all_scattered_submops(self, sv)

    def value(self, is_signed: "bool") -> "uint64":
        r"""
        value(self, is_signed) -> uint64
        Retrieve value of a constant integer operand. These functions can be called only
        for mop_n operands. See is_constant() that can be called on any operand.

        @param is_signed: (C++: bool)
        """
        return _ida_hexrays.mop_t_value(self, is_signed)

    def signed_value(self) -> "int64":
        r"""
        signed_value(self) -> int64
        """
        return _ida_hexrays.mop_t_signed_value(self)

    def unsigned_value(self) -> "uint64":
        r"""
        unsigned_value(self) -> uint64
        """
        return _ida_hexrays.mop_t_unsigned_value(self)

    def update_numop_value(self, val: "uint64") -> "void":
        r"""
        update_numop_value(self, val)

        @param val: uint64
        """
        return _ida_hexrays.mop_t_update_numop_value(self, val)

    def is_constant(self, is_signed: "bool"=True) -> "bool":
        r"""
        is_constant(self, is_signed=True) -> bool
        Retrieve value of a constant integer operand.

        @param is_signed: (C++: bool) should treat the value as signed
        @return: true if the operand is mop_n
        """
        return _ida_hexrays.mop_t_is_constant(self, is_signed)

    def is_equal_to(self, n: "uint64", is_signed: "bool"=True) -> "bool":
        r"""
        is_equal_to(self, n, is_signed=True) -> bool

        @param n: uint64
        @param is_signed: bool
        """
        return _ida_hexrays.mop_t_is_equal_to(self, n, is_signed)

    def is_zero(self) -> "bool":
        r"""
        is_zero(self) -> bool
        """
        return _ida_hexrays.mop_t_is_zero(self)

    def is_one(self) -> "bool":
        r"""
        is_one(self) -> bool
        """
        return _ida_hexrays.mop_t_is_one(self)

    def is_positive_constant(self) -> "bool":
        r"""
        is_positive_constant(self) -> bool
        """
        return _ida_hexrays.mop_t_is_positive_constant(self)

    def is_negative_constant(self) -> "bool":
        r"""
        is_negative_constant(self) -> bool
        """
        return _ida_hexrays.mop_t_is_negative_constant(self)

    def get_stkvar(self, udm: "udm_t"=None, p_idaoff: "uval_t *"=None) -> "ssize_t":
        r"""
        get_stkvar(self, udm=None, p_idaoff=None) -> ssize_t
        Retrieve the referenced stack variable.

        @param udm: (C++: udm_t *) stkvar, may be nullptr
        @param p_idaoff: (C++: uval_t *) if specified, will hold IDA stkoff after the call.
        @return: index of stkvar in the frame or -1
        """
        return _ida_hexrays.mop_t_get_stkvar(self, udm, p_idaoff)

    def get_stkoff(self, p_vdoff: "sval_t *") -> "bool":
        r"""
        get_stkoff(self, p_vdoff) -> bool
        Get the referenced stack offset. This function can also handle mop_sc if it is
        entirely mapped into a continuous stack region.

        @param p_vdoff: (C++: sval_t *) the output buffer
        @return: success
        """
        return _ida_hexrays.mop_t_get_stkoff(self, p_vdoff)

    def get_insn(self, *args) -> "minsn_t *":
        r"""
        get_insn(self, code) -> minsn_t

        @param code: enum mcode_t

        """
        return _ida_hexrays.mop_t_get_insn(self, *args)

    def make_low_half(self, width: "int") -> "bool":
        r"""
        make_low_half(self, width) -> bool
        Make the low part of the operand. This function takes into account the memory
        endianness (byte sex)

        @param width: (C++: int) the desired size of the operand part in bytes
        @return: success
        """
        return _ida_hexrays.mop_t_make_low_half(self, width)

    def make_high_half(self, width: "int") -> "bool":
        r"""
        make_high_half(self, width) -> bool
        Make the high part of the operand. This function takes into account the memory
        endianness (byte sex)

        @param width: (C++: int) the desired size of the operand part in bytes
        @return: success
        """
        return _ida_hexrays.mop_t_make_high_half(self, width)

    def make_first_half(self, width: "int") -> "bool":
        r"""
        make_first_half(self, width) -> bool
        Make the first part of the operand. This function does not care about the memory
        endianness

        @param width: (C++: int) the desired size of the operand part in bytes
        @return: success
        """
        return _ida_hexrays.mop_t_make_first_half(self, width)

    def make_second_half(self, width: "int") -> "bool":
        r"""
        make_second_half(self, width) -> bool
        Make the second part of the operand. This function does not care about the
        memory endianness

        @param width: (C++: int) the desired size of the operand part in bytes
        @return: success
        """
        return _ida_hexrays.mop_t_make_second_half(self, width)

    def shift_mop(self, offset: "int") -> "bool":
        r"""
        shift_mop(self, offset) -> bool
        Shift the operand. This function shifts only the beginning of the operand. The
        operand size will be changed. Examples: shift_mop(AH.1, -1) -> AX.2
        shift_mop(qword_00000008.8, 4) -> dword_0000000C.4 shift_mop(xdu.8(op.4), 4) ->
        #0.4 shift_mop(#0x12345678.4, 3) -> #12.1

        @param offset: (C++: int) shift count (the number of bytes to shift)
        @return: success
        """
        return _ida_hexrays.mop_t_shift_mop(self, offset)

    def change_size(self, nsize: "int", sideff: "side_effect_t"=WITH_SIDEFF) -> "bool":
        r"""
        change_size(self, nsize, sideff=WITH_SIDEFF) -> bool
        Change the operand size. Examples: change_size(AL.1, 2) -> AX.2
        change_size(qword_00000008.8, 4) -> dword_00000008.4 change_size(xdu.8(op.4), 4)
        -> op.4 change_size(#0x12345678.4, 1) -> #0x78.1

        @param nsize: (C++: int) new operand size
        @param sideff: (C++: side_effect_t) may modify the database because of the size change?
        @return: success
        """
        return _ida_hexrays.mop_t_change_size(self, nsize, sideff)

    def double_size(self, sideff: "side_effect_t"=WITH_SIDEFF) -> "bool":
        r"""
        double_size(self, sideff=WITH_SIDEFF) -> bool

        @param sideff: enum side_effect_t
        """
        return _ida_hexrays.mop_t_double_size(self, sideff)

    def preserve_side_effects(self, blk: "mblock_t", top: "minsn_t", moved_calls: "bool *"=None) -> "bool":
        r"""
        preserve_side_effects(self, blk, top, moved_calls=None) -> bool
        Move subinstructions with side effects out of the operand. If we decide to
        delete an instruction operand, it is a good idea to call this function.
        Alternatively we should skip such operands by calling mop_t::has_side_effects()
        For example, if we transform: jnz x, x, @blk => goto @blk then we must call this
        function before deleting the X operands.

        @param blk: (C++: mblock_t *) current block
        @param top: (C++: minsn_t *) top level instruction that contains our operand
        @param moved_calls: (C++: bool *) pointer to the boolean that will track if all side effects
                            get handled correctly. must be false initially.
        @return: false failed to preserve a side effect, it is not safe to delete the
                 operand true no side effects or successfully preserved them
        """
        return _ida_hexrays.mop_t_preserve_side_effects(self, blk, top, moved_calls)

    def apply_ld_mcode(self, mcode: "mcode_t", ea: "ea_t", newsize: "int") -> "void":
        r"""
        apply_ld_mcode(self, mcode, ea, newsize)
        Apply a unary opcode to the operand.

        @param mcode: (C++: mcode_t) opcode to apply. it must accept 'l' and 'd' operands but not 'r'.
        @param ea: (C++: ea_t) value of minsn_t::ea for the newly created insruction
        @param newsize: (C++: int) new operand size Example: apply_ld_mcode(m_low) will convert op
                        => low(op)
        """
        return _ida_hexrays.mop_t_apply_ld_mcode(self, mcode, ea, newsize)

    def apply_xdu(self, ea: "ea_t", newsize: "int") -> "void":
        r"""
        apply_xdu(self, ea, newsize)

        @param ea: ea_t
        @param newsize: int
        """
        return _ida_hexrays.mop_t_apply_xdu(self, ea, newsize)

    def apply_xds(self, ea: "ea_t", newsize: "int") -> "void":
        r"""
        apply_xds(self, ea, newsize)

        @param ea: ea_t
        @param newsize: int
        """
        return _ida_hexrays.mop_t_apply_xds(self, ea, newsize)

    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.mop_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.mop_t__deregister(self)

    def _get_t(self) -> "mopt_t":
        r"""_get_t(self) -> mopt_t"""
        return _ida_hexrays.mop_t__get_t(self)

    def _set_t(self, v: "mopt_t") -> "void":
        r"""
        _set_t(self, v)

        Parameters
        ----------
        v: mopt_t

        """
        return _ida_hexrays.mop_t__set_t(self, v)

    def _ensure_no_t(self):
        if self.t not in [mop_z]:
            raise Exception("%s has type %s; cannot be modified" % (self, self.t))
        return True
    t = property(
            _get_t,
            lambda self, v: self._ensure_no_t() and self._set_t(v))


    def __dbg_get_meminfo(self) -> "qstring":
        r"""
        __dbg_get_meminfo(self) -> qstring
        """
        return _ida_hexrays.mop_t___dbg_get_meminfo(self)

    def __dbg_get_registered_kind(self) -> "int":
        r"""
        __dbg_get_registered_kind(self) -> int
        """
        return _ida_hexrays.mop_t___dbg_get_registered_kind(self)

    def _obj_id(self) -> "PyObject *":
        r"""_obj_id(self) -> PyObject *"""
        return _ida_hexrays.mop_t__obj_id(self)

    obj_id = property(_obj_id)

    def _ensure_cond(self, ok, cond_str):
        if not ok:
            raise Exception("Condition \"%s\" not verified" % cond_str)
        return True

    def _ensure_no_obj(self, o, attr, attr_is_acquired):
        if attr_is_acquired and o is not None:
            raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
        return True

    def _ensure_ownership_transferrable(self, v):
        if not v.thisown:
            raise Exception("%s is already owned, and cannot be reused" % v)

    def _acquire_ownership(self, v, acquire):
        if acquire and (v is not None) and not isinstance(v, ida_idaapi.integer_types):
            self._ensure_ownership_transferrable(v)
            v.thisown = False
            dereg = getattr(v, "_deregister", None)
            if dereg:
                dereg()
        return True

    def _maybe_disown_and_deregister(self):
        if self.thisown:
            self.thisown = False
            self._deregister()

    def _own_and_register(self):
        assert(not self.thisown)
        self.thisown = True
        self._register()

    def replace_by(self, o):
        assert(isinstance(o, (cexpr_t, cinsn_t)))
        o._maybe_disown_and_deregister()
        self._replace_by(o)

    def _meminfo(self):
        cpp = self.__dbg_get_meminfo()
        rkind = self.__dbg_get_registered_kind()
        rkind_str = [
                "(not owned)",
                "cfuncptr_t",
                "cinsn_t",
                "cexpr_t",
                "cblock_t",
                "mba_t",
                "mop_t",
                "minsn_t",
                "optinsn_t",
                "optblock_t",
                "valrng_t",
                "udc_filter_t"][rkind]
        return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                cpp,
                self.thisown,
                rkind_str)
    meminfo = property(_meminfo)


    def _get_nnn(self) -> "mnumber_t *":
        r"""_get_nnn(self) -> mnumber_t"""
        return _ida_hexrays.mop_t__get_nnn(self)

    def _set_nnn(self, _v: "mnumber_t") -> "void":
        r"""
        _set_nnn(self, _v)

        Parameters
        ----------
        _v: mnumber_t *

        """
        return _ida_hexrays.mop_t__set_nnn(self, _v)

    nnn = property(
            lambda self: self._get_nnn() if self.t == mop_n else None,
            lambda self, v: self._ensure_cond(self.t == mop_n,"self.t == mop_n") \
                            and self._ensure_no_obj(self._get_nnn(),"nnn", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_nnn(v))


    def _get_d(self) -> "minsn_t *":
        r"""_get_d(self) -> minsn_t"""
        return _ida_hexrays.mop_t__get_d(self)

    def _set_d(self, _v: "minsn_t") -> "void":
        r"""
        _set_d(self, _v)

        Parameters
        ----------
        _v: minsn_t *

        """
        return _ida_hexrays.mop_t__set_d(self, _v)

    d = property(
            lambda self: self._get_d() if self.t == mop_d else None,
            lambda self, v: self._ensure_cond(self.t == mop_d,"self.t == mop_d") \
                            and self._ensure_no_obj(self._get_d(),"d", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_d(v))


    def _get_s(self) -> "stkvar_ref_t *":
        r"""_get_s(self) -> stkvar_ref_t"""
        return _ida_hexrays.mop_t__get_s(self)

    def _set_s(self, _v: "stkvar_ref_t") -> "void":
        r"""
        _set_s(self, _v)

        Parameters
        ----------
        _v: stkvar_ref_t *

        """
        return _ida_hexrays.mop_t__set_s(self, _v)

    s = property(
            lambda self: self._get_s() if self.t == mop_S else None,
            lambda self, v: self._ensure_cond(self.t == mop_S,"self.t == mop_S") \
                            and self._ensure_no_obj(self._get_s(),"s", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_s(v))


    def _get_f(self) -> "mcallinfo_t *":
        r"""_get_f(self) -> mcallinfo_t"""
        return _ida_hexrays.mop_t__get_f(self)

    def _set_f(self, _v: "mcallinfo_t") -> "void":
        r"""
        _set_f(self, _v)

        Parameters
        ----------
        _v: mcallinfo_t *

        """
        return _ida_hexrays.mop_t__set_f(self, _v)

    f = property(
            lambda self: self._get_f() if self.t == mop_f else None,
            lambda self, v: self._ensure_cond(self.t == mop_f,"self.t == mop_f") \
                            and self._ensure_no_obj(self._get_f(),"f", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_f(v))


    def _get_l(self) -> "lvar_ref_t *":
        r"""_get_l(self) -> lvar_ref_t"""
        return _ida_hexrays.mop_t__get_l(self)

    def _set_l(self, _v: "lvar_ref_t") -> "void":
        r"""
        _set_l(self, _v)

        Parameters
        ----------
        _v: lvar_ref_t *

        """
        return _ida_hexrays.mop_t__set_l(self, _v)

    l = property(
            lambda self: self._get_l() if self.t == mop_l else None,
            lambda self, v: self._ensure_cond(self.t == mop_l,"self.t == mop_l") \
                            and self._ensure_no_obj(self._get_l(),"l", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_l(v))


    def _get_a(self) -> "mop_addr_t *":
        r"""_get_a(self) -> mop_addr_t"""
        return _ida_hexrays.mop_t__get_a(self)

    def _set_a(self, _v: "mop_addr_t") -> "void":
        r"""
        _set_a(self, _v)

        Parameters
        ----------
        _v: mop_addr_t *

        """
        return _ida_hexrays.mop_t__set_a(self, _v)

    a = property(
            lambda self: self._get_a() if self.t == mop_a else None,
            lambda self, v: self._ensure_cond(self.t == mop_a,"self.t == mop_a") \
                            and self._ensure_no_obj(self._get_a(),"a", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_a(v))


    def _get_c(self) -> "mcases_t *":
        r"""_get_c(self) -> mcases_t"""
        return _ida_hexrays.mop_t__get_c(self)

    def _set_c(self, _v: "mcases_t") -> "void":
        r"""
        _set_c(self, _v)

        Parameters
        ----------
        _v: mcases_t *

        """
        return _ida_hexrays.mop_t__set_c(self, _v)

    c = property(
            lambda self: self._get_c() if self.t == mop_c else None,
            lambda self, v: self._ensure_cond(self.t == mop_c,"self.t == mop_c") \
                            and self._ensure_no_obj(self._get_c(),"c", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_c(v))


    def _get_fpc(self) -> "fnumber_t *":
        r"""_get_fpc(self) -> fnumber_t"""
        return _ida_hexrays.mop_t__get_fpc(self)

    def _set_fpc(self, _v: "fnumber_t") -> "void":
        r"""
        _set_fpc(self, _v)

        Parameters
        ----------
        _v: fnumber_t *

        """
        return _ida_hexrays.mop_t__set_fpc(self, _v)

    fpc = property(
            lambda self: self._get_fpc() if self.t == mop_fn else None,
            lambda self, v: self._ensure_cond(self.t == mop_fn,"self.t == mop_fn") \
                            and self._ensure_no_obj(self._get_fpc(),"fpc", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_fpc(v))


    def _get_pair(self) -> "mop_pair_t *":
        r"""_get_pair(self) -> mop_pair_t"""
        return _ida_hexrays.mop_t__get_pair(self)

    def _set_pair(self, _v: "mop_pair_t") -> "void":
        r"""
        _set_pair(self, _v)

        Parameters
        ----------
        _v: mop_pair_t *

        """
        return _ida_hexrays.mop_t__set_pair(self, _v)

    pair = property(
            lambda self: self._get_pair() if self.t == mop_p else None,
            lambda self, v: self._ensure_cond(self.t == mop_p,"self.t == mop_p") \
                            and self._ensure_no_obj(self._get_pair(),"pair", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_pair(v))


    def _get_scif(self) -> "scif_t *":
        r"""_get_scif(self) -> scif_t"""
        return _ida_hexrays.mop_t__get_scif(self)

    def _set_scif(self, _v: "scif_t") -> "void":
        r"""
        _set_scif(self, _v)

        Parameters
        ----------
        _v: scif_t *

        """
        return _ida_hexrays.mop_t__set_scif(self, _v)

    scif = property(
            lambda self: self._get_scif() if self.t == mop_sc else None,
            lambda self, v: self._ensure_cond(self.t == mop_sc,"self.t == mop_sc") \
                            and self._ensure_no_obj(self._get_scif(),"scif", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_scif(v))


    scif = property(
            lambda self: self._get_scif() if self.t == mop_sc else None,
            lambda self, v: self._ensure_cond(self.t == mop_sc,"self.t == mop_sc") \
                            and self._ensure_no_obj(self._get_scif(),"scif", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_scif(v))


    def _get_r(self) -> "mreg_t":
        r"""_get_r(self) -> mreg_t"""
        return _ida_hexrays.mop_t__get_r(self)

    def _set_r(self, _v: "mreg_t") -> "void":
        r"""
        _set_r(self, _v)

        Parameters
        ----------
        _v: mreg_t

        """
        return _ida_hexrays.mop_t__set_r(self, _v)

    r = property(
            lambda self: self._get_r() if self.t == mop_r else None,
            lambda self, v: self._ensure_cond(self.t == mop_r,"self.t == mop_r") and self._set_r(v))


    def _get_g(self) -> "ea_t":
        r"""_get_g(self) -> ea_t"""
        return _ida_hexrays.mop_t__get_g(self)

    def _set_g(self, _v: "ea_t") -> "void":
        r"""
        _set_g(self, _v)

        Parameters
        ----------
        _v: ea_t

        """
        return _ida_hexrays.mop_t__set_g(self, _v)

    g = property(
            lambda self: self._get_g() if self.t == mop_v else None,
            lambda self, v: self._ensure_cond(self.t == mop_v,"self.t == mop_v") and self._set_g(v))


    def _get_b(self) -> "int":
        r"""_get_b(self) -> int"""
        return _ida_hexrays.mop_t__get_b(self)

    def _set_b(self, _v: "int") -> "void":
        r"""
        _set_b(self, _v)

        Parameters
        ----------
        _v: int

        """
        return _ida_hexrays.mop_t__set_b(self, _v)

    b = property(
            lambda self: self._get_b() if self.t == mop_b else None,
            lambda self, v: self._ensure_cond(self.t == mop_b,"self.t == mop_b") and self._set_b(v))


    def _get_cstr(self) -> "char const *":
        r"""_get_cstr(self) -> char const *"""
        return _ida_hexrays.mop_t__get_cstr(self)

    def _set_cstr(self, _v: "char const *") -> "void":
        r"""
        _set_cstr(self, _v)

        Parameters
        ----------
        _v: char const *

        """
        return _ida_hexrays.mop_t__set_cstr(self, _v)

    cstr = property(
            lambda self: self._get_cstr() if self.t == mop_str else None,
            lambda self, v: self._ensure_cond(self.t == mop_str,"self.t == mop_str") \
                            and self._ensure_no_obj(self._get_cstr(),"cstr", False) \
                            and self._acquire_ownership(v, False) \
                            and self._set_cstr(v))


    def _get_helper(self) -> "char const *":
        r"""_get_helper(self) -> char const *"""
        return _ida_hexrays.mop_t__get_helper(self)

    def _set_helper(self, _v: "char const *") -> "void":
        r"""
        _set_helper(self, _v)

        Parameters
        ----------
        _v: char const *

        """
        return _ida_hexrays.mop_t__set_helper(self, _v)

    helper = property(
            lambda self: self._get_helper() if self.t == mop_h else None,
            lambda self, v: self._ensure_cond(self.t == mop_h,"self.t == mop_h") \
                            and self._ensure_no_obj(self._get_helper(),"helper", False) \
                            and self._acquire_ownership(v, False) \
                            and self._set_helper(v))


# Register mop_t in _ida_hexrays:
_ida_hexrays.mop_t_swigregister(mop_t)
OPROP_IMPDONE = _ida_hexrays.OPROP_IMPDONE
r"""
imported operand (a pointer) has been dereferenced
"""

OPROP_UDT = _ida_hexrays.OPROP_UDT
r"""
a struct or union
"""

OPROP_FLOAT = _ida_hexrays.OPROP_FLOAT
r"""
possibly floating value
"""

OPROP_CCFLAGS = _ida_hexrays.OPROP_CCFLAGS
r"""
mop_n: a pc-relative value mop_a: an address obtained from a relocation else:
value of a condition code register (like mr_cc)
"""

OPROP_UDEFVAL = _ida_hexrays.OPROP_UDEFVAL
r"""
uses undefined value
"""

OPROP_LOWADDR = _ida_hexrays.OPROP_LOWADDR
r"""
a low address offset
"""


def lexcompare(a: "mop_t", b: "mop_t") -> "int":
    r"""
    lexcompare(a, b) -> int

    @param a: mop_t const &
    @param b: mop_t const &
    """
    return _ida_hexrays.lexcompare(a, b)

class mop_pair_t(object):
    r"""
    Proxy of C++ mop_pair_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    lop: "mop_t" = property(_ida_hexrays.mop_pair_t_lop_get, _ida_hexrays.mop_pair_t_lop_set, doc=r"""lop""")
    r"""
    low operand
    """
    hop: "mop_t" = property(_ida_hexrays.mop_pair_t_hop_get, _ida_hexrays.mop_pair_t_hop_set, doc=r"""hop""")
    r"""
    high operand
    """

    def __init__(self):
        r"""
        __init__(self) -> mop_pair_t
        """
        _ida_hexrays.mop_pair_t_swiginit(self, _ida_hexrays.new_mop_pair_t())
    __swig_destroy__ = _ida_hexrays.delete_mop_pair_t

# Register mop_pair_t in _ida_hexrays:
_ida_hexrays.mop_pair_t_swigregister(mop_pair_t)
class mop_addr_t(mop_t):
    r"""
    Proxy of C++ mop_addr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    insize: "int" = property(_ida_hexrays.mop_addr_t_insize_get, _ida_hexrays.mop_addr_t_insize_set, doc=r"""insize""")
    outsize: "int" = property(_ida_hexrays.mop_addr_t_outsize_get, _ida_hexrays.mop_addr_t_outsize_set, doc=r"""outsize""")

    def __init__(self, *args):
        r"""
        __init__(self) -> mop_addr_t
        __init__(self, ra) -> mop_addr_t

        @param ra: mop_addr_t const &

        __init__(self, ra, isz, osz) -> mop_addr_t

        @param ra: mop_t const &
        @param isz: int
        @param osz: int
        """
        _ida_hexrays.mop_addr_t_swiginit(self, _ida_hexrays.new_mop_addr_t(*args))

    def lexcompare(self, ra: "mop_addr_t") -> "int":
        r"""
        lexcompare(self, ra) -> int

        @param ra: mop_addr_t const &
        """
        return _ida_hexrays.mop_addr_t_lexcompare(self, ra)
    __swig_destroy__ = _ida_hexrays.delete_mop_addr_t

# Register mop_addr_t in _ida_hexrays:
_ida_hexrays.mop_addr_t_swigregister(mop_addr_t)
class mcallarg_t(mop_t):
    r"""
    Proxy of C++ mcallarg_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.mcallarg_t_ea_get, _ida_hexrays.mcallarg_t_ea_set, doc=r"""ea""")
    r"""
    address where the argument was initialized. BADADDR means unknown.
    """
    type: "tinfo_t" = property(_ida_hexrays.mcallarg_t_type_get, _ida_hexrays.mcallarg_t_type_set, doc=r"""type""")
    r"""
    formal argument type
    """
    name: "qstring" = property(_ida_hexrays.mcallarg_t_name_get, _ida_hexrays.mcallarg_t_name_set, doc=r"""name""")
    r"""
    formal argument name
    """
    argloc: "argloc_t" = property(_ida_hexrays.mcallarg_t_argloc_get, _ida_hexrays.mcallarg_t_argloc_set, doc=r"""argloc""")
    r"""
    ida argloc
    """
    flags: "uint32" = property(_ida_hexrays.mcallarg_t_flags_get, _ida_hexrays.mcallarg_t_flags_set, doc=r"""flags""")
    r"""
    FAI_...
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> mcallarg_t
        __init__(self, rarg) -> mcallarg_t

        @param rarg: mop_t const &
        """
        _ida_hexrays.mcallarg_t_swiginit(self, _ida_hexrays.new_mcallarg_t(*args))

    def copy_mop(self, op: "mop_t") -> "void":
        r"""
        copy_mop(self, op)

        @param op: mop_t const &
        """
        return _ida_hexrays.mcallarg_t_copy_mop(self, op)

    def _print(self, *args) -> "void":
        r"""
        _print(self, shins_flags=0x04|0x02)

        Parameters
        ----------
        shins_flags: int

        """
        return _ida_hexrays.mcallarg_t__print(self, *args)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.mcallarg_t_dstr(self)

    def set_regarg(self, *args) -> "void":
        r"""
        set_regarg(self, mr, sz, tif)

        @param mr: mreg_t
        @param sz: int
        @param tif: tinfo_t const &

        set_regarg(self, mr, tif)

        @param mr: mreg_t
        @param tif: tinfo_t const &

        set_regarg(self, mr, dt, sign=type_unsigned)

        @param mr: mreg_t
        @param dt: char
        @param sign: type_sign_t
        """
        return _ida_hexrays.mcallarg_t_set_regarg(self, *args)

    def make_int(self, val: "int", val_ea: "ea_t", opno: "int"=0) -> "void":
        r"""
        make_int(self, val, val_ea, opno=0)

        @param val: int
        @param val_ea: ea_t
        @param opno: int
        """
        return _ida_hexrays.mcallarg_t_make_int(self, val, val_ea, opno)

    def make_uint(self, val: "int", val_ea: "ea_t", opno: "int"=0) -> "void":
        r"""
        make_uint(self, val, val_ea, opno=0)

        @param val: int
        @param val_ea: ea_t
        @param opno: int
        """
        return _ida_hexrays.mcallarg_t_make_uint(self, val, val_ea, opno)
    __swig_destroy__ = _ida_hexrays.delete_mcallarg_t

# Register mcallarg_t in _ida_hexrays:
_ida_hexrays.mcallarg_t_swigregister(mcallarg_t)
ROLE_UNK = _ida_hexrays.ROLE_UNK
r"""
unknown function role
"""

ROLE_EMPTY = _ida_hexrays.ROLE_EMPTY
r"""
empty, does not do anything (maybe spoils regs)
"""

ROLE_MEMSET = _ida_hexrays.ROLE_MEMSET
r"""
memset(void *dst, uchar value, size_t count);
"""

ROLE_MEMSET32 = _ida_hexrays.ROLE_MEMSET32
r"""
memset32(void *dst, uint32 value, size_t count);
"""

ROLE_MEMSET64 = _ida_hexrays.ROLE_MEMSET64
r"""
memset64(void *dst, uint64 value, size_t count);
"""

ROLE_MEMCPY = _ida_hexrays.ROLE_MEMCPY
r"""
memcpy(void *dst, const void *src, size_t count);
"""

ROLE_STRCPY = _ida_hexrays.ROLE_STRCPY
r"""
strcpy(char *dst, const char *src);
"""

ROLE_STRLEN = _ida_hexrays.ROLE_STRLEN
r"""
strlen(const char *src);
"""

ROLE_STRCAT = _ida_hexrays.ROLE_STRCAT
r"""
strcat(char *dst, const char *src);
"""

ROLE_TAIL = _ida_hexrays.ROLE_TAIL
r"""
char *tail(const char *str);
"""

ROLE_BUG = _ida_hexrays.ROLE_BUG
r"""
BUG() helper macro: never returns, causes exception.
"""

ROLE_ALLOCA = _ida_hexrays.ROLE_ALLOCA
r"""
alloca() function
"""

ROLE_BSWAP = _ida_hexrays.ROLE_BSWAP
r"""
bswap() function (any size)
"""

ROLE_PRESENT = _ida_hexrays.ROLE_PRESENT
r"""
present() function (used in patterns)
"""

ROLE_CONTAINING_RECORD = _ida_hexrays.ROLE_CONTAINING_RECORD
r"""
CONTAINING_RECORD() macro.
"""

ROLE_FASTFAIL = _ida_hexrays.ROLE_FASTFAIL
r"""
__fastfail()
"""

ROLE_READFLAGS = _ida_hexrays.ROLE_READFLAGS
r"""
__readeflags, __readcallersflags
"""

ROLE_IS_MUL_OK = _ida_hexrays.ROLE_IS_MUL_OK
r"""
is_mul_ok
"""

ROLE_SATURATED_MUL = _ida_hexrays.ROLE_SATURATED_MUL
r"""
saturated_mul
"""

ROLE_BITTEST = _ida_hexrays.ROLE_BITTEST
r"""
[lock] bt
"""

ROLE_BITTESTANDSET = _ida_hexrays.ROLE_BITTESTANDSET
r"""
[lock] bts
"""

ROLE_BITTESTANDRESET = _ida_hexrays.ROLE_BITTESTANDRESET
r"""
[lock] btr
"""

ROLE_BITTESTANDCOMPLEMENT = _ida_hexrays.ROLE_BITTESTANDCOMPLEMENT
r"""
[lock] btc
"""

ROLE_VA_ARG = _ida_hexrays.ROLE_VA_ARG
r"""
va_arg() macro
"""

ROLE_VA_COPY = _ida_hexrays.ROLE_VA_COPY
r"""
va_copy() function
"""

ROLE_VA_START = _ida_hexrays.ROLE_VA_START
r"""
va_start() function
"""

ROLE_VA_END = _ida_hexrays.ROLE_VA_END
r"""
va_end() function
"""

ROLE_ROL = _ida_hexrays.ROLE_ROL
r"""
rotate left
"""

ROLE_ROR = _ida_hexrays.ROLE_ROR
r"""
rotate right
"""

ROLE_CFSUB3 = _ida_hexrays.ROLE_CFSUB3
r"""
carry flag after subtract with carry
"""

ROLE_OFSUB3 = _ida_hexrays.ROLE_OFSUB3
r"""
overflow flag after subtract with carry
"""

ROLE_ABS = _ida_hexrays.ROLE_ABS
r"""
integer absolute value
"""

ROLE_3WAYCMP0 = _ida_hexrays.ROLE_3WAYCMP0
r"""
3-way compare helper, returns -1/0/1
"""

ROLE_3WAYCMP1 = _ida_hexrays.ROLE_3WAYCMP1
r"""
3-way compare helper, returns 0/1/2
"""

ROLE_WMEMCPY = _ida_hexrays.ROLE_WMEMCPY
r"""
wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)
"""

ROLE_WMEMSET = _ida_hexrays.ROLE_WMEMSET
r"""
wchar_t *wmemset(wchar_t *dst, wchar_t wc, size_t n)
"""

ROLE_WCSCPY = _ida_hexrays.ROLE_WCSCPY
r"""
wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);
"""

ROLE_WCSLEN = _ida_hexrays.ROLE_WCSLEN
r"""
size_t wcslen(const wchar_t *s)
"""

ROLE_WCSCAT = _ida_hexrays.ROLE_WCSCAT
r"""
wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
"""

ROLE_SSE_CMP4 = _ida_hexrays.ROLE_SSE_CMP4
r"""
e.g. _mm_cmpgt_ss
"""

ROLE_SSE_CMP8 = _ida_hexrays.ROLE_SSE_CMP8
r"""
e.g. _mm_cmpgt_sd
"""

FUNC_NAME_MEMCPY = _ida_hexrays.FUNC_NAME_MEMCPY

FUNC_NAME_WMEMCPY = _ida_hexrays.FUNC_NAME_WMEMCPY

FUNC_NAME_MEMSET = _ida_hexrays.FUNC_NAME_MEMSET

FUNC_NAME_WMEMSET = _ida_hexrays.FUNC_NAME_WMEMSET

FUNC_NAME_MEMSET32 = _ida_hexrays.FUNC_NAME_MEMSET32

FUNC_NAME_MEMSET64 = _ida_hexrays.FUNC_NAME_MEMSET64

FUNC_NAME_STRCPY = _ida_hexrays.FUNC_NAME_STRCPY

FUNC_NAME_WCSCPY = _ida_hexrays.FUNC_NAME_WCSCPY

FUNC_NAME_STRLEN = _ida_hexrays.FUNC_NAME_STRLEN

FUNC_NAME_WCSLEN = _ida_hexrays.FUNC_NAME_WCSLEN

FUNC_NAME_STRCAT = _ida_hexrays.FUNC_NAME_STRCAT

FUNC_NAME_WCSCAT = _ida_hexrays.FUNC_NAME_WCSCAT

FUNC_NAME_TAIL = _ida_hexrays.FUNC_NAME_TAIL

FUNC_NAME_VA_ARG = _ida_hexrays.FUNC_NAME_VA_ARG

FUNC_NAME_EMPTY = _ida_hexrays.FUNC_NAME_EMPTY

FUNC_NAME_PRESENT = _ida_hexrays.FUNC_NAME_PRESENT

FUNC_NAME_CONTAINING_RECORD = _ida_hexrays.FUNC_NAME_CONTAINING_RECORD

FUNC_NAME_MORESTACK = _ida_hexrays.FUNC_NAME_MORESTACK

class mcallinfo_t(object):
    r"""
    Proxy of C++ mcallinfo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    callee: "ea_t" = property(_ida_hexrays.mcallinfo_t_callee_get, _ida_hexrays.mcallinfo_t_callee_set, doc=r"""callee""")
    r"""
    address of the called function, if known
    """
    solid_args: "int" = property(_ida_hexrays.mcallinfo_t_solid_args_get, _ida_hexrays.mcallinfo_t_solid_args_set, doc=r"""solid_args""")
    r"""
    number of solid args. there may be variadic args in addtion
    """
    call_spd: "int" = property(_ida_hexrays.mcallinfo_t_call_spd_get, _ida_hexrays.mcallinfo_t_call_spd_set, doc=r"""call_spd""")
    r"""
    sp value at call insn
    """
    stkargs_top: "int" = property(_ida_hexrays.mcallinfo_t_stkargs_top_get, _ida_hexrays.mcallinfo_t_stkargs_top_set, doc=r"""stkargs_top""")
    r"""
    first offset past stack arguments
    """
    cc: "cm_t" = property(_ida_hexrays.mcallinfo_t_cc_get, _ida_hexrays.mcallinfo_t_cc_set, doc=r"""cc""")
    r"""
    calling convention
    """
    args: "mcallargs_t" = property(_ida_hexrays.mcallinfo_t_args_get, _ida_hexrays.mcallinfo_t_args_set, doc=r"""args""")
    r"""
    call arguments
    """
    retregs: "mopvec_t" = property(_ida_hexrays.mcallinfo_t_retregs_get, _ida_hexrays.mcallinfo_t_retregs_set, doc=r"""retregs""")
    r"""
    return register(s) (e.g., AX, AX:DX, etc.) this vector is built from return_regs
    """
    return_type: "tinfo_t" = property(_ida_hexrays.mcallinfo_t_return_type_get, _ida_hexrays.mcallinfo_t_return_type_set, doc=r"""return_type""")
    r"""
    type of the returned value
    """
    return_argloc: "argloc_t" = property(_ida_hexrays.mcallinfo_t_return_argloc_get, _ida_hexrays.mcallinfo_t_return_argloc_set, doc=r"""return_argloc""")
    r"""
    location of the returned value
    """
    return_regs: "mlist_t" = property(_ida_hexrays.mcallinfo_t_return_regs_get, _ida_hexrays.mcallinfo_t_return_regs_set, doc=r"""return_regs""")
    r"""
    list of values returned by the function
    """
    spoiled: "mlist_t" = property(_ida_hexrays.mcallinfo_t_spoiled_get, _ida_hexrays.mcallinfo_t_spoiled_set, doc=r"""spoiled""")
    r"""
    list of spoiled locations (includes return_regs)
    """
    pass_regs: "mlist_t" = property(_ida_hexrays.mcallinfo_t_pass_regs_get, _ida_hexrays.mcallinfo_t_pass_regs_set, doc=r"""pass_regs""")
    r"""
    passthrough registers: registers that depend on input values (subset of spoiled)
    """
    visible_memory: "ivlset_t" = property(_ida_hexrays.mcallinfo_t_visible_memory_get, _ida_hexrays.mcallinfo_t_visible_memory_set, doc=r"""visible_memory""")
    r"""
    what memory is visible to the call?
    """
    dead_regs: "mlist_t" = property(_ida_hexrays.mcallinfo_t_dead_regs_get, _ida_hexrays.mcallinfo_t_dead_regs_set, doc=r"""dead_regs""")
    r"""
    registers defined by the function but never used. upon propagation we do the
    following:
    * dead_regs += return_regs
    * retregs.clear() since the call is propagated
    """
    flags: "int" = property(_ida_hexrays.mcallinfo_t_flags_get, _ida_hexrays.mcallinfo_t_flags_set, doc=r"""flags""")
    r"""
    combination of Call properties... bits
    """
    role: "funcrole_t" = property(_ida_hexrays.mcallinfo_t_role_get, _ida_hexrays.mcallinfo_t_role_set, doc=r"""role""")
    r"""
    function role
    """
    fti_attrs: "type_attrs_t" = property(_ida_hexrays.mcallinfo_t_fti_attrs_get, _ida_hexrays.mcallinfo_t_fti_attrs_set, doc=r"""fti_attrs""")
    r"""
    extended function attributes
    """

    def __init__(self, *args):
        r"""
        __init__(self, _callee=BADADDR, _sargs=0) -> mcallinfo_t

        @param _callee: ea_t
        @param _sargs: int
        """
        _ida_hexrays.mcallinfo_t_swiginit(self, _ida_hexrays.new_mcallinfo_t(*args))

    def lexcompare(self, f: "mcallinfo_t") -> "int":
        r"""
        lexcompare(self, f) -> int

        @param f: mcallinfo_t const &
        """
        return _ida_hexrays.mcallinfo_t_lexcompare(self, f)

    def set_type(self, type: "tinfo_t") -> "bool":
        r"""
        set_type(self, type) -> bool

        @param type: tinfo_t const &
        """
        return _ida_hexrays.mcallinfo_t_set_type(self, type)

    def get_type(self) -> "tinfo_t":
        r"""
        get_type(self) -> tinfo_t
        """
        return _ida_hexrays.mcallinfo_t_get_type(self)

    def is_vararg(self) -> "bool":
        r"""
        is_vararg(self) -> bool
        """
        return _ida_hexrays.mcallinfo_t_is_vararg(self)

    def _print(self, *args) -> "void":
        r"""
        _print(self, size=-1, shins_flags=0x04|0x02)

        Parameters
        ----------
        size: int
        shins_flags: int

        """
        return _ida_hexrays.mcallinfo_t__print(self, *args)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.mcallinfo_t_dstr(self)
    __swig_destroy__ = _ida_hexrays.delete_mcallinfo_t

# Register mcallinfo_t in _ida_hexrays:
_ida_hexrays.mcallinfo_t_swigregister(mcallinfo_t)
FCI_PROP = _ida_hexrays.FCI_PROP
r"""
call has been propagated
"""

FCI_DEAD = _ida_hexrays.FCI_DEAD
r"""
some return registers were determined dead
"""

FCI_FINAL = _ida_hexrays.FCI_FINAL
r"""
call type is final, should not be changed
"""

FCI_NORET = _ida_hexrays.FCI_NORET
r"""
call does not return
"""

FCI_PURE = _ida_hexrays.FCI_PURE
r"""
pure function
"""

FCI_NOSIDE = _ida_hexrays.FCI_NOSIDE
r"""
call does not have side effects
"""

FCI_SPLOK = _ida_hexrays.FCI_SPLOK
r"""
spoiled/visible_memory lists have been optimized. for some functions we can
reduce them as soon as information about the arguments becomes available. in
order not to try optimize them again we use this bit.
"""

FCI_HASCALL = _ida_hexrays.FCI_HASCALL
r"""
A function is an synthetic helper combined from several instructions and at
least one of them was a call to a real functions
"""

FCI_HASFMT = _ida_hexrays.FCI_HASFMT
r"""
A variadic function with recognized printf- or scanf-style format string
"""

FCI_EXPLOCS = _ida_hexrays.FCI_EXPLOCS
r"""
all arglocs are specified explicitly
"""


class mcases_t(object):
    r"""
    Proxy of C++ mcases_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    values: "casevec_t" = property(_ida_hexrays.mcases_t_values_get, _ida_hexrays.mcases_t_values_set, doc=r"""values""")
    r"""
    expression values for each target
    """
    targets: "intvec_t" = property(_ida_hexrays.mcases_t_targets_get, _ida_hexrays.mcases_t_targets_set, doc=r"""targets""")
    r"""
    target block numbers
    """

    def swap(self, r: "mcases_t") -> "void":
        r"""
        swap(self, r)

        @param r: mcases_t &
        """
        return _ida_hexrays.mcases_t_swap(self, r)

    def __eq__(self, r: "mcases_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___eq__(self, r)

    def __ne__(self, r: "mcases_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___ne__(self, r)

    def __lt__(self, r: "mcases_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___lt__(self, r)

    def __gt__(self, r: "mcases_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___gt__(self, r)

    def __le__(self, r: "mcases_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___le__(self, r)

    def __ge__(self, r: "mcases_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t___ge__(self, r)

    def compare(self, r: "mcases_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: mcases_t const &
        """
        return _ida_hexrays.mcases_t_compare(self, r)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mcases_t_empty(self)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.mcases_t_size(self)

    def resize(self, s: "int") -> "void":
        r"""
        resize(self, s)

        @param s: int
        """
        return _ida_hexrays.mcases_t_resize(self, s)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.mcases_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.mcases_t_dstr(self)

    def __init__(self):
        r"""
        __init__(self) -> mcases_t
        """
        _ida_hexrays.mcases_t_swiginit(self, _ida_hexrays.new_mcases_t())
    __swig_destroy__ = _ida_hexrays.delete_mcases_t

# Register mcases_t in _ida_hexrays:
_ida_hexrays.mcases_t_swigregister(mcases_t)
class voff_t(object):
    r"""
    Proxy of C++ voff_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    off: "sval_t" = property(_ida_hexrays.voff_t_off_get, _ida_hexrays.voff_t_off_set, doc=r"""off""")
    r"""
    register number or stack offset
    """
    type: "mopt_t" = property(_ida_hexrays.voff_t_type_get, _ida_hexrays.voff_t_type_set, doc=r"""type""")
    r"""
    mop_r - register, mop_S - stack, mop_z - undefined
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> voff_t
        __init__(self, _type, _off) -> voff_t

        @param _type: mopt_t
        @param _off: sval_t

        __init__(self, op) -> voff_t

        @param op: mop_t const &
        """
        _ida_hexrays.voff_t_swiginit(self, _ida_hexrays.new_voff_t(*args))

    def set(self, _type: "mopt_t", _off: "sval_t") -> "void":
        r"""
        set(self, _type, _off)

        @param _type: mopt_t
        @param _off: sval_t
        """
        return _ida_hexrays.voff_t_set(self, _type, _off)

    def set_stkoff(self, stkoff: "sval_t") -> "void":
        r"""
        set_stkoff(self, stkoff)

        @param stkoff: sval_t
        """
        return _ida_hexrays.voff_t_set_stkoff(self, stkoff)

    def set_reg(self, mreg: "mreg_t") -> "void":
        r"""
        set_reg(self, mreg)

        @param mreg: mreg_t
        """
        return _ida_hexrays.voff_t_set_reg(self, mreg)

    def undef(self) -> "void":
        r"""
        undef(self)
        """
        return _ida_hexrays.voff_t_undef(self)

    def defined(self) -> "bool":
        r"""
        defined(self) -> bool
        """
        return _ida_hexrays.voff_t_defined(self)

    def is_reg(self) -> "bool":
        r"""
        is_reg(self) -> bool
        """
        return _ida_hexrays.voff_t_is_reg(self)

    def is_stkoff(self) -> "bool":
        r"""
        is_stkoff(self) -> bool
        """
        return _ida_hexrays.voff_t_is_stkoff(self)

    def get_reg(self) -> "mreg_t":
        r"""
        get_reg(self) -> mreg_t
        """
        return _ida_hexrays.voff_t_get_reg(self)

    def get_stkoff(self) -> "sval_t":
        r"""
        get_stkoff(self) -> sval_t
        """
        return _ida_hexrays.voff_t_get_stkoff(self)

    def inc(self, delta: "sval_t") -> "void":
        r"""
        inc(self, delta)

        @param delta: sval_t
        """
        return _ida_hexrays.voff_t_inc(self, delta)

    def add(self, width: "int") -> "voff_t":
        r"""
        add(self, width) -> voff_t

        @param width: int
        """
        return _ida_hexrays.voff_t_add(self, width)

    def diff(self, r: "voff_t") -> "sval_t":
        r"""
        diff(self, r) -> sval_t

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t_diff(self, r)

    def __eq__(self, r: "voff_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___eq__(self, r)

    def __ne__(self, r: "voff_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___ne__(self, r)

    def __lt__(self, r: "voff_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___lt__(self, r)

    def __gt__(self, r: "voff_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___gt__(self, r)

    def __le__(self, r: "voff_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___le__(self, r)

    def __ge__(self, r: "voff_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t___ge__(self, r)

    def compare(self, r: "voff_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: voff_t const &
        """
        return _ida_hexrays.voff_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_voff_t

# Register voff_t in _ida_hexrays:
_ida_hexrays.voff_t_swigregister(voff_t)
class vivl_t(voff_t):
    r"""
    Proxy of C++ vivl_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    size: "int" = property(_ida_hexrays.vivl_t_size_get, _ida_hexrays.vivl_t_size_set, doc=r"""size""")
    r"""
    Interval size in bytes.
    """

    def __init__(self, *args):
        r"""
        __init__(self, _type=mop_z, _off=-1, _size=0) -> vivl_t

        @param _type: mopt_t
        @param _off: sval_t
        @param _size: int

        __init__(self, ch) -> vivl_t

        @param ch: chain_t const &

        __init__(self, op) -> vivl_t

        @param op: mop_t const &
        """
        _ida_hexrays.vivl_t_swiginit(self, _ida_hexrays.new_vivl_t(*args))

    def set(self, *args) -> "void":
        r"""
        set(self, _type, _off, _size=0)

        @param _type: mopt_t
        @param _off: sval_t
        @param _size: int

        set(self, voff, _size)

        @param voff: voff_t const &
        @param _size: int
        """
        return _ida_hexrays.vivl_t_set(self, *args)

    def set_stkoff(self, stkoff: "sval_t", sz: "int"=0) -> "void":
        r"""
        set_stkoff(self, stkoff, sz=0)

        @param stkoff: sval_t
        @param sz: int
        """
        return _ida_hexrays.vivl_t_set_stkoff(self, stkoff, sz)

    def set_reg(self, mreg: "mreg_t", sz: "int"=0) -> "void":
        r"""
        set_reg(self, mreg, sz=0)

        @param mreg: mreg_t
        @param sz: int
        """
        return _ida_hexrays.vivl_t_set_reg(self, mreg, sz)

    def extend_to_cover(self, r: "vivl_t") -> "bool":
        r"""
        extend_to_cover(self, r) -> bool
        Extend a value interval using another value interval of the same type

        @param r: (C++: const vivl_t &) vivl_t const &
        @return: success
        """
        return _ida_hexrays.vivl_t_extend_to_cover(self, r)

    def intersect(self, r: "vivl_t") -> "uval_t":
        r"""
        intersect(self, r) -> uval_t
        Intersect value intervals the same type

        @param r: (C++: const vivl_t &) vivl_t const &
        @return: size of the resulting intersection
        """
        return _ida_hexrays.vivl_t_intersect(self, r)

    def overlap(self, r: "vivl_t") -> "bool":
        r"""
        overlap(self, r) -> bool
        Do two value intervals overlap?

        @param r: (C++: const vivl_t &) vivl_t const &
        """
        return _ida_hexrays.vivl_t_overlap(self, r)

    def includes(self, r: "vivl_t") -> "bool":
        r"""
        includes(self, r) -> bool
        Does our value interval include another?

        @param r: (C++: const vivl_t &) vivl_t const &
        """
        return _ida_hexrays.vivl_t_includes(self, r)

    def contains(self, voff2: "voff_t") -> "bool":
        r"""
        contains(self, voff2) -> bool
        Does our value interval contain the specified value offset?

        @param voff2: (C++: const voff_t &) voff_t const &
        """
        return _ida_hexrays.vivl_t_contains(self, voff2)

    def __ne__(self, r: "vivl_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t___ne__(self, r)

    def __lt__(self, r: "vivl_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t___lt__(self, r)

    def __gt__(self, r: "vivl_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t___gt__(self, r)

    def __le__(self, r: "vivl_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t___le__(self, r)

    def __ge__(self, r: "vivl_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t___ge__(self, r)

    def compare(self, r: "vivl_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: vivl_t const &
        """
        return _ida_hexrays.vivl_t_compare(self, r)

    def __eq__(self, *args) -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: vivl_t const &

        __eq__(self, mop) -> bool

        @param mop: mop_t const &
        """
        return _ida_hexrays.vivl_t___eq__(self, *args)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.vivl_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.vivl_t_dstr(self)
    __swig_destroy__ = _ida_hexrays.delete_vivl_t

# Register vivl_t in _ida_hexrays:
_ida_hexrays.vivl_t_swigregister(vivl_t)
class chain_t(ida_pro.intvec_t):
    r"""
    Proxy of C++ chain_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    width: "int" = property(_ida_hexrays.chain_t_width_get, _ida_hexrays.chain_t_width_set, doc=r"""width""")
    r"""
    size of the value in bytes
    """
    varnum: "int" = property(_ida_hexrays.chain_t_varnum_get, _ida_hexrays.chain_t_varnum_set, doc=r"""varnum""")
    r"""
    allocated variable index (-1 - not allocated yet)
    """
    flags: "uchar" = property(_ida_hexrays.chain_t_flags_get, _ida_hexrays.chain_t_flags_set, doc=r"""flags""")
    r"""
    combination Chain properties bits
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> chain_t
        __init__(self, t, off, w=1, v=-1) -> chain_t

        @param t: mopt_t
        @param off: sval_t
        @param w: int
        @param v: int

        __init__(self, _k, w=1) -> chain_t

        @param _k: voff_t const &
        @param w: int
        """
        _ida_hexrays.chain_t_swiginit(self, _ida_hexrays.new_chain_t(*args))

    def set_value(self, r: "chain_t") -> "void":
        r"""
        set_value(self, r)

        @param r: chain_t const &
        """
        return _ida_hexrays.chain_t_set_value(self, r)

    def key(self) -> "voff_t const &":
        r"""
        key(self) -> voff_t
        """
        return _ida_hexrays.chain_t_key(self)

    def is_inited(self) -> "bool":
        r"""
        is_inited(self) -> bool
        """
        return _ida_hexrays.chain_t_is_inited(self)

    def is_reg(self) -> "bool":
        r"""
        is_reg(self) -> bool
        """
        return _ida_hexrays.chain_t_is_reg(self)

    def is_stkoff(self) -> "bool":
        r"""
        is_stkoff(self) -> bool
        """
        return _ida_hexrays.chain_t_is_stkoff(self)

    def is_replaced(self) -> "bool":
        r"""
        is_replaced(self) -> bool
        """
        return _ida_hexrays.chain_t_is_replaced(self)

    def is_overlapped(self) -> "bool":
        r"""
        is_overlapped(self) -> bool
        """
        return _ida_hexrays.chain_t_is_overlapped(self)

    def is_fake(self) -> "bool":
        r"""
        is_fake(self) -> bool
        """
        return _ida_hexrays.chain_t_is_fake(self)

    def is_passreg(self) -> "bool":
        r"""
        is_passreg(self) -> bool
        """
        return _ida_hexrays.chain_t_is_passreg(self)

    def is_term(self) -> "bool":
        r"""
        is_term(self) -> bool
        """
        return _ida_hexrays.chain_t_is_term(self)

    def set_inited(self, b: "bool") -> "void":
        r"""
        set_inited(self, b)

        @param b: bool
        """
        return _ida_hexrays.chain_t_set_inited(self, b)

    def set_replaced(self, b: "bool") -> "void":
        r"""
        set_replaced(self, b)

        @param b: bool
        """
        return _ida_hexrays.chain_t_set_replaced(self, b)

    def set_overlapped(self, b: "bool") -> "void":
        r"""
        set_overlapped(self, b)

        @param b: bool
        """
        return _ida_hexrays.chain_t_set_overlapped(self, b)

    def set_term(self, b: "bool") -> "void":
        r"""
        set_term(self, b)

        @param b: bool
        """
        return _ida_hexrays.chain_t_set_term(self, b)

    def get_reg(self) -> "mreg_t":
        r"""
        get_reg(self) -> mreg_t
        """
        return _ida_hexrays.chain_t_get_reg(self)

    def get_stkoff(self) -> "sval_t":
        r"""
        get_stkoff(self) -> sval_t
        """
        return _ida_hexrays.chain_t_get_stkoff(self)

    def overlap(self, r: "chain_t") -> "bool":
        r"""
        overlap(self, r) -> bool

        @param r: chain_t const &
        """
        return _ida_hexrays.chain_t_overlap(self, r)

    def includes(self, r: "chain_t") -> "bool":
        r"""
        includes(self, r) -> bool

        @param r: chain_t const &
        """
        return _ida_hexrays.chain_t_includes(self, r)

    def endoff(self) -> "voff_t const":
        r"""
        endoff(self) -> voff_t
        """
        return _ida_hexrays.chain_t_endoff(self)

    def __lt__(self, r: "chain_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: chain_t const &
        """
        return _ida_hexrays.chain_t___lt__(self, r)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.chain_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.chain_t_dstr(self)

    def append_list(self, mba: "mba_t", list: "mlist_t") -> "void":
        r"""
        append_list(self, mba, list)
        Append the contents of the chain to the specified list of locations.

        @param mba: (C++: const mba_t *) mba_t const *
        @param list: (C++: mlist_t *)
        """
        return _ida_hexrays.chain_t_append_list(self, mba, list)

    def clear_varnum(self) -> "void":
        r"""
        clear_varnum(self)
        """
        return _ida_hexrays.chain_t_clear_varnum(self)
    __swig_destroy__ = _ida_hexrays.delete_chain_t

# Register chain_t in _ida_hexrays:
_ida_hexrays.chain_t_swigregister(chain_t)
CHF_INITED = _ida_hexrays.CHF_INITED
r"""
is chain initialized? (valid only after lvar allocation)
"""

CHF_REPLACED = _ida_hexrays.CHF_REPLACED
r"""
chain operands have been replaced?
"""

CHF_OVER = _ida_hexrays.CHF_OVER
r"""
overlapped chain
"""

CHF_FAKE = _ida_hexrays.CHF_FAKE
r"""
fake chain created by widen_chains()
"""

CHF_PASSTHRU = _ida_hexrays.CHF_PASSTHRU
r"""
pass-thru chain, must use the input variable to the block
"""

CHF_TERM = _ida_hexrays.CHF_TERM
r"""
terminating chain; the variable does not survive across the block
"""


SIZEOF_BLOCK_CHAINS = _ida_hexrays.SIZEOF_BLOCK_CHAINS

class block_chains_t(object):
    r"""
    Proxy of C++ block_chains_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def get_reg_chain(self, *args) -> "chain_t *":
        r"""
        get_reg_chain(self, reg, width=1) -> chain_t

        @param reg: mreg_t
        @param width: int

        """
        return _ida_hexrays.block_chains_t_get_reg_chain(self, *args)

    def get_stk_chain(self, *args) -> "chain_t *":
        r"""
        get_stk_chain(self, off, width=1) -> chain_t

        @param off: sval_t
        @param width: int

        """
        return _ida_hexrays.block_chains_t_get_stk_chain(self, *args)

    def get_chain(self, *args) -> "chain_t *":
        r"""
        get_chain(self, k, width=1) -> chain_t

        @param k: voff_t const &
        @param width: int

        get_chain(self, ch) -> chain_t

        @param ch: chain_t const &

        """
        return _ida_hexrays.block_chains_t_get_chain(self, *args)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.block_chains_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.block_chains_t_dstr(self)

    def __init__(self):
        r"""
        __init__(self) -> block_chains_t
        """
        _ida_hexrays.block_chains_t_swiginit(self, _ida_hexrays.new_block_chains_t())
    __swig_destroy__ = _ida_hexrays.delete_block_chains_t

# Register block_chains_t in _ida_hexrays:
_ida_hexrays.block_chains_t_swigregister(block_chains_t)
class chain_visitor_t(object):
    r"""
    Proxy of C++ chain_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    parent: "block_chains_t *" = property(_ida_hexrays.chain_visitor_t_parent_get, _ida_hexrays.chain_visitor_t_parent_set, doc=r"""parent""")
    r"""
    parent of the current chain
    """
    __swig_destroy__ = _ida_hexrays.delete_chain_visitor_t

    def visit_chain(self, nblock: "int", ch: "chain_t") -> "int":
        r"""
        visit_chain(self, nblock, ch) -> int

        @param nblock: int
        @param ch: chain_t &
        """
        return _ida_hexrays.chain_visitor_t_visit_chain(self, nblock, ch)

    def __init__(self):
        r"""
        __init__(self) -> chain_visitor_t

        @param self: PyObject *
        """
        if self.__class__ == chain_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.chain_visitor_t_swiginit(self, _ida_hexrays.new_chain_visitor_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_chain_visitor_t(self)
        return weakref.proxy(self)

# Register chain_visitor_t in _ida_hexrays:
_ida_hexrays.chain_visitor_t_swigregister(chain_visitor_t)
class graph_chains_t(block_chains_vec_t):
    r"""
    Proxy of C++ graph_chains_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_hexrays.delete_graph_chains_t

    def for_all_chains(self, cv: "chain_visitor_t", gca_flags: "int") -> "int":
        r"""
        for_all_chains(self, cv, gca_flags) -> int
        Visit all chains

        @param cv: (C++: chain_visitor_t &) chain visitor
        @param gca_flags: (C++: int) combination of GCA_ bits
        """
        return _ida_hexrays.graph_chains_t_for_all_chains(self, cv, gca_flags)

    def is_locked(self) -> "bool":
        r"""
        is_locked(self) -> bool
        Are the chains locked? It is a good idea to lock the chains before using them.
        This ensures that they won't be recalculated and reallocated during the use. See
        the chain_keeper_t class for that.
        """
        return _ida_hexrays.graph_chains_t_is_locked(self)

    def acquire(self) -> "void":
        r"""
        acquire(self)
        Lock the chains.
        """
        return _ida_hexrays.graph_chains_t_acquire(self)

    def release(self) -> "void":
        r"""
        release(self)
        Unlock the chains.
        """
        return _ida_hexrays.graph_chains_t_release(self)

    def swap(self, r: "graph_chains_t") -> "void":
        r"""
        swap(self, r)

        @param r: graph_chains_t &
        """
        return _ida_hexrays.graph_chains_t_swap(self, r)

    def __init__(self):
        r"""
        __init__(self) -> graph_chains_t
        """
        _ida_hexrays.graph_chains_t_swiginit(self, _ida_hexrays.new_graph_chains_t())

# Register graph_chains_t in _ida_hexrays:
_ida_hexrays.graph_chains_t_swigregister(graph_chains_t)
GCA_EMPTY = _ida_hexrays.GCA_EMPTY
r"""
include empty chains
"""

GCA_SPEC = _ida_hexrays.GCA_SPEC
r"""
include chains for special registers
"""

GCA_ALLOC = _ida_hexrays.GCA_ALLOC
r"""
enumerate only allocated chains
"""

GCA_NALLOC = _ida_hexrays.GCA_NALLOC
r"""
enumerate only non-allocated chains
"""

GCA_OFIRST = _ida_hexrays.GCA_OFIRST
r"""
consider only chains of the first block
"""

GCA_OLAST = _ida_hexrays.GCA_OLAST
r"""
consider only chains of the last block
"""


class minsn_t(object):
    r"""
    Proxy of C++ minsn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    opcode: "mcode_t" = property(_ida_hexrays.minsn_t_opcode_get, _ida_hexrays.minsn_t_opcode_set, doc=r"""opcode""")
    r"""
    instruction opcode
    """
    iprops: "int" = property(_ida_hexrays.minsn_t_iprops_get, _ida_hexrays.minsn_t_iprops_set, doc=r"""iprops""")
    r"""
    combination of instruction property bits bits
    """
    next: "minsn_t *" = property(_ida_hexrays.minsn_t_next_get, _ida_hexrays.minsn_t_next_set, doc=r"""next""")
    r"""
    next insn in doubly linked list. check also nexti()
    """
    prev: "minsn_t *" = property(_ida_hexrays.minsn_t_prev_get, _ida_hexrays.minsn_t_prev_set, doc=r"""prev""")
    r"""
    prev insn in doubly linked list. check also previ()
    """
    ea: "ea_t" = property(_ida_hexrays.minsn_t_ea_get, _ida_hexrays.minsn_t_ea_set, doc=r"""ea""")
    r"""
    instruction address
    """
    l: "mop_t" = property(_ida_hexrays.minsn_t_l_get, _ida_hexrays.minsn_t_l_set, doc=r"""l""")
    r"""
    left operand
    """
    r: "mop_t" = property(_ida_hexrays.minsn_t_r_get, _ida_hexrays.minsn_t_r_set, doc=r"""r""")
    r"""
    right operand
    """
    d: "mop_t" = property(_ida_hexrays.minsn_t_d_get, _ida_hexrays.minsn_t_d_set, doc=r"""d""")
    r"""
    destination operand
    """

    def is_optional(self) -> "bool":
        r"""
        is_optional(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_optional(self)

    def is_combined(self) -> "bool":
        r"""
        is_combined(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_combined(self)

    def is_farcall(self) -> "bool":
        r"""
        is_farcall(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_farcall(self)

    def is_cleaning_pop(self) -> "bool":
        r"""
        is_cleaning_pop(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_cleaning_pop(self)

    def is_extstx(self) -> "bool":
        r"""
        is_extstx(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_extstx(self)

    def is_tailcall(self) -> "bool":
        r"""
        is_tailcall(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_tailcall(self)

    def is_fpinsn(self) -> "bool":
        r"""
        is_fpinsn(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_fpinsn(self)

    def is_assert(self) -> "bool":
        r"""
        is_assert(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_assert(self)

    def is_persistent(self) -> "bool":
        r"""
        is_persistent(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_persistent(self)

    def is_wild_match(self) -> "bool":
        r"""
        is_wild_match(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_wild_match(self)

    def is_propagatable(self) -> "bool":
        r"""
        is_propagatable(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_propagatable(self)

    def is_ignlowsrc(self) -> "bool":
        r"""
        is_ignlowsrc(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_ignlowsrc(self)

    def is_inverted_jx(self) -> "bool":
        r"""
        is_inverted_jx(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_inverted_jx(self)

    def was_noret_icall(self) -> "bool":
        r"""
        was_noret_icall(self) -> bool
        """
        return _ida_hexrays.minsn_t_was_noret_icall(self)

    def is_multimov(self) -> "bool":
        r"""
        is_multimov(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_multimov(self)

    def is_combinable(self) -> "bool":
        r"""
        is_combinable(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_combinable(self)

    def was_split(self) -> "bool":
        r"""
        was_split(self) -> bool
        """
        return _ida_hexrays.minsn_t_was_split(self)

    def is_mbarrier(self) -> "bool":
        r"""
        is_mbarrier(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_mbarrier(self)

    def was_unmerged(self) -> "bool":
        r"""
        was_unmerged(self) -> bool
        """
        return _ida_hexrays.minsn_t_was_unmerged(self)

    def was_unpaired(self) -> "bool":
        r"""
        was_unpaired(self) -> bool
        """
        return _ida_hexrays.minsn_t_was_unpaired(self)

    def set_optional(self) -> "void":
        r"""
        set_optional(self)
        """
        return _ida_hexrays.minsn_t_set_optional(self)

    def clr_combined(self) -> "void":
        r"""
        clr_combined(self)
        """
        return _ida_hexrays.minsn_t_clr_combined(self)

    def set_farcall(self) -> "void":
        r"""
        set_farcall(self)
        """
        return _ida_hexrays.minsn_t_set_farcall(self)

    def set_cleaning_pop(self) -> "void":
        r"""
        set_cleaning_pop(self)
        """
        return _ida_hexrays.minsn_t_set_cleaning_pop(self)

    def set_extstx(self) -> "void":
        r"""
        set_extstx(self)
        """
        return _ida_hexrays.minsn_t_set_extstx(self)

    def set_tailcall(self) -> "void":
        r"""
        set_tailcall(self)
        """
        return _ida_hexrays.minsn_t_set_tailcall(self)

    def clr_tailcall(self) -> "void":
        r"""
        clr_tailcall(self)
        """
        return _ida_hexrays.minsn_t_clr_tailcall(self)

    def set_fpinsn(self) -> "void":
        r"""
        set_fpinsn(self)
        """
        return _ida_hexrays.minsn_t_set_fpinsn(self)

    def clr_fpinsn(self) -> "void":
        r"""
        clr_fpinsn(self)
        """
        return _ida_hexrays.minsn_t_clr_fpinsn(self)

    def set_assert(self) -> "void":
        r"""
        set_assert(self)
        """
        return _ida_hexrays.minsn_t_set_assert(self)

    def clr_assert(self) -> "void":
        r"""
        clr_assert(self)
        """
        return _ida_hexrays.minsn_t_clr_assert(self)

    def set_persistent(self) -> "void":
        r"""
        set_persistent(self)
        """
        return _ida_hexrays.minsn_t_set_persistent(self)

    def set_wild_match(self) -> "void":
        r"""
        set_wild_match(self)
        """
        return _ida_hexrays.minsn_t_set_wild_match(self)

    def clr_propagatable(self) -> "void":
        r"""
        clr_propagatable(self)
        """
        return _ida_hexrays.minsn_t_clr_propagatable(self)

    def set_ignlowsrc(self) -> "void":
        r"""
        set_ignlowsrc(self)
        """
        return _ida_hexrays.minsn_t_set_ignlowsrc(self)

    def clr_ignlowsrc(self) -> "void":
        r"""
        clr_ignlowsrc(self)
        """
        return _ida_hexrays.minsn_t_clr_ignlowsrc(self)

    def set_inverted_jx(self) -> "void":
        r"""
        set_inverted_jx(self)
        """
        return _ida_hexrays.minsn_t_set_inverted_jx(self)

    def set_noret_icall(self) -> "void":
        r"""
        set_noret_icall(self)
        """
        return _ida_hexrays.minsn_t_set_noret_icall(self)

    def clr_noret_icall(self) -> "void":
        r"""
        clr_noret_icall(self)
        """
        return _ida_hexrays.minsn_t_clr_noret_icall(self)

    def set_multimov(self) -> "void":
        r"""
        set_multimov(self)
        """
        return _ida_hexrays.minsn_t_set_multimov(self)

    def clr_multimov(self) -> "void":
        r"""
        clr_multimov(self)
        """
        return _ida_hexrays.minsn_t_clr_multimov(self)

    def set_combinable(self) -> "void":
        r"""
        set_combinable(self)
        """
        return _ida_hexrays.minsn_t_set_combinable(self)

    def clr_combinable(self) -> "void":
        r"""
        clr_combinable(self)
        """
        return _ida_hexrays.minsn_t_clr_combinable(self)

    def set_mbarrier(self) -> "void":
        r"""
        set_mbarrier(self)
        """
        return _ida_hexrays.minsn_t_set_mbarrier(self)

    def set_unmerged(self) -> "void":
        r"""
        set_unmerged(self)
        """
        return _ida_hexrays.minsn_t_set_unmerged(self)

    def set_split_size(self, s: "int") -> "void":
        r"""
        set_split_size(self, s)

        @param s: int
        """
        return _ida_hexrays.minsn_t_set_split_size(self, s)

    def get_split_size(self) -> "int":
        r"""
        get_split_size(self) -> int
        """
        return _ida_hexrays.minsn_t_get_split_size(self)

    def __init__(self, *args):
        r"""
        __init__(self, _ea) -> minsn_t

        @param _ea: ea_t

        __init__(self, m) -> minsn_t

        @param m: minsn_t const &
        """
        _ida_hexrays.minsn_t_swiginit(self, _ida_hexrays.new_minsn_t(*args))

    def swap(self, m: "minsn_t") -> "void":
        r"""
        swap(self, m)
        Swap two instructions. The prev/next fields are not modified by this function
        because it would corrupt the doubly linked list.

        @param m: (C++: minsn_t &)
        """
        return _ida_hexrays.minsn_t_swap(self, m)

    def _print(self, *args) -> "void":
        r"""
        _print(self, shins_flags=0x04|0x02)

        Parameters
        ----------
        shins_flags: int

        """
        return _ida_hexrays.minsn_t__print(self, *args)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        Get displayable text without tags in a static buffer.
        """
        return _ida_hexrays.minsn_t_dstr(self)

    def setaddr(self, new_ea: "ea_t") -> "void":
        r"""
        setaddr(self, new_ea)
        Change the instruction address. This function modifies subinstructions as well.

        @param new_ea: (C++: ea_t)
        """
        return _ida_hexrays.minsn_t_setaddr(self, new_ea)

    def optimize_solo(self, optflags: "int"=0) -> "int":
        r"""
        optimize_solo(self, optflags=0) -> int
        Optimize one instruction without context. This function does not have access to
        the instruction context (the previous and next instructions in the list, the
        block number, etc). It performs only basic optimizations that are available
        without this info.

        @param optflags: (C++: int) combination of optimization flags bits
        @return: number of changes, 0-unchanged See also mblock_t::optimize_insn()
        """
        return _ida_hexrays.minsn_t_optimize_solo(self, optflags)

    def optimize_subtree(self, blk: "mblock_t", top: "minsn_t", parent: "minsn_t", converted_call: "ea_t *", optflags: "int"=0x0002) -> "int":
        r"""
        optimize_subtree(self, blk, top, parent, converted_call, optflags=0x0002) -> int
        Optimize instruction in its context. Do not use this function, use
        mblock_t::optimize()

        @param blk: (C++: mblock_t *)
        @param top: (C++: minsn_t *)
        @param parent: (C++: minsn_t *)
        @param converted_call: (C++: ea_t *)
        @param optflags: (C++: int)
        """
        return _ida_hexrays.minsn_t_optimize_subtree(self, blk, top, parent, converted_call, optflags)

    def for_all_ops(self, mv: "mop_visitor_t") -> "int":
        r"""
        for_all_ops(self, mv) -> int
        Visit all instruction operands. This function visits subinstruction operands as
        well.

        @param mv: (C++: mop_visitor_t &) operand visitor
        @return: non-zero value returned by mv.visit_mop() or zero
        """
        return _ida_hexrays.minsn_t_for_all_ops(self, mv)

    def for_all_insns(self, mv: "minsn_visitor_t") -> "int":
        r"""
        for_all_insns(self, mv) -> int
        Visit all instructions. This function visits the instruction itself and all its
        subinstructions.

        @param mv: (C++: minsn_visitor_t &) instruction visitor
        @return: non-zero value returned by mv.visit_mop() or zero
        """
        return _ida_hexrays.minsn_t_for_all_insns(self, mv)

    def _make_nop(self) -> "void":
        r"""_make_nop(self)"""
        return _ida_hexrays.minsn_t__make_nop(self)

    def equal_insns(self, m: "minsn_t", eqflags: "int") -> "bool":
        r"""
        equal_insns(self, m, eqflags) -> bool
        Compare instructions. This is the main comparison function for instructions.

        @param m: (C++: const minsn_t &) instruction to compare with
        @param eqflags: (C++: int) combination of comparison bits bits
        """
        return _ida_hexrays.minsn_t_equal_insns(self, m, eqflags)

    def __lt__(self, ri: "minsn_t") -> "bool":
        r"""
        __lt__(self, ri) -> bool

        @param ri: minsn_t const &
        """
        return _ida_hexrays.minsn_t___lt__(self, ri)

    def lexcompare(self, ri: "minsn_t") -> "int":
        r"""
        lexcompare(self, ri) -> int

        @param ri: minsn_t const &
        """
        return _ida_hexrays.minsn_t_lexcompare(self, ri)

    def is_noret_call(self, flags: "int"=0) -> "bool":
        r"""
        is_noret_call(self, flags=0) -> bool
        Is a non-returing call?

        @param flags: (C++: int) combination of NORET_... bits
        """
        return _ida_hexrays.minsn_t_is_noret_call(self, flags)

    def is_unknown_call(self) -> "bool":
        r"""
        is_unknown_call(self) -> bool
        Is an unknown call? Unknown calls are calls without the argument list
        (mcallinfo_t). Usually the argument lists are determined by
        mba_t::analyze_calls(). Unknown calls exist until the MMAT_CALLS maturity level.
        See also mblock_t::is_call_block
        """
        return _ida_hexrays.minsn_t_is_unknown_call(self)

    def is_helper(self, name: "char const *") -> "bool":
        r"""
        is_helper(self, name) -> bool
        Is a helper call with the specified name? Helper calls usually have well-known
        function names (see Well known function names) but they may have any other name.
        The decompiler does not assume any special meaning for non-well-known names.

        @param name: (C++: const char *) char const *
        """
        return _ida_hexrays.minsn_t_is_helper(self, name)

    def find_call(self, with_helpers: "bool"=False) -> "minsn_t *":
        r"""
        find_call(self, with_helpers=False) -> minsn_t
        Find a call instruction. Check for the current instruction and its
        subinstructions.

        @param with_helpers: (C++: bool) consider helper calls as well?
        """
        return _ida_hexrays.minsn_t_find_call(self, with_helpers)

    def contains_call(self, with_helpers: "bool"=False) -> "bool":
        r"""
        contains_call(self, with_helpers=False) -> bool
        Does the instruction contain a call?

        @param with_helpers: (C++: bool)
        """
        return _ida_hexrays.minsn_t_contains_call(self, with_helpers)

    def has_side_effects(self, include_ldx_and_divs: "bool"=False) -> "bool":
        r"""
        has_side_effects(self, include_ldx_and_divs=False) -> bool
        Does the instruction have a side effect?

        @param include_ldx_and_divs: (C++: bool) consider ldx/div/mod as having side effects? stx is
                                     always considered as having side effects. Apart
                                     from ldx/std only call may have side effects.
        """
        return _ida_hexrays.minsn_t_has_side_effects(self, include_ldx_and_divs)

    def get_role(self) -> "funcrole_t":
        r"""
        get_role(self) -> funcrole_t
        Get the function role of a call.
        """
        return _ida_hexrays.minsn_t_get_role(self)

    def is_memcpy(self) -> "bool":
        r"""
        is_memcpy(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_memcpy(self)

    def is_memset(self) -> "bool":
        r"""
        is_memset(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_memset(self)

    def is_alloca(self) -> "bool":
        r"""
        is_alloca(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_alloca(self)

    def is_bswap(self) -> "bool":
        r"""
        is_bswap(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_bswap(self)

    def is_readflags(self) -> "bool":
        r"""
        is_readflags(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_readflags(self)

    def contains_opcode(self, mcode: "mcode_t") -> "bool":
        r"""
        contains_opcode(self, mcode) -> bool
        Does the instruction have the specified opcode? This function searches
        subinstructions as well.

        @param mcode: (C++: mcode_t) opcode to search for.
        """
        return _ida_hexrays.minsn_t_contains_opcode(self, mcode)

    def find_opcode(self, *args) -> "minsn_t *":
        r"""
        find_opcode(self, mcode) -> minsn_t

        @param mcode: enum mcode_t

        """
        return _ida_hexrays.minsn_t_find_opcode(self, *args)

    def find_ins_op(self, op: "mcode_t"=m_nop) -> "minsn_t *":
        r"""
        find_ins_op(self, op=m_nop) -> minsn_t

        @param op: enum mcode_t
        """
        return _ida_hexrays.minsn_t_find_ins_op(self, op)

    def find_num_op(self) -> "mop_t *":
        r"""
        find_num_op(self) -> mop_t
        """
        return _ida_hexrays.minsn_t_find_num_op(self)

    def is_mov(self) -> "bool":
        r"""
        is_mov(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_mov(self)

    def is_like_move(self) -> "bool":
        r"""
        is_like_move(self) -> bool
        """
        return _ida_hexrays.minsn_t_is_like_move(self)

    def modifies_d(self) -> "bool":
        r"""
        modifies_d(self) -> bool
        Does the instruction modify its 'd' operand? Some instructions (e.g. m_stx) do
        not modify the 'd' operand.
        """
        return _ida_hexrays.minsn_t_modifies_d(self)

    def modifies_pair_mop(self) -> "bool":
        r"""
        modifies_pair_mop(self) -> bool
        """
        return _ida_hexrays.minsn_t_modifies_pair_mop(self)

    def is_between(self, m1: "minsn_t", m2: "minsn_t") -> "bool":
        r"""
        is_between(self, m1, m2) -> bool
        Is the instruction in the specified range of instructions?

        @param m1: (C++: const minsn_t *) beginning of the range in the doubly linked list
        @param m2: (C++: const minsn_t *) end of the range in the doubly linked list (excluded, may be nullptr)
                   This function assumes that m1 and m2 belong to the same basic block
                   and they are top level instructions.
        """
        return _ida_hexrays.minsn_t_is_between(self, m1, m2)

    def is_after(self, m: "minsn_t") -> "bool":
        r"""
        is_after(self, m) -> bool
        Is the instruction after the specified one?

        @param m: (C++: const minsn_t *) the instruction to compare against in the list
        """
        return _ida_hexrays.minsn_t_is_after(self, m)

    def may_use_aliased_memory(self) -> "bool":
        r"""
        may_use_aliased_memory(self) -> bool
        Is it possible for the instruction to use aliased memory?
        """
        return _ida_hexrays.minsn_t_may_use_aliased_memory(self)

    def serialize(self, b: "bytevec_t *") -> "int":
        r"""
        serialize(self, b) -> int
        Serialize an instruction

        @param b: (C++: bytevec_t *) the output buffer
        @return: the serialization format that was used to store info
        """
        return _ida_hexrays.minsn_t_serialize(self, b)

    def deserialize(self, bytes: "uchar const *", format_version: "int") -> "bool":
        r"""
        deserialize(self, bytes, format_version) -> bool
        Deserialize an instruction

        @param bytes: (C++: const uchar *) pointer to serialized data
        @param format_version: (C++: int) serialization format version. this value is returned by
                               minsn_t::serialize()
        @return: success
        """
        return _ida_hexrays.minsn_t_deserialize(self, bytes, format_version)

    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.minsn_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.minsn_t__deregister(self)

    def __dbg_get_meminfo(self) -> "qstring":
        r"""
        __dbg_get_meminfo(self) -> qstring
        """
        return _ida_hexrays.minsn_t___dbg_get_meminfo(self)

    def __dbg_get_registered_kind(self) -> "int":
        r"""
        __dbg_get_registered_kind(self) -> int
        """
        return _ida_hexrays.minsn_t___dbg_get_registered_kind(self)

    def _obj_id(self) -> "PyObject *":
        r"""_obj_id(self) -> PyObject *"""
        return _ida_hexrays.minsn_t__obj_id(self)

    obj_id = property(_obj_id)

    def _ensure_cond(self, ok, cond_str):
        if not ok:
            raise Exception("Condition \"%s\" not verified" % cond_str)
        return True

    def _ensure_no_obj(self, o, attr, attr_is_acquired):
        if attr_is_acquired and o is not None:
            raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
        return True

    def _ensure_ownership_transferrable(self, v):
        if not v.thisown:
            raise Exception("%s is already owned, and cannot be reused" % v)

    def _acquire_ownership(self, v, acquire):
        if acquire and (v is not None) and not isinstance(v, ida_idaapi.integer_types):
            self._ensure_ownership_transferrable(v)
            v.thisown = False
            dereg = getattr(v, "_deregister", None)
            if dereg:
                dereg()
        return True

    def _maybe_disown_and_deregister(self):
        if self.thisown:
            self.thisown = False
            self._deregister()

    def _own_and_register(self):
        assert(not self.thisown)
        self.thisown = True
        self._register()

    def replace_by(self, o):
        assert(isinstance(o, (cexpr_t, cinsn_t)))
        o._maybe_disown_and_deregister()
        self._replace_by(o)

    def _meminfo(self):
        cpp = self.__dbg_get_meminfo()
        rkind = self.__dbg_get_registered_kind()
        rkind_str = [
                "(not owned)",
                "cfuncptr_t",
                "cinsn_t",
                "cexpr_t",
                "cblock_t",
                "mba_t",
                "mop_t",
                "minsn_t",
                "optinsn_t",
                "optblock_t",
                "valrng_t",
                "udc_filter_t"][rkind]
        return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                cpp,
                self.thisown,
                rkind_str)
    meminfo = property(_meminfo)

    __swig_destroy__ = _ida_hexrays.delete_minsn_t

# Register minsn_t in _ida_hexrays:
_ida_hexrays.minsn_t_swigregister(minsn_t)
IPROP_OPTIONAL = _ida_hexrays.IPROP_OPTIONAL
r"""
optional instruction
"""

IPROP_PERSIST = _ida_hexrays.IPROP_PERSIST
r"""
persistent insn; they are not destroyed
"""

IPROP_WILDMATCH = _ida_hexrays.IPROP_WILDMATCH
r"""
match multiple insns
"""

IPROP_CLNPOP = _ida_hexrays.IPROP_CLNPOP
r"""
the purpose of the instruction is to clean stack (e.g. "pop ecx" is often used
for that)
"""

IPROP_FPINSN = _ida_hexrays.IPROP_FPINSN
r"""
floating point insn
"""

IPROP_FARCALL = _ida_hexrays.IPROP_FARCALL
r"""
call of a far function using push cs/call sequence
"""

IPROP_TAILCALL = _ida_hexrays.IPROP_TAILCALL
r"""
tail call
"""

IPROP_ASSERT = _ida_hexrays.IPROP_ASSERT
r"""
assertion: usually mov #val, op. assertions are used to help the optimizer.
assertions are ignored when generating ctree
"""

IPROP_SPLIT = _ida_hexrays.IPROP_SPLIT
r"""
the instruction has been split:
"""

IPROP_SPLIT1 = _ida_hexrays.IPROP_SPLIT1
r"""
into 1 byte
"""

IPROP_SPLIT2 = _ida_hexrays.IPROP_SPLIT2
r"""
into 2 bytes
"""

IPROP_SPLIT4 = _ida_hexrays.IPROP_SPLIT4
r"""
into 4 bytes
"""

IPROP_SPLIT8 = _ida_hexrays.IPROP_SPLIT8
r"""
into 8 bytes
"""

IPROP_COMBINED = _ida_hexrays.IPROP_COMBINED
r"""
insn has been modified because of a partial reference
"""

IPROP_EXTSTX = _ida_hexrays.IPROP_EXTSTX
r"""
this is m_ext propagated into m_stx
"""

IPROP_IGNLOWSRC = _ida_hexrays.IPROP_IGNLOWSRC
r"""
low part of the instruction source operand has been created artificially (this
bit is used only for 'and x, 80...')
"""

IPROP_INV_JX = _ida_hexrays.IPROP_INV_JX
r"""
inverted conditional jump
"""

IPROP_WAS_NORET = _ida_hexrays.IPROP_WAS_NORET
r"""
was noret icall
"""

IPROP_MULTI_MOV = _ida_hexrays.IPROP_MULTI_MOV
r"""
bits that can be set by plugins:

the minsn was generated as part of insn that moves multiple registers (example:
STM on ARM may transfer multiple registers)
"""

IPROP_DONT_PROP = _ida_hexrays.IPROP_DONT_PROP
r"""
may not propagate
"""

IPROP_DONT_COMB = _ida_hexrays.IPROP_DONT_COMB
r"""
may not combine this instruction with others
"""

IPROP_MBARRIER = _ida_hexrays.IPROP_MBARRIER
r"""
this instruction acts as a memory barrier (instructions accessing memory may not
be reordered past it)
"""

IPROP_UNMERGED = _ida_hexrays.IPROP_UNMERGED
r"""
'goto' instruction was transformed info 'call'
"""

IPROP_UNPAIRED = _ida_hexrays.IPROP_UNPAIRED
r"""
instruction is a result of del_dest_pairs() transformation
"""

OPTI_ADDREXPRS = _ida_hexrays.OPTI_ADDREXPRS
r"""
optimize all address expressions (&x+N; &x-&y)
"""

OPTI_MINSTKREF = _ida_hexrays.OPTI_MINSTKREF
r"""
may update minstkref
"""

OPTI_COMBINSNS = _ida_hexrays.OPTI_COMBINSNS
r"""
may combine insns (only for optimize_insn)
"""

OPTI_NO_LDXOPT = _ida_hexrays.OPTI_NO_LDXOPT
r"""
the function is called after the propagation attempt, we do not optimize
low/high(ldx) in this case
"""

OPTI_NO_VALRNG = _ida_hexrays.OPTI_NO_VALRNG
r"""
forbid using valranges
"""

EQ_IGNSIZE = _ida_hexrays.EQ_IGNSIZE
r"""
ignore source operand sizes
"""

EQ_IGNCODE = _ida_hexrays.EQ_IGNCODE
r"""
ignore instruction opcodes
"""

EQ_CMPDEST = _ida_hexrays.EQ_CMPDEST
r"""
compare instruction destinations
"""

EQ_OPTINSN = _ida_hexrays.EQ_OPTINSN
r"""
optimize mop_d operands
"""

NORET_IGNORE_WAS_NORET_ICALL = _ida_hexrays.NORET_IGNORE_WAS_NORET_ICALL

NORET_FORBID_ANALYSIS = _ida_hexrays.NORET_FORBID_ANALYSIS



def getf_reginsn(ins: "minsn_t") -> "minsn_t *":
    r"""
    getf_reginsn(ins) -> minsn_t

    @param ins: minsn_t *
    """
    return _ida_hexrays.getf_reginsn(ins)

def getb_reginsn(ins: "minsn_t") -> "minsn_t *":
    r"""
    getb_reginsn(ins) -> minsn_t

    @param ins: minsn_t *
    """
    return _ida_hexrays.getb_reginsn(ins)
BLT_NONE = _ida_hexrays.BLT_NONE
r"""
unknown block type
"""

BLT_STOP = _ida_hexrays.BLT_STOP
r"""
stops execution regularly (must be the last block)
"""

BLT_0WAY = _ida_hexrays.BLT_0WAY
r"""
does not have successors (tail is a noret function)
"""

BLT_1WAY = _ida_hexrays.BLT_1WAY
r"""
passes execution to one block (regular or goto block)
"""

BLT_2WAY = _ida_hexrays.BLT_2WAY
r"""
passes execution to two blocks (conditional jump)
"""

BLT_NWAY = _ida_hexrays.BLT_NWAY
r"""
passes execution to many blocks (switch idiom)
"""

BLT_XTRN = _ida_hexrays.BLT_XTRN
r"""
external block (out of function address)
"""

class mblock_t(object):
    r"""
    Proxy of C++ mblock_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    nextb: "mblock_t *" = property(_ida_hexrays.mblock_t_nextb_get, _ida_hexrays.mblock_t_nextb_set, doc=r"""nextb""")
    r"""
    next block in the doubly linked list
    """
    prevb: "mblock_t *" = property(_ida_hexrays.mblock_t_prevb_get, _ida_hexrays.mblock_t_prevb_set, doc=r"""prevb""")
    r"""
    previous block in the doubly linked list
    """
    flags: "uint32" = property(_ida_hexrays.mblock_t_flags_get, _ida_hexrays.mblock_t_flags_set, doc=r"""flags""")
    r"""
    combination of Basic block properties bits
    """
    start: "ea_t" = property(_ida_hexrays.mblock_t_start_get, _ida_hexrays.mblock_t_start_set, doc=r"""start""")
    r"""
    start address
    """
    end: "ea_t" = property(_ida_hexrays.mblock_t_end_get, _ida_hexrays.mblock_t_end_set, doc=r"""end""")
    r"""
    end address note: we cannot rely on start/end addresses very much because
    instructions are propagated between blocks
    """
    head: "minsn_t *" = property(_ida_hexrays.mblock_t_head_get, _ida_hexrays.mblock_t_head_set, doc=r"""head""")
    r"""
    pointer to the first instruction of the block
    """
    tail: "minsn_t *" = property(_ida_hexrays.mblock_t_tail_get, _ida_hexrays.mblock_t_tail_set, doc=r"""tail""")
    r"""
    pointer to the last instruction of the block
    """
    mba: "mba_t *" = property(_ida_hexrays.mblock_t_mba_get, _ida_hexrays.mblock_t_mba_set, doc=r"""mba""")
    r"""
    the parent micro block array
    """
    serial: "int" = property(_ida_hexrays.mblock_t_serial_get, _ida_hexrays.mblock_t_serial_set, doc=r"""serial""")
    r"""
    block number
    """
    type: "mblock_type_t" = property(_ida_hexrays.mblock_t_type_get, _ida_hexrays.mblock_t_type_set, doc=r"""type""")
    r"""
    block type (BLT_NONE - not computed yet)
    """
    dead_at_start: "mlist_t" = property(_ida_hexrays.mblock_t_dead_at_start_get, _ida_hexrays.mblock_t_dead_at_start_set, doc=r"""dead_at_start""")
    r"""
    data that is dead at the block entry
    """
    mustbuse: "mlist_t" = property(_ida_hexrays.mblock_t_mustbuse_get, _ida_hexrays.mblock_t_mustbuse_set, doc=r"""mustbuse""")
    r"""
    data that must be used by the block
    """
    maybuse: "mlist_t" = property(_ida_hexrays.mblock_t_maybuse_get, _ida_hexrays.mblock_t_maybuse_set, doc=r"""maybuse""")
    r"""
    data that may be used by the block
    """
    mustbdef: "mlist_t" = property(_ida_hexrays.mblock_t_mustbdef_get, _ida_hexrays.mblock_t_mustbdef_set, doc=r"""mustbdef""")
    r"""
    data that must be defined by the block
    """
    maybdef: "mlist_t" = property(_ida_hexrays.mblock_t_maybdef_get, _ida_hexrays.mblock_t_maybdef_set, doc=r"""maybdef""")
    r"""
    data that may be defined by the block
    """
    dnu: "mlist_t" = property(_ida_hexrays.mblock_t_dnu_get, _ida_hexrays.mblock_t_dnu_set, doc=r"""dnu""")
    r"""
    data that is defined but not used in the block
    """
    maxbsp: "sval_t" = property(_ida_hexrays.mblock_t_maxbsp_get, _ida_hexrays.mblock_t_maxbsp_set, doc=r"""maxbsp""")
    r"""
    maximal sp value in the block (0...stacksize)
    """
    minbstkref: "sval_t" = property(_ida_hexrays.mblock_t_minbstkref_get, _ida_hexrays.mblock_t_minbstkref_set, doc=r"""minbstkref""")
    r"""
    lowest stack location accessible with indirect addressing (offset from the stack
    bottom) initially it is 0 (not computed)
    """
    minbargref: "sval_t" = property(_ida_hexrays.mblock_t_minbargref_get, _ida_hexrays.mblock_t_minbargref_set, doc=r"""minbargref""")
    r"""
    the same for arguments
    """
    predset: "intvec_t" = property(_ida_hexrays.mblock_t_predset_get, _ida_hexrays.mblock_t_predset_set, doc=r"""predset""")
    r"""
    control flow graph: list of our predecessors use npred() and pred() to access it
    """
    succset: "intvec_t" = property(_ida_hexrays.mblock_t_succset_get, _ida_hexrays.mblock_t_succset_set, doc=r"""succset""")
    r"""
    control flow graph: list of our successors use nsucc() and succ() to access it
    """

    def mark_lists_dirty(self) -> "void":
        r"""
        mark_lists_dirty(self)
        """
        return _ida_hexrays.mblock_t_mark_lists_dirty(self)

    def request_propagation(self) -> "void":
        r"""
        request_propagation(self)
        """
        return _ida_hexrays.mblock_t_request_propagation(self)

    def needs_propagation(self) -> "bool":
        r"""
        needs_propagation(self) -> bool
        """
        return _ida_hexrays.mblock_t_needs_propagation(self)

    def request_demote64(self) -> "void":
        r"""
        request_demote64(self)
        """
        return _ida_hexrays.mblock_t_request_demote64(self)

    def lists_dirty(self) -> "bool":
        r"""
        lists_dirty(self) -> bool
        """
        return _ida_hexrays.mblock_t_lists_dirty(self)

    def lists_ready(self) -> "bool":
        r"""
        lists_ready(self) -> bool
        """
        return _ida_hexrays.mblock_t_lists_ready(self)

    def make_lists_ready(self) -> "int":
        r"""
        make_lists_ready(self) -> int
        """
        return _ida_hexrays.mblock_t_make_lists_ready(self)

    def npred(self) -> "int":
        r"""
        npred(self) -> int
        Get number of block predecessors.
        """
        return _ida_hexrays.mblock_t_npred(self)

    def nsucc(self) -> "int":
        r"""
        nsucc(self) -> int
        Get number of block successors.
        """
        return _ida_hexrays.mblock_t_nsucc(self)

    def pred(self, n: "int") -> "int":
        r"""
        pred(self, n) -> int

        @param n: int
        """
        return _ida_hexrays.mblock_t_pred(self, n)

    def succ(self, n: "int") -> "int":
        r"""
        succ(self, n) -> int

        @param n: int
        """
        return _ida_hexrays.mblock_t_succ(self, n)
    __swig_destroy__ = _ida_hexrays.delete_mblock_t

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mblock_t_empty(self)

    def _print(self, vp: "vd_printer_t") -> "void":
        r"""
        _print(self, vp)

        Parameters
        ----------
        vp: vd_printer_t &

        """
        return _ida_hexrays.mblock_t__print(self, vp)

    def dump(self) -> "void":
        r"""
        dump(self)
        Dump block info. This function is useful for debugging, see mba_t::dump for info
        """
        return _ida_hexrays.mblock_t_dump(self)

    def dump_block(self, title: "char const *") -> "void":
        r"""
        dump_block(self, title)

        @param title: char const *
        """
        return _ida_hexrays.mblock_t_dump_block(self, title)

    def insert_into_block(self, nm: "minsn_t", om: "minsn_t") -> "minsn_t *":
        r"""
        insert_into_block(self, nm, om) -> minsn_t
        Insert instruction into the doubly linked list

        @param nm: (C++: minsn_t *) new instruction
        @param om: (C++: minsn_t *) existing instruction, part of the doubly linked list if nullptr, then
                   the instruction will be inserted at the beginning of the list NM will
                   be inserted immediately after OM
        @return: pointer to NM
        """
        val = _ida_hexrays.mblock_t_insert_into_block(self, nm, om)

        mn = nm
        mn._maybe_disown_and_deregister()


        return val


    def remove_from_block(self, m: "minsn_t") -> "minsn_t *":
        r"""
        remove_from_block(self, m) -> minsn_t
        Remove instruction from the doubly linked list

        @param m: (C++: minsn_t *) instruction to remove The removed instruction is not deleted, the
                  caller gets its ownership
        @return: pointer to the next instruction
        """

        mn = m


        val = _ida_hexrays.mblock_t_remove_from_block(self, m)

        if mn:
          mn._own_and_register()


        return val


    def for_all_insns(self, mv: "minsn_visitor_t") -> "int":
        r"""
        for_all_insns(self, mv) -> int
        Visit all instructions. This function visits subinstructions too.

        @param mv: (C++: minsn_visitor_t &) instruction visitor
        @return: zero or the value returned by mv.visit_insn() See also
                 mba_t::for_all_topinsns()
        """
        return _ida_hexrays.mblock_t_for_all_insns(self, mv)

    def for_all_ops(self, mv: "mop_visitor_t") -> "int":
        r"""
        for_all_ops(self, mv) -> int
        Visit all operands. This function visit subinstruction operands too.

        @param mv: (C++: mop_visitor_t &) operand visitor
        @return: zero or the value returned by mv.visit_mop()
        """
        return _ida_hexrays.mblock_t_for_all_ops(self, mv)

    def for_all_uses(self, list: "mlist_t", i1: "minsn_t", i2: "minsn_t", mmv: "mlist_mop_visitor_t") -> "int":
        r"""
        for_all_uses(self, list, i1, i2, mmv) -> int
        Visit all operands that use LIST.

        @param list: (C++: mlist_t *) ptr to the list of locations. it may be modified: parts that get
                     redefined by the instructions in [i1,i2) will be deleted.
        @param i1: (C++: minsn_t *) starting instruction. must be a top level insn.
        @param i2: (C++: minsn_t *) ending instruction (excluded). must be a top level insn.
        @param mmv: (C++: mlist_mop_visitor_t &) operand visitor
        @return: zero or the value returned by mmv.visit_mop()
        """
        return _ida_hexrays.mblock_t_for_all_uses(self, list, i1, i2, mmv)

    def optimize_insn(self, *args) -> "int":
        r"""
        optimize_insn(self, m, optflags=0x0002|0x0004) -> int
        Optimize one instruction in the context of the block.

        @param m: (C++: minsn_t *) pointer to a top level instruction
        @param optflags: (C++: int) combination of optimization flags bits
        @return: number of changes made to the block This function may change other
                 instructions in the block too. However, it will not destroy top level
                 instructions (it may convert them to nop's). This function performs
                 only intrablock modifications. See also minsn_t::optimize_solo()
        """
        return _ida_hexrays.mblock_t_optimize_insn(self, *args)

    def optimize_block(self) -> "int":
        r"""
        optimize_block(self) -> int
        Optimize a basic block. Usually there is no need to call this function
        explicitly because the decompiler will call it itself if optinsn_t::func or
        optblock_t::func return non-zero.

        @return: number of changes made to the block
        """
        return _ida_hexrays.mblock_t_optimize_block(self)

    def build_lists(self, kill_deads: "bool") -> "int":
        r"""
        build_lists(self, kill_deads) -> int
        Build def-use lists and eliminate deads.

        @param kill_deads: (C++: bool) do delete dead instructions?
        @return: the number of eliminated instructions Better mblock_t::call
                 make_lists_ready() rather than this function.
        """
        return _ida_hexrays.mblock_t_build_lists(self, kill_deads)

    def optimize_useless_jump(self) -> "int":
        r"""
        optimize_useless_jump(self) -> int
        Remove a jump at the end of the block if it is useless. This function preserves
        any side effects when removing a useless jump. Both conditional and
        unconditional jumps are handled (and jtbl too). This function deletes useless
        jumps, not only replaces them with a nop. (please note that \optimize_insn does
        not handle useless jumps).

        @return: number of changes made to the block
        """
        return _ida_hexrays.mblock_t_optimize_useless_jump(self)

    def append_use_list(self, *args) -> "void":
        r"""
        append_use_list(self, list, op, maymust, mask=bitrange_t(0, USHRT_MAX))
        Append use-list of an operand. This function calculates list of locations that
        may or must be used by the operand and appends it to LIST.

        @param list: (C++: mlist_t *) ptr to the output buffer. we will append to it.
        @param op: (C++: const mop_t &) operand to calculate the use list of
        @param maymust: (C++: maymust_t) should we calculate 'may-use' or 'must-use' list? see maymust_t
                        for more details.
        @param mask: (C++: bitrange_t) if only part of the operand should be considered, a bitmask can be
                     used to specify which part. example: op=AX,mask=0xFF means that we
                     will consider only AL.
        """
        return _ida_hexrays.mblock_t_append_use_list(self, *args)

    def append_def_list(self, list: "mlist_t", op: "mop_t", maymust: "maymust_t") -> "void":
        r"""
        append_def_list(self, list, op, maymust)
        Append def-list of an operand. This function calculates list of locations that
        may or must be modified by the operand and appends it to LIST.

        @param list: (C++: mlist_t *) ptr to the output buffer. we will append to it.
        @param op: (C++: const mop_t &) operand to calculate the def list of
        @param maymust: (C++: maymust_t) should we calculate 'may-def' or 'must-def' list? see maymust_t
                        for more details.
        """
        return _ida_hexrays.mblock_t_append_def_list(self, list, op, maymust)

    def build_use_list(self, ins: "minsn_t", maymust: "maymust_t") -> "mlist_t":
        r"""
        build_use_list(self, ins, maymust) -> mlist_t
        Build use-list of an instruction. This function calculates list of locations
        that may or must be used by the instruction. Examples: "ldx ds.2, eax.4, ebx.4",
        may-list: all aliasable memory "ldx ds.2, eax.4, ebx.4", must-list: empty Since
        LDX uses EAX for indirect access, it may access any aliasable memory. On the
        other hand, we cannot tell for sure which memory cells will be accessed, this is
        why the must-list is empty.

        @param ins: (C++: const minsn_t &) instruction to calculate the use list of
        @param maymust: (C++: maymust_t) should we calculate 'may-use' or 'must-use' list? see maymust_t
                        for more details.
        @return: the calculated use-list
        """
        return _ida_hexrays.mblock_t_build_use_list(self, ins, maymust)

    def build_def_list(self, ins: "minsn_t", maymust: "maymust_t") -> "mlist_t":
        r"""
        build_def_list(self, ins, maymust) -> mlist_t
        Build def-list of an instruction. This function calculates list of locations
        that may or must be modified by the instruction. Examples: "stx ebx.4, ds.2,
        eax.4", may-list: all aliasable memory "stx ebx.4, ds.2, eax.4", must-list:
        empty Since STX uses EAX for indirect access, it may modify any aliasable
        memory. On the other hand, we cannot tell for sure which memory cells will be
        modified, this is why the must-list is empty.

        @param ins: (C++: const minsn_t &) instruction to calculate the def list of
        @param maymust: (C++: maymust_t) should we calculate 'may-def' or 'must-def' list? see maymust_t
                        for more details.
        @return: the calculated def-list
        """
        return _ida_hexrays.mblock_t_build_def_list(self, ins, maymust)

    def is_used(self, *args) -> "bool":
        r"""
        is_used(self, list, i1, i2, maymust=MAY_ACCESS) -> bool
        Is the list used by the specified instruction range?

        @param list: (C++: mlist_t *) list of locations. LIST may be modified by the function: redefined
                     locations will be removed from it.
        @param i1: (C++: const minsn_t *) starting instruction of the range (must be a top level insn)
        @param i2: (C++: const minsn_t *) end instruction of the range (must be a top level insn) i2 is
                   excluded from the range. it can be specified as nullptr. i1 and i2
                   must belong to the same block.
        @param maymust: (C++: maymust_t) should we search in 'may-access' or 'must-access' mode?
        """
        return _ida_hexrays.mblock_t_is_used(self, *args)

    def find_first_use(self, *args) -> "minsn_t *":
        r"""
        find_first_use(self, list, i1, i2, maymust=MAY_ACCESS) -> minsn_t

        @param list: mlist_t *
        @param i1: minsn_t *
        @param i2: minsn_t const *
        @param maymust: maymust_t
        """
        return _ida_hexrays.mblock_t_find_first_use(self, *args)

    def is_redefined(self, *args) -> "bool":
        r"""
        is_redefined(self, list, i1, i2, maymust=MAY_ACCESS) -> bool
        Is the list redefined by the specified instructions?

        @param list: (C++: const mlist_t &) list of locations to check.
        @param i1: (C++: const minsn_t *) starting instruction of the range (must be a top level insn)
        @param i2: (C++: const minsn_t *) end instruction of the range (must be a top level insn) i2 is
                   excluded from the range. it can be specified as nullptr. i1 and i2
                   must belong to the same block.
        @param maymust: (C++: maymust_t) should we search in 'may-access' or 'must-access' mode?
        """
        return _ida_hexrays.mblock_t_is_redefined(self, *args)

    def find_redefinition(self, *args) -> "minsn_t *":
        r"""
        find_redefinition(self, list, i1, i2, maymust=MAY_ACCESS) -> minsn_t

        @param list: mlist_t const &
        @param i1: minsn_t *
        @param i2: minsn_t const *
        @param maymust: maymust_t
        """
        return _ida_hexrays.mblock_t_find_redefinition(self, *args)

    def is_rhs_redefined(self, ins: "minsn_t", i1: "minsn_t", i2: "minsn_t") -> "bool":
        r"""
        is_rhs_redefined(self, ins, i1, i2) -> bool
        Is the right hand side of the instruction redefined the insn range? "right hand
        side" corresponds to the source operands of the instruction.

        @param ins: (C++: const minsn_t *) instruction to consider
        @param i1: (C++: const minsn_t *) starting instruction of the range (must be a top level insn)
        @param i2: (C++: const minsn_t *) end instruction of the range (must be a top level insn) i2 is
                   excluded from the range. it can be specified as nullptr. i1 and i2
                   must belong to the same block.
        """
        return _ida_hexrays.mblock_t_is_rhs_redefined(self, ins, i1, i2)

    def find_access(self, op: "mop_t", parent: "minsn_t **", mend: "minsn_t", fdflags: "int") -> "minsn_t *":
        r"""
        find_access(self, op, parent, mend, fdflags) -> minsn_t
        Find the instruction that accesses the specified operand. This function search
        inside one block.

        @param op: (C++: const mop_t &) operand to search for
        @param parent: (C++: minsn_t **) ptr to ptr to a top level instruction. denotes the beginning of
                       the search range.
        @param mend: (C++: const minsn_t *) end instruction of the range (must be a top level insn) mend is
                     excluded from the range. it can be specified as nullptr. parent and
                     mend must belong to the same block.
        @param fdflags: (C++: int) combination of bits for mblock_t::find_access bits
        @return: the instruction that accesses the operand. this instruction may be a
                 sub-instruction. to find out the top level instruction, check out
                 *p_i1. nullptr means 'not found'.
        """
        return _ida_hexrays.mblock_t_find_access(self, op, parent, mend, fdflags)

    def find_def(self, op: "mop_t", p_i1: "minsn_t **", i2: "minsn_t", fdflags: "int") -> "minsn_t *":
        r"""
        find_def(self, op, p_i1, i2, fdflags) -> minsn_t

        @param op: mop_t const &
        @param p_i1: minsn_t **
        @param i2: minsn_t const *
        @param fdflags: int
        """
        return _ida_hexrays.mblock_t_find_def(self, op, p_i1, i2, fdflags)

    def find_use(self, op: "mop_t", p_i1: "minsn_t **", i2: "minsn_t", fdflags: "int") -> "minsn_t *":
        r"""
        find_use(self, op, p_i1, i2, fdflags) -> minsn_t

        @param op: mop_t const &
        @param p_i1: minsn_t **
        @param i2: minsn_t const *
        @param fdflags: int
        """
        return _ida_hexrays.mblock_t_find_use(self, op, p_i1, i2, fdflags)

    def get_valranges(self, *args) -> "bool":
        r"""
        get_valranges(self, res, vivl, vrflags) -> bool
        Find possible values for an instruction.

        @param res: (C++: valrng_t *) set of value ranges
        @param vivl: (C++: const vivl_t &) what to search for
        @param vrflags: (C++: int) combination of bits for get_valranges bits
        get_valranges(self, res, vivl, m, vrflags) -> bool

        @param res: valrng_t *
        @param vivl: vivl_t const &
        @param m: minsn_t const *
        @param vrflags: int
        """
        return _ida_hexrays.mblock_t_get_valranges(self, *args)

    def make_nop(self, m: "minsn_t") -> "void":
        r"""
        make_nop(self, m)
        Erase the instruction (convert it to nop) and mark the lists dirty. This is the
        recommended function to use because it also marks the block use-def lists dirty.

        @param m: (C++: minsn_t *)
        """
        return _ida_hexrays.mblock_t_make_nop(self, m)

    def get_reginsn_qty(self) -> "size_t":
        r"""
        get_reginsn_qty(self) -> size_t
        Calculate number of regular instructions in the block. Assertions are skipped by
        this function.

        @return: Number of non-assertion instructions in the block.
        """
        return _ida_hexrays.mblock_t_get_reginsn_qty(self)

    def is_call_block(self) -> "bool":
        r"""
        is_call_block(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_call_block(self)

    def is_unknown_call(self) -> "bool":
        r"""
        is_unknown_call(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_unknown_call(self)

    def is_nway(self) -> "bool":
        r"""
        is_nway(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_nway(self)

    def is_branch(self) -> "bool":
        r"""
        is_branch(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_branch(self)

    def is_simple_goto_block(self) -> "bool":
        r"""
        is_simple_goto_block(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_simple_goto_block(self)

    def is_simple_jcnd_block(self) -> "bool":
        r"""
        is_simple_jcnd_block(self) -> bool
        """
        return _ida_hexrays.mblock_t_is_simple_jcnd_block(self)

    def preds(self):
        r"""
        Iterates the list of predecessor blocks
        """
        for ser in self.predset:
            yield self.mba.get_mblock(ser)

    def succs(self):
        r"""
        Iterates the list of successor blocks
        """
        for ser in self.succset:
            yield self.mba.get_mblock(ser)


# Register mblock_t in _ida_hexrays:
_ida_hexrays.mblock_t_swigregister(mblock_t)
MBL_PRIV = _ida_hexrays.MBL_PRIV
r"""
private block - no instructions except the specified are accepted (used in
patterns)
"""

MBL_NONFAKE = _ida_hexrays.MBL_NONFAKE
r"""
regular block
"""

MBL_FAKE = _ida_hexrays.MBL_FAKE
r"""
fake block
"""

MBL_GOTO = _ida_hexrays.MBL_GOTO
r"""
this block is a goto target
"""

MBL_TCAL = _ida_hexrays.MBL_TCAL
r"""
aritifical call block for tail calls
"""

MBL_PUSH = _ida_hexrays.MBL_PUSH
r"""
needs "convert push/pop instructions"
"""

MBL_DMT64 = _ida_hexrays.MBL_DMT64
r"""
needs "demote 64bits"
"""

MBL_COMB = _ida_hexrays.MBL_COMB
r"""
needs "combine" pass
"""

MBL_PROP = _ida_hexrays.MBL_PROP
r"""
needs 'propagation' pass
"""

MBL_DEAD = _ida_hexrays.MBL_DEAD
r"""
needs "eliminate deads" pass
"""

MBL_LIST = _ida_hexrays.MBL_LIST
r"""
use/def lists are ready (not dirty)
"""

MBL_INCONST = _ida_hexrays.MBL_INCONST
r"""
inconsistent lists: we are building them
"""

MBL_CALL = _ida_hexrays.MBL_CALL
r"""
call information has been built
"""

MBL_BACKPROP = _ida_hexrays.MBL_BACKPROP
r"""
performed backprop_cc
"""

MBL_NORET = _ida_hexrays.MBL_NORET
r"""
dead end block: doesn't return execution control
"""

MBL_DSLOT = _ida_hexrays.MBL_DSLOT
r"""
block for delay slot
"""

MBL_VALRANGES = _ida_hexrays.MBL_VALRANGES
r"""
should optimize using value ranges
"""

MBL_KEEP = _ida_hexrays.MBL_KEEP
r"""
do not remove even if unreachable
"""

MBL_INLINED = _ida_hexrays.MBL_INLINED
r"""
block was inlined, not originally part of mbr
"""

MBL_EXTFRAME = _ida_hexrays.MBL_EXTFRAME
r"""
an inlined block with an external frame
"""

FD_BACKWARD = _ida_hexrays.FD_BACKWARD
r"""
search direction
"""

FD_FORWARD = _ida_hexrays.FD_FORWARD
r"""
search direction
"""

FD_USE = _ida_hexrays.FD_USE
r"""
look for use
"""

FD_DEF = _ida_hexrays.FD_DEF
r"""
look for definition
"""

FD_DIRTY = _ida_hexrays.FD_DIRTY
r"""
ignore possible implicit definitions by function calls and indirect memory
access
"""

VR_AT_START = _ida_hexrays.VR_AT_START
r"""
get value ranges before the instruction or at the block start (if M is nullptr)
"""

VR_AT_END = _ida_hexrays.VR_AT_END
r"""
get value ranges after the instruction or at the block end, just after the last
instruction (if M is nullptr)
"""

VR_EXACT = _ida_hexrays.VR_EXACT
r"""
find exact match. if not set, the returned valrng size will be >= vivl.size
"""


WARN_VARARG_REGS = _ida_hexrays.WARN_VARARG_REGS
r"""
0 cannot handle register arguments in vararg function, discarded them
"""

WARN_ILL_PURGED = _ida_hexrays.WARN_ILL_PURGED
r"""
1 odd caller purged bytes d, correcting
"""

WARN_ILL_FUNCTYPE = _ida_hexrays.WARN_ILL_FUNCTYPE
r"""
2 invalid function type 's' has been ignored
"""

WARN_VARARG_TCAL = _ida_hexrays.WARN_VARARG_TCAL
r"""
3 cannot handle tail call to vararg
"""

WARN_VARARG_NOSTK = _ida_hexrays.WARN_VARARG_NOSTK
r"""
4 call vararg without local stack
"""

WARN_VARARG_MANY = _ida_hexrays.WARN_VARARG_MANY
r"""
5 too many varargs, some ignored
"""

WARN_ADDR_OUTARGS = _ida_hexrays.WARN_ADDR_OUTARGS
r"""
6 cannot handle address arithmetics in outgoing argument area of stack frame -
unused
"""

WARN_DEP_UNK_CALLS = _ida_hexrays.WARN_DEP_UNK_CALLS
r"""
7 found interdependent unknown calls
"""

WARN_ILL_ELLIPSIS = _ida_hexrays.WARN_ILL_ELLIPSIS
r"""
8 erroneously detected ellipsis type has been ignored
"""

WARN_GUESSED_TYPE = _ida_hexrays.WARN_GUESSED_TYPE
r"""
9 using guessed type s;
"""

WARN_EXP_LINVAR = _ida_hexrays.WARN_EXP_LINVAR
r"""
10 failed to expand a linear variable
"""

WARN_WIDEN_CHAINS = _ida_hexrays.WARN_WIDEN_CHAINS
r"""
11 failed to widen chains
"""

WARN_BAD_PURGED = _ida_hexrays.WARN_BAD_PURGED
r"""
12 inconsistent function type and number of purged bytes
"""

WARN_CBUILD_LOOPS = _ida_hexrays.WARN_CBUILD_LOOPS
r"""
13 too many cbuild loops
"""

WARN_NO_SAVE_REST = _ida_hexrays.WARN_NO_SAVE_REST
r"""
14 could not find valid save-restore pair for s
"""

WARN_ODD_INPUT_REG = _ida_hexrays.WARN_ODD_INPUT_REG
r"""
15 odd input register s
"""

WARN_ODD_ADDR_USE = _ida_hexrays.WARN_ODD_ADDR_USE
r"""
16 odd use of a variable address
"""

WARN_MUST_RET_FP = _ida_hexrays.WARN_MUST_RET_FP
r"""
17 function return type is incorrect (must be floating point)
"""

WARN_ILL_FPU_STACK = _ida_hexrays.WARN_ILL_FPU_STACK
r"""
18 inconsistent fpu stack
"""

WARN_SELFREF_PROP = _ida_hexrays.WARN_SELFREF_PROP
r"""
19 self-referencing variable has been detected
"""

WARN_WOULD_OVERLAP = _ida_hexrays.WARN_WOULD_OVERLAP
r"""
20 variables would overlap: s
"""

WARN_ARRAY_INARG = _ida_hexrays.WARN_ARRAY_INARG
r"""
21 array has been used for an input argument
"""

WARN_MAX_ARGS = _ida_hexrays.WARN_MAX_ARGS
r"""
22 too many input arguments, some ignored
"""

WARN_BAD_FIELD_TYPE = _ida_hexrays.WARN_BAD_FIELD_TYPE
r"""
23 incorrect structure member type for s::s, ignored
"""

WARN_WRITE_CONST = _ida_hexrays.WARN_WRITE_CONST
r"""
24 write access to const memory at a has been detected
"""

WARN_BAD_RETVAR = _ida_hexrays.WARN_BAD_RETVAR
r"""
25 wrong return variable
"""

WARN_FRAG_LVAR = _ida_hexrays.WARN_FRAG_LVAR
r"""
26 fragmented variable at s may be wrong
"""

WARN_HUGE_STKOFF = _ida_hexrays.WARN_HUGE_STKOFF
r"""
27 exceedingly huge offset into the stack frame
"""

WARN_UNINITED_REG = _ida_hexrays.WARN_UNINITED_REG
r"""
28 reference to an uninitialized register has been removed: s
"""

WARN_FIXED_INSN = _ida_hexrays.WARN_FIXED_INSN
r"""
29 fixed broken insn
"""

WARN_WRONG_VA_OFF = _ida_hexrays.WARN_WRONG_VA_OFF
r"""
30 wrong offset of va_list variable
"""

WARN_CR_NOFIELD = _ida_hexrays.WARN_CR_NOFIELD
r"""
31 CONTAINING_RECORD: no field 's' in struct 's' at d
"""

WARN_CR_BADOFF = _ida_hexrays.WARN_CR_BADOFF
r"""
32 CONTAINING_RECORD: too small offset d for struct 's'
"""

WARN_BAD_STROFF = _ida_hexrays.WARN_BAD_STROFF
r"""
33 user specified stroff has not been processed: s
"""

WARN_BAD_VARSIZE = _ida_hexrays.WARN_BAD_VARSIZE
r"""
34 inconsistent variable size for 's'
"""

WARN_UNSUPP_REG = _ida_hexrays.WARN_UNSUPP_REG
r"""
35 unsupported processor register 's'
"""

WARN_UNALIGNED_ARG = _ida_hexrays.WARN_UNALIGNED_ARG
r"""
36 unaligned function argument 's'
"""

WARN_BAD_STD_TYPE = _ida_hexrays.WARN_BAD_STD_TYPE
r"""
37 corrupted or unexisting local type 's'
"""

WARN_BAD_CALL_SP = _ida_hexrays.WARN_BAD_CALL_SP
r"""
38 bad sp value at call
"""

WARN_MISSED_SWITCH = _ida_hexrays.WARN_MISSED_SWITCH
r"""
39 wrong markup of switch jump, skipped it
"""

WARN_BAD_SP = _ida_hexrays.WARN_BAD_SP
r"""
40 positive sp value a has been found
"""

WARN_BAD_STKPNT = _ida_hexrays.WARN_BAD_STKPNT
r"""
41 wrong sp change point
"""

WARN_UNDEF_LVAR = _ida_hexrays.WARN_UNDEF_LVAR
r"""
42 variable 's' is possibly undefined
"""

WARN_JUMPOUT = _ida_hexrays.WARN_JUMPOUT
r"""
43 control flows out of bounds
"""

WARN_BAD_VALRNG = _ida_hexrays.WARN_BAD_VALRNG
r"""
44 values range analysis failed
"""

WARN_BAD_SHADOW = _ida_hexrays.WARN_BAD_SHADOW
r"""
45 ignored the value written to the shadow area of the succeeding call
"""

WARN_OPT_VALRNG = _ida_hexrays.WARN_OPT_VALRNG
r"""
46 conditional instruction was optimized away because s
"""

WARN_RET_LOCREF = _ida_hexrays.WARN_RET_LOCREF
r"""
47 returning address of temporary local variable 's'
"""

WARN_BAD_MAPDST = _ida_hexrays.WARN_BAD_MAPDST
r"""
48 too short map destination 's' for variable 's'
"""

WARN_BAD_INSN = _ida_hexrays.WARN_BAD_INSN
r"""
49 bad instruction
"""

WARN_ODD_ABI = _ida_hexrays.WARN_ODD_ABI
r"""
50 encountered odd instruction for the current ABI
"""

WARN_UNBALANCED_STACK = _ida_hexrays.WARN_UNBALANCED_STACK
r"""
51 unbalanced stack, ignored a potential tail call
"""

WARN_OPT_VALRNG2 = _ida_hexrays.WARN_OPT_VALRNG2
r"""
52 mask 0xX is shortened because s <= 0xX"
"""

WARN_OPT_VALRNG3 = _ida_hexrays.WARN_OPT_VALRNG3
r"""
53 masking with 0XX was optimized away because s <= 0xX
"""

WARN_OPT_USELESS_JCND = _ida_hexrays.WARN_OPT_USELESS_JCND
r"""
54 simplified comparisons for 's': s became s
"""

WARN_SUBFRAME_OVERFLOW = _ida_hexrays.WARN_SUBFRAME_OVERFLOW
r"""
55 call arguments overflow the function chunk frame
"""

WARN_MAX = _ida_hexrays.WARN_MAX
r"""
may be used in notes as a placeholder when the warning id is not available
"""

class hexwarn_t(object):
    r"""
    Proxy of C++ hexwarn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.hexwarn_t_ea_get, _ida_hexrays.hexwarn_t_ea_set, doc=r"""ea""")
    r"""
    Address where the warning occurred.
    """
    id: "warnid_t" = property(_ida_hexrays.hexwarn_t_id_get, _ida_hexrays.hexwarn_t_id_set, doc=r"""id""")
    r"""
    Warning id.
    """
    text: "qstring" = property(_ida_hexrays.hexwarn_t_text_get, _ida_hexrays.hexwarn_t_text_set, doc=r"""text""")
    r"""
    Fully formatted text of the warning.
    """

    def __eq__(self, r: "hexwarn_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___eq__(self, r)

    def __ne__(self, r: "hexwarn_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___ne__(self, r)

    def __lt__(self, r: "hexwarn_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___lt__(self, r)

    def __gt__(self, r: "hexwarn_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___gt__(self, r)

    def __le__(self, r: "hexwarn_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___le__(self, r)

    def __ge__(self, r: "hexwarn_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t___ge__(self, r)

    def compare(self, r: "hexwarn_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: hexwarn_t const &
        """
        return _ida_hexrays.hexwarn_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> hexwarn_t
        """
        _ida_hexrays.hexwarn_t_swiginit(self, _ida_hexrays.new_hexwarn_t())
    __swig_destroy__ = _ida_hexrays.delete_hexwarn_t

# Register hexwarn_t in _ida_hexrays:
_ida_hexrays.hexwarn_t_swigregister(hexwarn_t)
MMAT_ZERO = _ida_hexrays.MMAT_ZERO
r"""
microcode does not exist
"""

MMAT_GENERATED = _ida_hexrays.MMAT_GENERATED
r"""
generated microcode
"""

MMAT_PREOPTIMIZED = _ida_hexrays.MMAT_PREOPTIMIZED
r"""
preoptimized pass is complete
"""

MMAT_LOCOPT = _ida_hexrays.MMAT_LOCOPT
r"""
local optimization of each basic block is complete. control flow graph is ready
too.
"""

MMAT_CALLS = _ida_hexrays.MMAT_CALLS
r"""
detected call arguments. see also hxe_calls_done
"""

MMAT_GLBOPT1 = _ida_hexrays.MMAT_GLBOPT1
r"""
performed the first pass of global optimization
"""

MMAT_GLBOPT2 = _ida_hexrays.MMAT_GLBOPT2
r"""
most global optimization passes are done
"""

MMAT_GLBOPT3 = _ida_hexrays.MMAT_GLBOPT3
r"""
completed all global optimization. microcode is fixed now.
"""

MMAT_LVARS = _ida_hexrays.MMAT_LVARS
r"""
allocated local variables
"""

MMIDX_GLBLOW = _ida_hexrays.MMIDX_GLBLOW
r"""
global memory: low part
"""

MMIDX_LVARS = _ida_hexrays.MMIDX_LVARS
r"""
stack: local variables
"""

MMIDX_RETADDR = _ida_hexrays.MMIDX_RETADDR
r"""
stack: return address
"""

MMIDX_SHADOW = _ida_hexrays.MMIDX_SHADOW
r"""
stack: shadow arguments
"""

MMIDX_ARGS = _ida_hexrays.MMIDX_ARGS
r"""
stack: regular stack arguments
"""

MMIDX_GLBHIGH = _ida_hexrays.MMIDX_GLBHIGH
r"""
global memory: high part
"""

class mba_ranges_t(object):
    r"""
    Proxy of C++ mba_ranges_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    pfn: "func_t *" = property(_ida_hexrays.mba_ranges_t_pfn_get, _ida_hexrays.mba_ranges_t_pfn_set, doc=r"""pfn""")
    r"""
    function to decompile. if not null, then function mode.
    """
    ranges: "rangevec_t" = property(_ida_hexrays.mba_ranges_t_ranges_get, _ida_hexrays.mba_ranges_t_ranges_set, doc=r"""ranges""")
    r"""
    snippet mode: ranges to decompile. function mode: list of outlined ranges
    """

    def __init__(self, *args):
        r"""
        __init__(self, _pfn=None) -> mba_ranges_t

        @param _pfn: func_t *

        __init__(self, r) -> mba_ranges_t

        @param r: rangevec_t const &
        """
        _ida_hexrays.mba_ranges_t_swiginit(self, _ida_hexrays.new_mba_ranges_t(*args))

    def start(self) -> "ea_t":
        r"""
        start(self) -> ea_t
        """
        return _ida_hexrays.mba_ranges_t_start(self)

    def empty(self) -> "bool":
        r"""
        empty(self) -> bool
        """
        return _ida_hexrays.mba_ranges_t_empty(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.mba_ranges_t_clear(self)

    def is_snippet(self) -> "bool":
        r"""
        is_snippet(self) -> bool
        """
        return _ida_hexrays.mba_ranges_t_is_snippet(self)

    def is_fragmented(self) -> "bool":
        r"""
        is_fragmented(self) -> bool
        """
        return _ida_hexrays.mba_ranges_t_is_fragmented(self)
    __swig_destroy__ = _ida_hexrays.delete_mba_ranges_t

# Register mba_ranges_t in _ida_hexrays:
_ida_hexrays.mba_ranges_t_swigregister(mba_ranges_t)
class mba_range_iterator_t(object):
    r"""
    Proxy of C++ mba_range_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    rii: "range_chunk_iterator_t" = property(_ida_hexrays.mba_range_iterator_t_rii_get, _ida_hexrays.mba_range_iterator_t_rii_set, doc=r"""rii""")
    fii: "func_tail_iterator_t" = property(_ida_hexrays.mba_range_iterator_t_fii_get, _ida_hexrays.mba_range_iterator_t_fii_set, doc=r"""fii""")

    def is_snippet(self) -> "bool":
        r"""
        is_snippet(self) -> bool
        """
        return _ida_hexrays.mba_range_iterator_t_is_snippet(self)

    def set(self, mbr: "mba_ranges_t") -> "bool":
        r"""
        set(self, mbr) -> bool

        @param mbr: mba_ranges_t const &
        """
        return _ida_hexrays.mba_range_iterator_t_set(self, mbr)

    def next(self) -> "bool":
        r"""
        next(self) -> bool
        """
        return _ida_hexrays.mba_range_iterator_t_next(self)

    def chunk(self) -> "range_t const &":
        r"""
        chunk(self) -> range_t
        """
        return _ida_hexrays.mba_range_iterator_t_chunk(self)

    def __init__(self):
        r"""
        __init__(self) -> mba_range_iterator_t
        """
        _ida_hexrays.mba_range_iterator_t_swiginit(self, _ida_hexrays.new_mba_range_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_mba_range_iterator_t

# Register mba_range_iterator_t in _ida_hexrays:
_ida_hexrays.mba_range_iterator_t_swigregister(mba_range_iterator_t)
class mba_t(object):
    r"""
    Proxy of C++ mba_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr

    def precise_defeas(self) -> "bool":
        r"""
        precise_defeas(self) -> bool
        """
        return _ida_hexrays.mba_t_precise_defeas(self)

    def optimized(self) -> "bool":
        r"""
        optimized(self) -> bool
        """
        return _ida_hexrays.mba_t_optimized(self)

    def short_display(self) -> "bool":
        r"""
        short_display(self) -> bool
        """
        return _ida_hexrays.mba_t_short_display(self)

    def show_reduction(self) -> "bool":
        r"""
        show_reduction(self) -> bool
        """
        return _ida_hexrays.mba_t_show_reduction(self)

    def graph_insns(self) -> "bool":
        r"""
        graph_insns(self) -> bool
        """
        return _ida_hexrays.mba_t_graph_insns(self)

    def loaded_gdl(self) -> "bool":
        r"""
        loaded_gdl(self) -> bool
        """
        return _ida_hexrays.mba_t_loaded_gdl(self)

    def should_beautify(self) -> "bool":
        r"""
        should_beautify(self) -> bool
        """
        return _ida_hexrays.mba_t_should_beautify(self)

    def rtype_refined(self) -> "bool":
        r"""
        rtype_refined(self) -> bool
        """
        return _ida_hexrays.mba_t_rtype_refined(self)

    def may_refine_rettype(self) -> "bool":
        r"""
        may_refine_rettype(self) -> bool
        """
        return _ida_hexrays.mba_t_may_refine_rettype(self)

    def use_wingraph32(self) -> "bool":
        r"""
        use_wingraph32(self) -> bool
        """
        return _ida_hexrays.mba_t_use_wingraph32(self)

    def display_numaddrs(self) -> "bool":
        r"""
        display_numaddrs(self) -> bool
        """
        return _ida_hexrays.mba_t_display_numaddrs(self)

    def display_valnums(self) -> "bool":
        r"""
        display_valnums(self) -> bool
        """
        return _ida_hexrays.mba_t_display_valnums(self)

    def is_pattern(self) -> "bool":
        r"""
        is_pattern(self) -> bool
        """
        return _ida_hexrays.mba_t_is_pattern(self)

    def is_thunk(self) -> "bool":
        r"""
        is_thunk(self) -> bool
        """
        return _ida_hexrays.mba_t_is_thunk(self)

    def saverest_done(self) -> "bool":
        r"""
        saverest_done(self) -> bool
        """
        return _ida_hexrays.mba_t_saverest_done(self)

    def callinfo_built(self) -> "bool":
        r"""
        callinfo_built(self) -> bool
        """
        return _ida_hexrays.mba_t_callinfo_built(self)

    def really_alloc(self) -> "bool":
        r"""
        really_alloc(self) -> bool
        """
        return _ida_hexrays.mba_t_really_alloc(self)

    def lvars_allocated(self) -> "bool":
        r"""
        lvars_allocated(self) -> bool
        """
        return _ida_hexrays.mba_t_lvars_allocated(self)

    def chain_varnums_ok(self) -> "bool":
        r"""
        chain_varnums_ok(self) -> bool
        """
        return _ida_hexrays.mba_t_chain_varnums_ok(self)

    def returns_fpval(self) -> "bool":
        r"""
        returns_fpval(self) -> bool
        """
        return _ida_hexrays.mba_t_returns_fpval(self)

    def has_passregs(self) -> "bool":
        r"""
        has_passregs(self) -> bool
        """
        return _ida_hexrays.mba_t_has_passregs(self)

    def generated_asserts(self) -> "bool":
        r"""
        generated_asserts(self) -> bool
        """
        return _ida_hexrays.mba_t_generated_asserts(self)

    def propagated_asserts(self) -> "bool":
        r"""
        propagated_asserts(self) -> bool
        """
        return _ida_hexrays.mba_t_propagated_asserts(self)

    def deleted_pairs(self) -> "bool":
        r"""
        deleted_pairs(self) -> bool
        """
        return _ida_hexrays.mba_t_deleted_pairs(self)

    def common_stkvars_stkargs(self) -> "bool":
        r"""
        common_stkvars_stkargs(self) -> bool
        """
        return _ida_hexrays.mba_t_common_stkvars_stkargs(self)

    def lvar_names_ok(self) -> "bool":
        r"""
        lvar_names_ok(self) -> bool
        """
        return _ida_hexrays.mba_t_lvar_names_ok(self)

    def lvars_renamed(self) -> "bool":
        r"""
        lvars_renamed(self) -> bool
        """
        return _ida_hexrays.mba_t_lvars_renamed(self)

    def has_over_chains(self) -> "bool":
        r"""
        has_over_chains(self) -> bool
        """
        return _ida_hexrays.mba_t_has_over_chains(self)

    def valranges_done(self) -> "bool":
        r"""
        valranges_done(self) -> bool
        """
        return _ida_hexrays.mba_t_valranges_done(self)

    def argidx_ok(self) -> "bool":
        r"""
        argidx_ok(self) -> bool
        """
        return _ida_hexrays.mba_t_argidx_ok(self)

    def argidx_sorted(self) -> "bool":
        r"""
        argidx_sorted(self) -> bool
        """
        return _ida_hexrays.mba_t_argidx_sorted(self)

    def code16_bit_removed(self) -> "bool":
        r"""
        code16_bit_removed(self) -> bool
        """
        return _ida_hexrays.mba_t_code16_bit_removed(self)

    def has_stack_retval(self) -> "bool":
        r"""
        has_stack_retval(self) -> bool
        """
        return _ida_hexrays.mba_t_has_stack_retval(self)

    def has_outlines(self) -> "bool":
        r"""
        has_outlines(self) -> bool
        """
        return _ida_hexrays.mba_t_has_outlines(self)

    def is_ctr(self) -> "bool":
        r"""
        is_ctr(self) -> bool
        """
        return _ida_hexrays.mba_t_is_ctr(self)

    def is_dtr(self) -> "bool":
        r"""
        is_dtr(self) -> bool
        """
        return _ida_hexrays.mba_t_is_dtr(self)

    def is_cdtr(self) -> "bool":
        r"""
        is_cdtr(self) -> bool
        """
        return _ida_hexrays.mba_t_is_cdtr(self)

    def prop_complex(self) -> "bool":
        r"""
        prop_complex(self) -> bool
        """
        return _ida_hexrays.mba_t_prop_complex(self)

    def get_mba_flags(self) -> "int":
        r"""
        get_mba_flags(self) -> int
        """
        return _ida_hexrays.mba_t_get_mba_flags(self)

    def get_mba_flags2(self) -> "int":
        r"""
        get_mba_flags2(self) -> int
        """
        return _ida_hexrays.mba_t_get_mba_flags2(self)

    def set_mba_flags(self, f: "int") -> "void":
        r"""
        set_mba_flags(self, f)

        @param f: int
        """
        return _ida_hexrays.mba_t_set_mba_flags(self, f)

    def clr_mba_flags(self, f: "int") -> "void":
        r"""
        clr_mba_flags(self, f)

        @param f: int
        """
        return _ida_hexrays.mba_t_clr_mba_flags(self, f)

    def set_mba_flags2(self, f: "int") -> "void":
        r"""
        set_mba_flags2(self, f)

        @param f: int
        """
        return _ida_hexrays.mba_t_set_mba_flags2(self, f)

    def clr_mba_flags2(self, f: "int") -> "void":
        r"""
        clr_mba_flags2(self, f)

        @param f: int
        """
        return _ida_hexrays.mba_t_clr_mba_flags2(self, f)

    def clr_cdtr(self) -> "void":
        r"""
        clr_cdtr(self)
        """
        return _ida_hexrays.mba_t_clr_cdtr(self)

    def calc_shins_flags(self) -> "int":
        r"""
        calc_shins_flags(self) -> int
        """
        return _ida_hexrays.mba_t_calc_shins_flags(self)

    def stkoff_vd2ida(self, off: "sval_t") -> "sval_t":
        r"""
        stkoff_vd2ida(self, off) -> sval_t

        @param off: sval_t
        """
        return _ida_hexrays.mba_t_stkoff_vd2ida(self, off)

    def stkoff_ida2vd(self, off: "sval_t") -> "sval_t":
        r"""
        stkoff_ida2vd(self, off) -> sval_t

        @param off: sval_t
        """
        return _ida_hexrays.mba_t_stkoff_ida2vd(self, off)

    def argbase(self) -> "sval_t":
        r"""
        argbase(self) -> sval_t
        """
        return _ida_hexrays.mba_t_argbase(self)

    def idaloc2vd(self, loc: "argloc_t", width: "int") -> "vdloc_t":
        r"""
        idaloc2vd(self, loc, width) -> vdloc_t

        @param loc: argloc_t const &
        @param width: int
        """
        return _ida_hexrays.mba_t_idaloc2vd(self, loc, width)

    def vd2idaloc(self, *args) -> "argloc_t":
        r"""
        vd2idaloc(self, loc, width, spd) -> argloc_t

        @param loc: vdloc_t const &
        @param width: int
        @param spd: sval_t

        vd2idaloc(self, loc, width) -> argloc_t

        @param loc: vdloc_t const &
        @param width: int
        """
        return _ida_hexrays.mba_t_vd2idaloc(self, *args)

    def is_stkarg(self, v: "lvar_t") -> "bool":
        r"""
        is_stkarg(self, v) -> bool

        @param v: lvar_t const &
        """
        return _ida_hexrays.mba_t_is_stkarg(self, v)

    def get_ida_argloc(self, v: "lvar_t") -> "argloc_t":
        r"""
        get_ida_argloc(self, v) -> argloc_t

        @param v: lvar_t const &
        """
        return _ida_hexrays.mba_t_get_ida_argloc(self, v)
    mbr: "mba_ranges_t" = property(_ida_hexrays.mba_t_mbr_get, _ida_hexrays.mba_t_mbr_set, doc=r"""mbr""")
    entry_ea: "ea_t" = property(_ida_hexrays.mba_t_entry_ea_get, _ida_hexrays.mba_t_entry_ea_set, doc=r"""entry_ea""")
    last_prolog_ea: "ea_t" = property(_ida_hexrays.mba_t_last_prolog_ea_get, _ida_hexrays.mba_t_last_prolog_ea_set, doc=r"""last_prolog_ea""")
    first_epilog_ea: "ea_t" = property(_ida_hexrays.mba_t_first_epilog_ea_get, _ida_hexrays.mba_t_first_epilog_ea_set, doc=r"""first_epilog_ea""")
    qty: "int" = property(_ida_hexrays.mba_t_qty_get, _ida_hexrays.mba_t_qty_set, doc=r"""qty""")
    r"""
    number of basic blocks
    """
    npurged: "int" = property(_ida_hexrays.mba_t_npurged_get, _ida_hexrays.mba_t_npurged_set, doc=r"""npurged""")
    r"""
    -1 - unknown
    """
    cc: "cm_t" = property(_ida_hexrays.mba_t_cc_get, _ida_hexrays.mba_t_cc_set, doc=r"""cc""")
    r"""
    calling convention
    """
    tmpstk_size: "sval_t" = property(_ida_hexrays.mba_t_tmpstk_size_get, _ida_hexrays.mba_t_tmpstk_size_set, doc=r"""tmpstk_size""")
    r"""
    size of the temporary stack part (which dynamically changes with push/pops)
    """
    frsize: "sval_t" = property(_ida_hexrays.mba_t_frsize_get, _ida_hexrays.mba_t_frsize_set, doc=r"""frsize""")
    r"""
    size of local stkvars range in the stack frame
    """
    frregs: "sval_t" = property(_ida_hexrays.mba_t_frregs_get, _ida_hexrays.mba_t_frregs_set, doc=r"""frregs""")
    r"""
    size of saved registers range in the stack frame
    """
    fpd: "sval_t" = property(_ida_hexrays.mba_t_fpd_get, _ida_hexrays.mba_t_fpd_set, doc=r"""fpd""")
    r"""
    frame pointer delta
    """
    pfn_flags: "int" = property(_ida_hexrays.mba_t_pfn_flags_get, _ida_hexrays.mba_t_pfn_flags_set, doc=r"""pfn_flags""")
    r"""
    copy of func_t::flags
    """
    retsize: "int" = property(_ida_hexrays.mba_t_retsize_get, _ida_hexrays.mba_t_retsize_set, doc=r"""retsize""")
    r"""
    size of return address in the stack frame
    """
    shadow_args: "int" = property(_ida_hexrays.mba_t_shadow_args_get, _ida_hexrays.mba_t_shadow_args_set, doc=r"""shadow_args""")
    r"""
    size of shadow argument area
    """
    fullsize: "sval_t" = property(_ida_hexrays.mba_t_fullsize_get, _ida_hexrays.mba_t_fullsize_set, doc=r"""fullsize""")
    r"""
    Full stack size including incoming args.
    """
    stacksize: "sval_t" = property(_ida_hexrays.mba_t_stacksize_get, _ida_hexrays.mba_t_stacksize_set, doc=r"""stacksize""")
    r"""
    The maximal size of the function stack including bytes allocated for outgoing
    call arguments (up to retaddr)
    """
    inargoff: "sval_t" = property(_ida_hexrays.mba_t_inargoff_get, _ida_hexrays.mba_t_inargoff_set, doc=r"""inargoff""")
    r"""
    offset of the first stack argument; after fix_scattered_movs() INARGOFF may be
    less than STACKSIZE
    """
    minstkref: "sval_t" = property(_ida_hexrays.mba_t_minstkref_get, _ida_hexrays.mba_t_minstkref_set, doc=r"""minstkref""")
    r"""
    The lowest stack location whose address was taken.
    """
    minstkref_ea: "ea_t" = property(_ida_hexrays.mba_t_minstkref_ea_get, _ida_hexrays.mba_t_minstkref_ea_set, doc=r"""minstkref_ea""")
    r"""
    address with lowest minstkref (for debugging)
    """
    minargref: "sval_t" = property(_ida_hexrays.mba_t_minargref_get, _ida_hexrays.mba_t_minargref_set, doc=r"""minargref""")
    r"""
    The lowest stack argument location whose address was taken This location and
    locations above it can be aliased It controls locations >= inargoff-shadow_args
    """
    spd_adjust: "sval_t" = property(_ida_hexrays.mba_t_spd_adjust_get, _ida_hexrays.mba_t_spd_adjust_set, doc=r"""spd_adjust""")
    r"""
    If sp>0, the max positive sp value.
    """
    gotoff_stkvars: "ivlset_t" = property(_ida_hexrays.mba_t_gotoff_stkvars_get, _ida_hexrays.mba_t_gotoff_stkvars_set, doc=r"""gotoff_stkvars""")
    r"""
    stkvars that hold .got offsets. considered to be unaliasable
    """
    restricted_memory: "ivlset_t" = property(_ida_hexrays.mba_t_restricted_memory_get, _ida_hexrays.mba_t_restricted_memory_set, doc=r"""restricted_memory""")
    aliased_memory: "ivlset_t" = property(_ida_hexrays.mba_t_aliased_memory_get, _ida_hexrays.mba_t_aliased_memory_set, doc=r"""aliased_memory""")
    r"""
    aliased_memory+restricted_memory=ALLMEM
    """
    nodel_memory: "mlist_t" = property(_ida_hexrays.mba_t_nodel_memory_get, _ida_hexrays.mba_t_nodel_memory_set, doc=r"""nodel_memory""")
    r"""
    global dead elimination may not delete references to this area
    """
    consumed_argregs: "rlist_t" = property(_ida_hexrays.mba_t_consumed_argregs_get, _ida_hexrays.mba_t_consumed_argregs_set, doc=r"""consumed_argregs""")
    r"""
    registers converted into stack arguments, should not be used as arguments
    """
    maturity: "mba_maturity_t" = property(_ida_hexrays.mba_t_maturity_get, _ida_hexrays.mba_t_maturity_set, doc=r"""maturity""")
    r"""
    current maturity level
    """
    reqmat: "mba_maturity_t" = property(_ida_hexrays.mba_t_reqmat_get, _ida_hexrays.mba_t_reqmat_set, doc=r"""reqmat""")
    r"""
    required maturity level
    """
    final_type: "bool" = property(_ida_hexrays.mba_t_final_type_get, _ida_hexrays.mba_t_final_type_set, doc=r"""final_type""")
    r"""
    is the function type final? (specified by the user)
    """
    idb_type: "tinfo_t" = property(_ida_hexrays.mba_t_idb_type_get, _ida_hexrays.mba_t_idb_type_set, doc=r"""idb_type""")
    r"""
    function type as retrieved from the database
    """
    idb_spoiled: "reginfovec_t" = property(_ida_hexrays.mba_t_idb_spoiled_get, _ida_hexrays.mba_t_idb_spoiled_set, doc=r"""idb_spoiled""")
    r"""
    MBA_SPLINFO && final_type: info in ida format.
    """
    spoiled_list: "mlist_t" = property(_ida_hexrays.mba_t_spoiled_list_get, _ida_hexrays.mba_t_spoiled_list_set, doc=r"""spoiled_list""")
    r"""
    MBA_SPLINFO && !final_type: info in vd format.
    """
    fti_flags: "int" = property(_ida_hexrays.mba_t_fti_flags_get, _ida_hexrays.mba_t_fti_flags_set, doc=r"""fti_flags""")
    r"""
    FTI_... constants for the current function.
    """
    label: "qstring" = property(_ida_hexrays.mba_t_label_get, _ida_hexrays.mba_t_label_set, doc=r"""label""")
    r"""
    name of the function or pattern (colored)
    """
    vars: "lvars_t" = property(_ida_hexrays.mba_t_vars_get, _ida_hexrays.mba_t_vars_set, doc=r"""vars""")
    r"""
    local variables
    """
    argidx: "intvec_t" = property(_ida_hexrays.mba_t_argidx_get, _ida_hexrays.mba_t_argidx_set, doc=r"""argidx""")
    r"""
    input arguments (indexes into 'vars')
    """
    retvaridx: "int" = property(_ida_hexrays.mba_t_retvaridx_get, _ida_hexrays.mba_t_retvaridx_set, doc=r"""retvaridx""")
    r"""
    index of variable holding the return value -1 means none
    """
    error_ea: "ea_t" = property(_ida_hexrays.mba_t_error_ea_get, _ida_hexrays.mba_t_error_ea_set, doc=r"""error_ea""")
    r"""
    during microcode generation holds ins.ea
    """
    error_strarg: "qstring" = property(_ida_hexrays.mba_t_error_strarg_get, _ida_hexrays.mba_t_error_strarg_set, doc=r"""error_strarg""")
    blocks: "mblock_t *" = property(_ida_hexrays.mba_t_blocks_get, _ida_hexrays.mba_t_blocks_set, doc=r"""blocks""")
    r"""
    double linked list of blocks
    """
    natural: "mblock_t **" = property(_ida_hexrays.mba_t_natural_get, _ida_hexrays.mba_t_natural_set, doc=r"""natural""")
    r"""
    natural order of blocks
    """
    std_ivls: "ivl_with_name_t [6]" = property(_ida_hexrays.mba_t_std_ivls_get, _ida_hexrays.mba_t_std_ivls_set, doc=r"""std_ivls""")
    r"""
    we treat memory as consisting of 6 parts see memreg_index_t
    """
    notes: "hexwarns_t" = property(_ida_hexrays.mba_t_notes_get, _ida_hexrays.mba_t_notes_set, doc=r"""notes""")
    occurred_warns: "uchar [32]" = property(_ida_hexrays.mba_t_occurred_warns_get, _ida_hexrays.mba_t_occurred_warns_set, doc=r"""occurred_warns""")

    def write_to_const_detected(self) -> "bool":
        r"""
        write_to_const_detected(self) -> bool
        """
        return _ida_hexrays.mba_t_write_to_const_detected(self)

    def bad_call_sp_detected(self) -> "bool":
        r"""
        bad_call_sp_detected(self) -> bool
        """
        return _ida_hexrays.mba_t_bad_call_sp_detected(self)

    def regargs_is_not_aligned(self) -> "bool":
        r"""
        regargs_is_not_aligned(self) -> bool
        """
        return _ida_hexrays.mba_t_regargs_is_not_aligned(self)

    def has_bad_sp(self) -> "bool":
        r"""
        has_bad_sp(self) -> bool
        """
        return _ida_hexrays.mba_t_has_bad_sp(self)
    __swig_destroy__ = _ida_hexrays.delete_mba_t

    def term(self) -> "void":
        r"""
        term(self)
        """
        return _ida_hexrays.mba_t_term(self)

    def get_curfunc(self) -> "func_t *":
        r"""
        get_curfunc(self) -> func_t *
        """
        return _ida_hexrays.mba_t_get_curfunc(self)

    def use_frame(self) -> "bool":
        r"""
        use_frame(self) -> bool
        """
        return _ida_hexrays.mba_t_use_frame(self)

    def is_snippet(self) -> "bool":
        r"""
        is_snippet(self) -> bool
        """
        return _ida_hexrays.mba_t_is_snippet(self)

    def set_maturity(self, mat: "mba_maturity_t") -> "bool":
        r"""
        set_maturity(self, mat) -> bool
        Set maturity level.

        @param mat: (C++: mba_maturity_t) new maturity level
        @return: true if it is time to stop analysis Plugins may use this function to
                 skip some parts of the analysis. The maturity level cannot be
                 decreased.
        """
        return _ida_hexrays.mba_t_set_maturity(self, mat)

    def optimize_local(self, locopt_bits: "int") -> "int":
        r"""
        optimize_local(self, locopt_bits) -> int
        Optimize each basic block locally

        @param locopt_bits: (C++: int) combination of Bits for optimize_local() bits
        @return: number of changes. 0 means nothing changed This function is called by
                 the decompiler, usually there is no need to call it explicitly.
        """
        return _ida_hexrays.mba_t_optimize_local(self, locopt_bits)

    def build_graph(self) -> "merror_t":
        r"""
        build_graph(self) -> merror_t
        Build control flow graph. This function may be called only once. It calculates
        the type of each basic block and the adjacency list. optimize_local() calls this
        function if necessary. You need to call this function only before MMAT_LOCOPT.

        @return: error code
        """
        return _ida_hexrays.mba_t_build_graph(self)

    def get_graph(self) -> "mbl_graph_t *":
        r"""
        get_graph(self) -> mbl_graph_t
        Get control graph. Call build_graph() if you need the graph before MMAT_LOCOPT.
        """
        return _ida_hexrays.mba_t_get_graph(self)

    def analyze_calls(self, acflags: "int") -> "int":
        r"""
        analyze_calls(self, acflags) -> int
        Analyze calls and determine calling conventions.

        @param acflags: (C++: int) permitted actions that are necessary for successful detection of
                        calling conventions. See Bits for analyze_calls()
        @return: number of calls. -1 means error.
        """
        return _ida_hexrays.mba_t_analyze_calls(self, acflags)

    def optimize_global(self) -> "merror_t":
        r"""
        optimize_global(self) -> merror_t
        Optimize microcode globally. This function applies various optimization methods
        until we reach the fixed point. After that it preallocates lvars unless reqmat
        forbids it.

        @return: error code
        """
        return _ida_hexrays.mba_t_optimize_global(self)

    def alloc_lvars(self) -> "void":
        r"""
        alloc_lvars(self)
        Allocate local variables. Must be called only immediately after
        optimize_global(), with no modifications to the microcode. Converts registers,
        stack variables, and similar operands into mop_l. This call will not fail
        because all necessary checks were performed in optimize_global(). After this
        call the microcode reaches its final state.
        """
        return _ida_hexrays.mba_t_alloc_lvars(self)

    def dump(self) -> "void":
        r"""
        dump(self)
        Dump microcode to a file. The file will be created in the directory pointed by
        IDA_DUMPDIR envvar. Dump will be created only if IDA is run under debugger.
        """
        return _ida_hexrays.mba_t_dump(self)

    def dump_mba(self, _verify: "bool", title: "char const *") -> "void":
        r"""
        dump_mba(self, _verify, title)

        @param _verify: bool
        @param title: char const *
        """
        return _ida_hexrays.mba_t_dump_mba(self, _verify, title)

    def _print(self, vp: "vd_printer_t") -> "void":
        r"""
        _print(self, vp)

        Parameters
        ----------
        vp: vd_printer_t &

        """
        return _ida_hexrays.mba_t__print(self, vp)

    def verify(self, always: "bool") -> "void":
        r"""
        verify(self, always)
        Verify microcode consistency.

        @param always: (C++: bool) if false, the check will be performed only if ida runs under
                       debugger If any inconsistency is discovered, an internal error
                       will be generated. We strongly recommend you to call this
                       function before returing control to the decompiler from your
                       callbacks, in the case if you modified the microcode. If the
                       microcode is inconsistent, this function will generate an
                       internal error. We provide the source code of this function in
                       the plugins/hexrays_sdk/verifier directory for your reference.
        """
        return _ida_hexrays.mba_t_verify(self, always)

    def mark_chains_dirty(self) -> "void":
        r"""
        mark_chains_dirty(self)
        Mark the microcode use-def chains dirty. Call this function is any inter-block
        data dependencies got changed because of your modifications to the microcode.
        Failing to do so may cause an internal error.
        """
        return _ida_hexrays.mba_t_mark_chains_dirty(self)

    def get_mblock(self, *args) -> "mblock_t *":
        r"""
        get_mblock(self, n) -> mblock_t

        @param n: uint

        """
        return _ida_hexrays.mba_t_get_mblock(self, *args)

    def insert_block(self, bblk: "int") -> "mblock_t *":
        r"""
        insert_block(self, bblk) -> mblock_t
        Insert a block in the middle of the mbl array. The very first block of microcode
        must be empty, it is the entry block. The very last block of microcode must be
        BLT_STOP, it is the exit block. Therefore inserting a new block before the entry
        point or after the exit block is not a good idea.

        @param bblk: (C++: int) the new block will be inserted before BBLK
        @return: ptr to the new block
        """
        return _ida_hexrays.mba_t_insert_block(self, bblk)

    def split_block(self, blk: "mblock_t", start_insn: "minsn_t") -> "mblock_t *":
        r"""
        split_block(self, blk, start_insn) -> mblock_t
        Split a block: insert a new one after the block, move some instructions to new
        block

        @param blk: (C++: mblock_t *) block to be split
        @param start_insn: (C++: minsn_t *) all instructions to be moved to new block: starting with this
                           one up to the end
        @return: ptr to the new block
        """
        return _ida_hexrays.mba_t_split_block(self, blk, start_insn)

    def remove_block(self, blk: "mblock_t") -> "bool":
        r"""
        remove_block(self, blk) -> bool
        Delete a block.

        @param blk: (C++: mblock_t *) block to delete
        @return: true if at least one of the other blocks became empty or unreachable
        """
        return _ida_hexrays.mba_t_remove_block(self, blk)

    def remove_blocks(self, start_blk: "int", end_blk: "int") -> "bool":
        r"""
        remove_blocks(self, start_blk, end_blk) -> bool

        @param start_blk: int
        @param end_blk: int
        """
        return _ida_hexrays.mba_t_remove_blocks(self, start_blk, end_blk)

    def copy_block(self, blk: "mblock_t", new_serial: "int", cpblk_flags: "int"=3) -> "mblock_t *":
        r"""
        copy_block(self, blk, new_serial, cpblk_flags=3) -> mblock_t
        Make a copy of a block. This function makes a simple copy of the block. It does
        not fix the predecessor and successor lists, they must be fixed if necessary.

        @param blk: (C++: mblock_t *) block to copy
        @param new_serial: (C++: int) position of the copied block
        @param cpblk_flags: (C++: int) combination of Batch decompilation bits... bits
        @return: pointer to the new copy
        """
        return _ida_hexrays.mba_t_copy_block(self, blk, new_serial, cpblk_flags)

    def remove_empty_and_unreachable_blocks(self) -> "bool":
        r"""
        remove_empty_and_unreachable_blocks(self) -> bool
        Delete all empty and unreachable blocks. Blocks marked with MBL_KEEP won't be
        deleted.
        """
        return _ida_hexrays.mba_t_remove_empty_and_unreachable_blocks(self)

    def merge_blocks(self) -> "bool":
        r"""
        merge_blocks(self) -> bool
        Merge blocks. This function merges blocks constituting linear flow. It calls
        remove_empty_and_unreachable_blocks() as well.

        @return: true if changed any blocks
        """
        return _ida_hexrays.mba_t_merge_blocks(self)

    def for_all_ops(self, mv: "mop_visitor_t") -> "int":
        r"""
        for_all_ops(self, mv) -> int
        Visit all operands of all instructions.

        @param mv: (C++: mop_visitor_t &) operand visitor
        @return: non-zero value returned by mv.visit_mop() or zero
        """
        return _ida_hexrays.mba_t_for_all_ops(self, mv)

    def for_all_insns(self, mv: "minsn_visitor_t") -> "int":
        r"""
        for_all_insns(self, mv) -> int
        Visit all instructions. This function visits all instruction and
        subinstructions.

        @param mv: (C++: minsn_visitor_t &) instruction visitor
        @return: non-zero value returned by mv.visit_mop() or zero
        """
        return _ida_hexrays.mba_t_for_all_insns(self, mv)

    def for_all_topinsns(self, mv: "minsn_visitor_t") -> "int":
        r"""
        for_all_topinsns(self, mv) -> int
        Visit all top level instructions.

        @param mv: (C++: minsn_visitor_t &) instruction visitor
        @return: non-zero value returned by mv.visit_mop() or zero
        """
        return _ida_hexrays.mba_t_for_all_topinsns(self, mv)

    def find_mop(self, ctx: "op_parent_info_t", ea: "ea_t", is_dest: "bool", list: "mlist_t") -> "mop_t *":
        r"""
        find_mop(self, ctx, ea, is_dest, list) -> mop_t
        Find an operand in the microcode. This function tries to find the operand that
        matches LIST. Any operand that overlaps with LIST is considered as a match.

        @param ctx: (C++: op_parent_info_t *) context information for the result
        @param ea: (C++: ea_t) desired address of the operand. BADADDR means to accept any address.
        @param is_dest: (C++: bool) search for destination operand? this argument may be ignored if
                        the exact match could not be found
        @param list: (C++: const mlist_t &) list of locations the correspond to the operand
        @return: pointer to the operand or nullptr.
        """
        return _ida_hexrays.mba_t_find_mop(self, ctx, ea, is_dest, list)

    def create_helper_call(self, ea: "ea_t", helper: "char const *", rettype: "tinfo_t"=None, callargs: "mcallargs_t"=None, out: "mop_t"=None) -> "minsn_t *":
        r"""
        create_helper_call(self, ea, helper, rettype=None, callargs=None, out=None) -> minsn_t
        Create a call of a helper function.

        @param ea: (C++: ea_t) The desired address of the instruction
        @param helper: (C++: const char *) The helper name
        @param rettype: (C++: const tinfo_t *) The return type (nullptr or empty type means 'void')
        @param callargs: (C++: const mcallargs_t *) The helper arguments (nullptr-no arguments)
        @param out: (C++: const mop_t *) The operand where the call result should be stored. If this argument
                    is not nullptr, "mov helper_call(), out" will be generated.
                    Otherwise "call helper()" will be generated. Note: the size of this
                    operand must be equal to the RETTYPE size
        @return: pointer to the created instruction or nullptr if error
        """
        return _ida_hexrays.mba_t_create_helper_call(self, ea, helper, rettype, callargs, out)

    def get_func_output_lists(self, *args) -> "void":
        r"""
        get_func_output_lists(self, return_regs, spoiled, type, call_ea=BADADDR, tail_call=False)
        Prepare the lists of registers & memory that are defined/killed by a function

        @param return_regs: (C++: mlist_t *) defined regs to return (eax,edx)
        @param spoiled: (C++: mlist_t *) spoiled regs (flags,ecx,mem)
        @param type: (C++: const tinfo_t &) the function type
        @param call_ea: (C++: ea_t) the call insn address (if known)
        @param tail_call: (C++: bool) is it the tail call?
        """
        return _ida_hexrays.mba_t_get_func_output_lists(self, *args)

    def arg(self, *args) -> "lvar_t const &":
        r"""
        arg(self, n) -> lvar_t

        @param n: int

        """
        return _ida_hexrays.mba_t_arg(self, *args)

    def alloc_fict_ea(self, real_ea: "ea_t") -> "ea_t":
        r"""
        alloc_fict_ea(self, real_ea) -> ea_t
        Allocate a fictional address. This function can be used to allocate a new unique
        address for a new instruction, if re-using any existing address leads to
        conflicts. For example, if the last instruction of the function modifies R0 and
        falls through to the next function, it will be a tail call: LDM R0!, {R4,R7} end
        of the function start of another function In this case R0 generates two
        different lvars at the same address:
        * one modified by LDM
        * another that represents the return value from the tail call Another example: a
        third-party plugin makes a copy of an instruction. This may lead to the
        generation of two variables at the same address. Example 3: fictional addresses
        can be used for new instructions created while modifying the microcode. This
        function can be used to allocate a new unique address for a new instruction or a
        variable. The fictional address is selected from an unallocated address range.

        @param real_ea: (C++: ea_t) real instruction address (BADADDR is ok too)
        @return: a unique fictional address
        """
        return _ida_hexrays.mba_t_alloc_fict_ea(self, real_ea)

    def map_fict_ea(self, fict_ea: "ea_t") -> "ea_t":
        r"""
        map_fict_ea(self, fict_ea) -> ea_t
        Resolve a fictional address. This function provides a reverse of the mapping
        made by alloc_fict_ea().

        @param fict_ea: (C++: ea_t) fictional definition address
        @return: the real instruction address
        """
        return _ida_hexrays.mba_t_map_fict_ea(self, fict_ea)

    def get_std_region(self, idx: "memreg_index_t") -> "ivl_t const &":
        r"""
        get_std_region(self, idx) -> ivl_t
        Get information about various memory regions. We map the stack frame to the
        global memory, to some unused range.

        @param idx: (C++: memreg_index_t) enum memreg_index_t
        """
        return _ida_hexrays.mba_t_get_std_region(self, idx)

    def get_lvars_region(self) -> "ivl_t const &":
        r"""
        get_lvars_region(self) -> ivl_t
        """
        return _ida_hexrays.mba_t_get_lvars_region(self)

    def get_shadow_region(self) -> "ivl_t const &":
        r"""
        get_shadow_region(self) -> ivl_t
        """
        return _ida_hexrays.mba_t_get_shadow_region(self)

    def get_args_region(self) -> "ivl_t const &":
        r"""
        get_args_region(self) -> ivl_t
        """
        return _ida_hexrays.mba_t_get_args_region(self)

    def get_stack_region(self) -> "ivl_t":
        r"""
        get_stack_region(self) -> ivl_t
        """
        return _ida_hexrays.mba_t_get_stack_region(self)

    def serialize(self) -> "void":
        r"""
        serialize(self)
        Serialize mbl array into a sequence of bytes.
        """
        return _ida_hexrays.mba_t_serialize(self)

    @staticmethod
    def deserialize(bytes: "uchar const *") -> "mba_t *":
        r"""
        deserialize(bytes) -> mba_t
        Deserialize a byte sequence into mbl array.

        @param bytes: (C++: const uchar *) pointer to the beginning of the byte sequence.
        @return: new mbl array
        """
        return _ida_hexrays.mba_t_deserialize(bytes)

    def save_snapshot(self, description: "char const *") -> "void":
        r"""
        save_snapshot(self, description)
        Create and save microcode snapshot.

        @param description: (C++: const char *) char const *
        """
        return _ida_hexrays.mba_t_save_snapshot(self, description)

    def alloc_kreg(self, size: "size_t", check_size: "bool"=True) -> "mreg_t":
        r"""
        alloc_kreg(self, size, check_size=True) -> mreg_t
        Allocate a kernel register.

        @param size: (C++: size_t) size of the register in bytes
        @param check_size: (C++: bool) if true, only the sizes that correspond to a size of a basic
                           type will be accepted.
        @return: allocated register. mr_none means failure.
        """
        return _ida_hexrays.mba_t_alloc_kreg(self, size, check_size)

    def free_kreg(self, reg: "mreg_t", size: "size_t") -> "void":
        r"""
        free_kreg(self, reg, size)
        Free a kernel register. If wrong arguments are passed, this function will
        generate an internal error.

        @param reg: (C++: mreg_t) a previously allocated kernel register
        @param size: (C++: size_t) size of the register in bytes
        """
        return _ida_hexrays.mba_t_free_kreg(self, reg, size)

    def inline_func(self, cdg: "codegen_t", blknum: "int", ranges: "mba_ranges_t", decomp_flags: "int"=0, inline_flags: "int"=0) -> "merror_t":
        r"""
        inline_func(self, cdg, blknum, ranges, decomp_flags=0, inline_flags=0) -> merror_t
        Inline a range. Currently only functions are supported, not arbitrary ranges.
        This function may be called only during the initial microcode generation phase.

        @param cdg: (C++: codegen_t &) the codegenerator object
        @param blknum: (C++: int) the block contaning the call/jump instruction to inline
        @param ranges: (C++: mba_ranges_t &) the set of ranges to inline
        @param decomp_flags: (C++: int) combination of decompile() flags bits
        @param inline_flags: (C++: int) combination of inline_func() flags bits
        @return: error code
        """
        return _ida_hexrays.mba_t_inline_func(self, cdg, blknum, ranges, decomp_flags, inline_flags)

    def locate_stkpnt(self, ea: "ea_t") -> "stkpnt_t const *":
        r"""
        locate_stkpnt(self, ea) -> stkpnt_t const *

        @param ea: ea_t
        """
        return _ida_hexrays.mba_t_locate_stkpnt(self, ea)

    def set_lvar_name(self, v: "lvar_t", name: "char const *", flagbits: "int") -> "bool":
        r"""
        set_lvar_name(self, v, name, flagbits) -> bool

        @param v: lvar_t &
        @param name: char const *
        @param flagbits: int
        """
        return _ida_hexrays.mba_t_set_lvar_name(self, v, name, flagbits)

    def set_nice_lvar_name(self, v: "lvar_t", name: "char const *") -> "bool":
        r"""
        set_nice_lvar_name(self, v, name) -> bool

        @param v: lvar_t &
        @param name: char const *
        """
        return _ida_hexrays.mba_t_set_nice_lvar_name(self, v, name)

    def set_user_lvar_name(self, v: "lvar_t", name: "char const *") -> "bool":
        r"""
        set_user_lvar_name(self, v, name) -> bool

        @param v: lvar_t &
        @param name: char const *
        """
        return _ida_hexrays.mba_t_set_user_lvar_name(self, v, name)

    """
    Deprecated. Please do not use.
    """
    idb_node = property(lambda self: self.deprecated_idb_node)


    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.mba_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.mba_t__deregister(self)

# Register mba_t in _ida_hexrays:
_ida_hexrays.mba_t_swigregister(mba_t)
MBA_PRCDEFS = _ida_hexrays.MBA_PRCDEFS
r"""
use precise defeas for chain-allocated lvars
"""

MBA_NOFUNC = _ida_hexrays.MBA_NOFUNC
r"""
function is not present, addresses might be wrong
"""

MBA_PATTERN = _ida_hexrays.MBA_PATTERN
r"""
microcode pattern, callinfo is present
"""

MBA_LOADED = _ida_hexrays.MBA_LOADED
r"""
loaded gdl, no instructions (debugging)
"""

MBA_RETFP = _ida_hexrays.MBA_RETFP
r"""
function returns floating point value
"""

MBA_SPLINFO = _ida_hexrays.MBA_SPLINFO
r"""
(final_type ? idb_spoiled : spoiled_regs) is valid
"""

MBA_PASSREGS = _ida_hexrays.MBA_PASSREGS
r"""
has mcallinfo_t::pass_regs
"""

MBA_THUNK = _ida_hexrays.MBA_THUNK
r"""
thunk function
"""

MBA_CMNSTK = _ida_hexrays.MBA_CMNSTK
r"""
stkvars+stkargs should be considered as one area
"""

MBA_PREOPT = _ida_hexrays.MBA_PREOPT
r"""
preoptimization stage complete
"""

MBA_CMBBLK = _ida_hexrays.MBA_CMBBLK
r"""
request to combine blocks
"""

MBA_ASRTOK = _ida_hexrays.MBA_ASRTOK
r"""
assertions have been generated
"""

MBA_CALLS = _ida_hexrays.MBA_CALLS
r"""
callinfo has been built
"""

MBA_ASRPROP = _ida_hexrays.MBA_ASRPROP
r"""
assertion have been propagated
"""

MBA_SAVRST = _ida_hexrays.MBA_SAVRST
r"""
save-restore analysis has been performed
"""

MBA_RETREF = _ida_hexrays.MBA_RETREF
r"""
return type has been refined
"""

MBA_GLBOPT = _ida_hexrays.MBA_GLBOPT
r"""
microcode has been optimized globally
"""

MBA_LVARS0 = _ida_hexrays.MBA_LVARS0
r"""
lvar pre-allocation has been performed
"""

MBA_LVARS1 = _ida_hexrays.MBA_LVARS1
r"""
lvar real allocation has been performed
"""

MBA_DELPAIRS = _ida_hexrays.MBA_DELPAIRS
r"""
pairs have been deleted once
"""

MBA_CHVARS = _ida_hexrays.MBA_CHVARS
r"""
can verify chain varnums
"""

MBA_SHORT = _ida_hexrays.MBA_SHORT
r"""
use short display
"""

MBA_COLGDL = _ida_hexrays.MBA_COLGDL
r"""
display graph after each reduction
"""

MBA_INSGDL = _ida_hexrays.MBA_INSGDL
r"""
display instruction in graphs
"""

MBA_NICE = _ida_hexrays.MBA_NICE
r"""
apply transformations to c code
"""

MBA_REFINE = _ida_hexrays.MBA_REFINE
r"""
may refine return value size
"""

MBA_WINGR32 = _ida_hexrays.MBA_WINGR32
r"""
use wingraph32
"""

MBA_NUMADDR = _ida_hexrays.MBA_NUMADDR
r"""
display definition addresses for numbers
"""

MBA_VALNUM = _ida_hexrays.MBA_VALNUM
r"""
display value numbers
"""

MBA_INITIAL_FLAGS = _ida_hexrays.MBA_INITIAL_FLAGS

MBA2_LVARNAMES_OK = _ida_hexrays.MBA2_LVARNAMES_OK
r"""
may verify lvar_names?
"""

MBA2_LVARS_RENAMED = _ida_hexrays.MBA2_LVARS_RENAMED
r"""
accept empty names now?
"""

MBA2_OVER_CHAINS = _ida_hexrays.MBA2_OVER_CHAINS
r"""
has overlapped chains?
"""

MBA2_VALRNG_DONE = _ida_hexrays.MBA2_VALRNG_DONE
r"""
calculated valranges?
"""

MBA2_IS_CTR = _ida_hexrays.MBA2_IS_CTR
r"""
is constructor?
"""

MBA2_IS_DTR = _ida_hexrays.MBA2_IS_DTR
r"""
is destructor?
"""

MBA2_ARGIDX_OK = _ida_hexrays.MBA2_ARGIDX_OK
r"""
may verify input argument list?
"""

MBA2_NO_DUP_CALLS = _ida_hexrays.MBA2_NO_DUP_CALLS
r"""
forbid multiple calls with the same ea
"""

MBA2_NO_DUP_LVARS = _ida_hexrays.MBA2_NO_DUP_LVARS
r"""
forbid multiple lvars with the same ea
"""

MBA2_UNDEF_RETVAR = _ida_hexrays.MBA2_UNDEF_RETVAR
r"""
return value is undefined
"""

MBA2_ARGIDX_SORTED = _ida_hexrays.MBA2_ARGIDX_SORTED
r"""
args finally sorted according to ABI (e.g. reverse stkarg order in Borland)
"""

MBA2_CODE16_BIT = _ida_hexrays.MBA2_CODE16_BIT
r"""
the code16 bit got removed
"""

MBA2_STACK_RETVAL = _ida_hexrays.MBA2_STACK_RETVAL
r"""
the return value is on the stack
"""

MBA2_HAS_OUTLINES = _ida_hexrays.MBA2_HAS_OUTLINES
r"""
calls to outlined code have been inlined
"""

MBA2_NO_FRAME = _ida_hexrays.MBA2_NO_FRAME
r"""
do not use function frame info (only snippet mode)
"""

MBA2_PROP_COMPLEX = _ida_hexrays.MBA2_PROP_COMPLEX
r"""
allow propagation of more complex variable definitions
"""

MBA2_DONT_VERIFY = _ida_hexrays.MBA2_DONT_VERIFY
r"""
Do not verify microcode. This flag is recomended to be set only when debugging
decompiler plugins
"""

MBA2_INITIAL_FLAGS = _ida_hexrays.MBA2_INITIAL_FLAGS

MBA2_ALL_FLAGS = _ida_hexrays.MBA2_ALL_FLAGS

NALT_VD = _ida_hexrays.NALT_VD
r"""
this index is not used by ida
"""

LOCOPT_ALL = _ida_hexrays.LOCOPT_ALL
r"""
redo optimization for all blocks. if this bit is not set, only dirty blocks will
be optimized
"""

LOCOPT_REFINE = _ida_hexrays.LOCOPT_REFINE
r"""
refine return type, ok to fail
"""

LOCOPT_REFINE2 = _ida_hexrays.LOCOPT_REFINE2
r"""
refine return type, try harder
"""

ACFL_LOCOPT = _ida_hexrays.ACFL_LOCOPT
r"""
perform local propagation (requires ACFL_BLKOPT)
"""

ACFL_BLKOPT = _ida_hexrays.ACFL_BLKOPT
r"""
perform interblock transformations
"""

ACFL_GLBPROP = _ida_hexrays.ACFL_GLBPROP
r"""
perform global propagation
"""

ACFL_GLBDEL = _ida_hexrays.ACFL_GLBDEL
r"""
perform dead code eliminition
"""

ACFL_GUESS = _ida_hexrays.ACFL_GUESS
r"""
may guess calling conventions
"""

CPBLK_FAST = _ida_hexrays.CPBLK_FAST
r"""
do not update minbstkref and minbargref
"""

CPBLK_MINREF = _ida_hexrays.CPBLK_MINREF
r"""
update minbstkref and minbargref
"""

CPBLK_OPTJMP = _ida_hexrays.CPBLK_OPTJMP
r"""
del the jump insn at the end of the block if it becomes useless
"""

INLINE_EXTFRAME = _ida_hexrays.INLINE_EXTFRAME
r"""
Inlined function has its own (external) frame.
"""

INLINE_DONTCOPY = _ida_hexrays.INLINE_DONTCOPY
r"""
Do not reuse old inlined copy even if it exists.
"""


class chain_keeper_t(object):
    r"""
    Proxy of C++ chain_keeper_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, _gc: "graph_chains_t"):
        r"""
        __init__(self, _gc) -> chain_keeper_t

        @param _gc: graph_chains_t *
        """
        _ida_hexrays.chain_keeper_t_swiginit(self, _ida_hexrays.new_chain_keeper_t(_gc))
    __swig_destroy__ = _ida_hexrays.delete_chain_keeper_t

    def front(self) -> "block_chains_t &":
        r"""
        front(self) -> block_chains_t
        """
        return _ida_hexrays.chain_keeper_t_front(self)

    def back(self) -> "block_chains_t &":
        r"""
        back(self) -> block_chains_t
        """
        return _ida_hexrays.chain_keeper_t_back(self)

    def for_all_chains(self, cv: "chain_visitor_t", gca: "int") -> "int":
        r"""
        for_all_chains(self, cv, gca) -> int

        @param cv: chain_visitor_t &
        @param gca: int
        """
        return _ida_hexrays.chain_keeper_t_for_all_chains(self, cv, gca)

# Register chain_keeper_t in _ida_hexrays:
_ida_hexrays.chain_keeper_t_swigregister(chain_keeper_t)
GC_REGS_AND_STKVARS = _ida_hexrays.GC_REGS_AND_STKVARS
r"""
registers and stkvars (restricted memory only)
"""

GC_ASR = _ida_hexrays.GC_ASR
r"""
all the above and assertions
"""

GC_XDSU = _ida_hexrays.GC_XDSU
r"""
only registers calculated with FULL_XDSU
"""

GC_END = _ida_hexrays.GC_END
r"""
number of chain types
"""

GC_DIRTY_ALL = _ida_hexrays.GC_DIRTY_ALL
r"""
bitmask to represent all chains
"""

class mbl_graph_t(simple_graph_t):
    r"""
    Proxy of C++ mbl_graph_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr

    def is_ud_chain_dirty(self, gctype: "gctype_t") -> "bool":
        r"""
        is_ud_chain_dirty(self, gctype) -> bool
        Is the use-def chain of the specified kind dirty?

        @param gctype: (C++: gctype_t) enum gctype_t
        """
        return _ida_hexrays.mbl_graph_t_is_ud_chain_dirty(self, gctype)

    def is_du_chain_dirty(self, gctype: "gctype_t") -> "bool":
        r"""
        is_du_chain_dirty(self, gctype) -> bool
        Is the def-use chain of the specified kind dirty?

        @param gctype: (C++: gctype_t) enum gctype_t
        """
        return _ida_hexrays.mbl_graph_t_is_du_chain_dirty(self, gctype)

    def get_chain_stamp(self) -> "int":
        r"""
        get_chain_stamp(self) -> int
        """
        return _ida_hexrays.mbl_graph_t_get_chain_stamp(self)

    def get_ud(self, gctype: "gctype_t") -> "graph_chains_t *":
        r"""
        get_ud(self, gctype) -> graph_chains_t
        Get use-def chains.

        @param gctype: (C++: gctype_t) enum gctype_t
        """
        return _ida_hexrays.mbl_graph_t_get_ud(self, gctype)

    def get_du(self, gctype: "gctype_t") -> "graph_chains_t *":
        r"""
        get_du(self, gctype) -> graph_chains_t
        Get def-use chains.

        @param gctype: (C++: gctype_t) enum gctype_t
        """
        return _ida_hexrays.mbl_graph_t_get_du(self, gctype)

    def is_redefined_globally(self, *args) -> "bool":
        r"""
        is_redefined_globally(self, list, b1, b2, m1, m2, maymust=MAY_ACCESS) -> bool
        Is LIST redefined in the graph?

        @param list: (C++: const mlist_t &) mlist_t const &
        @param b1: (C++: int)
        @param b2: (C++: int)
        @param m1: (C++: const minsn_t *) minsn_t const *
        @param m2: (C++: const minsn_t *) minsn_t const *
        @param maymust: (C++: maymust_t)
        """
        return _ida_hexrays.mbl_graph_t_is_redefined_globally(self, *args)

    def is_used_globally(self, *args) -> "bool":
        r"""
        is_used_globally(self, list, b1, b2, m1, m2, maymust=MAY_ACCESS) -> bool
        Is LIST used in the graph?

        @param list: (C++: const mlist_t &) mlist_t const &
        @param b1: (C++: int)
        @param b2: (C++: int)
        @param m1: (C++: const minsn_t *) minsn_t const *
        @param m2: (C++: const minsn_t *) minsn_t const *
        @param maymust: (C++: maymust_t)
        """
        return _ida_hexrays.mbl_graph_t_is_used_globally(self, *args)

    def get_mblock(self, n: "int") -> "mblock_t *":
        r"""
        get_mblock(self, n) -> mblock_t

        @param n: int
        """
        return _ida_hexrays.mbl_graph_t_get_mblock(self, n)

# Register mbl_graph_t in _ida_hexrays:
_ida_hexrays.mbl_graph_t_swigregister(mbl_graph_t)
class cdg_insn_iterator_t(object):
    r"""
    Proxy of C++ cdg_insn_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t const *" = property(_ida_hexrays.cdg_insn_iterator_t_mba_get, _ida_hexrays.cdg_insn_iterator_t_mba_set, doc=r"""mba""")
    ea: "ea_t" = property(_ida_hexrays.cdg_insn_iterator_t_ea_get, _ida_hexrays.cdg_insn_iterator_t_ea_set, doc=r"""ea""")
    end: "ea_t" = property(_ida_hexrays.cdg_insn_iterator_t_end_get, _ida_hexrays.cdg_insn_iterator_t_end_set, doc=r"""end""")
    dslot: "ea_t" = property(_ida_hexrays.cdg_insn_iterator_t_dslot_get, _ida_hexrays.cdg_insn_iterator_t_dslot_set, doc=r"""dslot""")
    dslot_insn: "insn_t" = property(_ida_hexrays.cdg_insn_iterator_t_dslot_insn_get, _ida_hexrays.cdg_insn_iterator_t_dslot_insn_set, doc=r"""dslot_insn""")
    severed_branch: "ea_t" = property(_ida_hexrays.cdg_insn_iterator_t_severed_branch_get, _ida_hexrays.cdg_insn_iterator_t_severed_branch_set, doc=r"""severed_branch""")
    is_likely_dslot: "bool" = property(_ida_hexrays.cdg_insn_iterator_t_is_likely_dslot_get, _ida_hexrays.cdg_insn_iterator_t_is_likely_dslot_set, doc=r"""is_likely_dslot""")

    def __init__(self, *args):
        r"""
        __init__(self, mba_) -> cdg_insn_iterator_t

        @param mba_: mba_t const *

        __init__(self, r) -> cdg_insn_iterator_t

        @param r: cdg_insn_iterator_t const &
        """
        _ida_hexrays.cdg_insn_iterator_t_swiginit(self, _ida_hexrays.new_cdg_insn_iterator_t(*args))

    def ok(self) -> "bool":
        r"""
        ok(self) -> bool
        """
        return _ida_hexrays.cdg_insn_iterator_t_ok(self)

    def has_dslot(self) -> "bool":
        r"""
        has_dslot(self) -> bool
        """
        return _ida_hexrays.cdg_insn_iterator_t_has_dslot(self)

    def dslot_with_xrefs(self) -> "bool":
        r"""
        dslot_with_xrefs(self) -> bool
        """
        return _ida_hexrays.cdg_insn_iterator_t_dslot_with_xrefs(self)

    def is_severed_dslot(self) -> "bool":
        r"""
        is_severed_dslot(self) -> bool
        """
        return _ida_hexrays.cdg_insn_iterator_t_is_severed_dslot(self)

    def start(self, rng: "range_t") -> "void":
        r"""
        start(self, rng)

        @param rng: range_t const &
        """
        return _ida_hexrays.cdg_insn_iterator_t_start(self, rng)

    def next(self, ins: "insn_t *") -> "merror_t":
        r"""
        next(self, ins) -> merror_t

        @param ins: insn_t *
        """
        return _ida_hexrays.cdg_insn_iterator_t_next(self, ins)
    __swig_destroy__ = _ida_hexrays.delete_cdg_insn_iterator_t

# Register cdg_insn_iterator_t in _ida_hexrays:
_ida_hexrays.cdg_insn_iterator_t_swigregister(cdg_insn_iterator_t)
class codegen_t(object):
    r"""
    Proxy of C++ codegen_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    mba: "mba_t *" = property(_ida_hexrays.codegen_t_mba_get, _ida_hexrays.codegen_t_mba_set, doc=r"""mba""")
    mb: "mblock_t *" = property(_ida_hexrays.codegen_t_mb_get, _ida_hexrays.codegen_t_mb_set, doc=r"""mb""")
    insn: "insn_t" = property(_ida_hexrays.codegen_t_insn_get, _ida_hexrays.codegen_t_insn_set, doc=r"""insn""")
    ignore_micro: "char" = property(_ida_hexrays.codegen_t_ignore_micro_get, _ida_hexrays.codegen_t_ignore_micro_set, doc=r"""ignore_micro""")
    ii: "cdg_insn_iterator_t" = property(_ida_hexrays.codegen_t_ii_get, _ida_hexrays.codegen_t_ii_set, doc=r"""ii""")
    __swig_destroy__ = _ida_hexrays.delete_codegen_t

    def clear(self) -> "void":
        r"""
        clear(self)
        """
        return _ida_hexrays.codegen_t_clear(self)

    def analyze_prolog(self, fc: "qflow_chart_t", reachable: "bitset_t") -> "merror_t":
        r"""
        analyze_prolog(self, fc, reachable) -> merror_t
        Analyze prolog/epilog of the function to decompile. If prolog is found, allocate
        and fill 'mba->pi' structure.

        @param fc: (C++: const class qflow_chart_t &) flow chart
        @param reachable: (C++: const class bitset_t &) bitmap of reachable blocks
        @return: error code
        """
        return _ida_hexrays.codegen_t_analyze_prolog(self, fc, reachable)

    def gen_micro(self) -> "merror_t":
        r"""
        gen_micro(self) -> merror_t
        Generate microcode for one instruction. The instruction is in INSN

        @return: MERR_OK - all ok MERR_BLOCK - all ok, need to switch to new block
                 MERR_BADBLK - delete current block and continue other error codes are
                 fatal
        """
        return _ida_hexrays.codegen_t_gen_micro(self)

    def load_operand(self, opnum: "int", flags: "int"=0) -> "mreg_t":
        r"""
        load_operand(self, opnum, flags=0) -> mreg_t
        Generate microcode to load one operand.

        @param opnum: (C++: int) number of INSN operand
        @param flags: (C++: int) reserved for future use
        @return: register containing the operand.
        """
        return _ida_hexrays.codegen_t_load_operand(self, opnum, flags)

    def microgen_completed(self) -> "void":
        r"""
        microgen_completed(self)
        This method is called when the microcode generation is done.
        """
        return _ida_hexrays.codegen_t_microgen_completed(self)

    def prepare_gen_micro(self) -> "merror_t":
        r"""
        prepare_gen_micro(self) -> merror_t
        Setup internal data to handle new instruction. This method should be called
        before calling gen_micro(). Usually gen_micro() is called by the decompiler. You
        have to call this function explicitly only if you yourself call gen_micro(). The
        instruction is in INSN

        @return: MERR_OK - all ok other error codes are fatal
        """
        return _ida_hexrays.codegen_t_prepare_gen_micro(self)

    def load_effective_address(self, n: "int", flags: "int"=0) -> "mreg_t":
        r"""
        load_effective_address(self, n, flags=0) -> mreg_t
        Generate microcode to calculate the address of a memory operand.

        @param n: (C++: int) - number of INSN operand
        @param flags: (C++: int) - reserved for future use
        @return: register containing the operand address. mr_none - failed (not a memory
                 operand)
        """
        return _ida_hexrays.codegen_t_load_effective_address(self, n, flags)

    def store_operand(self, n: "int", mop: "mop_t", flags: "int"=0, outins: "minsn_t **"=None) -> "bool":
        r"""
        store_operand(self, n, mop, flags=0, outins=None) -> bool
        Generate microcode to store an operand. In case of success an arbitrary number
        of instructions can be generated (and even no instruction if the source and
        target are the same)

        @param n: (C++: int) - number of target INSN operand
        @param mop: (C++: const mop_t &) - operand to be stored
        @param flags: (C++: int) - reserved for future use
        @param outins: (C++: minsn_t **) - (OUT) the last generated instruction
        @return: success
        """
        return _ida_hexrays.codegen_t_store_operand(self, n, mop, flags, outins)

    def emit_micro_mvm(self, code: "mcode_t", dtype: "op_dtype_t", l: "uval_t", r: "uval_t", d: "uval_t", offsize: "int") -> "minsn_t *":
        r"""
        emit_micro_mvm(self, code, dtype, l, r, d, offsize) -> minsn_t
        Emit one microinstruction. This variant takes a data type not a size.

        @param code: (C++: mcode_t) enum mcode_t
        @param dtype: (C++: op_dtype_t)
        @param l: (C++: uval_t)
        @param r: (C++: uval_t)
        @param d: (C++: uval_t)
        @param offsize: (C++: int)
        """
        return _ida_hexrays.codegen_t_emit_micro_mvm(self, code, dtype, l, r, d, offsize)

    def emit(self, *args) -> "minsn_t *":
        r"""
        emit(self, code, width, l, r, d, offsize) -> minsn_t
        Emit one microinstruction. This variant accepts pointers to operands. It is more
        difficult to use but permits to create virtually any instruction. Operands may
        be nullptr when it makes sense.

        @param code: (C++: mcode_t) enum mcode_t
        @param width: int
        @param l: (C++: const mop_t *) uval_t
        @param r: (C++: const mop_t *) uval_t
        @param d: (C++: const mop_t *) uval_t
        @param offsize: int

        emit(self, code, l, r, d) -> minsn_t

        @param code: enum mcode_t
        @param l: mop_t const *
        @param r: mop_t const *
        @param d: mop_t const *
        """
        return _ida_hexrays.codegen_t_emit(self, *args)

# Register codegen_t in _ida_hexrays:
_ida_hexrays.codegen_t_swigregister(codegen_t)

def change_hexrays_config(directive: "char const *") -> "bool":
    r"""
    change_hexrays_config(directive) -> bool
    Parse DIRECTIVE and update the current configuration variables. For the syntax
    see hexrays.cfg

    @param directive: (C++: const char *) char const *
    """
    return _ida_hexrays.change_hexrays_config(directive)

def get_hexrays_version() -> "char const *":
    r"""
    get_hexrays_version() -> char const *
    Get decompiler version. The returned string is of the form
    <major>.<minor>.<revision>.<build-date>

    @return: pointer to version string. For example: "2.0.0.140605"
    """
    return _ida_hexrays.get_hexrays_version()
OPF_REUSE = _ida_hexrays.OPF_REUSE
r"""
reuse existing window
"""

OPF_NEW_WINDOW = _ida_hexrays.OPF_NEW_WINDOW
r"""
open new window
"""

OPF_REUSE_ACTIVE = _ida_hexrays.OPF_REUSE_ACTIVE
r"""
reuse existing window, only if the currently active widget is a pseudocode view
"""

OPF_NO_WAIT = _ida_hexrays.OPF_NO_WAIT
r"""
do not display waitbox if decompilation happens
"""

OPF_WINDOW_MGMT_MASK = _ida_hexrays.OPF_WINDOW_MGMT_MASK


def open_pseudocode(ea: "ea_t", flags: "int") -> "vdui_t *":
    r"""
    open_pseudocode(ea, flags) -> vdui_t
    Open pseudocode window. The specified function is decompiled and the pseudocode
    window is opened.

    @param ea: (C++: ea_t) function to decompile
    @param flags: (C++: int) a combination of OPF_ flags
    @return: false if failed
    """
    return _ida_hexrays.open_pseudocode(ea, flags)

def close_pseudocode(f: "TWidget *") -> "bool":
    r"""
    close_pseudocode(f) -> bool
    Close pseudocode window.

    @param f: (C++: TWidget *) pointer to window
    @return: false if failed
    """
    return _ida_hexrays.close_pseudocode(f)
VDRUN_NEWFILE = _ida_hexrays.VDRUN_NEWFILE
r"""
Create a new file or overwrite existing file.
"""

VDRUN_APPEND = _ida_hexrays.VDRUN_APPEND
r"""
Create a new file or append to existing file.
"""

VDRUN_ONLYNEW = _ida_hexrays.VDRUN_ONLYNEW
r"""
Fail if output file already exists.
"""

VDRUN_SILENT = _ida_hexrays.VDRUN_SILENT
r"""
Silent decompilation.
"""

VDRUN_SENDIDB = _ida_hexrays.VDRUN_SENDIDB
r"""
Send problematic databases to hex-rays.com.
"""

VDRUN_MAYSTOP = _ida_hexrays.VDRUN_MAYSTOP
r"""
The user can cancel decompilation.
"""

VDRUN_CMDLINE = _ida_hexrays.VDRUN_CMDLINE
r"""
Called from ida's command line.
"""

VDRUN_STATS = _ida_hexrays.VDRUN_STATS
r"""
Print statistics into vd_stats.txt.
"""

VDRUN_LUMINA = _ida_hexrays.VDRUN_LUMINA
r"""
Use lumina server.
"""


def decompile_many(outfile: "char const *", funcaddrs: "uint64vec_t", flags: "int") -> "bool":
    r"""
    decompile_many(outfile, funcaddrs, flags) -> bool
    Batch decompilation. Decompile all or the specified functions

    @param outfile: (C++: const char *) name of the output file
    @param funcaddrs: (C++: const eavec_t *) list of functions to decompile. If nullptr or empty, then
                      decompile all nonlib functions
    @param flags: (C++: int) Batch decompilation bits
    @return: true if no internal error occurred and the user has not cancelled
             decompilation
    """
    return _ida_hexrays.decompile_many(outfile, funcaddrs, flags)
class hexrays_failure_t(object):
    r"""
    Proxy of C++ hexrays_failure_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    code: "merror_t" = property(_ida_hexrays.hexrays_failure_t_code_get, _ida_hexrays.hexrays_failure_t_code_set, doc=r"""code""")
    r"""
    Microcode error codes
    """
    errea: "ea_t" = property(_ida_hexrays.hexrays_failure_t_errea_get, _ida_hexrays.hexrays_failure_t_errea_set, doc=r"""errea""")
    r"""
    associated address
    """
    str: "qstring" = property(_ida_hexrays.hexrays_failure_t_str_get, _ida_hexrays.hexrays_failure_t_str_set, doc=r"""str""")
    r"""
    string information
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> hexrays_failure_t
        __init__(self, c, ea, buf=None) -> hexrays_failure_t

        @param c: enum merror_t
        @param ea: ea_t
        @param buf: char const *

        __init__(self, c, ea, buf) -> hexrays_failure_t

        @param c: enum merror_t
        @param ea: ea_t
        @param buf: qstring const &
        """
        _ida_hexrays.hexrays_failure_t_swiginit(self, _ida_hexrays.new_hexrays_failure_t(*args))

    def desc(self) -> "qstring":
        r"""
        desc(self) -> qstring
        """
        return _ida_hexrays.hexrays_failure_t_desc(self)
    __swig_destroy__ = _ida_hexrays.delete_hexrays_failure_t

# Register hexrays_failure_t in _ida_hexrays:
_ida_hexrays.hexrays_failure_t_swigregister(hexrays_failure_t)
class vd_failure_t(object):
    r"""
    Proxy of C++ vd_failure_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    hf: "hexrays_failure_t" = property(_ida_hexrays.vd_failure_t_hf_get, _ida_hexrays.vd_failure_t_hf_set, doc=r"""hf""")

    def __init__(self, *args):
        r"""
        __init__(self) -> vd_failure_t
        __init__(self, code, ea, buf=None) -> vd_failure_t

        @param code: enum merror_t
        @param ea: ea_t
        @param buf: char const *

        __init__(self, code, ea, buf) -> vd_failure_t

        @param code: enum merror_t
        @param ea: ea_t
        @param buf: qstring const &

        __init__(self, _hf) -> vd_failure_t

        @param _hf: hexrays_failure_t const &
        """
        _ida_hexrays.vd_failure_t_swiginit(self, _ida_hexrays.new_vd_failure_t(*args))

    def desc(self) -> "qstring":
        r"""
        desc(self) -> qstring
        """
        return _ida_hexrays.vd_failure_t_desc(self)
    __swig_destroy__ = _ida_hexrays.delete_vd_failure_t

# Register vd_failure_t in _ida_hexrays:
_ida_hexrays.vd_failure_t_swigregister(vd_failure_t)
class vd_interr_t(vd_failure_t):
    r"""
    Proxy of C++ vd_interr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, ea: "ea_t", buf: "char const *"):
        r"""
        __init__(self, ea, buf) -> vd_interr_t

        @param ea: ea_t
        @param buf: char const *
        """
        _ida_hexrays.vd_interr_t_swiginit(self, _ida_hexrays.new_vd_interr_t(ea, buf))
    __swig_destroy__ = _ida_hexrays.delete_vd_interr_t

# Register vd_interr_t in _ida_hexrays:
_ida_hexrays.vd_interr_t_swigregister(vd_interr_t)

def send_database(err: "hexrays_failure_t", silent: "bool") -> "void":
    r"""
    send_database(err, silent)
    Send the database to Hex-Rays. This function sends the current database to the
    Hex-Rays server. The database is sent in the compressed form over an encrypted
    (SSL) connection.

    @param err: (C++: const hexrays_failure_t &) failure description object. Empty hexrays_failure_t object can be
                used if error information is not available.
    @param silent: (C++: bool) if false, a dialog box will be displayed before sending the
                   database.
    """
    return _ida_hexrays.send_database(err, silent)
class gco_info_t(object):
    r"""
    Proxy of C++ gco_info_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    name: "qstring" = property(_ida_hexrays.gco_info_t_name_get, _ida_hexrays.gco_info_t_name_set, doc=r"""name""")
    r"""
    register or stkvar name
    """
    stkoff: "sval_t" = property(_ida_hexrays.gco_info_t_stkoff_get, _ida_hexrays.gco_info_t_stkoff_set, doc=r"""stkoff""")
    r"""
    if stkvar, stack offset
    """
    regnum: "int" = property(_ida_hexrays.gco_info_t_regnum_get, _ida_hexrays.gco_info_t_regnum_set, doc=r"""regnum""")
    r"""
    if register, the register id
    """
    size: "int" = property(_ida_hexrays.gco_info_t_size_get, _ida_hexrays.gco_info_t_size_set, doc=r"""size""")
    r"""
    operand size
    """
    flags: "int" = property(_ida_hexrays.gco_info_t_flags_get, _ida_hexrays.gco_info_t_flags_set, doc=r"""flags""")

    def is_reg(self) -> "bool":
        r"""
        is_reg(self) -> bool
        """
        return _ida_hexrays.gco_info_t_is_reg(self)

    def is_use(self) -> "bool":
        r"""
        is_use(self) -> bool
        """
        return _ida_hexrays.gco_info_t_is_use(self)

    def is_def(self) -> "bool":
        r"""
        is_def(self) -> bool
        """
        return _ida_hexrays.gco_info_t_is_def(self)

    def append_to_list(self, list: "mlist_t", mba: "mba_t") -> "bool":
        r"""
        append_to_list(self, list, mba) -> bool
        Append operand info to LIST. This function converts IDA register number or stack
        offset to a decompiler list.

        @param list: (C++: mlist_t *) list to append to
        @param mba: (C++: const mba_t *) microcode object
        """
        return _ida_hexrays.gco_info_t_append_to_list(self, list, mba)

    def cvt_to_ivl(self) -> "vivl_t":
        r"""
        cvt_to_ivl(self) -> vivl_t
        Convert operand info to VIVL. The returned VIVL can be used, for example, in a
        call of get_valranges().
        """
        return _ida_hexrays.gco_info_t_cvt_to_ivl(self)

    def __init__(self):
        r"""
        __init__(self) -> gco_info_t
        """
        _ida_hexrays.gco_info_t_swiginit(self, _ida_hexrays.new_gco_info_t())
    __swig_destroy__ = _ida_hexrays.delete_gco_info_t

# Register gco_info_t in _ida_hexrays:
_ida_hexrays.gco_info_t_swigregister(gco_info_t)
GCO_STK = _ida_hexrays.GCO_STK
r"""
a stack variable
"""

GCO_REG = _ida_hexrays.GCO_REG
r"""
is register? otherwise a stack variable
"""

GCO_USE = _ida_hexrays.GCO_USE
r"""
is source operand?
"""

GCO_DEF = _ida_hexrays.GCO_DEF
r"""
is destination operand?
"""



def get_current_operand(out: "gco_info_t") -> "bool":
    r"""
    get_current_operand(out) -> bool
    Get the instruction operand under the cursor. This function determines the
    operand that is under the cursor in the active disassembly listing. If the
    operand refers to a register or stack variable, it returns true.

    @param out: (C++: gco_info_t *) [out]: output buffer
    """
    return _ida_hexrays.get_current_operand(out)

def remitem(e: "citem_t") -> "void":
    r"""
    remitem(e)

    @param e: citem_t const *
    """
    return _ida_hexrays.remitem(e)
cot_empty = _ida_hexrays.cot_empty

cot_comma = _ida_hexrays.cot_comma
r"""
x, y
"""

cot_asg = _ida_hexrays.cot_asg
r"""
x = y
"""

cot_asgbor = _ida_hexrays.cot_asgbor
r"""
x |= y
"""

cot_asgxor = _ida_hexrays.cot_asgxor
r"""
x ^= y
"""

cot_asgband = _ida_hexrays.cot_asgband
r"""
x &= y
"""

cot_asgadd = _ida_hexrays.cot_asgadd
r"""
x += y
"""

cot_asgsub = _ida_hexrays.cot_asgsub
r"""
x -= y
"""

cot_asgmul = _ida_hexrays.cot_asgmul
r"""
x *= y
"""

cot_asgsshr = _ida_hexrays.cot_asgsshr
r"""
x >>= y signed
"""

cot_asgushr = _ida_hexrays.cot_asgushr
r"""
x >>= y unsigned
"""

cot_asgshl = _ida_hexrays.cot_asgshl
r"""
x <<= y
"""

cot_asgsdiv = _ida_hexrays.cot_asgsdiv
r"""
x /= y signed
"""

cot_asgudiv = _ida_hexrays.cot_asgudiv
r"""
x /= y unsigned
"""

cot_asgsmod = _ida_hexrays.cot_asgsmod
r"""
x %= y signed
"""

cot_asgumod = _ida_hexrays.cot_asgumod
r"""
x %= y unsigned
"""

cot_tern = _ida_hexrays.cot_tern
r"""
x ? y : z
"""

cot_lor = _ida_hexrays.cot_lor
r"""
x || y
"""

cot_land = _ida_hexrays.cot_land
r"""
x && y
"""

cot_bor = _ida_hexrays.cot_bor
r"""
x | y
"""

cot_xor = _ida_hexrays.cot_xor
r"""
x ^ y
"""

cot_band = _ida_hexrays.cot_band
r"""
x & y
"""

cot_eq = _ida_hexrays.cot_eq
r"""
x == y int or fpu (see EXFL_FPOP)
"""

cot_ne = _ida_hexrays.cot_ne
r"""
x != y int or fpu (see EXFL_FPOP)
"""

cot_sge = _ida_hexrays.cot_sge
r"""
x >= y signed or fpu (see EXFL_FPOP)
"""

cot_uge = _ida_hexrays.cot_uge
r"""
x >= y unsigned
"""

cot_sle = _ida_hexrays.cot_sle
r"""
x <= y signed or fpu (see EXFL_FPOP)
"""

cot_ule = _ida_hexrays.cot_ule
r"""
x <= y unsigned
"""

cot_sgt = _ida_hexrays.cot_sgt
r"""
x > y signed or fpu (see EXFL_FPOP)
"""

cot_ugt = _ida_hexrays.cot_ugt
r"""
x > y unsigned
"""

cot_slt = _ida_hexrays.cot_slt
r"""
x < y signed or fpu (see EXFL_FPOP)
"""

cot_ult = _ida_hexrays.cot_ult
r"""
x < y unsigned
"""

cot_sshr = _ida_hexrays.cot_sshr
r"""
x >> y signed
"""

cot_ushr = _ida_hexrays.cot_ushr
r"""
x >> y unsigned
"""

cot_shl = _ida_hexrays.cot_shl
r"""
x << y
"""

cot_add = _ida_hexrays.cot_add
r"""
x + y
"""

cot_sub = _ida_hexrays.cot_sub
r"""
x - y
"""

cot_mul = _ida_hexrays.cot_mul
r"""
x * y
"""

cot_sdiv = _ida_hexrays.cot_sdiv
r"""
x / y signed
"""

cot_udiv = _ida_hexrays.cot_udiv
r"""
x / y unsigned
"""

cot_smod = _ida_hexrays.cot_smod
r"""
x % y signed
"""

cot_umod = _ida_hexrays.cot_umod
r"""
x % y unsigned
"""

cot_fadd = _ida_hexrays.cot_fadd
r"""
x + y fp
"""

cot_fsub = _ida_hexrays.cot_fsub
r"""
x - y fp
"""

cot_fmul = _ida_hexrays.cot_fmul
r"""
x * y fp
"""

cot_fdiv = _ida_hexrays.cot_fdiv
r"""
x / y fp
"""

cot_fneg = _ida_hexrays.cot_fneg
r"""
-x fp
"""

cot_neg = _ida_hexrays.cot_neg
r"""
-x
"""

cot_cast = _ida_hexrays.cot_cast
r"""
(type)x
"""

cot_lnot = _ida_hexrays.cot_lnot
r"""
!x
"""

cot_bnot = _ida_hexrays.cot_bnot
r"""
~x
"""

cot_ptr = _ida_hexrays.cot_ptr
r"""
*x, access size in 'ptrsize'
"""

cot_ref = _ida_hexrays.cot_ref
r"""
&x
"""

cot_postinc = _ida_hexrays.cot_postinc
r"""
x++
"""

cot_postdec = _ida_hexrays.cot_postdec
r"""
x-
"""

cot_preinc = _ida_hexrays.cot_preinc
r"""
++x
"""

cot_predec = _ida_hexrays.cot_predec
r"""
-x
"""

cot_call = _ida_hexrays.cot_call
r"""
x(...)
"""

cot_idx = _ida_hexrays.cot_idx
r"""
x[y]
"""

cot_memref = _ida_hexrays.cot_memref
r"""
x.m
"""

cot_memptr = _ida_hexrays.cot_memptr
r"""
x->m, access size in 'ptrsize'
"""

cot_num = _ida_hexrays.cot_num
r"""
n
"""

cot_fnum = _ida_hexrays.cot_fnum
r"""
fpc
"""

cot_str = _ida_hexrays.cot_str
r"""
string constant (user representation)
"""

cot_obj = _ida_hexrays.cot_obj
r"""
obj_ea
"""

cot_var = _ida_hexrays.cot_var
r"""
v
"""

cot_insn = _ida_hexrays.cot_insn
r"""
instruction in expression, internal representation only
"""

cot_sizeof = _ida_hexrays.cot_sizeof
r"""
sizeof(x)
"""

cot_helper = _ida_hexrays.cot_helper
r"""
arbitrary name
"""

cot_type = _ida_hexrays.cot_type
r"""
arbitrary type
"""

cot_last = _ida_hexrays.cot_last

cit_empty = _ida_hexrays.cit_empty
r"""
instruction types start here
"""

cit_block = _ida_hexrays.cit_block
r"""
block-statement: { ... }
"""

cit_expr = _ida_hexrays.cit_expr
r"""
expression-statement: expr;
"""

cit_if = _ida_hexrays.cit_if
r"""
if-statement
"""

cit_for = _ida_hexrays.cit_for
r"""
for-statement
"""

cit_while = _ida_hexrays.cit_while
r"""
while-statement
"""

cit_do = _ida_hexrays.cit_do
r"""
do-statement
"""

cit_switch = _ida_hexrays.cit_switch
r"""
switch-statement
"""

cit_break = _ida_hexrays.cit_break
r"""
break-statement
"""

cit_continue = _ida_hexrays.cit_continue
r"""
continue-statement
"""

cit_return = _ida_hexrays.cit_return
r"""
return-statement
"""

cit_goto = _ida_hexrays.cit_goto
r"""
goto-statement
"""

cit_asm = _ida_hexrays.cit_asm
r"""
asm-statement
"""

cit_try = _ida_hexrays.cit_try
r"""
C++ try-statement.
"""

cit_throw = _ida_hexrays.cit_throw
r"""
C++ throw-statement.
"""

cit_end = _ida_hexrays.cit_end


def negated_relation(op: "ctype_t") -> "ctype_t":
    r"""
    negated_relation(op) -> ctype_t
    Negate a comparison operator. For example, cot_sge becomes cot_slt.

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.negated_relation(op)

def swapped_relation(op: "ctype_t") -> "ctype_t":
    r"""
    swapped_relation(op) -> ctype_t
    Swap a comparison operator. For example, cot_sge becomes cot_sle.

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.swapped_relation(op)

def get_op_signness(op: "ctype_t") -> "type_sign_t":
    r"""
    get_op_signness(op) -> type_sign_t
    Get operator sign. Meaningful for sign-dependent operators, like cot_sdiv.

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.get_op_signness(op)

def asgop(cop: "ctype_t") -> "ctype_t":
    r"""
    asgop(cop) -> ctype_t
    Convert plain operator into assignment operator. For example, cot_add returns
    cot_asgadd.

    @param cop: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.asgop(cop)

def asgop_revert(cop: "ctype_t") -> "ctype_t":
    r"""
    asgop_revert(cop) -> ctype_t
    Convert assignment operator into plain operator. For example, cot_asgadd returns
    cot_add

    @param cop: (C++: ctype_t) enum ctype_t
    @return: cot_empty is the input operator is not an assignment operator.
    """
    return _ida_hexrays.asgop_revert(cop)

def op_uses_x(op: "ctype_t") -> "bool":
    r"""
    op_uses_x(op) -> bool
    Does operator use the 'x' field of cexpr_t?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.op_uses_x(op)

def op_uses_y(op: "ctype_t") -> "bool":
    r"""
    op_uses_y(op) -> bool
    Does operator use the 'y' field of cexpr_t?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.op_uses_y(op)

def op_uses_z(op: "ctype_t") -> "bool":
    r"""
    op_uses_z(op) -> bool
    Does operator use the 'z' field of cexpr_t?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.op_uses_z(op)

def is_binary(op: "ctype_t") -> "bool":
    r"""
    is_binary(op) -> bool
    Is binary operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_binary(op)

def is_unary(op: "ctype_t") -> "bool":
    r"""
    is_unary(op) -> bool
    Is unary operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_unary(op)

def is_relational(op: "ctype_t") -> "bool":
    r"""
    is_relational(op) -> bool
    Is comparison operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_relational(op)

def is_assignment(op: "ctype_t") -> "bool":
    r"""
    is_assignment(op) -> bool
    Is assignment operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_assignment(op)

def accepts_udts(op: "ctype_t") -> "bool":
    r"""
    accepts_udts(op) -> bool

    @param op: enum ctype_t
    """
    return _ida_hexrays.accepts_udts(op)

def is_prepost(op: "ctype_t") -> "bool":
    r"""
    is_prepost(op) -> bool
    Is pre/post increment/decrement operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_prepost(op)

def is_commutative(op: "ctype_t") -> "bool":
    r"""
    is_commutative(op) -> bool
    Is commutative operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_commutative(op)

def is_additive(op: "ctype_t") -> "bool":
    r"""
    is_additive(op) -> bool
    Is additive operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_additive(op)

def is_multiplicative(op: "ctype_t") -> "bool":
    r"""
    is_multiplicative(op) -> bool
    Is multiplicative operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_multiplicative(op)

def is_bitop(op: "ctype_t") -> "bool":
    r"""
    is_bitop(op) -> bool
    Is bit related operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_bitop(op)

def is_logical(op: "ctype_t") -> "bool":
    r"""
    is_logical(op) -> bool
    Is logical operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_logical(op)

def is_loop(op: "ctype_t") -> "bool":
    r"""
    is_loop(op) -> bool
    Is loop statement code?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_loop(op)

def is_break_consumer(op: "ctype_t") -> "bool":
    r"""
    is_break_consumer(op) -> bool
    Does a break statement influence the specified statement code?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_break_consumer(op)

def is_lvalue(op: "ctype_t") -> "bool":
    r"""
    is_lvalue(op) -> bool
    Is Lvalue operator?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.is_lvalue(op)

def accepts_small_udts(op: "ctype_t") -> "bool":
    r"""
    accepts_small_udts(op) -> bool
    Is the operator allowed on small structure or union?

    @param op: (C++: ctype_t) enum ctype_t
    """
    return _ida_hexrays.accepts_small_udts(op)
class cnumber_t(object):
    r"""
    Proxy of C++ cnumber_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    _value: "uint64" = property(_ida_hexrays.cnumber_t__value_get, _ida_hexrays.cnumber_t__value_set, doc=r"""_value""")
    r"""
    its value
    """
    nf: "number_format_t" = property(_ida_hexrays.cnumber_t_nf_get, _ida_hexrays.cnumber_t_nf_set, doc=r"""nf""")
    r"""
    how to represent it
    """

    def __init__(self, _opnum: "int"=0):
        r"""
        __init__(self, _opnum=0) -> cnumber_t

        @param _opnum: int
        """
        _ida_hexrays.cnumber_t_swiginit(self, _ida_hexrays.new_cnumber_t(_opnum))

    def _print(self, type: "tinfo_t", parent: "citem_t"=None, nice_stroff: "bool *"=None) -> "void":
        r"""
        _print(self, type, parent=None, nice_stroff=None)

        Parameters
        ----------
        type: tinfo_t const &
        parent: citem_t const *
        nice_stroff: bool *

        """
        return _ida_hexrays.cnumber_t__print(self, type, parent, nice_stroff)

    def value(self, type: "tinfo_t") -> "uint64":
        r"""
        value(self, type) -> uint64
        Get value. This function will properly extend the number sign to 64bits
        depending on the type sign.

        @param type: (C++: const tinfo_t &) tinfo_t const &
        """
        return _ida_hexrays.cnumber_t_value(self, type)

    def assign(self, v: "uint64", nbytes: "int", sign: "type_sign_t") -> "void":
        r"""
        assign(self, v, nbytes, sign)
        Assign new value

        @param v: (C++: uint64) new value
        @param nbytes: (C++: int) size of the new value in bytes
        @param sign: (C++: type_sign_t) sign of the value
        """
        return _ida_hexrays.cnumber_t_assign(self, v, nbytes, sign)

    def __eq__(self, r: "cnumber_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___eq__(self, r)

    def __ne__(self, r: "cnumber_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___ne__(self, r)

    def __lt__(self, r: "cnumber_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___lt__(self, r)

    def __gt__(self, r: "cnumber_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___gt__(self, r)

    def __le__(self, r: "cnumber_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___le__(self, r)

    def __ge__(self, r: "cnumber_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t___ge__(self, r)

    def compare(self, r: "cnumber_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cnumber_t const &
        """
        return _ida_hexrays.cnumber_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_cnumber_t

# Register cnumber_t in _ida_hexrays:
_ida_hexrays.cnumber_t_swigregister(cnumber_t)
class var_ref_t(object):
    r"""
    Proxy of C++ var_ref_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mba: "mba_t *" = property(_ida_hexrays.var_ref_t_mba_get, _ida_hexrays.var_ref_t_mba_set, doc=r"""mba""")
    r"""
    pointer to the underlying micro array
    """
    idx: "int" = property(_ida_hexrays.var_ref_t_idx_get, _ida_hexrays.var_ref_t_idx_set, doc=r"""idx""")
    r"""
    index into lvars_t
    """

    def getv(self) -> "lvar_t &":
        r"""
        getv(self) -> lvar_t
        """
        return _ida_hexrays.var_ref_t_getv(self)

    def __eq__(self, r: "var_ref_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___eq__(self, r)

    def __ne__(self, r: "var_ref_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___ne__(self, r)

    def __lt__(self, r: "var_ref_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___lt__(self, r)

    def __gt__(self, r: "var_ref_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___gt__(self, r)

    def __le__(self, r: "var_ref_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___le__(self, r)

    def __ge__(self, r: "var_ref_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t___ge__(self, r)

    def compare(self, r: "var_ref_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: var_ref_t const &
        """
        return _ida_hexrays.var_ref_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> var_ref_t
        """
        _ida_hexrays.var_ref_t_swiginit(self, _ida_hexrays.new_var_ref_t())
    __swig_destroy__ = _ida_hexrays.delete_var_ref_t

# Register var_ref_t in _ida_hexrays:
_ida_hexrays.var_ref_t_swigregister(var_ref_t)
CMAT_ZERO = _ida_hexrays.CMAT_ZERO
r"""
does not exist
"""

CMAT_BUILT = _ida_hexrays.CMAT_BUILT
r"""
just generated
"""

CMAT_TRANS1 = _ida_hexrays.CMAT_TRANS1
r"""
applied first wave of transformations
"""

CMAT_NICE = _ida_hexrays.CMAT_NICE
r"""
nicefied expressions
"""

CMAT_TRANS2 = _ida_hexrays.CMAT_TRANS2
r"""
applied second wave of transformations
"""

CMAT_CPA = _ida_hexrays.CMAT_CPA
r"""
corrected pointer arithmetic
"""

CMAT_TRANS3 = _ida_hexrays.CMAT_TRANS3
r"""
applied third wave of transformations
"""

CMAT_CASTED = _ida_hexrays.CMAT_CASTED
r"""
added necessary casts
"""

CMAT_FINAL = _ida_hexrays.CMAT_FINAL
r"""
ready-to-use
"""

ITP_EMPTY = _ida_hexrays.ITP_EMPTY
r"""
nothing
"""

ITP_ARG1 = _ida_hexrays.ITP_ARG1
r"""
, (64 entries are reserved for 64 call arguments)
"""

ITP_ARG64 = _ida_hexrays.ITP_ARG64

ITP_BRACE1 = _ida_hexrays.ITP_BRACE1

ITP_INNER_LAST = _ida_hexrays.ITP_INNER_LAST

ITP_ASM = _ida_hexrays.ITP_ASM
r"""
__asm-line
"""

ITP_ELSE = _ida_hexrays.ITP_ELSE
r"""
else-line
"""

ITP_DO = _ida_hexrays.ITP_DO
r"""
do-line
"""

ITP_SEMI = _ida_hexrays.ITP_SEMI
r"""
semicolon
"""

ITP_CURLY1 = _ida_hexrays.ITP_CURLY1
r"""
{
"""

ITP_CURLY2 = _ida_hexrays.ITP_CURLY2
r"""
}
"""

ITP_BRACE2 = _ida_hexrays.ITP_BRACE2
r"""
)
"""

ITP_COLON = _ida_hexrays.ITP_COLON
r"""
: (label)
"""

ITP_BLOCK1 = _ida_hexrays.ITP_BLOCK1
r"""
opening block comment. this comment is printed before the item (other comments
are indented and printed after the item)
"""

ITP_BLOCK2 = _ida_hexrays.ITP_BLOCK2
r"""
closing block comment.
"""

ITP_TRY = _ida_hexrays.ITP_TRY
r"""
C++ try statement.
"""

ITP_CASE = _ida_hexrays.ITP_CASE
r"""
bit for switch cases
"""

ITP_SIGN = _ida_hexrays.ITP_SIGN
r"""
if this bit is set too, then we have a negative case value
"""

class treeloc_t(object):
    r"""
    Proxy of C++ treeloc_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.treeloc_t_ea_get, _ida_hexrays.treeloc_t_ea_set, doc=r"""ea""")
    itp: "item_preciser_t" = property(_ida_hexrays.treeloc_t_itp_get, _ida_hexrays.treeloc_t_itp_set, doc=r"""itp""")

    def __lt__(self, r: "treeloc_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: treeloc_t const &
        """
        return _ida_hexrays.treeloc_t___lt__(self, r)

    def __eq__(self, r: "treeloc_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: treeloc_t const &
        """
        return _ida_hexrays.treeloc_t___eq__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> treeloc_t
        """
        _ida_hexrays.treeloc_t_swiginit(self, _ida_hexrays.new_treeloc_t())
    __swig_destroy__ = _ida_hexrays.delete_treeloc_t

# Register treeloc_t in _ida_hexrays:
_ida_hexrays.treeloc_t_swigregister(treeloc_t)
RETRIEVE_ONCE = _ida_hexrays.RETRIEVE_ONCE
r"""
Retrieve comment if it has not been used yet.
"""

RETRIEVE_ALWAYS = _ida_hexrays.RETRIEVE_ALWAYS
r"""
Retrieve comment even if it has been used.
"""

class citem_cmt_t(object):
    r"""
    Proxy of C++ citem_cmt_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    used: "bool" = property(_ida_hexrays.citem_cmt_t_used_get, _ida_hexrays.citem_cmt_t_used_set, doc=r"""used""")
    r"""
    the comment has been retrieved?
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> citem_cmt_t
        __init__(self, s) -> citem_cmt_t

        @param s: char const *
        """
        _ida_hexrays.citem_cmt_t_swiginit(self, _ida_hexrays.new_citem_cmt_t(*args))

    def c_str(self) -> "char const *":
        r"""
        c_str(self) -> char const *
        """
        return _ida_hexrays.citem_cmt_t_c_str(self)

    def __str__(self) -> "char const *":
        r"""
        __str__(self) -> char const *
        """
        return _ida_hexrays.citem_cmt_t___str__(self)
    __swig_destroy__ = _ida_hexrays.delete_citem_cmt_t

# Register citem_cmt_t in _ida_hexrays:
_ida_hexrays.citem_cmt_t_swigregister(citem_cmt_t)
class citem_locator_t(object):
    r"""
    Proxy of C++ citem_locator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.citem_locator_t_ea_get, _ida_hexrays.citem_locator_t_ea_set, doc=r"""ea""")
    r"""
    citem address
    """
    op: "ctype_t" = property(_ida_hexrays.citem_locator_t_op_get, _ida_hexrays.citem_locator_t_op_set, doc=r"""op""")
    r"""
    citem operation
    """

    def __init__(self, *args):
        r"""
        __init__(self, _ea, _op) -> citem_locator_t

        @param _ea: ea_t
        @param _op: enum ctype_t

        __init__(self, i) -> citem_locator_t

        @param i: citem_t const *
        """
        _ida_hexrays.citem_locator_t_swiginit(self, _ida_hexrays.new_citem_locator_t(*args))

    def __eq__(self, r: "citem_locator_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___eq__(self, r)

    def __ne__(self, r: "citem_locator_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___ne__(self, r)

    def __lt__(self, r: "citem_locator_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___lt__(self, r)

    def __gt__(self, r: "citem_locator_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___gt__(self, r)

    def __le__(self, r: "citem_locator_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___le__(self, r)

    def __ge__(self, r: "citem_locator_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t___ge__(self, r)

    def compare(self, r: "citem_locator_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: citem_locator_t const &
        """
        return _ida_hexrays.citem_locator_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_citem_locator_t

# Register citem_locator_t in _ida_hexrays:
_ida_hexrays.citem_locator_t_swigregister(citem_locator_t)
class bit_bound_t(object):
    r"""
    Proxy of C++ bit_bound_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    nbits: "int16" = property(_ida_hexrays.bit_bound_t_nbits_get, _ida_hexrays.bit_bound_t_nbits_set, doc=r"""nbits""")
    sbits: "int16" = property(_ida_hexrays.bit_bound_t_sbits_get, _ida_hexrays.bit_bound_t_sbits_set, doc=r"""sbits""")

    def __init__(self, n: "int"=0, s: "int"=0):
        r"""
        __init__(self, n=0, s=0) -> bit_bound_t

        @param n: int
        @param s: int
        """
        _ida_hexrays.bit_bound_t_swiginit(self, _ida_hexrays.new_bit_bound_t(n, s))
    __swig_destroy__ = _ida_hexrays.delete_bit_bound_t

# Register bit_bound_t in _ida_hexrays:
_ida_hexrays.bit_bound_t_swigregister(bit_bound_t)
class citem_t(object):
    r"""
    Proxy of C++ citem_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ea: "ea_t" = property(_ida_hexrays.citem_t_ea_get, _ida_hexrays.citem_t_ea_set, doc=r"""ea""")
    r"""
    address that corresponds to the item. may be BADADDR
    """
    label_num: "int" = property(_ida_hexrays.citem_t_label_num_get, _ida_hexrays.citem_t_label_num_set, doc=r"""label_num""")
    r"""
    label number. -1 means no label. items of the expression types (cot_...) should
    not have labels at the final maturity level, but at the intermediate levels any
    ctree item may have a label. Labels must be unique. Usually they correspond to
    the basic block numbers.
    """
    index: "int" = property(_ida_hexrays.citem_t_index_get, _ida_hexrays.citem_t_index_set, doc=r"""index""")
    r"""
    an index in cfunc_t::treeitems. meaningful only after print_func()
    """

    def __init__(self, o: "ctype_t"=cot_empty):
        r"""
        __init__(self, o=cot_empty) -> citem_t

        @param o: enum ctype_t
        """
        _ida_hexrays.citem_t_swiginit(self, _ida_hexrays.new_citem_t(o))

    def swap(self, r: "citem_t") -> "void":
        r"""
        swap(self, r)
        Swap two citem_t.

        @param r: (C++: citem_t &)
        """
        return _ida_hexrays.citem_t_swap(self, r)

    def is_expr(self) -> "bool":
        r"""
        is_expr(self) -> bool
        Is an expression?
        """
        return _ida_hexrays.citem_t_is_expr(self)

    def contains_expr(self, e: "cexpr_t") -> "bool":
        r"""
        contains_expr(self, e) -> bool
        Does the item contain an expression?

        @param e: (C++: const cexpr_t *) cexpr_t const *
        """
        return _ida_hexrays.citem_t_contains_expr(self, e)

    def contains_label(self) -> "bool":
        r"""
        contains_label(self) -> bool
        Does the item contain a label?
        """
        return _ida_hexrays.citem_t_contains_label(self)

    def find_parent_of(self, *args) -> "citem_t *":
        r"""
        find_parent_of(self, sitem) -> citem_t

        @param sitem: citem_t const *

        find_parent_of(self, item) -> citem_t

        @param item: citem_t const *
        """
        return _ida_hexrays.citem_t_find_parent_of(self, *args)

    def find_closest_addr(self, _ea: "ea_t") -> "citem_t *":
        r"""
        find_closest_addr(self, _ea) -> citem_t

        @param _ea: ea_t
        """
        return _ida_hexrays.citem_t_find_closest_addr(self, _ea)

    def print1(self, func: "cfunc_t") -> "void":
        r"""
        print1(self, func)
        Print item into one line.

        @param func: (C++: const cfunc_t *) parent function. This argument is used to find out the referenced
                     variable names.
        @return: length of the generated text.
        """
        return _ida_hexrays.citem_t_print1(self, func)
    __swig_destroy__ = _ida_hexrays.delete_citem_t
    cinsn: "cinsn_t *const" = property(_ida_hexrays.citem_t_cinsn_get, doc=r"""cinsn""")
    cexpr: "cexpr_t *const" = property(_ida_hexrays.citem_t_cexpr_get, doc=r"""cexpr""")

    def _get_op(self) -> "ctype_t":
        r"""_get_op(self) -> ctype_t"""
        return _ida_hexrays.citem_t__get_op(self)

    def _set_op(self, v: "ctype_t") -> "void":
        r"""
        _set_op(self, v)

        Parameters
        ----------
        v: enum ctype_t

        """
        return _ida_hexrays.citem_t__set_op(self, v)

    def _ensure_no_op(self):
        if self.op not in [cot_empty, cit_empty]:
            raise Exception("%s has op %s; cannot be modified" % (self, self.op))
        return True
    op = property(
            _get_op,
            lambda self, v: self._ensure_no_op() and self._set_op(v))
    r"""
    item type
    """


    def __dbg_get_meminfo(self) -> "qstring":
        r"""
        __dbg_get_meminfo(self) -> qstring
        """
        return _ida_hexrays.citem_t___dbg_get_meminfo(self)

    def __dbg_get_registered_kind(self) -> "int":
        r"""
        __dbg_get_registered_kind(self) -> int
        """
        return _ida_hexrays.citem_t___dbg_get_registered_kind(self)

    def _obj_id(self) -> "PyObject *":
        r"""_obj_id(self) -> PyObject *"""
        return _ida_hexrays.citem_t__obj_id(self)

    obj_id = property(_obj_id)

    def _ensure_cond(self, ok, cond_str):
        if not ok:
            raise Exception("Condition \"%s\" not verified" % cond_str)
        return True

    def _ensure_no_obj(self, o, attr, attr_is_acquired):
        if attr_is_acquired and o is not None:
            raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
        return True

    def _ensure_ownership_transferrable(self, v):
        if not v.thisown:
            raise Exception("%s is already owned, and cannot be reused" % v)

    def _acquire_ownership(self, v, acquire):
        if acquire and (v is not None) and not isinstance(v, ida_idaapi.integer_types):
            self._ensure_ownership_transferrable(v)
            v.thisown = False
            dereg = getattr(v, "_deregister", None)
            if dereg:
                dereg()
        return True

    def _maybe_disown_and_deregister(self):
        if self.thisown:
            self.thisown = False
            self._deregister()

    def _own_and_register(self):
        assert(not self.thisown)
        self.thisown = True
        self._register()

    def replace_by(self, o):
        assert(isinstance(o, (cexpr_t, cinsn_t)))
        o._maybe_disown_and_deregister()
        self._replace_by(o)

    def _meminfo(self):
        cpp = self.__dbg_get_meminfo()
        rkind = self.__dbg_get_registered_kind()
        rkind_str = [
                "(not owned)",
                "cfuncptr_t",
                "cinsn_t",
                "cexpr_t",
                "cblock_t",
                "mba_t",
                "mop_t",
                "minsn_t",
                "optinsn_t",
                "optblock_t",
                "valrng_t",
                "udc_filter_t"][rkind]
        return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                cpp,
                self.thisown,
                rkind_str)
    meminfo = property(_meminfo)


# Register citem_t in _ida_hexrays:
_ida_hexrays.citem_t_swigregister(citem_t)
class cexpr_t(citem_t):
    r"""
    Proxy of C++ cexpr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    type: "tinfo_t" = property(_ida_hexrays.cexpr_t_type_get, _ida_hexrays.cexpr_t_type_set, doc=r"""type""")
    r"""
    expression type. must be carefully maintained
    """
    exflags: "uint32" = property(_ida_hexrays.cexpr_t_exflags_get, _ida_hexrays.cexpr_t_exflags_set, doc=r"""exflags""")
    r"""
    Expression attributes
    """

    def cpadone(self) -> "bool":
        r"""
        cpadone(self) -> bool
        Pointer arithmetic correction done for this expression?
        """
        return _ida_hexrays.cexpr_t_cpadone(self)

    def is_odd_lvalue(self) -> "bool":
        r"""
        is_odd_lvalue(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_odd_lvalue(self)

    def is_fpop(self) -> "bool":
        r"""
        is_fpop(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_fpop(self)

    def is_cstr(self) -> "bool":
        r"""
        is_cstr(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_cstr(self)

    def is_undef_val(self) -> "bool":
        r"""
        is_undef_val(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_undef_val(self)

    def is_jumpout(self) -> "bool":
        r"""
        is_jumpout(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_jumpout(self)

    def is_vftable(self) -> "bool":
        r"""
        is_vftable(self) -> bool
        """
        return _ida_hexrays.cexpr_t_is_vftable(self)

    def set_cpadone(self) -> "void":
        r"""
        set_cpadone(self)
        """
        return _ida_hexrays.cexpr_t_set_cpadone(self)

    def set_vftable(self) -> "void":
        r"""
        set_vftable(self)
        """
        return _ida_hexrays.cexpr_t_set_vftable(self)

    def __init__(self, *args):
        r"""
        __init__(self) -> cexpr_t
        __init__(self, cexpr_op, _x, _y=None, _z=None) -> cexpr_t

        @param cexpr_op: enum ctype_t
        @param _x: cexpr_t *
        @param _y: cexpr_t *
        @param _z: cexpr_t *

        __init__(self, r) -> cexpr_t

        @param r: cexpr_t const &
        """

        for arg in args[1:]: # skip copy constructor's arg
            if isinstance(arg, cexpr_t):
                self._ensure_ownership_transferrable(arg)


        _ida_hexrays.cexpr_t_swiginit(self, _ida_hexrays.new_cexpr_t(*args))

        for arg in args[1:]: # skip copy constructor's arg
            if isinstance(arg, cexpr_t):
                self._acquire_ownership(arg, True)




    def swap(self, r: "cexpr_t") -> "void":
        r"""
        swap(self, r)

        @param r: cexpr_t &
        """
        return _ida_hexrays.cexpr_t_swap(self, r)

    def assign(self, r: "cexpr_t") -> "cexpr_t &":
        r"""
        assign(self, r) -> cexpr_t

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t_assign(self, r)

    def __eq__(self, r: "cexpr_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___eq__(self, r)

    def __ne__(self, r: "cexpr_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___ne__(self, r)

    def __lt__(self, r: "cexpr_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___lt__(self, r)

    def __gt__(self, r: "cexpr_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___gt__(self, r)

    def __le__(self, r: "cexpr_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___le__(self, r)

    def __ge__(self, r: "cexpr_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t___ge__(self, r)

    def compare(self, r: "cexpr_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cexpr_t const &
        """
        return _ida_hexrays.cexpr_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_cexpr_t

    def _replace_by(self, r: "cexpr_t") -> "void":
        r"""
        _replace_by(self, r)

        Parameters
        ----------
        r: cexpr_t *

        """
        return _ida_hexrays.cexpr_t__replace_by(self, r)

    def cleanup(self) -> "void":
        r"""
        cleanup(self)
        Cleanup the expression. This function properly deletes all children and sets the
        item type to cot_empty.
        """
        return _ida_hexrays.cexpr_t_cleanup(self)

    def put_number(self, *args) -> "void":
        r"""
        put_number(self, func, value, nbytes, sign=no_sign)
        Assign a number to the expression.

        @param func: (C++: cfunc_t *) current function
        @param value: (C++: uint64) number value
        @param nbytes: (C++: int) size of the number in bytes
        @param sign: (C++: type_sign_t) number sign
        """
        return _ida_hexrays.cexpr_t_put_number(self, *args)

    def print1(self, func: "cfunc_t") -> "void":
        r"""
        print1(self, func)
        Print expression into one line.

        @param func: (C++: const cfunc_t *) parent function. This argument is used to find out the referenced
                     variable names.
        """
        return _ida_hexrays.cexpr_t_print1(self, func)

    def calc_type(self, recursive: "bool") -> "void":
        r"""
        calc_type(self, recursive)
        Calculate the type of the expression. Use this function to calculate the
        expression type when a new expression is built

        @param recursive: (C++: bool) if true, types of all children expression will be calculated
                          before calculating our type
        """
        return _ida_hexrays.cexpr_t_calc_type(self, recursive)

    def equal_effect(self, r: "cexpr_t") -> "bool":
        r"""
        equal_effect(self, r) -> bool
        Compare two expressions. This function tries to compare two expressions in an
        'intelligent' manner. For example, it knows about commutitive operators and can
        ignore useless casts.

        @param r: (C++: const cexpr_t &) the expression to compare against the current expression
        @return: true expressions can be considered equal
        """
        return _ida_hexrays.cexpr_t_equal_effect(self, r)

    def is_child_of(self, parent: "citem_t") -> "bool":
        r"""
        is_child_of(self, parent) -> bool
        Verify if the specified item is our parent.

        @param parent: (C++: const citem_t *) possible parent item
        @return: true if the specified item is our parent
        """
        return _ida_hexrays.cexpr_t_is_child_of(self, parent)

    def contains_operator(self, needed_op: "ctype_t", times: "int"=1) -> "bool":
        r"""
        contains_operator(self, needed_op, times=1) -> bool
        Check if the expression contains the specified operator.

        @param needed_op: (C++: ctype_t) operator code to search for
        @param times: (C++: int) how many times the operator code should be present
        @return: true if the expression has at least TIMES children with NEEDED_OP
        """
        return _ida_hexrays.cexpr_t_contains_operator(self, needed_op, times)

    def contains_comma(self, times: "int"=1) -> "bool":
        r"""
        contains_comma(self, times=1) -> bool
        Does the expression contain a comma operator?

        @param times: (C++: int)
        """
        return _ida_hexrays.cexpr_t_contains_comma(self, times)

    def contains_insn(self, times: "int"=1) -> "bool":
        r"""
        contains_insn(self, times=1) -> bool
        Does the expression contain an embedded statement operator?

        @param times: (C++: int)
        """
        return _ida_hexrays.cexpr_t_contains_insn(self, times)

    def contains_insn_or_label(self) -> "bool":
        r"""
        contains_insn_or_label(self) -> bool
        Does the expression contain an embedded statement operator or a label?
        """
        return _ida_hexrays.cexpr_t_contains_insn_or_label(self)

    def contains_comma_or_insn_or_label(self, maxcommas: "int"=1) -> "bool":
        r"""
        contains_comma_or_insn_or_label(self, maxcommas=1) -> bool
        Does the expression contain a comma operator or an embedded statement operator
        or a label?

        @param maxcommas: (C++: int)
        """
        return _ida_hexrays.cexpr_t_contains_comma_or_insn_or_label(self, maxcommas)

    def is_nice_expr(self) -> "bool":
        r"""
        is_nice_expr(self) -> bool
        Is nice expression? Nice expressions do not contain comma operators, embedded
        statements, or labels.
        """
        return _ida_hexrays.cexpr_t_is_nice_expr(self)

    def is_nice_cond(self) -> "bool":
        r"""
        is_nice_cond(self) -> bool
        Is nice condition?. Nice condition is a nice expression of the boolean type.
        """
        return _ida_hexrays.cexpr_t_is_nice_cond(self)

    def is_call_object_of(self, parent: "citem_t") -> "bool":
        r"""
        is_call_object_of(self, parent) -> bool
        Is call object?

        @param parent: (C++: const citem_t *) citem_t const *
        @return: true if our expression is the call object of the specified parent
                 expression.
        """
        return _ida_hexrays.cexpr_t_is_call_object_of(self, parent)

    def is_call_arg_of(self, parent: "citem_t") -> "bool":
        r"""
        is_call_arg_of(self, parent) -> bool
        Is call argument?

        @param parent: (C++: const citem_t *) citem_t const *
        @return: true if our expression is a call argument of the specified parent
                 expression.
        """
        return _ida_hexrays.cexpr_t_is_call_arg_of(self, parent)

    def get_type_sign(self) -> "type_sign_t":
        r"""
        get_type_sign(self) -> type_sign_t
        Get expression sign.
        """
        return _ida_hexrays.cexpr_t_get_type_sign(self)

    def is_type_unsigned(self) -> "bool":
        r"""
        is_type_unsigned(self) -> bool
        Is expression unsigned?
        """
        return _ida_hexrays.cexpr_t_is_type_unsigned(self)

    def is_type_signed(self) -> "bool":
        r"""
        is_type_signed(self) -> bool
        Is expression signed?
        """
        return _ida_hexrays.cexpr_t_is_type_signed(self)

    def get_high_nbit_bound(self) -> "bit_bound_t":
        r"""
        get_high_nbit_bound(self) -> bit_bound_t
        Get max number of bits that can really be used by the expression. For example, x
        % 16 can yield only 4 non-zero bits, higher bits are zero
        """
        return _ida_hexrays.cexpr_t_get_high_nbit_bound(self)

    def get_low_nbit_bound(self) -> "int":
        r"""
        get_low_nbit_bound(self) -> int
        Get min number of bits that are certainly required to represent the expression.
        For example, constant 16 always uses 5 bits: 10000.
        """
        return _ida_hexrays.cexpr_t_get_low_nbit_bound(self)

    def requires_lvalue(self, child: "cexpr_t") -> "bool":
        r"""
        requires_lvalue(self, child) -> bool
        Check if the expression requires an lvalue.

        @param child: (C++: const cexpr_t *) The function will check if this child of our expression must be an
                      lvalue.
        @return: true if child must be an lvalue.
        """
        return _ida_hexrays.cexpr_t_requires_lvalue(self, child)

    def has_side_effects(self) -> "bool":
        r"""
        has_side_effects(self) -> bool
        Check if the expression has side effects. Calls, pre/post inc/dec, and
        assignments have side effects.
        """
        return _ida_hexrays.cexpr_t_has_side_effects(self)

    def numval(self) -> "uint64":
        r"""
        numval(self) -> uint64
        Get numeric value of the expression. This function can be called only on cot_num
        expressions!
        """
        return _ida_hexrays.cexpr_t_numval(self)

    def is_const_value(self, _v: "uint64") -> "bool":
        r"""
        is_const_value(self, _v) -> bool
        Check if the expression is a number with the specified value.

        @param _v: (C++: uint64)
        """
        return _ida_hexrays.cexpr_t_is_const_value(self, _v)

    def is_negative_const(self) -> "bool":
        r"""
        is_negative_const(self) -> bool
        Check if the expression is a negative number.
        """
        return _ida_hexrays.cexpr_t_is_negative_const(self)

    def is_non_negative_const(self) -> "bool":
        r"""
        is_non_negative_const(self) -> bool
        Check if the expression is a non-negative number.
        """
        return _ida_hexrays.cexpr_t_is_non_negative_const(self)

    def is_non_zero_const(self) -> "bool":
        r"""
        is_non_zero_const(self) -> bool
        Check if the expression is a non-zero number.
        """
        return _ida_hexrays.cexpr_t_is_non_zero_const(self)

    def is_zero_const(self) -> "bool":
        r"""
        is_zero_const(self) -> bool
        Check if the expression is a zero.
        """
        return _ida_hexrays.cexpr_t_is_zero_const(self)

    def get_const_value(self) -> "bool":
        r"""
        get_const_value(self) -> bool
        Get expression value.

        @return: true if the expression is a number.
        """
        return _ida_hexrays.cexpr_t_get_const_value(self)

    def maybe_ptr(self) -> "bool":
        r"""
        maybe_ptr(self) -> bool
        May the expression be a pointer?
        """
        return _ida_hexrays.cexpr_t_maybe_ptr(self)

    def get_ptr_or_array(self) -> "cexpr_t *":
        r"""
        get_ptr_or_array(self) -> cexpr_t
        Find pointer or array child.
        """
        return _ida_hexrays.cexpr_t_get_ptr_or_array(self)

    def find_op(self, *args) -> "cexpr_t *":
        r"""
        find_op(self, _op) -> cexpr_t

        @param _op: enum ctype_t

        """
        return _ida_hexrays.cexpr_t_find_op(self, *args)

    def find_num_op(self, *args) -> "cexpr_t *":
        r"""
        find_num_op(self) -> cexpr_t
        """
        return _ida_hexrays.cexpr_t_find_num_op(self, *args)

    def theother(self, *args) -> "cexpr_t *":
        r"""
        theother(self, what) -> cexpr_t

        @param what: cexpr_t const *

        """
        return _ida_hexrays.cexpr_t_theother(self, *args)

    def get_1num_op(self, o1: "cexpr_t **", o2: "cexpr_t **") -> "bool":
        r"""
        get_1num_op(self, o1, o2) -> bool

        @param o1: cexpr_t **
        @param o2: cexpr_t **
        """
        return _ida_hexrays.cexpr_t_get_1num_op(self, o1, o2)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.cexpr_t_dstr(self)

    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.cexpr_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.cexpr_t__deregister(self)

    def get_v(self) -> "var_ref_t *":
        r"""
        get_v(self) -> var_ref_t
        """
        return _ida_hexrays.cexpr_t_get_v(self)

    def set_v(self, v: "var_ref_t") -> "void":
        r"""
        set_v(self, v)

        @param v: var_ref_t const *
        """
        return _ida_hexrays.cexpr_t_set_v(self, v)

    v = property(lambda self: self.get_v(), lambda self, v: self.set_v(v))
    r"""
    used for cot_var
    """


    def _get_n(self) -> "cnumber_t *":
        r"""_get_n(self) -> cnumber_t"""
        return _ida_hexrays.cexpr_t__get_n(self)

    def _set_n(self, _v: "cnumber_t") -> "void":
        r"""
        _set_n(self, _v)

        Parameters
        ----------
        _v: cnumber_t *

        """
        return _ida_hexrays.cexpr_t__set_n(self, _v)

    n = property(
            lambda self: self._get_n() if self.op == cot_num else None,
            lambda self, v: self._ensure_cond(self.op == cot_num,"self.op == cot_num") \
                            and self._ensure_no_obj(self._get_n(),"n", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_n(v))
    r"""
    used for cot_num
    """


    def _get_fpc(self) -> "fnumber_t *":
        r"""_get_fpc(self) -> fnumber_t"""
        return _ida_hexrays.cexpr_t__get_fpc(self)

    def _set_fpc(self, _v: "fnumber_t") -> "void":
        r"""
        _set_fpc(self, _v)

        Parameters
        ----------
        _v: fnumber_t *

        """
        return _ida_hexrays.cexpr_t__set_fpc(self, _v)

    fpc = property(
            lambda self: self._get_fpc() if self.op == cot_fnum else None,
            lambda self, v: self._ensure_cond(self.op == cot_fnum,"self.op == cot_fnum") \
                            and self._ensure_no_obj(self._get_fpc(),"fpc", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_fpc(v))
    r"""
    used for cot_fnum
    """


    def _get_x(self) -> "cexpr_t *":
        r"""_get_x(self) -> cexpr_t"""
        return _ida_hexrays.cexpr_t__get_x(self)

    def _set_x(self, _v: "cexpr_t") -> "void":
        r"""
        _set_x(self, _v)

        Parameters
        ----------
        _v: cexpr_t *

        """
        return _ida_hexrays.cexpr_t__set_x(self, _v)

    x = property(
            lambda self: self._get_x() if op_uses_x(self.op) else None,
            lambda self, v: self._ensure_cond(op_uses_x(self.op),"op_uses_x(self.op)") \
                            and self._ensure_no_obj(self._get_x(),"x", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_x(v))
    r"""
    the first operand of the expression
    """


    def _get_y(self) -> "cexpr_t *":
        r"""_get_y(self) -> cexpr_t"""
        return _ida_hexrays.cexpr_t__get_y(self)

    def _set_y(self, _v: "cexpr_t") -> "void":
        r"""
        _set_y(self, _v)

        Parameters
        ----------
        _v: cexpr_t *

        """
        return _ida_hexrays.cexpr_t__set_y(self, _v)

    y = property(
            lambda self: self._get_y() if op_uses_y(self.op) else None,
            lambda self, v: self._ensure_cond(op_uses_y(self.op),"op_uses_y(self.op)") \
                            and self._ensure_no_obj(self._get_y(),"y", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_y(v))
    r"""
    the second operand of the expression
    """


    def _get_z(self) -> "cexpr_t *":
        r"""_get_z(self) -> cexpr_t"""
        return _ida_hexrays.cexpr_t__get_z(self)

    def _set_z(self, _v: "cexpr_t") -> "void":
        r"""
        _set_z(self, _v)

        Parameters
        ----------
        _v: cexpr_t *

        """
        return _ida_hexrays.cexpr_t__set_z(self, _v)

    z = property(
            lambda self: self._get_z() if op_uses_z(self.op) else None,
            lambda self, v: self._ensure_cond(op_uses_z(self.op),"op_uses_z(self.op)") \
                            and self._ensure_no_obj(self._get_z(),"z", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_z(v))
    r"""
    the third operand of the expression
    """


    def _get_a(self) -> "carglist_t *":
        r"""_get_a(self) -> carglist_t"""
        return _ida_hexrays.cexpr_t__get_a(self)

    def _set_a(self, _v: "carglist_t") -> "void":
        r"""
        _set_a(self, _v)

        Parameters
        ----------
        _v: carglist_t *

        """
        return _ida_hexrays.cexpr_t__set_a(self, _v)

    a = property(
            lambda self: self._get_a() if self.op == cot_call else None,
            lambda self, v: self._ensure_cond(self.op == cot_call,"self.op == cot_call") \
                            and self._ensure_no_obj(self._get_a(),"a", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_a(v))
    r"""
    argument list (used for cot_call)
    """


    def _get_insn(self) -> "cinsn_t *":
        r"""_get_insn(self) -> cinsn_t"""
        return _ida_hexrays.cexpr_t__get_insn(self)

    def _set_insn(self, _v: "cinsn_t") -> "void":
        r"""
        _set_insn(self, _v)

        Parameters
        ----------
        _v: cinsn_t *

        """
        return _ida_hexrays.cexpr_t__set_insn(self, _v)

    insn = property(
            lambda self: self._get_insn() if self.op == cot_insn else None,
            lambda self, v: self._ensure_cond(self.op == cot_insn,"self.op == cot_insn") \
                            and self._ensure_no_obj(self._get_insn(),"insn", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_insn(v))
    r"""
    an embedded statement, they are prohibited at the final maturity stage
    (CMAT_FINAL)
    """


    def _get_m(self) -> "int":
        r"""_get_m(self) -> int"""
        return _ida_hexrays.cexpr_t__get_m(self)

    def _set_m(self, _v: "int") -> "void":
        r"""
        _set_m(self, _v)

        Parameters
        ----------
        _v: int

        """
        return _ida_hexrays.cexpr_t__set_m(self, _v)

    m = property(
            lambda self: self._get_m() if self.op == cot_memptr or self.op == cot_memref else 0,
            lambda self, v: self._ensure_cond(self.op == cot_memptr or self.op == cot_memref,"self.op == cot_memptr or self.op == cot_memref") and self._set_m(v))
    r"""
    member offset (used for cot_memptr, cot_memref) for unions, the member number
    """


    def _get_ptrsize(self) -> "int":
        r"""_get_ptrsize(self) -> int"""
        return _ida_hexrays.cexpr_t__get_ptrsize(self)

    def _set_ptrsize(self, _v: "int") -> "void":
        r"""
        _set_ptrsize(self, _v)

        Parameters
        ----------
        _v: int

        """
        return _ida_hexrays.cexpr_t__set_ptrsize(self, _v)

    ptrsize = property(
            lambda self: self._get_ptrsize() if self.op == cot_ptr or self.op == cot_memptr else 0,
            lambda self, v: self._ensure_cond(self.op == cot_ptr or self.op == cot_memptr,"self.op == cot_ptr or self.op == cot_memptr") and self._set_ptrsize(v))
    r"""
    memory access size (used for cot_ptr, cot_memptr)
    """


    def _get_obj_ea(self) -> "ea_t":
        r"""_get_obj_ea(self) -> ea_t"""
        return _ida_hexrays.cexpr_t__get_obj_ea(self)

    def _set_obj_ea(self, _v: "ea_t") -> "void":
        r"""
        _set_obj_ea(self, _v)

        Parameters
        ----------
        _v: ea_t

        """
        return _ida_hexrays.cexpr_t__set_obj_ea(self, _v)

    obj_ea = property(
            lambda self: self._get_obj_ea() if self.op == cot_obj else ida_idaapi.BADADDR,
            lambda self, v: self._ensure_cond(self.op == cot_obj,"self.op == cot_obj") and self._set_obj_ea(v))
    r"""
    used for cot_obj
    """


    def _get_refwidth(self) -> "int":
        r"""_get_refwidth(self) -> int"""
        return _ida_hexrays.cexpr_t__get_refwidth(self)

    def _set_refwidth(self, _v: "int") -> "void":
        r"""
        _set_refwidth(self, _v)

        Parameters
        ----------
        _v: int

        """
        return _ida_hexrays.cexpr_t__set_refwidth(self, _v)

    refwidth = property(
            lambda self: self._get_refwidth() if True else 0,
            lambda self, v: self._ensure_cond(True,"True") and self._set_refwidth(v))
    r"""
    how many bytes are accessed? (-1: none)
    """


    def _get_helper(self) -> "char const *":
        r"""_get_helper(self) -> char const *"""
        return _ida_hexrays.cexpr_t__get_helper(self)

    def _set_helper(self, _v: "char const *") -> "void":
        r"""
        _set_helper(self, _v)

        Parameters
        ----------
        _v: char const *

        """
        return _ida_hexrays.cexpr_t__set_helper(self, _v)

    helper = property(
            lambda self: self._get_helper() if self.op == cot_helper else None,
            lambda self, v: self._ensure_cond(self.op == cot_helper,"self.op == cot_helper") \
                            and self._ensure_no_obj(self._get_helper(),"helper", False) \
                            and self._acquire_ownership(v, False) \
                            and self._set_helper(v))
    r"""
    helper name (used for cot_helper)
    """


    def _get_string(self) -> "char const *":
        r"""_get_string(self) -> char const *"""
        return _ida_hexrays.cexpr_t__get_string(self)

    def _set_string(self, _v: "char const *") -> "void":
        r"""
        _set_string(self, _v)

        Parameters
        ----------
        _v: char const *

        """
        return _ida_hexrays.cexpr_t__set_string(self, _v)

    string = property(
            lambda self: self._get_string() if self.op == cot_str else None,
            lambda self, v: self._ensure_cond(self.op == cot_str,"self.op == cot_str") \
                            and self._ensure_no_obj(self._get_string(),"string", False) \
                            and self._acquire_ownership(v, False) \
                            and self._set_string(v))
    r"""
    utf8 string constant, user representation (used for cot_str)
    """


# Register cexpr_t in _ida_hexrays:
_ida_hexrays.cexpr_t_swigregister(cexpr_t)
EXFL_CPADONE = _ida_hexrays.EXFL_CPADONE
r"""
pointer arithmetic correction done
"""

EXFL_LVALUE = _ida_hexrays.EXFL_LVALUE
r"""
expression is lvalue even if it doesn't look like it
"""

EXFL_FPOP = _ida_hexrays.EXFL_FPOP
r"""
floating point operation
"""

EXFL_ALONE = _ida_hexrays.EXFL_ALONE
r"""
standalone helper
"""

EXFL_CSTR = _ida_hexrays.EXFL_CSTR
r"""
string literal
"""

EXFL_PARTIAL = _ida_hexrays.EXFL_PARTIAL
r"""
type of the expression is considered partial
"""

EXFL_UNDEF = _ida_hexrays.EXFL_UNDEF
r"""
expression uses undefined value
"""

EXFL_JUMPOUT = _ida_hexrays.EXFL_JUMPOUT
r"""
jump out-of-function
"""

EXFL_VFTABLE = _ida_hexrays.EXFL_VFTABLE
r"""
is ptr to vftable (used for cot_memptr, cot_memref)
"""

EXFL_ALL = _ida_hexrays.EXFL_ALL
r"""
all currently defined bits
"""


class ceinsn_t(object):
    r"""
    Proxy of C++ ceinsn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    expr: "cexpr_t" = property(_ida_hexrays.ceinsn_t_expr_get, _ida_hexrays.ceinsn_t_expr_set, doc=r"""expr""")
    r"""
    Expression of the statement.
    """

    def __init__(self):
        r"""
        __init__(self) -> ceinsn_t
        """
        _ida_hexrays.ceinsn_t_swiginit(self, _ida_hexrays.new_ceinsn_t())
    __swig_destroy__ = _ida_hexrays.delete_ceinsn_t

# Register ceinsn_t in _ida_hexrays:
_ida_hexrays.ceinsn_t_swigregister(ceinsn_t)
CALC_CURLY_BRACES = _ida_hexrays.CALC_CURLY_BRACES
r"""
print curly braces if necessary
"""

NO_CURLY_BRACES = _ida_hexrays.NO_CURLY_BRACES
r"""
don't print curly braces
"""

USE_CURLY_BRACES = _ida_hexrays.USE_CURLY_BRACES
r"""
print curly braces without any checks
"""

class cif_t(ceinsn_t):
    r"""
    Proxy of C++ cif_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ithen: "cinsn_t *" = property(_ida_hexrays.cif_t_ithen_get, _ida_hexrays.cif_t_ithen_set, doc=r"""ithen""")
    r"""
    Then-branch of the if-statement.
    """
    ielse: "cinsn_t *" = property(_ida_hexrays.cif_t_ielse_get, _ida_hexrays.cif_t_ielse_set, doc=r"""ielse""")
    r"""
    Else-branch of the if-statement. May be nullptr.
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> cif_t
        __init__(self, r) -> cif_t

        @param r: cif_t const &
        """
        _ida_hexrays.cif_t_swiginit(self, _ida_hexrays.new_cif_t(*args))

    def assign(self, r: "cif_t") -> "cif_t &":
        r"""
        assign(self, r) -> cif_t

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t_assign(self, r)

    def __eq__(self, r: "cif_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___eq__(self, r)

    def __ne__(self, r: "cif_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___ne__(self, r)

    def __lt__(self, r: "cif_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___lt__(self, r)

    def __gt__(self, r: "cif_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___gt__(self, r)

    def __le__(self, r: "cif_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___le__(self, r)

    def __ge__(self, r: "cif_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t___ge__(self, r)

    def compare(self, r: "cif_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cif_t const &
        """
        return _ida_hexrays.cif_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_cif_t

    def cleanup(self) -> "void":
        r"""
        cleanup(self)
        """
        return _ida_hexrays.cif_t_cleanup(self)

# Register cif_t in _ida_hexrays:
_ida_hexrays.cif_t_swigregister(cif_t)
class cloop_t(ceinsn_t):
    r"""
    Proxy of C++ cloop_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    body: "cinsn_t *" = property(_ida_hexrays.cloop_t_body_get, _ida_hexrays.cloop_t_body_set, doc=r"""body""")

    def __init__(self, *args):
        r"""
        __init__(self, b=None) -> cloop_t

        @param b: cinsn_t *

        __init__(self, r) -> cloop_t

        @param r: cloop_t const &
        """
        _ida_hexrays.cloop_t_swiginit(self, _ida_hexrays.new_cloop_t(*args))

    def assign(self, r: "cloop_t") -> "cloop_t &":
        r"""
        assign(self, r) -> cloop_t

        @param r: cloop_t const &
        """
        return _ida_hexrays.cloop_t_assign(self, r)
    __swig_destroy__ = _ida_hexrays.delete_cloop_t

    def cleanup(self) -> "void":
        r"""
        cleanup(self)
        """
        return _ida_hexrays.cloop_t_cleanup(self)

# Register cloop_t in _ida_hexrays:
_ida_hexrays.cloop_t_swigregister(cloop_t)
class cfor_t(cloop_t):
    r"""
    Proxy of C++ cfor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    init: "cexpr_t" = property(_ida_hexrays.cfor_t_init_get, _ida_hexrays.cfor_t_init_set, doc=r"""init""")
    r"""
    Initialization expression.
    """
    step: "cexpr_t" = property(_ida_hexrays.cfor_t_step_get, _ida_hexrays.cfor_t_step_set, doc=r"""step""")
    r"""
    Step expression.
    """

    def __eq__(self, r: "cfor_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___eq__(self, r)

    def __ne__(self, r: "cfor_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___ne__(self, r)

    def __lt__(self, r: "cfor_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___lt__(self, r)

    def __gt__(self, r: "cfor_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___gt__(self, r)

    def __le__(self, r: "cfor_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___le__(self, r)

    def __ge__(self, r: "cfor_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t___ge__(self, r)

    def compare(self, r: "cfor_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cfor_t const &
        """
        return _ida_hexrays.cfor_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cfor_t
        """
        _ida_hexrays.cfor_t_swiginit(self, _ida_hexrays.new_cfor_t())
    __swig_destroy__ = _ida_hexrays.delete_cfor_t

# Register cfor_t in _ida_hexrays:
_ida_hexrays.cfor_t_swigregister(cfor_t)
class cwhile_t(cloop_t):
    r"""
    Proxy of C++ cwhile_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "cwhile_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___eq__(self, r)

    def __ne__(self, r: "cwhile_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___ne__(self, r)

    def __lt__(self, r: "cwhile_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___lt__(self, r)

    def __gt__(self, r: "cwhile_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___gt__(self, r)

    def __le__(self, r: "cwhile_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___le__(self, r)

    def __ge__(self, r: "cwhile_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t___ge__(self, r)

    def compare(self, r: "cwhile_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cwhile_t const &
        """
        return _ida_hexrays.cwhile_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cwhile_t
        """
        _ida_hexrays.cwhile_t_swiginit(self, _ida_hexrays.new_cwhile_t())
    __swig_destroy__ = _ida_hexrays.delete_cwhile_t

# Register cwhile_t in _ida_hexrays:
_ida_hexrays.cwhile_t_swigregister(cwhile_t)
class cdo_t(cloop_t):
    r"""
    Proxy of C++ cdo_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "cdo_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___eq__(self, r)

    def __ne__(self, r: "cdo_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___ne__(self, r)

    def __lt__(self, r: "cdo_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___lt__(self, r)

    def __gt__(self, r: "cdo_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___gt__(self, r)

    def __le__(self, r: "cdo_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___le__(self, r)

    def __ge__(self, r: "cdo_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t___ge__(self, r)

    def compare(self, r: "cdo_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cdo_t const &
        """
        return _ida_hexrays.cdo_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cdo_t
        """
        _ida_hexrays.cdo_t_swiginit(self, _ida_hexrays.new_cdo_t())
    __swig_destroy__ = _ida_hexrays.delete_cdo_t

# Register cdo_t in _ida_hexrays:
_ida_hexrays.cdo_t_swigregister(cdo_t)
class creturn_t(ceinsn_t):
    r"""
    Proxy of C++ creturn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "creturn_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___eq__(self, r)

    def __ne__(self, r: "creturn_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___ne__(self, r)

    def __lt__(self, r: "creturn_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___lt__(self, r)

    def __gt__(self, r: "creturn_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___gt__(self, r)

    def __le__(self, r: "creturn_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___le__(self, r)

    def __ge__(self, r: "creturn_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t___ge__(self, r)

    def compare(self, r: "creturn_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: creturn_t const &
        """
        return _ida_hexrays.creturn_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> creturn_t
        """
        _ida_hexrays.creturn_t_swiginit(self, _ida_hexrays.new_creturn_t())
    __swig_destroy__ = _ida_hexrays.delete_creturn_t

# Register creturn_t in _ida_hexrays:
_ida_hexrays.creturn_t_swigregister(creturn_t)
class cgoto_t(object):
    r"""
    Proxy of C++ cgoto_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    label_num: "int" = property(_ida_hexrays.cgoto_t_label_num_get, _ida_hexrays.cgoto_t_label_num_set, doc=r"""label_num""")
    r"""
    Target label number.
    """

    def __eq__(self, r: "cgoto_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___eq__(self, r)

    def __ne__(self, r: "cgoto_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___ne__(self, r)

    def __lt__(self, r: "cgoto_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___lt__(self, r)

    def __gt__(self, r: "cgoto_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___gt__(self, r)

    def __le__(self, r: "cgoto_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___le__(self, r)

    def __ge__(self, r: "cgoto_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t___ge__(self, r)

    def compare(self, r: "cgoto_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cgoto_t const &
        """
        return _ida_hexrays.cgoto_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cgoto_t
        """
        _ida_hexrays.cgoto_t_swiginit(self, _ida_hexrays.new_cgoto_t())
    __swig_destroy__ = _ida_hexrays.delete_cgoto_t

# Register cgoto_t in _ida_hexrays:
_ida_hexrays.cgoto_t_swigregister(cgoto_t)
class casm_t(ida_pro.eavec_t):
    r"""
    Proxy of C++ casm_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""
        __init__(self, ea) -> casm_t

        @param ea: ea_t

        __init__(self, r) -> casm_t

        @param r: casm_t const &
        """
        _ida_hexrays.casm_t_swiginit(self, _ida_hexrays.new_casm_t(*args))

    def __eq__(self, r: "casm_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___eq__(self, r)

    def __ne__(self, r: "casm_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___ne__(self, r)

    def __lt__(self, r: "casm_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___lt__(self, r)

    def __gt__(self, r: "casm_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___gt__(self, r)

    def __le__(self, r: "casm_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___le__(self, r)

    def __ge__(self, r: "casm_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t___ge__(self, r)

    def compare(self, r: "casm_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: casm_t const &
        """
        return _ida_hexrays.casm_t_compare(self, r)

    def one_insn(self) -> "bool":
        r"""
        one_insn(self) -> bool
        """
        return _ida_hexrays.casm_t_one_insn(self)
    __swig_destroy__ = _ida_hexrays.delete_casm_t

# Register casm_t in _ida_hexrays:
_ida_hexrays.casm_t_swigregister(casm_t)
class cinsn_t(citem_t):
    r"""
    Proxy of C++ cinsn_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    ctry: "ctry_t *" = property(_ida_hexrays.cinsn_t_ctry_get, _ida_hexrays.cinsn_t_ctry_set, doc=r"""ctry""")
    r"""
    details of try-statement
    """
    cthrow: "cthrow_t *" = property(_ida_hexrays.cinsn_t_cthrow_get, _ida_hexrays.cinsn_t_cthrow_set, doc=r"""cthrow""")
    r"""
    details of throw-statement
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> cinsn_t
        __init__(self, r) -> cinsn_t

        @param r: cinsn_t const &
        """
        _ida_hexrays.cinsn_t_swiginit(self, _ida_hexrays.new_cinsn_t(*args))

    def swap(self, r: "cinsn_t") -> "void":
        r"""
        swap(self, r)

        @param r: cinsn_t &
        """
        return _ida_hexrays.cinsn_t_swap(self, r)

    def assign(self, r: "cinsn_t") -> "cinsn_t &":
        r"""
        assign(self, r) -> cinsn_t

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t_assign(self, r)

    def __eq__(self, r: "cinsn_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___eq__(self, r)

    def __ne__(self, r: "cinsn_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___ne__(self, r)

    def __lt__(self, r: "cinsn_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___lt__(self, r)

    def __gt__(self, r: "cinsn_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___gt__(self, r)

    def __le__(self, r: "cinsn_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___le__(self, r)

    def __ge__(self, r: "cinsn_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t___ge__(self, r)

    def compare(self, r: "cinsn_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cinsn_t const &
        """
        return _ida_hexrays.cinsn_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_cinsn_t

    def _replace_by(self, r: "cinsn_t") -> "void":
        r"""
        _replace_by(self, r)

        Parameters
        ----------
        r: cinsn_t *

        """
        return _ida_hexrays.cinsn_t__replace_by(self, r)

    def cleanup(self) -> "void":
        r"""
        cleanup(self)
        Cleanup the statement. This function properly deletes all children and sets the
        item type to cit_empty.
        """
        return _ida_hexrays.cinsn_t_cleanup(self)

    def zero(self) -> "void":
        r"""
        zero(self)
        Overwrite with zeroes without cleaning memory or deleting children.
        """
        return _ida_hexrays.cinsn_t_zero(self)

    def new_insn(self, insn_ea: "ea_t") -> "cinsn_t &":
        r"""
        new_insn(self, insn_ea) -> cinsn_t
        Create a new statement. The current statement must be a block. The new statement
        will be appended to it.

        @param insn_ea: (C++: ea_t) statement address
        """
        return _ida_hexrays.cinsn_t_new_insn(self, insn_ea)

    def create_if(self, cnd: "cexpr_t") -> "cif_t &":
        r"""
        create_if(self, cnd) -> cif_t
        Create a new if-statement. The current statement must be a block. The new
        statement will be appended to it.

        @param cnd: (C++: cexpr_t *) if condition. It will be deleted after being copied.
        """
        return _ida_hexrays.cinsn_t_create_if(self, cnd)

    def _print(self, indent: "int", vp: "vc_printer_t", use_curly: "use_curly_t"=CALC_CURLY_BRACES) -> "void":
        r"""
        _print(self, indent, vp, use_curly=CALC_CURLY_BRACES)

        Parameters
        ----------
        indent: int
        vp: vc_printer_t &
        use_curly: enum use_curly_t

        """
        return _ida_hexrays.cinsn_t__print(self, indent, vp, use_curly)

    def print1(self, func: "cfunc_t") -> "void":
        r"""
        print1(self, func)
        Print the statement into one line. Currently this function is not available.

        @param func: (C++: const cfunc_t *) parent function. This argument is used to find out the referenced
                     variable names.
        """
        return _ida_hexrays.cinsn_t_print1(self, func)

    def is_ordinary_flow(self) -> "bool":
        r"""
        is_ordinary_flow(self) -> bool
        Check if the statement passes execution to the next statement.

        @return: false if the statement breaks the control flow (like goto, return, etc)
        """
        return _ida_hexrays.cinsn_t_is_ordinary_flow(self)

    def contains_insn(self, type: "ctype_t", times: "int"=1) -> "bool":
        r"""
        contains_insn(self, type, times=1) -> bool
        Check if the statement contains a statement of the specified type.

        @param type: (C++: ctype_t) statement opcode to look for
        @param times: (C++: int) how many times TYPE should be present
        @return: true if the statement has at least TIMES children with opcode == TYPE
        """
        return _ida_hexrays.cinsn_t_contains_insn(self, type, times)

    def collect_free_breaks(self, breaks: "cinsnptrvec_t") -> "bool":
        r"""
        collect_free_breaks(self, breaks) -> bool
        Collect free break statements. This function finds all free break statements
        within the current statement. A break statement is free if it does not have a
        loop or switch parent that that is also within the current statement.

        @param breaks: (C++: cinsnptrvec_t *) pointer to the variable where the vector of all found free break
                       statements is returned. This argument can be nullptr.
        @return: true if some free break statements have been found
        """
        return _ida_hexrays.cinsn_t_collect_free_breaks(self, breaks)

    def collect_free_continues(self, continues: "cinsnptrvec_t") -> "bool":
        r"""
        collect_free_continues(self, continues) -> bool
        Collect free continue statements. This function finds all free continue
        statements within the current statement. A continue statement is free if it does
        not have a loop parent that that is also within the current statement.

        @param continues: (C++: cinsnptrvec_t *) pointer to the variable where the vector of all found free
                          continue statements is returned. This argument can be nullptr.
        @return: true if some free continue statements have been found
        """
        return _ida_hexrays.cinsn_t_collect_free_continues(self, continues)

    def contains_free_break(self) -> "bool":
        r"""
        contains_free_break(self) -> bool
        Check if the statement has free break statements.
        """
        return _ida_hexrays.cinsn_t_contains_free_break(self)

    def contains_free_continue(self) -> "bool":
        r"""
        contains_free_continue(self) -> bool
        Check if the statement has free continue statements.
        """
        return _ida_hexrays.cinsn_t_contains_free_continue(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.cinsn_t_dstr(self)

    def _register(self) -> "void":
        r"""_register(self)"""
        return _ida_hexrays.cinsn_t__register(self)

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.cinsn_t__deregister(self)

    @staticmethod
    def insn_is_epilog(insn: "cinsn_t") -> "bool":
        r"""
        insn_is_epilog(insn) -> bool

        @param insn: cinsn_t const *
        """
        return _ida_hexrays.cinsn_t_insn_is_epilog(insn)

    def is_epilog(self):
        return cinsn_t.insn_is_epilog(self)


    def _get_cblock(self) -> "cblock_t *":
        r"""_get_cblock(self) -> cblock_t"""
        return _ida_hexrays.cinsn_t__get_cblock(self)

    def _set_cblock(self, _v: "cblock_t") -> "void":
        r"""
        _set_cblock(self, _v)

        Parameters
        ----------
        _v: cblock_t *

        """
        return _ida_hexrays.cinsn_t__set_cblock(self, _v)

    cblock = property(
            lambda self: self._get_cblock() if self.op == cit_block else None,
            lambda self, v: self._ensure_cond(self.op == cit_block,"self.op == cit_block") \
                            and self._ensure_no_obj(self._get_cblock(),"cblock", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cblock(v))
    r"""
    details of block-statement
    """


    def _get_cexpr(self) -> "cexpr_t *":
        r"""_get_cexpr(self) -> cexpr_t"""
        return _ida_hexrays.cinsn_t__get_cexpr(self)

    def _set_cexpr(self, _v: "cexpr_t") -> "void":
        r"""
        _set_cexpr(self, _v)

        Parameters
        ----------
        _v: cexpr_t *

        """
        return _ida_hexrays.cinsn_t__set_cexpr(self, _v)

    cexpr = property(
            lambda self: self._get_cexpr() if self.op == cit_expr else None,
            lambda self, v: self._ensure_cond(self.op == cit_expr,"self.op == cit_expr") \
                            and self._ensure_no_obj(self._get_cexpr(),"cexpr", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cexpr(v))
    r"""
    details of expression-statement
    """


    def _get_cif(self) -> "cif_t *":
        r"""_get_cif(self) -> cif_t"""
        return _ida_hexrays.cinsn_t__get_cif(self)

    def _set_cif(self, _v: "cif_t") -> "void":
        r"""
        _set_cif(self, _v)

        Parameters
        ----------
        _v: cif_t *

        """
        return _ida_hexrays.cinsn_t__set_cif(self, _v)

    cif = property(
            lambda self: self._get_cif() if self.op == cit_if else None,
            lambda self, v: self._ensure_cond(self.op == cit_if,"self.op == cit_if") \
                            and self._ensure_no_obj(self._get_cif(),"cif", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cif(v))
    r"""
    details of if-statement
    """


    def _get_cfor(self) -> "cfor_t *":
        r"""_get_cfor(self) -> cfor_t"""
        return _ida_hexrays.cinsn_t__get_cfor(self)

    def _set_cfor(self, _v: "cfor_t") -> "void":
        r"""
        _set_cfor(self, _v)

        Parameters
        ----------
        _v: cfor_t *

        """
        return _ida_hexrays.cinsn_t__set_cfor(self, _v)

    cfor = property(
            lambda self: self._get_cfor() if self.op == cit_for else None,
            lambda self, v: self._ensure_cond(self.op == cit_for,"self.op == cit_for") \
                            and self._ensure_no_obj(self._get_cfor(),"cfor", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cfor(v))
    r"""
    details of for-statement
    """


    def _get_cwhile(self) -> "cwhile_t *":
        r"""_get_cwhile(self) -> cwhile_t"""
        return _ida_hexrays.cinsn_t__get_cwhile(self)

    def _set_cwhile(self, _v: "cwhile_t") -> "void":
        r"""
        _set_cwhile(self, _v)

        Parameters
        ----------
        _v: cwhile_t *

        """
        return _ida_hexrays.cinsn_t__set_cwhile(self, _v)

    cwhile = property(
            lambda self: self._get_cwhile() if self.op == cit_while else None,
            lambda self, v: self._ensure_cond(self.op == cit_while,"self.op == cit_while") \
                            and self._ensure_no_obj(self._get_cwhile(),"cwhile", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cwhile(v))
    r"""
    details of while-statement
    """


    def _get_cdo(self) -> "cdo_t *":
        r"""_get_cdo(self) -> cdo_t"""
        return _ida_hexrays.cinsn_t__get_cdo(self)

    def _set_cdo(self, _v: "cdo_t") -> "void":
        r"""
        _set_cdo(self, _v)

        Parameters
        ----------
        _v: cdo_t *

        """
        return _ida_hexrays.cinsn_t__set_cdo(self, _v)

    cdo = property(
            lambda self: self._get_cdo() if self.op == cit_do else None,
            lambda self, v: self._ensure_cond(self.op == cit_do,"self.op == cit_do") \
                            and self._ensure_no_obj(self._get_cdo(),"cdo", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cdo(v))
    r"""
    details of do-statement
    """


    def _get_cswitch(self) -> "cswitch_t *":
        r"""_get_cswitch(self) -> cswitch_t"""
        return _ida_hexrays.cinsn_t__get_cswitch(self)

    def _set_cswitch(self, _v: "cswitch_t") -> "void":
        r"""
        _set_cswitch(self, _v)

        Parameters
        ----------
        _v: cswitch_t *

        """
        return _ida_hexrays.cinsn_t__set_cswitch(self, _v)

    cswitch = property(
            lambda self: self._get_cswitch() if self.op == cit_switch else None,
            lambda self, v: self._ensure_cond(self.op == cit_switch,"self.op == cit_switch") \
                            and self._ensure_no_obj(self._get_cswitch(),"cswitch", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cswitch(v))
    r"""
    details of switch-statement
    """


    def _get_creturn(self) -> "creturn_t *":
        r"""_get_creturn(self) -> creturn_t"""
        return _ida_hexrays.cinsn_t__get_creturn(self)

    def _set_creturn(self, _v: "creturn_t") -> "void":
        r"""
        _set_creturn(self, _v)

        Parameters
        ----------
        _v: creturn_t *

        """
        return _ida_hexrays.cinsn_t__set_creturn(self, _v)

    creturn = property(
            lambda self: self._get_creturn() if self.op == cit_return else None,
            lambda self, v: self._ensure_cond(self.op == cit_return,"self.op == cit_return") \
                            and self._ensure_no_obj(self._get_creturn(),"creturn", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_creturn(v))
    r"""
    details of return-statement
    """


    def _get_cgoto(self) -> "cgoto_t *":
        r"""_get_cgoto(self) -> cgoto_t"""
        return _ida_hexrays.cinsn_t__get_cgoto(self)

    def _set_cgoto(self, _v: "cgoto_t") -> "void":
        r"""
        _set_cgoto(self, _v)

        Parameters
        ----------
        _v: cgoto_t *

        """
        return _ida_hexrays.cinsn_t__set_cgoto(self, _v)

    cgoto = property(
            lambda self: self._get_cgoto() if self.op == cit_goto else None,
            lambda self, v: self._ensure_cond(self.op == cit_goto,"self.op == cit_goto") \
                            and self._ensure_no_obj(self._get_cgoto(),"cgoto", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_cgoto(v))
    r"""
    details of goto-statement
    """


    def _get_casm(self) -> "casm_t *":
        r"""_get_casm(self) -> casm_t"""
        return _ida_hexrays.cinsn_t__get_casm(self)

    def _set_casm(self, _v: "casm_t") -> "void":
        r"""
        _set_casm(self, _v)

        Parameters
        ----------
        _v: casm_t *

        """
        return _ida_hexrays.cinsn_t__set_casm(self, _v)

    casm = property(
            lambda self: self._get_casm() if self.op == cit_asm else None,
            lambda self, v: self._ensure_cond(self.op == cit_asm,"self.op == cit_asm") \
                            and self._ensure_no_obj(self._get_casm(),"casm", True) \
                            and self._acquire_ownership(v, True) \
                            and self._set_casm(v))
    r"""
    details of asm-statement
    """


# Register cinsn_t in _ida_hexrays:
_ida_hexrays.cinsn_t_swigregister(cinsn_t)
class cblock_t(cinsn_list_t):
    r"""
    Proxy of C++ cblock_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "cblock_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___eq__(self, r)

    def __ne__(self, r: "cblock_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___ne__(self, r)

    def __lt__(self, r: "cblock_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___lt__(self, r)

    def __gt__(self, r: "cblock_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___gt__(self, r)

    def __le__(self, r: "cblock_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___le__(self, r)

    def __ge__(self, r: "cblock_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t___ge__(self, r)

    def compare(self, r: "cblock_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cblock_t const &
        """
        return _ida_hexrays.cblock_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cblock_t
        """
        _ida_hexrays.cblock_t_swiginit(self, _ida_hexrays.new_cblock_t())
    __swig_destroy__ = _ida_hexrays.delete_cblock_t

    def _deregister(self) -> "void":
        r"""_deregister(self)"""
        return _ida_hexrays.cblock_t__deregister(self)

# Register cblock_t in _ida_hexrays:
_ida_hexrays.cblock_t_swigregister(cblock_t)
class carg_t(cexpr_t):
    r"""
    Proxy of C++ carg_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    is_vararg: "bool" = property(_ida_hexrays.carg_t_is_vararg_get, _ida_hexrays.carg_t_is_vararg_set, doc=r"""is_vararg""")
    r"""
    is a vararg (matches ...)
    """
    formal_type: "tinfo_t" = property(_ida_hexrays.carg_t_formal_type_get, _ida_hexrays.carg_t_formal_type_set, doc=r"""formal_type""")
    r"""
    formal parameter type (if known)
    """

    def consume_cexpr(self, e: "cexpr_t") -> "void":
        r"""
        consume_cexpr(self, e)

        @param e: cexpr_t *
        """
        return _ida_hexrays.carg_t_consume_cexpr(self, e)

    def __eq__(self, r: "carg_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___eq__(self, r)

    def __ne__(self, r: "carg_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___ne__(self, r)

    def __lt__(self, r: "carg_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___lt__(self, r)

    def __gt__(self, r: "carg_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___gt__(self, r)

    def __le__(self, r: "carg_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___le__(self, r)

    def __ge__(self, r: "carg_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t___ge__(self, r)

    def compare(self, r: "carg_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: carg_t const &
        """
        return _ida_hexrays.carg_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> carg_t
        """
        _ida_hexrays.carg_t_swiginit(self, _ida_hexrays.new_carg_t())
    __swig_destroy__ = _ida_hexrays.delete_carg_t

# Register carg_t in _ida_hexrays:
_ida_hexrays.carg_t_swigregister(carg_t)
class carglist_t(qvector_carg_t):
    r"""
    Proxy of C++ carglist_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    functype: "tinfo_t" = property(_ida_hexrays.carglist_t_functype_get, _ida_hexrays.carglist_t_functype_set, doc=r"""functype""")
    r"""
    function object type
    """
    flags: "int" = property(_ida_hexrays.carglist_t_flags_get, _ida_hexrays.carglist_t_flags_set, doc=r"""flags""")
    r"""
    call flags
    """

    def __init__(self, *args):
        r"""
        __init__(self) -> carglist_t
        __init__(self, ftype, fl=0) -> carglist_t

        @param ftype: tinfo_t const &
        @param fl: int
        """
        _ida_hexrays.carglist_t_swiginit(self, _ida_hexrays.new_carglist_t(*args))

    def __eq__(self, r: "carglist_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___eq__(self, r)

    def __ne__(self, r: "carglist_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___ne__(self, r)

    def __lt__(self, r: "carglist_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___lt__(self, r)

    def __gt__(self, r: "carglist_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___gt__(self, r)

    def __le__(self, r: "carglist_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___le__(self, r)

    def __ge__(self, r: "carglist_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t___ge__(self, r)

    def compare(self, r: "carglist_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: carglist_t const &
        """
        return _ida_hexrays.carglist_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_carglist_t

# Register carglist_t in _ida_hexrays:
_ida_hexrays.carglist_t_swigregister(carglist_t)
CFL_FINAL = _ida_hexrays.CFL_FINAL
r"""
call type is final, should not be changed
"""

CFL_HELPER = _ida_hexrays.CFL_HELPER
r"""
created from a decompiler helper function
"""

CFL_NORET = _ida_hexrays.CFL_NORET
r"""
call does not return
"""


class ccase_t(cinsn_t):
    r"""
    Proxy of C++ ccase_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    values: "uint64vec_t" = property(_ida_hexrays.ccase_t_values_get, _ida_hexrays.ccase_t_values_set, doc=r"""values""")
    r"""
    List of case values. if empty, then 'default' case
    """

    def __eq__(self, r: "ccase_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___eq__(self, r)

    def __ne__(self, r: "ccase_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___ne__(self, r)

    def __lt__(self, r: "ccase_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___lt__(self, r)

    def __gt__(self, r: "ccase_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___gt__(self, r)

    def __le__(self, r: "ccase_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___le__(self, r)

    def __ge__(self, r: "ccase_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t___ge__(self, r)

    def compare(self, r: "ccase_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ccase_t const &
        """
        return _ida_hexrays.ccase_t_compare(self, r)

    def size(self) -> "size_t":
        r"""
        size(self) -> size_t
        """
        return _ida_hexrays.ccase_t_size(self)

    def value(self, i: "int") -> "uint64 const &":
        r"""
        value(self, i) -> uint64 const &

        @param i: int
        """
        return _ida_hexrays.ccase_t_value(self, i)

    def __init__(self):
        r"""
        __init__(self) -> ccase_t
        """
        _ida_hexrays.ccase_t_swiginit(self, _ida_hexrays.new_ccase_t())
    __swig_destroy__ = _ida_hexrays.delete_ccase_t

# Register ccase_t in _ida_hexrays:
_ida_hexrays.ccase_t_swigregister(ccase_t)
class ccases_t(qvector_ccase_t):
    r"""
    Proxy of C++ ccases_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "ccases_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___eq__(self, r)

    def __ne__(self, r: "ccases_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___ne__(self, r)

    def __lt__(self, r: "ccases_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___lt__(self, r)

    def __gt__(self, r: "ccases_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___gt__(self, r)

    def __le__(self, r: "ccases_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___le__(self, r)

    def __ge__(self, r: "ccases_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t___ge__(self, r)

    def compare(self, r: "ccases_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ccases_t const &
        """
        return _ida_hexrays.ccases_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> ccases_t
        """
        _ida_hexrays.ccases_t_swiginit(self, _ida_hexrays.new_ccases_t())
    __swig_destroy__ = _ida_hexrays.delete_ccases_t

# Register ccases_t in _ida_hexrays:
_ida_hexrays.ccases_t_swigregister(ccases_t)
class cswitch_t(ceinsn_t):
    r"""
    Proxy of C++ cswitch_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    mvnf: "cnumber_t" = property(_ida_hexrays.cswitch_t_mvnf_get, _ida_hexrays.cswitch_t_mvnf_set, doc=r"""mvnf""")
    r"""
    Maximal switch value and number format.
    """
    cases: "ccases_t" = property(_ida_hexrays.cswitch_t_cases_get, _ida_hexrays.cswitch_t_cases_set, doc=r"""cases""")
    r"""
    Switch cases: values and instructions.
    """

    def __eq__(self, r: "cswitch_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___eq__(self, r)

    def __ne__(self, r: "cswitch_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___ne__(self, r)

    def __lt__(self, r: "cswitch_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___lt__(self, r)

    def __gt__(self, r: "cswitch_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___gt__(self, r)

    def __le__(self, r: "cswitch_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___le__(self, r)

    def __ge__(self, r: "cswitch_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t___ge__(self, r)

    def compare(self, r: "cswitch_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cswitch_t const &
        """
        return _ida_hexrays.cswitch_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cswitch_t
        """
        _ida_hexrays.cswitch_t_swiginit(self, _ida_hexrays.new_cswitch_t())
    __swig_destroy__ = _ida_hexrays.delete_cswitch_t

# Register cswitch_t in _ida_hexrays:
_ida_hexrays.cswitch_t_swigregister(cswitch_t)
class catchexpr_t(object):
    r"""
    Proxy of C++ catchexpr_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    obj: "cexpr_t" = property(_ida_hexrays.catchexpr_t_obj_get, _ida_hexrays.catchexpr_t_obj_set, doc=r"""obj""")
    r"""
    the caught object. if obj.op==cot_empty, no object. ideally, obj.op==cot_var
    """
    fake_type: "qstring" = property(_ida_hexrays.catchexpr_t_fake_type_get, _ida_hexrays.catchexpr_t_fake_type_set, doc=r"""fake_type""")
    r"""
    if not empty, type of the caught object. ideally, obj.type should be enough.
    however, in some cases the detailed type info is not available.
    """

    def __eq__(self, r: "catchexpr_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___eq__(self, r)

    def __ne__(self, r: "catchexpr_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___ne__(self, r)

    def __lt__(self, r: "catchexpr_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___lt__(self, r)

    def __gt__(self, r: "catchexpr_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___gt__(self, r)

    def __le__(self, r: "catchexpr_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___le__(self, r)

    def __ge__(self, r: "catchexpr_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t___ge__(self, r)

    def compare(self, r: "catchexpr_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: catchexpr_t const &
        """
        return _ida_hexrays.catchexpr_t_compare(self, r)

    def swap(self, r: "catchexpr_t") -> "void":
        r"""
        swap(self, r)

        @param r: catchexpr_t &
        """
        return _ida_hexrays.catchexpr_t_swap(self, r)

    def is_catch_all(self) -> "bool":
        r"""
        is_catch_all(self) -> bool
        """
        return _ida_hexrays.catchexpr_t_is_catch_all(self)

    def __init__(self):
        r"""
        __init__(self) -> catchexpr_t
        """
        _ida_hexrays.catchexpr_t_swiginit(self, _ida_hexrays.new_catchexpr_t())
    __swig_destroy__ = _ida_hexrays.delete_catchexpr_t

# Register catchexpr_t in _ida_hexrays:
_ida_hexrays.catchexpr_t_swigregister(catchexpr_t)
class ccatch_t(cblock_t):
    r"""
    Proxy of C++ ccatch_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    exprs: "catchexprs_t" = property(_ida_hexrays.ccatch_t_exprs_get, _ida_hexrays.ccatch_t_exprs_set, doc=r"""exprs""")

    def __eq__(self, r: "ccatch_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___eq__(self, r)

    def __ne__(self, r: "ccatch_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___ne__(self, r)

    def __lt__(self, r: "ccatch_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___lt__(self, r)

    def __gt__(self, r: "ccatch_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___gt__(self, r)

    def __le__(self, r: "ccatch_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___le__(self, r)

    def __ge__(self, r: "ccatch_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t___ge__(self, r)

    def compare(self, r: "ccatch_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ccatch_t const &
        """
        return _ida_hexrays.ccatch_t_compare(self, r)

    def is_catch_all(self) -> "bool":
        r"""
        is_catch_all(self) -> bool
        """
        return _ida_hexrays.ccatch_t_is_catch_all(self)

    def swap(self, r: "ccatch_t") -> "void":
        r"""
        swap(self, r)

        @param r: ccatch_t &
        """
        return _ida_hexrays.ccatch_t_swap(self, r)
    __swig_destroy__ = _ida_hexrays.delete_ccatch_t

# Register ccatch_t in _ida_hexrays:
_ida_hexrays.ccatch_t_swigregister(ccatch_t)
class ctry_t(cblock_t):
    r"""
    Proxy of C++ ctry_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    catchs: "ccatchvec_t" = property(_ida_hexrays.ctry_t_catchs_get, _ida_hexrays.ctry_t_catchs_set, doc=r"""catchs""")
    r"""
    "catch all", if present, must be the last element. wind-statements must have
    "catch all" and nothing else.
    """
    old_state: "size_t" = property(_ida_hexrays.ctry_t_old_state_get, _ida_hexrays.ctry_t_old_state_set, doc=r"""old_state""")
    r"""
    old state number (internal, MSVC related)
    """
    new_state: "size_t" = property(_ida_hexrays.ctry_t_new_state_get, _ida_hexrays.ctry_t_new_state_set, doc=r"""new_state""")
    r"""
    new state number (internal, MSVC related)
    """
    is_wind: "bool" = property(_ida_hexrays.ctry_t_is_wind_get, _ida_hexrays.ctry_t_is_wind_set, doc=r"""is_wind""")
    r"""
    Is C++ wind statement? (not part of the C++ language) MSVC generates code like
    the following to keep track of constructed objects and destroy them upon an
    exception. Example:

    /* an object is constructed at this point *
    / __wind { /* some other code that may throw an exception *
    / } __unwind { /* this code is executed only if there was an exception *
    / /* in the __wind block. normally here we destroy the object *
    / *
    / after that the exception is passed to the *
    / /* exception handler, regular control flow is interrupted here. *
    / } /* regular logic continues here, if there were no exceptions *
    / /* also the object's destructor is called *
    /
    """

    def __eq__(self, r: "ctry_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___eq__(self, r)

    def __ne__(self, r: "ctry_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___ne__(self, r)

    def __lt__(self, r: "ctry_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___lt__(self, r)

    def __gt__(self, r: "ctry_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___gt__(self, r)

    def __le__(self, r: "ctry_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___le__(self, r)

    def __ge__(self, r: "ctry_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t___ge__(self, r)

    def compare(self, r: "ctry_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ctry_t const &
        """
        return _ida_hexrays.ctry_t_compare(self, r)
    __swig_destroy__ = _ida_hexrays.delete_ctry_t

# Register ctry_t in _ida_hexrays:
_ida_hexrays.ctry_t_swigregister(ctry_t)
class cthrow_t(ceinsn_t):
    r"""
    Proxy of C++ cthrow_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __eq__(self, r: "cthrow_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___eq__(self, r)

    def __ne__(self, r: "cthrow_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___ne__(self, r)

    def __lt__(self, r: "cthrow_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___lt__(self, r)

    def __gt__(self, r: "cthrow_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___gt__(self, r)

    def __le__(self, r: "cthrow_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___le__(self, r)

    def __ge__(self, r: "cthrow_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t___ge__(self, r)

    def compare(self, r: "cthrow_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: cthrow_t const &
        """
        return _ida_hexrays.cthrow_t_compare(self, r)

    def __init__(self):
        r"""
        __init__(self) -> cthrow_t
        """
        _ida_hexrays.cthrow_t_swiginit(self, _ida_hexrays.new_cthrow_t())
    __swig_destroy__ = _ida_hexrays.delete_cthrow_t

# Register cthrow_t in _ida_hexrays:
_ida_hexrays.cthrow_t_swigregister(cthrow_t)
class cblock_pos_t(object):
    r"""
    Proxy of C++ cblock_pos_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    blk: "cblock_t *" = property(_ida_hexrays.cblock_pos_t_blk_get, _ida_hexrays.cblock_pos_t_blk_set, doc=r"""blk""")
    p: "cblock_t::iterator" = property(_ida_hexrays.cblock_pos_t_p_get, _ida_hexrays.cblock_pos_t_p_set, doc=r"""p""")

    def is_first_insn(self) -> "bool":
        r"""
        is_first_insn(self) -> bool
        """
        return _ida_hexrays.cblock_pos_t_is_first_insn(self)

    def insn(self) -> "cinsn_t *":
        r"""
        insn(self) -> cinsn_t
        """
        return _ida_hexrays.cblock_pos_t_insn(self)

    def prev_insn(self) -> "cinsn_t *":
        r"""
        prev_insn(self) -> cinsn_t
        """
        return _ida_hexrays.cblock_pos_t_prev_insn(self)

    def __init__(self):
        r"""
        __init__(self) -> cblock_pos_t
        """
        _ida_hexrays.cblock_pos_t_swiginit(self, _ida_hexrays.new_cblock_pos_t())
    __swig_destroy__ = _ida_hexrays.delete_cblock_pos_t

# Register cblock_pos_t in _ida_hexrays:
_ida_hexrays.cblock_pos_t_swigregister(cblock_pos_t)
class ctree_visitor_t(object):
    r"""
    Proxy of C++ ctree_visitor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    cv_flags: "int" = property(_ida_hexrays.ctree_visitor_t_cv_flags_get, _ida_hexrays.ctree_visitor_t_cv_flags_set, doc=r"""cv_flags""")
    r"""
    Ctree visitor property bits
    """

    def maintain_parents(self) -> "bool":
        r"""
        maintain_parents(self) -> bool
        Should the parent information by maintained?
        """
        return _ida_hexrays.ctree_visitor_t_maintain_parents(self)

    def must_prune(self) -> "bool":
        r"""
        must_prune(self) -> bool
        Should the traversal skip the children of the current item?
        """
        return _ida_hexrays.ctree_visitor_t_must_prune(self)

    def must_restart(self) -> "bool":
        r"""
        must_restart(self) -> bool
        Should the traversal restart?
        """
        return _ida_hexrays.ctree_visitor_t_must_restart(self)

    def is_postorder(self) -> "bool":
        r"""
        is_postorder(self) -> bool
        Should the leave...() functions be called?
        """
        return _ida_hexrays.ctree_visitor_t_is_postorder(self)

    def only_insns(self) -> "bool":
        r"""
        only_insns(self) -> bool
        Should all expressions be automatically pruned?
        """
        return _ida_hexrays.ctree_visitor_t_only_insns(self)

    def prune_now(self) -> "void":
        r"""
        prune_now(self)
        Prune children. This function may be called by a visitor() to skip all children
        of the current item.
        """
        return _ida_hexrays.ctree_visitor_t_prune_now(self)

    def clr_prune(self) -> "void":
        r"""
        clr_prune(self)
        Do not prune children. This is an internal function, no need to call it.
        """
        return _ida_hexrays.ctree_visitor_t_clr_prune(self)

    def set_restart(self) -> "void":
        r"""
        set_restart(self)
        Restart the travesal. Meaningful only in apply_to_exprs()
        """
        return _ida_hexrays.ctree_visitor_t_set_restart(self)

    def clr_restart(self) -> "void":
        r"""
        clr_restart(self)
        Do not restart. This is an internal function, no need to call it.
        """
        return _ida_hexrays.ctree_visitor_t_clr_restart(self)
    parents: "parents_t" = property(_ida_hexrays.ctree_visitor_t_parents_get, _ida_hexrays.ctree_visitor_t_parents_set, doc=r"""parents""")
    r"""
    Vector of parents of the current item.
    """
    bposvec: "cblock_posvec_t" = property(_ida_hexrays.ctree_visitor_t_bposvec_get, _ida_hexrays.ctree_visitor_t_bposvec_set, doc=r"""bposvec""")
    r"""
    Vector of block positions. Only cit_block and cit_try parents have the
    corresponding element in this vector.
    """

    def __init__(self, _flags: "int"):
        r"""
        __init__(self, _flags) -> ctree_visitor_t

        @param _flags: int
        """
        if self.__class__ == ctree_visitor_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.ctree_visitor_t_swiginit(self, _ida_hexrays.new_ctree_visitor_t(_self, _flags))
    __swig_destroy__ = _ida_hexrays.delete_ctree_visitor_t

    def apply_to(self, item: "citem_t", parent: "citem_t") -> "int":
        r"""
        apply_to(self, item, parent) -> int
        Traverse ctree. The traversal will start at the specified item and continue
        until of one the visit_...() functions return a non-zero value.

        @param item: (C++: citem_t *) root of the ctree to traverse
        @param parent: (C++: citem_t *) parent of the specified item. can be specified as nullptr.
        @return: 0 or a non-zero value returned by a visit_...() function
        """
        return _ida_hexrays.ctree_visitor_t_apply_to(self, item, parent)

    def apply_to_exprs(self, item: "citem_t", parent: "citem_t") -> "int":
        r"""
        apply_to_exprs(self, item, parent) -> int
        Traverse only expressions. The traversal will start at the specified item and
        continue until of one the visit_...() functions return a non-zero value.

        @param item: (C++: citem_t *) root of the ctree to traverse
        @param parent: (C++: citem_t *) parent of the specified item. can be specified as nullptr.
        @return: 0 or a non-zero value returned by a visit_...() function
        """
        return _ida_hexrays.ctree_visitor_t_apply_to_exprs(self, item, parent)

    def parent_expr(self) -> "cexpr_t *":
        r"""
        parent_expr(self) -> cexpr_t
        Get parent of the current item as an expression.
        """
        return _ida_hexrays.ctree_visitor_t_parent_expr(self)

    def parent_insn(self) -> "cinsn_t *":
        r"""
        parent_insn(self) -> cinsn_t
        Get parent of the current item as a statement.
        """
        return _ida_hexrays.ctree_visitor_t_parent_insn(self)

    def visit_insn(self, arg0: "cinsn_t") -> "int":
        r"""
        visit_insn(self, arg0) -> int
        Visit a statement. This is a visitor function which should be overridden by a
        derived class to do some useful work. This visitor performs pre-order traserval,
        i.e. an item is visited before its children.

        @param arg0: cinsn_t *
        @return: 0 to continue the traversal, nonzero to stop.
        """
        return _ida_hexrays.ctree_visitor_t_visit_insn(self, arg0)

    def visit_expr(self, arg0: "cexpr_t") -> "int":
        r"""
        visit_expr(self, arg0) -> int
        Visit an expression. This is a visitor function which should be overridden by a
        derived class to do some useful work. This visitor performs pre-order traserval,
        i.e. an item is visited before its children.

        @param arg0: cexpr_t *
        @return: 0 to continue the traversal, nonzero to stop.
        """
        return _ida_hexrays.ctree_visitor_t_visit_expr(self, arg0)

    def leave_insn(self, arg0: "cinsn_t") -> "int":
        r"""
        leave_insn(self, arg0) -> int
        Visit a statement after having visited its children. This is a visitor function
        which should be overridden by a derived class to do some useful work. This
        visitor performs post-order traserval, i.e. an item is visited after its
        children.

        @param arg0: cinsn_t *
        @return: 0 to continue the traversal, nonzero to stop.
        """
        return _ida_hexrays.ctree_visitor_t_leave_insn(self, arg0)

    def leave_expr(self, arg0: "cexpr_t") -> "int":
        r"""
        leave_expr(self, arg0) -> int
        Visit an expression after having visited its children. This is a visitor
        function which should be overridden by a derived class to do some useful work.
        This visitor performs post-order traserval, i.e. an item is visited after its
        children.

        @param arg0: cexpr_t *
        @return: 0 to continue the traversal, nonzero to stop.
        """
        return _ida_hexrays.ctree_visitor_t_leave_expr(self, arg0)
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_ctree_visitor_t(self)
        return weakref.proxy(self)

# Register ctree_visitor_t in _ida_hexrays:
_ida_hexrays.ctree_visitor_t_swigregister(ctree_visitor_t)
CV_FAST = _ida_hexrays.CV_FAST
r"""
do not maintain parent information
"""

CV_PRUNE = _ida_hexrays.CV_PRUNE
r"""
this bit is set by visit...() to prune the walk
"""

CV_PARENTS = _ida_hexrays.CV_PARENTS
r"""
maintain parent information
"""

CV_POST = _ida_hexrays.CV_POST
r"""
call the leave...() functions
"""

CV_RESTART = _ida_hexrays.CV_RESTART
r"""
restart enumeration at the top expr (apply_to_exprs)
"""

CV_INSNS = _ida_hexrays.CV_INSNS
r"""
visit only statements, prune all expressions do not use before the final ctree
maturity because expressions may contain statements at intermediate stages (see
cot_insn). Otherwise you risk missing statements embedded into expressions.
"""


class ctree_parentee_t(ctree_visitor_t):
    r"""
    Proxy of C++ ctree_parentee_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, post: "bool"=False):
        r"""
        __init__(self, post=False) -> ctree_parentee_t

        @param post: bool
        """
        if self.__class__ == ctree_parentee_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.ctree_parentee_t_swiginit(self, _ida_hexrays.new_ctree_parentee_t(_self, post))

    def recalc_parent_types(self) -> "bool":
        r"""
        recalc_parent_types(self) -> bool
        Recalculate type of parent nodes. If a node type has been changed, the visitor
        must recalculate all parent types, otherwise the ctree becomes inconsistent. If
        during this recalculation a parent node is added/deleted, this function returns
        true. In this case the traversal must be stopped because the information about
        parent nodes is stale.

        @return: false-ok to continue the traversal, true-must stop.
        """
        return _ida_hexrays.ctree_parentee_t_recalc_parent_types(self)
    __swig_destroy__ = _ida_hexrays.delete_ctree_parentee_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_ctree_parentee_t(self)
        return weakref.proxy(self)

# Register ctree_parentee_t in _ida_hexrays:
_ida_hexrays.ctree_parentee_t_swigregister(ctree_parentee_t)
class cfunc_parentee_t(ctree_parentee_t):
    r"""
    Proxy of C++ cfunc_parentee_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    func: "cfunc_t *" = property(_ida_hexrays.cfunc_parentee_t_func_get, _ida_hexrays.cfunc_parentee_t_func_set, doc=r"""func""")
    r"""
    Pointer to current function.
    """

    def __init__(self, f: "cfunc_t", post: "bool"=False):
        r"""
        __init__(self, f, post=False) -> cfunc_parentee_t

        @param f: cfunc_t *
        @param post: bool
        """
        if self.__class__ == cfunc_parentee_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.cfunc_parentee_t_swiginit(self, _ida_hexrays.new_cfunc_parentee_t(_self, f, post))

    def calc_rvalue_type(self, target: "tinfo_t", e: "cexpr_t") -> "bool":
        r"""
        calc_rvalue_type(self, target, e) -> bool
        Calculate rvalue type. This function tries to determine the type of the
        specified item based on its context. For example, if the current expression is
        the right side of an assignment operator, the type of its left side will be
        returned. This function can be used to determine the 'best' type of the
        specified expression.

        @param target: (C++: tinfo_t *) 'best' type of the expression will be returned here
        @param e: (C++: const cexpr_t *) expression to determine the desired type
        @return: false if failed
        """
        return _ida_hexrays.cfunc_parentee_t_calc_rvalue_type(self, target, e)
    __swig_destroy__ = _ida_hexrays.delete_cfunc_parentee_t
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_cfunc_parentee_t(self)
        return weakref.proxy(self)

# Register cfunc_parentee_t in _ida_hexrays:
_ida_hexrays.cfunc_parentee_t_swigregister(cfunc_parentee_t)
class ctree_anchor_t(object):
    r"""
    Proxy of C++ ctree_anchor_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    value: "uval_t" = property(_ida_hexrays.ctree_anchor_t_value_get, _ida_hexrays.ctree_anchor_t_value_set, doc=r"""value""")

    def get_index(self) -> "int":
        r"""
        get_index(self) -> int
        """
        return _ida_hexrays.ctree_anchor_t_get_index(self)

    def get_itp(self) -> "item_preciser_t":
        r"""
        get_itp(self) -> item_preciser_t
        """
        return _ida_hexrays.ctree_anchor_t_get_itp(self)

    def is_valid_anchor(self) -> "bool":
        r"""
        is_valid_anchor(self) -> bool
        """
        return _ida_hexrays.ctree_anchor_t_is_valid_anchor(self)

    def is_citem_anchor(self) -> "bool":
        r"""
        is_citem_anchor(self) -> bool
        """
        return _ida_hexrays.ctree_anchor_t_is_citem_anchor(self)

    def is_lvar_anchor(self) -> "bool":
        r"""
        is_lvar_anchor(self) -> bool
        """
        return _ida_hexrays.ctree_anchor_t_is_lvar_anchor(self)

    def is_itp_anchor(self) -> "bool":
        r"""
        is_itp_anchor(self) -> bool
        """
        return _ida_hexrays.ctree_anchor_t_is_itp_anchor(self)

    def is_blkcmt_anchor(self) -> "bool":
        r"""
        is_blkcmt_anchor(self) -> bool
        """
        return _ida_hexrays.ctree_anchor_t_is_blkcmt_anchor(self)

    def __init__(self):
        r"""
        __init__(self) -> ctree_anchor_t
        """
        _ida_hexrays.ctree_anchor_t_swiginit(self, _ida_hexrays.new_ctree_anchor_t())
    __swig_destroy__ = _ida_hexrays.delete_ctree_anchor_t

# Register ctree_anchor_t in _ida_hexrays:
_ida_hexrays.ctree_anchor_t_swigregister(ctree_anchor_t)
ANCHOR_INDEX = _ida_hexrays.ANCHOR_INDEX

ANCHOR_MASK = _ida_hexrays.ANCHOR_MASK

ANCHOR_CITEM = _ida_hexrays.ANCHOR_CITEM
r"""
c-tree item
"""

ANCHOR_LVAR = _ida_hexrays.ANCHOR_LVAR
r"""
declaration of local variable
"""

ANCHOR_ITP = _ida_hexrays.ANCHOR_ITP
r"""
item type preciser
"""

ANCHOR_BLKCMT = _ida_hexrays.ANCHOR_BLKCMT
r"""
block comment (for ctree items)
"""


VDI_NONE = _ida_hexrays.VDI_NONE
r"""
undefined
"""

VDI_EXPR = _ida_hexrays.VDI_EXPR
r"""
c-tree item
"""

VDI_LVAR = _ida_hexrays.VDI_LVAR
r"""
declaration of local variable
"""

VDI_FUNC = _ida_hexrays.VDI_FUNC
r"""
the function itself (the very first line with the function prototype)
"""

VDI_TAIL = _ida_hexrays.VDI_TAIL
r"""
cursor is at (beyond) the line end (commentable line)
"""

class ctree_item_t(object):
    r"""
    Proxy of C++ ctree_item_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    citype: "cursor_item_type_t" = property(_ida_hexrays.ctree_item_t_citype_get, _ida_hexrays.ctree_item_t_citype_set, doc=r"""citype""")
    r"""
    Item type.
    """
    it: "citem_t *" = property(_ida_hexrays.ctree_item_t_it_get, _ida_hexrays.ctree_item_t_it_set, doc=r"""it""")
    e: "cexpr_t *" = property(_ida_hexrays.ctree_item_t_e_get, _ida_hexrays.ctree_item_t_e_set, doc=r"""e""")
    r"""
    VDI_EXPR: Expression.
    """
    i: "cinsn_t *" = property(_ida_hexrays.ctree_item_t_i_get, _ida_hexrays.ctree_item_t_i_set, doc=r"""i""")
    r"""
    VDI_EXPR: Statement.
    """
    l: "lvar_t *" = property(_ida_hexrays.ctree_item_t_l_get, _ida_hexrays.ctree_item_t_l_set, doc=r"""l""")
    r"""
    VDI_LVAR: Local variable.
    """
    f: "cfunc_t *" = property(_ida_hexrays.ctree_item_t_f_get, _ida_hexrays.ctree_item_t_f_set, doc=r"""f""")
    r"""
    VDI_FUNC: Function.
    """

    def get_udm(self, udm: "udm_t"=None, parent: "tinfo_t"=None, p_offset: "uint64 *"=None) -> "int":
        r"""
        get_udm(self, udm=None, parent=None, p_offset=None) -> int
        Get type of a structure field. If the current item is a structure/union field,
        this function will return information about it.

        @param udm: (C++: udm_t *) pointer to buffer for the udt member info.
        @param parent: (C++: tinfo_t *) pointer to buffer for the struct/union type.
        @param p_offset: (C++: uint64 *) pointer to the offset in bits inside udt.
        @return: member index or -1 if failed Both output parameters can be nullptr.
        """
        return _ida_hexrays.ctree_item_t_get_udm(self, udm, parent, p_offset)

    def get_edm(self, parent: "tinfo_t") -> "int":
        r"""
        get_edm(self, parent) -> int
        Get type of an enum member. If the current item is a symbolic constant, this
        function will return information about it.

        @param parent: (C++: tinfo_t *) pointer to buffer for the enum type.
        @return: member index or -1 if failed
        """
        return _ida_hexrays.ctree_item_t_get_edm(self, parent)

    def get_lvar(self) -> "lvar_t *":
        r"""
        get_lvar(self) -> lvar_t
        Get pointer to local variable. If the current item is a local variable, this
        function will return pointer to its definition.

        @return: nullptr if failed
        """
        return _ida_hexrays.ctree_item_t_get_lvar(self)

    def get_ea(self) -> "ea_t":
        r"""
        get_ea(self) -> ea_t
        Get address of the current item. Each ctree item has an address.

        @return: BADADDR if failed
        """
        return _ida_hexrays.ctree_item_t_get_ea(self)

    def get_label_num(self, gln_flags: "int") -> "int":
        r"""
        get_label_num(self, gln_flags) -> int
        Get label number of the current item.

        @param gln_flags: (C++: int) Combination of get_label_num control bits
        @return: -1 if failed or no label
        """
        return _ida_hexrays.ctree_item_t_get_label_num(self, gln_flags)

    def is_citem(self) -> "bool":
        r"""
        is_citem(self) -> bool
        Is the current item is a ctree item?
        """
        return _ida_hexrays.ctree_item_t_is_citem(self)

    def _print(self) -> "void":
        r"""_print(self)"""
        return _ida_hexrays.ctree_item_t__print(self)

    def dstr(self) -> "char const *":
        r"""
        dstr(self) -> char const *
        """
        return _ida_hexrays.ctree_item_t_dstr(self)

    def _get_it(self) -> "citem_t *":
        r"""_get_it(self) -> citem_t"""
        return _ida_hexrays.ctree_item_t__get_it(self)
    it = property(lambda self: self._get_it())

    def _get_e(self) -> "cexpr_t *":
        r"""_get_e(self) -> cexpr_t"""
        return _ida_hexrays.ctree_item_t__get_e(self)
    e = property(lambda self: self._get_e())

    def _get_i(self) -> "cinsn_t *":
        r"""_get_i(self) -> cinsn_t"""
        return _ida_hexrays.ctree_item_t__get_i(self)
    i = property(lambda self: self._get_i())

    def _get_l(self) -> "lvar_t *":
        r"""_get_l(self) -> lvar_t"""
        return _ida_hexrays.ctree_item_t__get_l(self)
    l = property(lambda self: self._get_l())

    def _get_f(self) -> "cfunc_t *":
        r"""_get_f(self) -> cfunc_t"""
        return _ida_hexrays.ctree_item_t__get_f(self)
    f = property(lambda self: self._get_f())
    loc: "treeloc_t *const" = property(_ida_hexrays.ctree_item_t_loc_get, doc=r"""loc""")
    r"""
    VDI_TAIL: Line tail.
    """

    def __init__(self):
        r"""
        __init__(self) -> ctree_item_t
        """
        _ida_hexrays.ctree_item_t_swiginit(self, _ida_hexrays.new_ctree_item_t())
    __swig_destroy__ = _ida_hexrays.delete_ctree_item_t

# Register ctree_item_t in _ida_hexrays:
_ida_hexrays.ctree_item_t_swigregister(ctree_item_t)
GLN_CURRENT = _ida_hexrays.GLN_CURRENT
r"""
get label of the current item
"""

GLN_GOTO_TARGET = _ida_hexrays.GLN_GOTO_TARGET
r"""
get goto target
"""

GLN_ALL = _ida_hexrays.GLN_ALL
r"""
get both
"""


FORBID_UNUSED_LABELS = _ida_hexrays.FORBID_UNUSED_LABELS
r"""
Unused labels cause interr.
"""

ALLOW_UNUSED_LABELS = _ida_hexrays.ALLOW_UNUSED_LABELS
r"""
Unused labels are permitted.
"""


def _ll_lnot(e: "cexpr_t") -> "cexpr_t *":
    r"""
    _ll_lnot(e) -> cexpr_t

    Parameters
    ----------
    e: cexpr_t *

    """
    return _ida_hexrays._ll_lnot(e)

def _ll_new_block() -> "cinsn_t *":
    r"""_ll_new_block() -> cinsn_t"""
    return _ida_hexrays._ll_new_block()

def _ll_create_helper(*args) -> "cexpr_t *":
    r"""
    _ll_create_helper(standalone, type, format) -> cexpr_t

    Parameters
    ----------
    standalone: bool
    type: tinfo_t const &
    format: char const *

    """
    return _ida_hexrays._ll_create_helper(*args)

def _ll_call_helper(*args) -> "cexpr_t *":
    r"""
    _ll_call_helper(rettype, args, format) -> cexpr_t

    Parameters
    ----------
    rettype: tinfo_t const &
    args: carglist_t *
    format: char const *

    """
    return _ida_hexrays._ll_call_helper(*args)

def _ll_make_num(*args) -> "cexpr_t *":
    r"""
    _ll_make_num(n, func=None, ea=BADADDR, opnum=0, sign=no_sign, size=0) -> cexpr_t

    Parameters
    ----------
    n: uint64
    func: cfunc_t *
    ea: ea_t
    opnum: int
    sign: type_sign_t
    size: int

    """
    return _ida_hexrays._ll_make_num(*args)

def _ll_make_ref(e: "cexpr_t") -> "cexpr_t *":
    r"""
    _ll_make_ref(e) -> cexpr_t

    Parameters
    ----------
    e: cexpr_t *

    """
    return _ida_hexrays._ll_make_ref(e)

def _ll_dereference(e: "cexpr_t", ptrsize: "int", is_flt: "bool"=False) -> "cexpr_t *":
    r"""
    _ll_dereference(e, ptrsize, is_flt=False) -> cexpr_t

    Parameters
    ----------
    e: cexpr_t *
    ptrsize: int
    is_flt: bool

    """
    return _ida_hexrays._ll_dereference(e, ptrsize, is_flt)

def save_user_labels(func_ea: "ea_t", user_labels: "user_labels_t", func: "cfunc_t"=None) -> "void":
    r"""
    save_user_labels(func_ea, user_labels, func=None)
    Save user defined labels into the database.

    @param func_ea: (C++: ea_t) the entry address of the function, ignored if FUNC != nullptr
    @param user_labels: (C++: const user_labels_t *) collection of user defined labels
    @param func: (C++: const cfunc_t *) pointer to current function, if FUNC != nullptr, then save labels
                 using a more stable method that preserves them even when the
                 decompiler output drastically changes
    """
    return _ida_hexrays.save_user_labels(func_ea, user_labels, func)

def save_user_cmts(func_ea: "ea_t", user_cmts: "user_cmts_t") -> "void":
    r"""
    save_user_cmts(func_ea, user_cmts)
    Save user defined comments into the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @param user_cmts: (C++: const user_cmts_t *) collection of user defined comments
    """
    return _ida_hexrays.save_user_cmts(func_ea, user_cmts)

def save_user_numforms(func_ea: "ea_t", numforms: "user_numforms_t") -> "void":
    r"""
    save_user_numforms(func_ea, numforms)
    Save user defined number formats into the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @param numforms: (C++: const user_numforms_t *) collection of user defined comments
    """
    return _ida_hexrays.save_user_numforms(func_ea, numforms)

def save_user_iflags(func_ea: "ea_t", iflags: "user_iflags_t") -> "void":
    r"""
    save_user_iflags(func_ea, iflags)
    Save user defined citem iflags into the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @param iflags: (C++: const user_iflags_t *) collection of user defined citem iflags
    """
    return _ida_hexrays.save_user_iflags(func_ea, iflags)

def save_user_unions(func_ea: "ea_t", unions: "user_unions_t") -> "void":
    r"""
    save_user_unions(func_ea, unions)
    Save user defined union field selections into the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @param unions: (C++: const user_unions_t *) collection of union field selections
    """
    return _ida_hexrays.save_user_unions(func_ea, unions)

def restore_user_labels(func_ea: "ea_t", func: "cfunc_t"=None) -> "user_labels_t *":
    r"""
    restore_user_labels(func_ea, func=None) -> user_labels_t
    Restore user defined labels from the database.

    @param func_ea: (C++: ea_t) the entry address of the function, ignored if FUNC != nullptr
    @param func: (C++: const cfunc_t *) pointer to current function
    @return: collection of user defined labels. The returned object must be deleted
             by the caller using delete_user_labels()
    """
    return _ida_hexrays.restore_user_labels(func_ea, func)

def restore_user_cmts(func_ea: "ea_t") -> "user_cmts_t *":
    r"""
    restore_user_cmts(func_ea) -> user_cmts_t
    Restore user defined comments from the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @return: collection of user defined comments. The returned object must be
             deleted by the caller using delete_user_cmts()
    """
    return _ida_hexrays.restore_user_cmts(func_ea)

def restore_user_numforms(func_ea: "ea_t") -> "user_numforms_t *":
    r"""
    restore_user_numforms(func_ea) -> user_numforms_t
    Restore user defined number formats from the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @return: collection of user defined number formats. The returned object must be
             deleted by the caller using delete_user_numforms()
    """
    return _ida_hexrays.restore_user_numforms(func_ea)

def restore_user_iflags(func_ea: "ea_t") -> "user_iflags_t *":
    r"""
    restore_user_iflags(func_ea) -> user_iflags_t
    Restore user defined citem iflags from the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @return: collection of user defined iflags. The returned object must be deleted
             by the caller using delete_user_iflags()
    """
    return _ida_hexrays.restore_user_iflags(func_ea)

def restore_user_unions(func_ea: "ea_t") -> "user_unions_t *":
    r"""
    restore_user_unions(func_ea) -> user_unions_t
    Restore user defined union field selections from the database.

    @param func_ea: (C++: ea_t) the entry address of the function
    @return: collection of union field selections The returned object must be
             deleted by the caller using delete_user_unions()
    """
    return _ida_hexrays.restore_user_unions(func_ea)
class cfunc_t(object):
    r"""
    Proxy of C++ cfunc_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    entry_ea: "ea_t" = property(_ida_hexrays.cfunc_t_entry_ea_get, _ida_hexrays.cfunc_t_entry_ea_set, doc=r"""entry_ea""")
    r"""
    function entry address
    """
    mba: "mba_t *" = property(_ida_hexrays.cfunc_t_mba_get, _ida_hexrays.cfunc_t_mba_set, doc=r"""mba""")
    r"""
    underlying microcode
    """
    body: "cinsn_t" = property(_ida_hexrays.cfunc_t_body_get, _ida_hexrays.cfunc_t_body_set, doc=r"""body""")
    r"""
    function body, must be a block
    """
    argidx: "intvec_t &" = property(_ida_hexrays.cfunc_t_argidx_get, doc=r"""argidx""")
    r"""
    list of arguments (indexes into vars)
    """
    maturity: "ctree_maturity_t" = property(_ida_hexrays.cfunc_t_maturity_get, _ida_hexrays.cfunc_t_maturity_set, doc=r"""maturity""")
    r"""
    maturity level
    """
    user_labels: "user_labels_t *" = property(_ida_hexrays.cfunc_t_user_labels_get, _ida_hexrays.cfunc_t_user_labels_set, doc=r"""user_labels""")
    r"""
    user-defined labels.
    """
    user_cmts: "user_cmts_t *" = property(_ida_hexrays.cfunc_t_user_cmts_get, _ida_hexrays.cfunc_t_user_cmts_set, doc=r"""user_cmts""")
    r"""
    user-defined comments.
    """
    numforms: "user_numforms_t *" = property(_ida_hexrays.cfunc_t_numforms_get, _ida_hexrays.cfunc_t_numforms_set, doc=r"""numforms""")
    r"""
    user-defined number formats.
    """
    user_iflags: "user_iflags_t *" = property(_ida_hexrays.cfunc_t_user_iflags_get, _ida_hexrays.cfunc_t_user_iflags_set, doc=r"""user_iflags""")
    r"""
    user-defined item flags ctree item iflags bits
    """
    user_unions: "user_unions_t *" = property(_ida_hexrays.cfunc_t_user_unions_get, _ida_hexrays.cfunc_t_user_unions_set, doc=r"""user_unions""")
    r"""
    user-defined union field selections.
    """
    refcnt: "int" = property(_ida_hexrays.cfunc_t_refcnt_get, _ida_hexrays.cfunc_t_refcnt_set, doc=r"""refcnt""")
    r"""
    reference count to this object. use cfuncptr_t
    """
    statebits: "int" = property(_ida_hexrays.cfunc_t_statebits_get, _ida_hexrays.cfunc_t_statebits_set, doc=r"""statebits""")
    r"""
    current cfunc_t state. see cfunc state bits
    """
    hdrlines: "int" = property(_ida_hexrays.cfunc_t_hdrlines_get, _ida_hexrays.cfunc_t_hdrlines_set, doc=r"""hdrlines""")
    r"""
    number of lines in the declaration area
    """
    treeitems: "citem_pointers_t" = property(_ida_hexrays.cfunc_t_treeitems_get, _ida_hexrays.cfunc_t_treeitems_set, doc=r"""treeitems""")
    r"""
    vector of pointers to citem_t objects (nodes constituting the ctree)
    """
    __swig_destroy__ = _ida_hexrays.delete_cfunc_t

    def release(self) -> "void":
        r"""
        release(self)
        """
        return _ida_hexrays.cfunc_t_release(self)

    def build_c_tree(self) -> "void":
        r"""
        build_c_tree(self)
        Generate the function body. This function (re)generates the function body from
        the underlying microcode.
        """
        return _ida_hexrays.cfunc_t_build_c_tree(self)

    def verify(self, aul: "allow_unused_labels_t", even_without_debugger: "bool") -> "void":
        r"""
        verify(self, aul, even_without_debugger)
        Verify the ctree. This function verifies the ctree. If the ctree is malformed,
        an internal error is generated. Use it to verify the ctree after your
        modifications.

        @param aul: (C++: allow_unused_labels_t) Are unused labels acceptable?
        @param even_without_debugger: (C++: bool) if false and there is no debugger, the
                                      verification will be skipped
        """
        return _ida_hexrays.cfunc_t_verify(self, aul, even_without_debugger)

    def print_dcl(self) -> "void":
        r"""
        print_dcl(self)
        Print function prototype.
        """
        return _ida_hexrays.cfunc_t_print_dcl(self)

    def print_func(self, vp: "vc_printer_t") -> "void":
        r"""
        print_func(self, vp)
        Print function text.

        @param vp: (C++: vc_printer_t &) printer helper class to receive the generated text.
        """
        return _ida_hexrays.cfunc_t_print_func(self, vp)

    def get_func_type(self, type: "tinfo_t") -> "bool":
        r"""
        get_func_type(self, type) -> bool
        Get the function type.

        @param type: (C++: tinfo_t *) variable where the function type is returned
        @return: false if failure
        """
        return _ida_hexrays.cfunc_t_get_func_type(self, type)

    def get_lvars(self) -> "lvars_t *":
        r"""
        get_lvars(self) -> lvars_t
        Get vector of local variables.

        @return: pointer to the vector of local variables. If you modify this vector,
                 the ctree must be regenerated in order to have correct cast operators.
                 Use build_c_tree() for that. Removing lvars should be done carefully:
                 all references in ctree and microcode must be corrected after that.
        """
        return _ida_hexrays.cfunc_t_get_lvars(self)

    def get_stkoff_delta(self) -> "sval_t":
        r"""
        get_stkoff_delta(self) -> sval_t
        Get stack offset delta. The local variable stack offsets retrieved by
        v.location.stkoff() should be adjusted before being used as stack frame offsets
        in IDA.

        @return: the delta to apply. example: ida_stkoff = v.location.stkoff() -
                 f->get_stkoff_delta()
        """
        return _ida_hexrays.cfunc_t_get_stkoff_delta(self)

    def find_label(self, label: "int") -> "citem_t *":
        r"""
        find_label(self, label) -> citem_t
        Find the label.

        @param label: (C++: int)
        @return: pointer to the ctree item with the specified label number.
        """
        return _ida_hexrays.cfunc_t_find_label(self, label)

    def remove_unused_labels(self) -> "void":
        r"""
        remove_unused_labels(self)
        Remove unused labels. This function checks what labels are really used by the
        function and removes the unused ones. You must call it after deleting a goto
        statement.
        """
        return _ida_hexrays.cfunc_t_remove_unused_labels(self)

    def get_user_cmt(self, loc: "treeloc_t", rt: "cmt_retrieval_type_t") -> "char const *":
        r"""
        get_user_cmt(self, loc, rt) -> char const *
        Retrieve a user defined comment.

        @param loc: (C++: const treeloc_t &) ctree location
        @param rt: (C++: cmt_retrieval_type_t) should already retrieved comments retrieved again?
        @return: pointer to the comment string or nullptr
        """
        return _ida_hexrays.cfunc_t_get_user_cmt(self, loc, rt)

    def set_user_cmt(self, loc: "treeloc_t", cmt: "char const *") -> "void":
        r"""
        set_user_cmt(self, loc, cmt)
        Set a user defined comment. This function stores the specified comment in the
        cfunc_t structure. The save_user_cmts() function must be called after it.

        @param loc: (C++: const treeloc_t &) ctree location
        @param cmt: (C++: const char *) new comment. if empty or nullptr, then an existing comment is
                    deleted.
        """
        return _ida_hexrays.cfunc_t_set_user_cmt(self, loc, cmt)

    def get_user_iflags(self, loc: "citem_locator_t") -> "int32":
        r"""
        get_user_iflags(self, loc) -> int32
        Retrieve citem iflags.

        @param loc: (C++: const citem_locator_t &) citem locator
        @return: ctree item iflags bits or 0
        """
        return _ida_hexrays.cfunc_t_get_user_iflags(self, loc)

    def set_user_iflags(self, loc: "citem_locator_t", iflags: "int32") -> "void":
        r"""
        set_user_iflags(self, loc, iflags)
        Set citem iflags.

        @param loc: (C++: const citem_locator_t &) citem locator
        @param iflags: (C++: int32) new iflags
        """
        return _ida_hexrays.cfunc_t_set_user_iflags(self, loc, iflags)

    def has_orphan_cmts(self) -> "bool":
        r"""
        has_orphan_cmts(self) -> bool
        Check if there are orphan comments.
        """
        return _ida_hexrays.cfunc_t_has_orphan_cmts(self)

    def del_orphan_cmts(self) -> "int":
        r"""
        del_orphan_cmts(self) -> int
        Delete all orphan comments. The save_user_cmts() function must be called after
        this call.
        """
        return _ida_hexrays.cfunc_t_del_orphan_cmts(self)

    def get_user_union_selection(self, ea: "ea_t", path: "intvec_t") -> "bool":
        r"""
        get_user_union_selection(self, ea, path) -> bool
        Retrieve a user defined union field selection.

        @param ea: (C++: ea_t) address
        @param path: (C++: intvec_t *) out: path describing the union selection.
        @return: pointer to the path or nullptr
        """
        return _ida_hexrays.cfunc_t_get_user_union_selection(self, ea, path)

    def set_user_union_selection(self, ea: "ea_t", path: "intvec_t") -> "void":
        r"""
        set_user_union_selection(self, ea, path)
        Set a union field selection. The save_user_unions() function must be called
        after calling this function.

        @param ea: (C++: ea_t) address
        @param path: (C++: const intvec_t &) in: path describing the union selection.
        """
        return _ida_hexrays.cfunc_t_set_user_union_selection(self, ea, path)

    def save_user_labels(self) -> "void":
        r"""
        save_user_labels(self)
        Save user-defined labels into the database.
        """
        return _ida_hexrays.cfunc_t_save_user_labels(self)

    def save_user_cmts(self) -> "void":
        r"""
        save_user_cmts(self)
        Save user-defined comments into the database.
        """
        return _ida_hexrays.cfunc_t_save_user_cmts(self)

    def save_user_numforms(self) -> "void":
        r"""
        save_user_numforms(self)
        Save user-defined number formats into the database.
        """
        return _ida_hexrays.cfunc_t_save_user_numforms(self)

    def save_user_iflags(self) -> "void":
        r"""
        save_user_iflags(self)
        Save user-defined iflags into the database.
        """
        return _ida_hexrays.cfunc_t_save_user_iflags(self)

    def save_user_unions(self) -> "void":
        r"""
        save_user_unions(self)
        Save user-defined union field selections into the database.
        """
        return _ida_hexrays.cfunc_t_save_user_unions(self)

    def get_line_item(self, line: "char const *", x: "int", is_ctree_line: "bool", phead: "ctree_item_t", pitem: "ctree_item_t", ptail: "ctree_item_t") -> "bool":
        r"""
        get_line_item(self, line, x, is_ctree_line, phead, pitem, ptail) -> bool
        Get ctree item for the specified cursor position.

        @param line: (C++: const char *) line of decompilation text (element of sv)
        @param x: (C++: int) x cursor coordinate in the line
        @param is_ctree_line: (C++: bool) does the line belong to statement area? (if not, it is
                              assumed to belong to the declaration area)
        @param phead: (C++: ctree_item_t *) ptr to the first item on the line (used to attach block comments).
                      May be nullptr
        @param pitem: (C++: ctree_item_t *) ptr to the current item. May be nullptr
        @param ptail: (C++: ctree_item_t *) ptr to the last item on the line (used to attach indented
                      comments). May be nullptr
        @see: vdui_t::get_current_item()
        @return: false if failed to get the current item
        """
        return _ida_hexrays.cfunc_t_get_line_item(self, line, x, is_ctree_line, phead, pitem, ptail)

    def get_warnings(self) -> "hexwarns_t &":
        r"""
        get_warnings(self) -> hexwarns_t
        Get information about decompilation warnings.

        @return: reference to the vector of warnings
        """
        return _ida_hexrays.cfunc_t_get_warnings(self)

    def get_eamap(self) -> "eamap_t &":
        r"""
        get_eamap(self) -> eamap_t
        Get pointer to ea->insn map. This function initializes eamap if not done yet.
        """
        return _ida_hexrays.cfunc_t_get_eamap(self)

    def get_boundaries(self) -> "boundaries_t &":
        r"""
        get_boundaries(self) -> boundaries_t
        Get pointer to map of instruction boundaries. This function initializes the
        boundary map if not done yet.
        """
        return _ida_hexrays.cfunc_t_get_boundaries(self)

    def get_pseudocode(self) -> "strvec_t const &":
        r"""
        get_pseudocode(self) -> strvec_t
        Get pointer to decompilation output: the pseudocode. This function generates
        pseudocode if not done yet.
        """
        return _ida_hexrays.cfunc_t_get_pseudocode(self)

    def refresh_func_ctext(self) -> "void":
        r"""
        refresh_func_ctext(self)
        Refresh ctext after a ctree modification. This function informs the decompiler
        that ctree (body) have been modified and ctext (sv) does not correspond to it
        anymore. It also refreshes the pseudocode windows if there is any.
        """
        return _ida_hexrays.cfunc_t_refresh_func_ctext(self)

    def gather_derefs(self, ci: "ctree_item_t", udm: "udt_type_data_t"=None) -> "bool":
        r"""
        gather_derefs(self, ci, udm=None) -> bool

        @param ci: ctree_item_t const &
        @param udm: udt_type_data_t *
        """
        return _ida_hexrays.cfunc_t_gather_derefs(self, ci, udm)

    def locked(self) -> "bool":
        r"""
        locked(self) -> bool
        """
        return _ida_hexrays.cfunc_t_locked(self)

    def find_item_coords(self, *args) -> "PyObject *":
        r"""
        find_item_coords(self, item, px, py) -> bool

        @param item: citem_t const *
        @param px: int *
        @param py: int *

        find_item_coords(self, item) -> PyObject *

        @param item: citem_t const *
        """
        return _ida_hexrays.cfunc_t_find_item_coords(self, *args)

    def __str__(self) -> "qstring":
        r"""
        __str__(self) -> qstring
        """
        return _ida_hexrays.cfunc_t___str__(self)

# Register cfunc_t in _ida_hexrays:
_ida_hexrays.cfunc_t_swigregister(cfunc_t)
CIT_COLLAPSED = _ida_hexrays.CIT_COLLAPSED
r"""
display ctree item in collapsed form
"""

CFS_BOUNDS = _ida_hexrays.CFS_BOUNDS
r"""
'eamap' and 'boundaries' are ready
"""

CFS_TEXT = _ida_hexrays.CFS_TEXT
r"""
'sv' is ready (and hdrlines)
"""

CFS_LVARS_HIDDEN = _ida_hexrays.CFS_LVARS_HIDDEN
r"""
local variable definitions are collapsed
"""

CFS_LOCKED = _ida_hexrays.CFS_LOCKED
r"""
cfunc is temporarily locked
"""


DECOMP_NO_WAIT = _ida_hexrays.DECOMP_NO_WAIT
r"""
do not display waitbox
"""

DECOMP_NO_CACHE = _ida_hexrays.DECOMP_NO_CACHE
r"""
do not use decompilation cache (snippets are never cached)
"""

DECOMP_NO_FRAME = _ida_hexrays.DECOMP_NO_FRAME
r"""
do not use function frame info (only snippet mode)
"""

DECOMP_WARNINGS = _ida_hexrays.DECOMP_WARNINGS
r"""
display warnings in the output window
"""

DECOMP_ALL_BLKS = _ida_hexrays.DECOMP_ALL_BLKS
r"""
generate microcode for unreachable blocks
"""

DECOMP_NO_HIDE = _ida_hexrays.DECOMP_NO_HIDE
r"""
do not close display waitbox. see close_hexrays_waitboxes()
"""

DECOMP_NO_XREFS = _ida_hexrays.DECOMP_NO_XREFS
r"""
Obsolete. Use DECOMP_GXREFS_NOUPD.
"""

DECOMP_GXREFS_DEFLT = _ida_hexrays.DECOMP_GXREFS_DEFLT
r"""
the default behavior: do not update the global xrefs cache upon decompile()
call, but when the pseudocode text is generated (e.g., through
cfunc_t.get_pseudocode())
"""

DECOMP_GXREFS_NOUPD = _ida_hexrays.DECOMP_GXREFS_NOUPD
r"""
do not update the global xrefs cache
"""

DECOMP_GXREFS_FORCE = _ida_hexrays.DECOMP_GXREFS_FORCE
r"""
update the global xrefs cache immediately
"""

DECOMP_VOID_MBA = _ida_hexrays.DECOMP_VOID_MBA
r"""
return empty mba object (to be used with gen_microcode)
"""


def close_hexrays_waitbox() -> "void":
    r"""
    close_hexrays_waitbox()
    Close the waitbox displayed by the decompiler. Useful if DECOMP_NO_HIDE was used
    during decompilation.
    """
    return _ida_hexrays.close_hexrays_waitbox()

def decompile(mbr: "mba_ranges_t", hf: "hexrays_failure_t"=None, decomp_flags: "int"=0) -> "cfuncptr_t":
    r"""
    decompile(mbr, hf=None, decomp_flags=0) -> cfuncptr_t
    Decompile a snippet or a function.

    @param mbr: (C++: const mba_ranges_t &) what to decompile
    @param hf: (C++: hexrays_failure_t *) extended error information (if failed)
    @param decomp_flags: (C++: int) bitwise combination of decompile() flags... bits
    @return: pointer to the decompilation result (a reference counted pointer).
             nullptr if failed.
    """
    return _ida_hexrays.decompile(mbr, hf, decomp_flags)

def decompile_func(pfn: "func_t *", hf: "hexrays_failure_t"=None, decomp_flags: "int"=0) -> "cfuncptr_t":
    r"""
    decompile_func(pfn, hf=None, decomp_flags=0) -> cfuncptr_t
    Decompile a function. Multiple decompilations of the same function return the
    same object.

    @param pfn: (C++: func_t *) pointer to function to decompile
    @param hf: (C++: hexrays_failure_t *) extended error information (if failed)
    @param decomp_flags: (C++: int) bitwise combination of decompile() flags... bits
    @return: pointer to the decompilation result (a reference counted pointer).
             nullptr if failed.
    """
    val = _ida_hexrays.decompile_func(pfn, hf, decomp_flags)

    if val.__deref__() is None:
        val = None


    return val

def gen_microcode(mbr: "mba_ranges_t", hf: "hexrays_failure_t"=None, retlist: "mlist_t"=None, decomp_flags: "int"=0, reqmat: "mba_maturity_t"=MMAT_GLBOPT3) -> "mba_t *":
    r"""
    gen_microcode(mbr, hf=None, retlist=None, decomp_flags=0, reqmat=MMAT_GLBOPT3) -> mba_t
    Generate microcode of an arbitrary code snippet

    @param mbr: (C++: const mba_ranges_t &) snippet ranges
    @param hf: (C++: hexrays_failure_t *) extended error information (if failed)
    @param retlist: (C++: const mlist_t *) list of registers the snippet returns
    @param decomp_flags: (C++: int) bitwise combination of decompile() flags... bits
    @param reqmat: (C++: mba_maturity_t) required microcode maturity
    @return: pointer to the microcode, nullptr if failed.
    """
    return _ida_hexrays.gen_microcode(mbr, hf, retlist, decomp_flags, reqmat)

def create_empty_mba(mbr: "mba_ranges_t", hf: "hexrays_failure_t"=None) -> "mba_t *":
    r"""
    create_empty_mba(mbr, hf=None) -> mba_t
    Create an empty microcode object.

    @param mbr: (C++: const mba_ranges_t &) mba_ranges_t const &
    @param hf: (C++: hexrays_failure_t *)
    """
    return _ida_hexrays.create_empty_mba(mbr, hf)

def create_cfunc(mba: "mba_t") -> "cfuncptr_t":
    r"""
    create_cfunc(mba) -> cfuncptr_t
    Create a new cfunc_t object.

    @param mba: (C++: mba_t *) microcode object. After creating the cfunc object it takes the
                ownership of MBA.
    """
    return _ida_hexrays.create_cfunc(mba)

def mark_cfunc_dirty(ea: "ea_t", close_views: "bool"=False) -> "bool":
    r"""
    mark_cfunc_dirty(ea, close_views=False) -> bool
    Flush the cached decompilation results. Erases a cache entry for the specified
    function.

    @param ea: (C++: ea_t) function to erase from the cache
    @param close_views: (C++: bool) close pseudocode windows that show the function
    @return: if a cache entry existed.
    """
    return _ida_hexrays.mark_cfunc_dirty(ea, close_views)

def clear_cached_cfuncs() -> "void":
    r"""
    clear_cached_cfuncs()
    Flush all cached decompilation results.
    """
    return _ida_hexrays.clear_cached_cfuncs()

def has_cached_cfunc(ea: "ea_t") -> "bool":
    r"""
    has_cached_cfunc(ea) -> bool
    Do we have a cached decompilation result for 'ea'?

    @param ea: (C++: ea_t)
    """
    return _ida_hexrays.has_cached_cfunc(ea)

def get_ctype_name(op: "ctype_t") -> "char const *":
    r"""
    get_ctype_name(op) -> char const *

    @param op: enum ctype_t
    """
    return _ida_hexrays.get_ctype_name(op)

def create_field_name(*args) -> "qstring":
    r"""
    create_field_name(type, offset=BADADDR) -> qstring

    @param type: tinfo_t const &
    @param offset: uval_t
    """
    return _ida_hexrays.create_field_name(*args)
hxe_flowchart = _ida_hexrays.hxe_flowchart
r"""
Flowchart has been generated.
@param fc: (qflow_chart_t *)
@param mba: (mba_t *)
"""

hxe_stkpnts = _ida_hexrays.hxe_stkpnts
r"""
SP change points have been calculated.
@param mba: (mba_t *)
@param stkpnts: (stkpnts_t *)
@return: Microcode error codes code This event is generated for each inlined
         range as well.
"""

hxe_prolog = _ida_hexrays.hxe_prolog
r"""
Prolog analysis has been finished.
@param mba: (mba_t *)
@param fc: (qflow_chart_t *)
@param reachable_blocks: (bitset_t *)
@param decomp_flags: (int)
@return: Microcode error codes code This event is generated for each inlined
         range as well.
"""

hxe_microcode = _ida_hexrays.hxe_microcode
r"""
Microcode has been generated.
@param mba: (mba_t *)
@return: Microcode error codes code
"""

hxe_preoptimized = _ida_hexrays.hxe_preoptimized
r"""
Microcode has been preoptimized.
@param mba: (mba_t *)
@return: Microcode error codes code
"""

hxe_locopt = _ida_hexrays.hxe_locopt
r"""
Basic block level optimization has been finished.
@param mba: (mba_t *)
@return: Microcode error codes code
"""

hxe_prealloc = _ida_hexrays.hxe_prealloc
r"""
Local variables: preallocation step begins.
@param mba: (mba_t *) This event may occur several times. Should return: 1 if
            modified microcode Negative values are Microcode error codes error
            codes
"""

hxe_glbopt = _ida_hexrays.hxe_glbopt
r"""
Global optimization has been finished. If microcode is modified, MERR_LOOP must
be returned. It will cause a complete restart of the optimization.
@param mba: (mba_t *)
@return: Microcode error codes code
"""

hxe_pre_structural = _ida_hexrays.hxe_pre_structural
r"""
Structure analysis is starting.
@param ct: (control_graph_t *) in/out: control graph
@param cfunc: (cfunc_t *) in: the current function
@param g: (const simple_graph_t *) in: control flow graph
@return: Microcode error codes code; MERR_BLOCK means that the analysis has been
         performed by a plugin
"""

hxe_structural = _ida_hexrays.hxe_structural
r"""
Structural analysis has been finished.
@param ct: (control_graph_t *)
"""

hxe_maturity = _ida_hexrays.hxe_maturity
r"""
Ctree maturity level is being changed.
@param cfunc: (cfunc_t *)
@param new_maturity: (ctree_maturity_t)
"""

hxe_interr = _ida_hexrays.hxe_interr
r"""
Internal error has occurred.
@param errcode: (int )
"""

hxe_combine = _ida_hexrays.hxe_combine
r"""
Trying to combine instructions of basic block.
@param blk: (mblock_t *)
@param insn: (minsn_t *) Should return: 1 if combined the current instruction
             with a preceding one -1 if the instruction should not be combined 0
             else
"""

hxe_print_func = _ida_hexrays.hxe_print_func
r"""
Printing ctree and generating text.
@param cfunc: (cfunc_t *)
@param vp: (vc_printer_t *) Returns: 1 if text has been generated by the plugin
           It is forbidden to modify ctree at this event.
"""

hxe_func_printed = _ida_hexrays.hxe_func_printed
r"""
Function text has been generated. Plugins may modify the text in cfunc_t::sv.
The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store
pointers to ctree items.
@param cfunc: (cfunc_t *)
"""

hxe_resolve_stkaddrs = _ida_hexrays.hxe_resolve_stkaddrs
r"""
The optimizer is about to resolve stack addresses.
@param mba: (mba_t *)
"""

hxe_build_callinfo = _ida_hexrays.hxe_build_callinfo
r"""
Analyzing a call instruction.
@param blk: (mblock_t *) blk->tail is the call.
@param type: (tinfo_t *) buffer for the output type.
@param callinfo: (mcallinfo_t **) prepared callinfo. The plugin should either
                 specify the function type, either allocate and return a new
                 mcallinfo_t object.
"""

hxe_callinfo_built = _ida_hexrays.hxe_callinfo_built
r"""
A call instruction has been anallyzed.
@param blk: (mblock_t *) blk->tail is the call.
"""

hxe_calls_done = _ida_hexrays.hxe_calls_done
r"""
All calls have been analyzed.
@param mba: (mba_t *) This event is generated immediately after analyzing all
            calls, before any optimizitions, call unmerging and block merging.
"""

hxe_begin_inlining = _ida_hexrays.hxe_begin_inlining
r"""
Starting to inline outlined functions.
@param cdg: (codegen_t *)
@param decomp_flags: (int)
@return: Microcode error codes code This is an opportunity to inline other
         ranges.
"""

hxe_inlining_func = _ida_hexrays.hxe_inlining_func
r"""
A set of ranges is going to be inlined.
@param cdg: (codegen_t *)
@param blk: (int) the block containing call/jump to inline
@param mbr: (mba_ranges_t *) the range to inline
"""

hxe_inlined_func = _ida_hexrays.hxe_inlined_func
r"""
A set of ranges got inlined.
@param cdg: (codegen_t *)
@param blk: (int) the block containing call/jump to inline
@param mbr: (mba_ranges_t *) the range to inline
@param i1: (int) blknum of the first inlined block
@param i2: (int) blknum of the last inlined block (excluded)
"""

hxe_collect_warnings = _ida_hexrays.hxe_collect_warnings
r"""
Collect warning messages from plugins. These warnings will be displayed at the
function header, after the user-defined comments.
@param warnings: (qstrvec_t *)
@param cfunc: (cfunc_t *)
"""

hxe_open_pseudocode = _ida_hexrays.hxe_open_pseudocode
r"""
New pseudocode view has been opened.
@param vu: (vdui_t *)
"""

hxe_switch_pseudocode = _ida_hexrays.hxe_switch_pseudocode
r"""
Existing pseudocode view has been reloaded with a new function. Its text has not
been refreshed yet, only cfunc and mba pointers are ready.
@param vu: (vdui_t *)
"""

hxe_refresh_pseudocode = _ida_hexrays.hxe_refresh_pseudocode
r"""
Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is
forbidden in this event.
@param vu: (vdui_t *) See also hxe_text_ready, which happens earlier
"""

hxe_close_pseudocode = _ida_hexrays.hxe_close_pseudocode
r"""
Pseudocode view is being closed.
@param vu: (vdui_t *)
"""

hxe_keyboard = _ida_hexrays.hxe_keyboard
r"""
Keyboard has been hit.
@param vu: (vdui_t *)
@param key_code: (int) VK_...
@param shift_state: (int) Should return: 1 if the event has been handled
"""

hxe_right_click = _ida_hexrays.hxe_right_click
r"""
Mouse right click. Use hxe_populating_popup instead, in case you want to add
items in the popup menu.
@param vu: (vdui_t *)
"""

hxe_double_click = _ida_hexrays.hxe_double_click
r"""
Mouse double click.
@param vu: (vdui_t *)
@param shift_state: (int) Should return: 1 if the event has been handled
"""

hxe_curpos = _ida_hexrays.hxe_curpos
r"""
Current cursor position has been changed. (for example, by left-clicking or
using keyboard)
@param vu: (vdui_t *)
"""

hxe_create_hint = _ida_hexrays.hxe_create_hint
r"""
Create a hint for the current item.
@see: ui_get_custom_viewer_hint
@param vu: (vdui_t *)
@param hint: (qstring *)
@param important_lines: (int *) Possible return values:
@retval 0: continue collecting hints with other subscribers
@retval 1: stop collecting hints
"""

hxe_text_ready = _ida_hexrays.hxe_text_ready
r"""
Decompiled text is ready.
@param vu: (vdui_t *) This event can be used to modify the output text (sv).
           Obsolete. Please use hxe_func_printed instead.
"""

hxe_populating_popup = _ida_hexrays.hxe_populating_popup
r"""
Populating popup menu. We can add menu items now.
@param widget: (TWidget *)
@param popup_handle: (TPopupMenu *)
@param vu: (vdui_t *)
"""

lxe_lvar_name_changed = _ida_hexrays.lxe_lvar_name_changed
r"""
Local variable got renamed.
@param vu: (vdui_t *)
@param v: (lvar_t *)
@param name: (const char *)
@param is_user_name: (bool) Please note that it is possible to read/write user
                     settings for lvars directly from the idb.
"""

lxe_lvar_type_changed = _ida_hexrays.lxe_lvar_type_changed
r"""
Local variable type got changed.
@param vu: (vdui_t *)
@param v: (lvar_t *)
@param tinfo: (const tinfo_t *) Please note that it is possible to read/write
              user settings for lvars directly from the idb.
"""

lxe_lvar_cmt_changed = _ida_hexrays.lxe_lvar_cmt_changed
r"""
Local variable comment got changed.
@param vu: (vdui_t *)
@param v: (lvar_t *)
@param cmt: (const char *) Please note that it is possible to read/write user
            settings for lvars directly from the idb.
"""

lxe_lvar_mapping_changed = _ida_hexrays.lxe_lvar_mapping_changed
r"""
Local variable mapping got changed.
@param vu: (vdui_t *)
@param from: (lvar_t *)
@param to: (lvar_t *) Please note that it is possible to read/write user
           settings for lvars directly from the idb.
"""

hxe_cmt_changed = _ida_hexrays.hxe_cmt_changed
r"""
Comment got changed.
@param cfunc: (cfunc_t *)
@param loc: (const treeloc_t *)
@param cmt: (const char *)
"""

USE_KEYBOARD = _ida_hexrays.USE_KEYBOARD
r"""
Keyboard.
"""

USE_MOUSE = _ida_hexrays.USE_MOUSE
r"""
Mouse.
"""

class ctext_position_t(object):
    r"""
    Proxy of C++ ctext_position_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    lnnum: "int" = property(_ida_hexrays.ctext_position_t_lnnum_get, _ida_hexrays.ctext_position_t_lnnum_set, doc=r"""lnnum""")
    r"""
    Line number.
    """
    x: "int" = property(_ida_hexrays.ctext_position_t_x_get, _ida_hexrays.ctext_position_t_x_set, doc=r"""x""")
    r"""
    x coordinate of the cursor within the window
    """
    y: "int" = property(_ida_hexrays.ctext_position_t_y_get, _ida_hexrays.ctext_position_t_y_set, doc=r"""y""")
    r"""
    y coordinate of the cursor within the window
    """

    def in_ctree(self, hdrlines: "int") -> "bool":
        r"""
        in_ctree(self, hdrlines) -> bool
        Is the cursor in the variable/type declaration area?

        @param hdrlines: (C++: int) Number of lines of the declaration area
        """
        return _ida_hexrays.ctext_position_t_in_ctree(self, hdrlines)

    def __eq__(self, r: "ctext_position_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___eq__(self, r)

    def __ne__(self, r: "ctext_position_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___ne__(self, r)

    def __lt__(self, r: "ctext_position_t") -> "bool":
        r"""
        __lt__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___lt__(self, r)

    def __gt__(self, r: "ctext_position_t") -> "bool":
        r"""
        __gt__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___gt__(self, r)

    def __le__(self, r: "ctext_position_t") -> "bool":
        r"""
        __le__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___le__(self, r)

    def __ge__(self, r: "ctext_position_t") -> "bool":
        r"""
        __ge__(self, r) -> bool

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t___ge__(self, r)

    def compare(self, r: "ctext_position_t") -> "int":
        r"""
        compare(self, r) -> int

        @param r: ctext_position_t const &
        """
        return _ida_hexrays.ctext_position_t_compare(self, r)

    def __init__(self, _lnnum: "int"=-1, _x: "int"=0, _y: "int"=0):
        r"""
        __init__(self, _lnnum=-1, _x=0, _y=0) -> ctext_position_t

        @param _lnnum: int
        @param _x: int
        @param _y: int
        """
        _ida_hexrays.ctext_position_t_swiginit(self, _ida_hexrays.new_ctext_position_t(_lnnum, _x, _y))
    __swig_destroy__ = _ida_hexrays.delete_ctext_position_t

# Register ctext_position_t in _ida_hexrays:
_ida_hexrays.ctext_position_t_swigregister(ctext_position_t)
HEXRAYS_API_MAGIC = cvar.HEXRAYS_API_MAGIC

class history_item_t(ctext_position_t):
    r"""
    Proxy of C++ history_item_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    func_ea: "ea_t" = property(_ida_hexrays.history_item_t_func_ea_get, _ida_hexrays.history_item_t_func_ea_set, doc=r"""func_ea""")
    r"""
    The entry address of the decompiled function.
    """
    curr_ea: "ea_t" = property(_ida_hexrays.history_item_t_curr_ea_get, _ida_hexrays.history_item_t_curr_ea_set, doc=r"""curr_ea""")
    r"""
    Current address.
    """
    end: "ea_t" = property(_ida_hexrays.history_item_t_end_get, _ida_hexrays.history_item_t_end_set, doc=r"""end""")
    r"""
    BADADDR-decompile a function; otherwise end of the range.
    """

    def __init__(self, *args):
        r"""
        __init__(self, fea=BADADDR, cea=BADADDR, _lnnum=-1, _x=0, _y=0) -> history_item_t

        @param fea: ea_t
        @param cea: ea_t
        @param _lnnum: int
        @param _x: int
        @param _y: int

        __init__(self, fea, cea, p) -> history_item_t

        @param fea: ea_t
        @param cea: ea_t
        @param p: ctext_position_t const &
        """
        _ida_hexrays.history_item_t_swiginit(self, _ida_hexrays.new_history_item_t(*args))
    __swig_destroy__ = _ida_hexrays.delete_history_item_t

# Register history_item_t in _ida_hexrays:
_ida_hexrays.history_item_t_swigregister(history_item_t)
class vdui_t(object):
    r"""
    Proxy of C++ vdui_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    flags: "int" = property(_ida_hexrays.vdui_t_flags_get, _ida_hexrays.vdui_t_flags_set, doc=r"""flags""")
    r"""
    Properties of pseudocode window
    """

    def visible(self) -> "bool":
        r"""
        visible(self) -> bool
        Is the pseudocode window visible? if not, it might be invisible or destroyed
        """
        return _ida_hexrays.vdui_t_visible(self)

    def valid(self) -> "bool":
        r"""
        valid(self) -> bool
        Does the pseudocode window contain valid code? It can become invalid if the
        function type gets changed in IDA.
        """
        return _ida_hexrays.vdui_t_valid(self)

    def locked(self) -> "bool":
        r"""
        locked(self) -> bool
        Does the pseudocode window contain valid code? We lock windows before modifying
        them, to avoid recursion due to the events generated by the IDA kernel.
        @retval true: The window is locked and may have stale info
        """
        return _ida_hexrays.vdui_t_locked(self)

    def set_visible(self, v: "bool") -> "void":
        r"""
        set_visible(self, v)

        @param v: bool
        """
        return _ida_hexrays.vdui_t_set_visible(self, v)

    def set_valid(self, v: "bool") -> "void":
        r"""
        set_valid(self, v)

        @param v: bool
        """
        return _ida_hexrays.vdui_t_set_valid(self, v)

    def set_locked(self, v: "bool") -> "bool":
        r"""
        set_locked(self, v) -> bool

        @param v: bool
        """
        return _ida_hexrays.vdui_t_set_locked(self, v)
    view_idx: "int" = property(_ida_hexrays.vdui_t_view_idx_get, _ida_hexrays.vdui_t_view_idx_set, doc=r"""view_idx""")
    r"""
    pseudocode window index (0..)
    """
    ct: "TWidget *" = property(_ida_hexrays.vdui_t_ct_get, _ida_hexrays.vdui_t_ct_set, doc=r"""ct""")
    r"""
    pseudocode view
    """
    toplevel: "TWidget *" = property(_ida_hexrays.vdui_t_toplevel_get, _ida_hexrays.vdui_t_toplevel_set, doc=r"""toplevel""")
    mba: "mba_t *" = property(_ida_hexrays.vdui_t_mba_get, _ida_hexrays.vdui_t_mba_set, doc=r"""mba""")
    r"""
    pointer to underlying microcode
    """
    cfunc: "cfuncptr_t" = property(_ida_hexrays.vdui_t_cfunc_get, _ida_hexrays.vdui_t_cfunc_set, doc=r"""cfunc""")
    r"""
    pointer to function object
    """
    last_code: "merror_t" = property(_ida_hexrays.vdui_t_last_code_get, _ida_hexrays.vdui_t_last_code_set, doc=r"""last_code""")
    r"""
    result of the last user action. See Microcode error codes
    """
    cpos: "ctext_position_t" = property(_ida_hexrays.vdui_t_cpos_get, _ida_hexrays.vdui_t_cpos_set, doc=r"""cpos""")
    r"""
    Current ctext position.
    """
    head: "ctree_item_t" = property(_ida_hexrays.vdui_t_head_get, doc=r"""head""")
    r"""
    First ctree item on the current line (for block comments)
    """
    item: "ctree_item_t" = property(_ida_hexrays.vdui_t_item_get, doc=r"""item""")
    r"""
    Current ctree item.
    """
    tail: "ctree_item_t" = property(_ida_hexrays.vdui_t_tail_get, doc=r"""tail""")
    r"""
    Tail ctree item on the current line (for indented comments)
    """

    def refresh_view(self, redo_mba: "bool") -> "void":
        r"""
        refresh_view(self, redo_mba)
        Refresh pseudocode window. This is the highest level refresh function. It causes
        the most profound refresh possible and can lead to redecompilation of the
        current function. Please consider using refresh_ctext() if you need a more
        superficial refresh.

        @param redo_mba: (C++: bool) true means to redecompile the current function
        false means to rebuild ctree without regenerating microcode
        @see: refresh_ctext()
        """
        return _ida_hexrays.vdui_t_refresh_view(self, redo_mba)

    def refresh_ctext(self, activate: "bool"=True) -> "void":
        r"""
        refresh_ctext(self, activate=True)
        Refresh pseudocode window. This function refreshes the pseudocode window by
        regenerating its text from cfunc_t. Instead of this function use
        refresh_func_ctext(), which refreshes all pseudocode windows for the function.
        @see: refresh_view(), refresh_func_ctext()

        @param activate: (C++: bool)
        """
        return _ida_hexrays.vdui_t_refresh_ctext(self, activate)

    def switch_to(self, f: "cfuncptr_t", activate: "bool") -> "void":
        r"""
        switch_to(self, f, activate)
        Display the specified pseudocode. This function replaces the pseudocode window
        contents with the specified cfunc_t.

        @param f: (C++: cfuncptr_t) pointer to the function to display.
        @param activate: (C++: bool) should the pseudocode window get focus?
        """
        return _ida_hexrays.vdui_t_switch_to(self, f, activate)

    def in_ctree(self) -> "bool":
        r"""
        in_ctree(self) -> bool
        Is the current item a statement?

        @return: false if the cursor is in the local variable/type declaration area
        true if the cursor is in the statement area
        """
        return _ida_hexrays.vdui_t_in_ctree(self)

    def get_number(self) -> "cnumber_t *":
        r"""
        get_number(self) -> cnumber_t
        Get current number. If the current item is a number, return pointer to it.

        @return: nullptr if the current item is not a number This function returns non-
                 null for the cases of a 'switch' statement Also, if the current item is
                 a casted number, then this function will succeed.
        """
        return _ida_hexrays.vdui_t_get_number(self)

    def get_current_label(self) -> "int":
        r"""
        get_current_label(self) -> int
        Get current label. If there is a label under the cursor, return its number.

        @return: -1 if there is no label under the cursor. prereq: get_current_item()
                 has been called
        """
        return _ida_hexrays.vdui_t_get_current_label(self)

    def clear(self) -> "void":
        r"""
        clear(self)
        Clear the pseudocode window. It deletes the current function and microcode.
        """
        return _ida_hexrays.vdui_t_clear(self)

    def refresh_cpos(self, idv: "input_device_t") -> "bool":
        r"""
        refresh_cpos(self, idv) -> bool
        Refresh the current position. This function refreshes the cpos field.

        @param idv: (C++: input_device_t) keyboard or mouse
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_refresh_cpos(self, idv)

    def get_current_item(self, idv: "input_device_t") -> "bool":
        r"""
        get_current_item(self, idv) -> bool
        Get current item. This function refreshes the cpos, item, tail fields.

        @param idv: (C++: input_device_t) keyboard or mouse
        @see: cfunc_t::get_line_item()
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_get_current_item(self, idv)

    def ui_rename_lvar(self, v: "lvar_t") -> "bool":
        r"""
        ui_rename_lvar(self, v) -> bool
        Rename local variable. This function displays a dialog box and allows the user
        to rename a local variable.

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_rename_lvar(self, v)

    def rename_lvar(self, v: "lvar_t", name: "char const *", is_user_name: "bool") -> "bool":
        r"""
        rename_lvar(self, v, name, is_user_name) -> bool
        Rename local variable. This function permanently renames a local variable.

        @param v: (C++: lvar_t *) pointer to local variable
        @param name: (C++: const char *) new variable name
        @param is_user_name: (C++: bool) use true to save the new name into the database. use false
                             to delete the saved name.
        @see: ::rename_lvar()
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_rename_lvar(self, v, name, is_user_name)

    def ui_set_call_type(self, e: "cexpr_t") -> "bool":
        r"""
        ui_set_call_type(self, e) -> bool
        Set type of a function call This function displays a dialog box and allows the
        user to change the type of a function call

        @param e: (C++: const cexpr_t *) pointer to call expression
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_set_call_type(self, e)

    def ui_set_lvar_type(self, v: "lvar_t") -> "bool":
        r"""
        ui_set_lvar_type(self, v) -> bool
        Set local variable type. This function displays a dialog box and allows the user
        to change the type of a local variable.

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_set_lvar_type(self, v)

    def set_lvar_type(self, v: "lvar_t", type: "tinfo_t") -> "bool":
        r"""
        set_lvar_type(self, v, type) -> bool
        Set local variable type. This function permanently sets a local variable type
        and clears NOPTR flag if it was set before by function 'set_noptr_lvar'

        @param v: (C++: lvar_t *) pointer to local variable
        @param type: (C++: const tinfo_t &) new variable type
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_set_lvar_type(self, v, type)

    def set_noptr_lvar(self, v: "lvar_t") -> "bool":
        r"""
        set_noptr_lvar(self, v) -> bool
        Inform that local variable should have a non-pointer type This function
        permanently sets a corresponding variable flag (NOPTR) and removes type if it
        was set before by function 'set_lvar_type'

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_set_noptr_lvar(self, v)

    def ui_edit_lvar_cmt(self, v: "lvar_t") -> "bool":
        r"""
        ui_edit_lvar_cmt(self, v) -> bool
        Set local variable comment. This function displays a dialog box and allows the
        user to edit the comment of a local variable.

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_edit_lvar_cmt(self, v)

    def set_lvar_cmt(self, v: "lvar_t", cmt: "char const *") -> "bool":
        r"""
        set_lvar_cmt(self, v, cmt) -> bool
        Set local variable comment. This function permanently sets a variable comment.

        @param v: (C++: lvar_t *) pointer to local variable
        @param cmt: (C++: const char *) new comment
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_set_lvar_cmt(self, v, cmt)

    def ui_map_lvar(self, v: "lvar_t") -> "bool":
        r"""
        ui_map_lvar(self, v) -> bool
        Map a local variable to another. This function displays a variable list and
        allows the user to select mapping.

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_map_lvar(self, v)

    def ui_unmap_lvar(self, v: "lvar_t") -> "bool":
        r"""
        ui_unmap_lvar(self, v) -> bool
        Unmap a local variable. This function displays list of variables mapped to the
        specified variable and allows the user to select a variable to unmap.

        @param v: (C++: lvar_t *) pointer to local variable
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_ui_unmap_lvar(self, v)

    def map_lvar(self, frm: "lvar_t", to: "lvar_t") -> "bool":
        r"""
        map_lvar(self, frm, to) -> bool
        Map a local variable to another. This function permanently maps one lvar to
        another. All occurrences of the mapped variable are replaced by the new variable

        @param from: (C++: lvar_t *) the variable being mapped
        @param to: (C++: lvar_t *) the variable to map to. if nullptr, unmaps the variable
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_map_lvar(self, frm, to)

    def set_udm_type(self, udt_type: "tinfo_t", udm_idx: "int") -> "bool":
        r"""
        set_udm_type(self, udt_type, udm_idx) -> bool
        Set structure field type. This function displays a dialog box and allows the
        user to change the type of a structure field.

        @param udt_type: (C++: tinfo_t &) structure/union type
        @param udm_idx: (C++: int) index of the structure/union member
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_set_udm_type(self, udt_type, udm_idx)

    def rename_udm(self, udt_type: "tinfo_t", udm_idx: "int") -> "bool":
        r"""
        rename_udm(self, udt_type, udm_idx) -> bool
        Rename structure field. This function displays a dialog box and allows the user
        to rename a structure field.

        @param udt_type: (C++: tinfo_t &) structure/union type
        @param udm_idx: (C++: int) index of the structure/union member
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_rename_udm(self, udt_type, udm_idx)

    def set_global_type(self, ea: "ea_t") -> "bool":
        r"""
        set_global_type(self, ea) -> bool
        Set global item type. This function displays a dialog box and allows the user to
        change the type of a global item (data or function).

        @param ea: (C++: ea_t) address of the global item
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_set_global_type(self, ea)

    def rename_global(self, ea: "ea_t") -> "bool":
        r"""
        rename_global(self, ea) -> bool
        Rename global item. This function displays a dialog box and allows the user to
        rename a global item (data or function).

        @param ea: (C++: ea_t) address of the global item
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_rename_global(self, ea)

    def rename_label(self, label: "int") -> "bool":
        r"""
        rename_label(self, label) -> bool
        Rename a label. This function displays a dialog box and allows the user to
        rename a statement label.

        @param label: (C++: int) label number
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_rename_label(self, label)

    def jump_enter(self, idv: "input_device_t", omflags: "int") -> "bool":
        r"""
        jump_enter(self, idv, omflags) -> bool
        Process the Enter key. This function jumps to the definition of the item under
        the cursor. If the current item is a function, it will be decompiled. If the
        current item is a global data, its disassemly text will be displayed.

        @param idv: (C++: input_device_t) what cursor must be used, the keyboard or the mouse
        @param omflags: (C++: int) OM_NEWWIN: new pseudocode window will open, 0: reuse the
                        existing window
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_jump_enter(self, idv, omflags)

    def ctree_to_disasm(self) -> "bool":
        r"""
        ctree_to_disasm(self) -> bool
        Jump to disassembly. This function jumps to the address in the disassembly
        window which corresponds to the current item. The current item is determined
        based on the current keyboard cursor position.

        @return: false if failed
        """
        return _ida_hexrays.vdui_t_ctree_to_disasm(self)

    def calc_cmt_type(self, lnnum: "size_t", cmttype: "cmt_type_t") -> "cmt_type_t":
        r"""
        calc_cmt_type(self, lnnum, cmttype) -> cmt_type_t
        Check if the specified line can have a comment. Due to the coordinate system for
        comments: (\link{https://www.hex-rays.com/blog/coordinate-system-for-hex-rays})
        some function lines cannot have comments. This function checks if a comment can
        be attached to the specified line.

        @param lnnum: (C++: size_t) line number (0 based)
        @param cmttype: (C++: cmt_type_t) comment types to check
        @return: possible comment types
        """
        return _ida_hexrays.vdui_t_calc_cmt_type(self, lnnum, cmttype)

    def edit_cmt(self, loc: "treeloc_t") -> "bool":
        r"""
        edit_cmt(self, loc) -> bool
        Edit an indented comment. This function displays a dialog box and allows the
        user to edit the comment for the specified ctree location.

        @param loc: (C++: const treeloc_t &) comment location
        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_edit_cmt(self, loc)

    def edit_func_cmt(self) -> "bool":
        r"""
        edit_func_cmt(self) -> bool
        Edit a function comment. This function displays a dialog box and allows the user
        to edit the function comment.

        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_edit_func_cmt(self)

    def del_orphan_cmts(self) -> "bool":
        r"""
        del_orphan_cmts(self) -> bool
        Delete all orphan comments. Delete all orphan comments and refresh the screen.

        @return: true
        """
        return _ida_hexrays.vdui_t_del_orphan_cmts(self)

    def set_num_radix(self, base: "int") -> "bool":
        r"""
        set_num_radix(self, base) -> bool
        Change number base. This function changes the current number representation.

        @param base: (C++: int) number radix (10 or 16)
        0 means a character constant
        @return: false if failed
        """
        return _ida_hexrays.vdui_t_set_num_radix(self, base)

    def set_num_enum(self) -> "bool":
        r"""
        set_num_enum(self) -> bool
        Convert number to symbolic constant. This function displays a dialog box and
        allows the user to select a symbolic constant to represent the number.

        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_set_num_enum(self)

    def set_num_stroff(self) -> "bool":
        r"""
        set_num_stroff(self) -> bool
        Convert number to structure field offset. Currently not implemented.

        @return: false if failed or cancelled
        """
        return _ida_hexrays.vdui_t_set_num_stroff(self)

    def invert_sign(self) -> "bool":
        r"""
        invert_sign(self) -> bool
        Negate a number. This function negates the current number.

        @return: false if failed.
        """
        return _ida_hexrays.vdui_t_invert_sign(self)

    def invert_bits(self) -> "bool":
        r"""
        invert_bits(self) -> bool
        Bitwise negate a number. This function inverts all bits of the current number.

        @return: false if failed.
        """
        return _ida_hexrays.vdui_t_invert_bits(self)

    def collapse_item(self, hide: "bool") -> "bool":
        r"""
        collapse_item(self, hide) -> bool
        Collapse/uncollapse item. This function collapses the current item.

        @param hide: (C++: bool)
        @return: false if failed.
        """
        return _ida_hexrays.vdui_t_collapse_item(self, hide)

    def collapse_lvars(self, hide: "bool") -> "bool":
        r"""
        collapse_lvars(self, hide) -> bool
        Collapse/uncollapse local variable declarations.

        @param hide: (C++: bool)
        @return: false if failed.
        """
        return _ida_hexrays.vdui_t_collapse_lvars(self, hide)

    def split_item(self, split: "bool") -> "bool":
        r"""
        split_item(self, split) -> bool
        Split/unsplit item. This function splits the current assignment expression.

        @param split: (C++: bool)
        @return: false if failed.
        """
        return _ida_hexrays.vdui_t_split_item(self, split)
    __swig_destroy__ = _ida_hexrays.delete_vdui_t

# Register vdui_t in _ida_hexrays:
_ida_hexrays.vdui_t_swigregister(vdui_t)
CMT_NONE = cvar.CMT_NONE
r"""
No comment is possible.
"""
CMT_TAIL = cvar.CMT_TAIL
r"""
Indented comment.
"""
CMT_BLOCK1 = cvar.CMT_BLOCK1
r"""
Anterioir block comment.
"""
CMT_BLOCK2 = cvar.CMT_BLOCK2
r"""
Posterior block comment.
"""
CMT_LVAR = cvar.CMT_LVAR
r"""
Local variable comment.
"""
CMT_FUNC = cvar.CMT_FUNC
r"""
Function comment.
"""
CMT_ALL = cvar.CMT_ALL
r"""
All comments.
"""
VDUI_VISIBLE = _ida_hexrays.VDUI_VISIBLE
r"""
is visible?
"""

VDUI_VALID = _ida_hexrays.VDUI_VALID
r"""
is valid?
"""


class ui_stroff_op_t(object):
    r"""
    Proxy of C++ ui_stroff_op_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    text: "qstring" = property(_ida_hexrays.ui_stroff_op_t_text_get, _ida_hexrays.ui_stroff_op_t_text_set, doc=r"""text""")
    r"""
    any text for the column "Operand" of widget
    """
    offset: "uval_t" = property(_ida_hexrays.ui_stroff_op_t_offset_get, _ida_hexrays.ui_stroff_op_t_offset_set, doc=r"""offset""")
    r"""
    operand offset, will be used when calculating the UDT path
    """

    def __eq__(self, r: "ui_stroff_op_t") -> "bool":
        r"""
        __eq__(self, r) -> bool

        @param r: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_op_t___eq__(self, r)

    def __ne__(self, r: "ui_stroff_op_t") -> "bool":
        r"""
        __ne__(self, r) -> bool

        @param r: ui_stroff_op_t const &
        """
        return _ida_hexrays.ui_stroff_op_t___ne__(self, r)

    def __init__(self):
        r"""
        __init__(self) -> ui_stroff_op_t
        """
        _ida_hexrays.ui_stroff_op_t_swiginit(self, _ida_hexrays.new_ui_stroff_op_t())
    __swig_destroy__ = _ida_hexrays.delete_ui_stroff_op_t

# Register ui_stroff_op_t in _ida_hexrays:
_ida_hexrays.ui_stroff_op_t_swigregister(ui_stroff_op_t)
class ui_stroff_applicator_t(object):
    r"""
    Proxy of C++ ui_stroff_applicator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_hexrays.delete_ui_stroff_applicator_t

    def apply(self, opnum: "size_t", path: "intvec_t", top_tif: "tinfo_t", spath: "char const *") -> "bool":
        r"""
        apply(self, opnum, path, top_tif, spath) -> bool

        @param opnum: (C++: size_t) operand ordinal number, see below
        @param path: (C++: const intvec_t &) path describing the union selection, maybe empty
        @param top_tif: (C++: const tinfo_t &) tinfo_t of the selected toplevel UDT
        @param spath: (C++: const char *) selected path
        """
        return _ida_hexrays.ui_stroff_applicator_t_apply(self, opnum, path, top_tif, spath)

    def __init__(self):
        r"""
        __init__(self) -> ui_stroff_applicator_t

        @param self: PyObject *
        """
        if self.__class__ == ui_stroff_applicator_t:
            _self = None
        else:
            _self = self
        _ida_hexrays.ui_stroff_applicator_t_swiginit(self, _ida_hexrays.new_ui_stroff_applicator_t(_self, ))
    def __disown__(self):
        self.this.disown()
        _ida_hexrays.disown_ui_stroff_applicator_t(self)
        return weakref.proxy(self)

# Register ui_stroff_applicator_t in _ida_hexrays:
_ida_hexrays.ui_stroff_applicator_t_swigregister(ui_stroff_applicator_t)

def select_udt_by_offset(udts: "qvector< tinfo_t > const *", ops: "ui_stroff_ops_t", applicator: "ui_stroff_applicator_t") -> "int":
    r"""
    select_udt_by_offset(udts, ops, applicator) -> int
    Select UDT

    @param udts: (C++: const qvector< tinfo_t > *) list of UDT tinfo_t for the selection, if nullptr or empty then
                 UDTs from the "Local types" will be used
    @param ops: (C++: const ui_stroff_ops_t &) operands
    @param applicator: (C++: ui_stroff_applicator_t &) callback will be called to apply the selection for every
                       operand
    """
    return _ida_hexrays.select_udt_by_offset(udts, ops, applicator)
hx_user_numforms_begin = _ida_hexrays.hx_user_numforms_begin

hx_user_numforms_end = _ida_hexrays.hx_user_numforms_end

hx_user_numforms_next = _ida_hexrays.hx_user_numforms_next

hx_user_numforms_prev = _ida_hexrays.hx_user_numforms_prev

hx_user_numforms_first = _ida_hexrays.hx_user_numforms_first

hx_user_numforms_second = _ida_hexrays.hx_user_numforms_second

hx_user_numforms_find = _ida_hexrays.hx_user_numforms_find

hx_user_numforms_insert = _ida_hexrays.hx_user_numforms_insert

hx_user_numforms_erase = _ida_hexrays.hx_user_numforms_erase

hx_user_numforms_clear = _ida_hexrays.hx_user_numforms_clear

hx_user_numforms_size = _ida_hexrays.hx_user_numforms_size

hx_user_numforms_free = _ida_hexrays.hx_user_numforms_free

hx_user_numforms_new = _ida_hexrays.hx_user_numforms_new

hx_lvar_mapping_begin = _ida_hexrays.hx_lvar_mapping_begin

hx_lvar_mapping_end = _ida_hexrays.hx_lvar_mapping_end

hx_lvar_mapping_next = _ida_hexrays.hx_lvar_mapping_next

hx_lvar_mapping_prev = _ida_hexrays.hx_lvar_mapping_prev

hx_lvar_mapping_first = _ida_hexrays.hx_lvar_mapping_first

hx_lvar_mapping_second = _ida_hexrays.hx_lvar_mapping_second

hx_lvar_mapping_find = _ida_hexrays.hx_lvar_mapping_find

hx_lvar_mapping_insert = _ida_hexrays.hx_lvar_mapping_insert

hx_lvar_mapping_erase = _ida_hexrays.hx_lvar_mapping_erase

hx_lvar_mapping_clear = _ida_hexrays.hx_lvar_mapping_clear

hx_lvar_mapping_size = _ida_hexrays.hx_lvar_mapping_size

hx_lvar_mapping_free = _ida_hexrays.hx_lvar_mapping_free

hx_lvar_mapping_new = _ida_hexrays.hx_lvar_mapping_new

hx_udcall_map_begin = _ida_hexrays.hx_udcall_map_begin

hx_udcall_map_end = _ida_hexrays.hx_udcall_map_end

hx_udcall_map_next = _ida_hexrays.hx_udcall_map_next

hx_udcall_map_prev = _ida_hexrays.hx_udcall_map_prev

hx_udcall_map_first = _ida_hexrays.hx_udcall_map_first

hx_udcall_map_second = _ida_hexrays.hx_udcall_map_second

hx_udcall_map_find = _ida_hexrays.hx_udcall_map_find

hx_udcall_map_insert = _ida_hexrays.hx_udcall_map_insert

hx_udcall_map_erase = _ida_hexrays.hx_udcall_map_erase

hx_udcall_map_clear = _ida_hexrays.hx_udcall_map_clear

hx_udcall_map_size = _ida_hexrays.hx_udcall_map_size

hx_udcall_map_free = _ida_hexrays.hx_udcall_map_free

hx_udcall_map_new = _ida_hexrays.hx_udcall_map_new

hx_user_cmts_begin = _ida_hexrays.hx_user_cmts_begin

hx_user_cmts_end = _ida_hexrays.hx_user_cmts_end

hx_user_cmts_next = _ida_hexrays.hx_user_cmts_next

hx_user_cmts_prev = _ida_hexrays.hx_user_cmts_prev

hx_user_cmts_first = _ida_hexrays.hx_user_cmts_first

hx_user_cmts_second = _ida_hexrays.hx_user_cmts_second

hx_user_cmts_find = _ida_hexrays.hx_user_cmts_find

hx_user_cmts_insert = _ida_hexrays.hx_user_cmts_insert

hx_user_cmts_erase = _ida_hexrays.hx_user_cmts_erase

hx_user_cmts_clear = _ida_hexrays.hx_user_cmts_clear

hx_user_cmts_size = _ida_hexrays.hx_user_cmts_size

hx_user_cmts_free = _ida_hexrays.hx_user_cmts_free

hx_user_cmts_new = _ida_hexrays.hx_user_cmts_new

hx_user_iflags_begin = _ida_hexrays.hx_user_iflags_begin

hx_user_iflags_end = _ida_hexrays.hx_user_iflags_end

hx_user_iflags_next = _ida_hexrays.hx_user_iflags_next

hx_user_iflags_prev = _ida_hexrays.hx_user_iflags_prev

hx_user_iflags_first = _ida_hexrays.hx_user_iflags_first

hx_user_iflags_second = _ida_hexrays.hx_user_iflags_second

hx_user_iflags_find = _ida_hexrays.hx_user_iflags_find

hx_user_iflags_insert = _ida_hexrays.hx_user_iflags_insert

hx_user_iflags_erase = _ida_hexrays.hx_user_iflags_erase

hx_user_iflags_clear = _ida_hexrays.hx_user_iflags_clear

hx_user_iflags_size = _ida_hexrays.hx_user_iflags_size

hx_user_iflags_free = _ida_hexrays.hx_user_iflags_free

hx_user_iflags_new = _ida_hexrays.hx_user_iflags_new

hx_user_unions_begin = _ida_hexrays.hx_user_unions_begin

hx_user_unions_end = _ida_hexrays.hx_user_unions_end

hx_user_unions_next = _ida_hexrays.hx_user_unions_next

hx_user_unions_prev = _ida_hexrays.hx_user_unions_prev

hx_user_unions_first = _ida_hexrays.hx_user_unions_first

hx_user_unions_second = _ida_hexrays.hx_user_unions_second

hx_user_unions_find = _ida_hexrays.hx_user_unions_find

hx_user_unions_insert = _ida_hexrays.hx_user_unions_insert

hx_user_unions_erase = _ida_hexrays.hx_user_unions_erase

hx_user_unions_clear = _ida_hexrays.hx_user_unions_clear

hx_user_unions_size = _ida_hexrays.hx_user_unions_size

hx_user_unions_free = _ida_hexrays.hx_user_unions_free

hx_user_unions_new = _ida_hexrays.hx_user_unions_new

hx_user_labels_begin = _ida_hexrays.hx_user_labels_begin

hx_user_labels_end = _ida_hexrays.hx_user_labels_end

hx_user_labels_next = _ida_hexrays.hx_user_labels_next

hx_user_labels_prev = _ida_hexrays.hx_user_labels_prev

hx_user_labels_first = _ida_hexrays.hx_user_labels_first

hx_user_labels_second = _ida_hexrays.hx_user_labels_second

hx_user_labels_find = _ida_hexrays.hx_user_labels_find

hx_user_labels_insert = _ida_hexrays.hx_user_labels_insert

hx_user_labels_erase = _ida_hexrays.hx_user_labels_erase

hx_user_labels_clear = _ida_hexrays.hx_user_labels_clear

hx_user_labels_size = _ida_hexrays.hx_user_labels_size

hx_user_labels_free = _ida_hexrays.hx_user_labels_free

hx_user_labels_new = _ida_hexrays.hx_user_labels_new

hx_eamap_begin = _ida_hexrays.hx_eamap_begin

hx_eamap_end = _ida_hexrays.hx_eamap_end

hx_eamap_next = _ida_hexrays.hx_eamap_next

hx_eamap_prev = _ida_hexrays.hx_eamap_prev

hx_eamap_first = _ida_hexrays.hx_eamap_first

hx_eamap_second = _ida_hexrays.hx_eamap_second

hx_eamap_find = _ida_hexrays.hx_eamap_find

hx_eamap_insert = _ida_hexrays.hx_eamap_insert

hx_eamap_erase = _ida_hexrays.hx_eamap_erase

hx_eamap_clear = _ida_hexrays.hx_eamap_clear

hx_eamap_size = _ida_hexrays.hx_eamap_size

hx_eamap_free = _ida_hexrays.hx_eamap_free

hx_eamap_new = _ida_hexrays.hx_eamap_new

hx_boundaries_begin = _ida_hexrays.hx_boundaries_begin

hx_boundaries_end = _ida_hexrays.hx_boundaries_end

hx_boundaries_next = _ida_hexrays.hx_boundaries_next

hx_boundaries_prev = _ida_hexrays.hx_boundaries_prev

hx_boundaries_first = _ida_hexrays.hx_boundaries_first

hx_boundaries_second = _ida_hexrays.hx_boundaries_second

hx_boundaries_find = _ida_hexrays.hx_boundaries_find

hx_boundaries_insert = _ida_hexrays.hx_boundaries_insert

hx_boundaries_erase = _ida_hexrays.hx_boundaries_erase

hx_boundaries_clear = _ida_hexrays.hx_boundaries_clear

hx_boundaries_size = _ida_hexrays.hx_boundaries_size

hx_boundaries_free = _ida_hexrays.hx_boundaries_free

hx_boundaries_new = _ida_hexrays.hx_boundaries_new

hx_block_chains_begin = _ida_hexrays.hx_block_chains_begin

hx_block_chains_end = _ida_hexrays.hx_block_chains_end

hx_block_chains_next = _ida_hexrays.hx_block_chains_next

hx_block_chains_prev = _ida_hexrays.hx_block_chains_prev

hx_block_chains_get = _ida_hexrays.hx_block_chains_get

hx_block_chains_find = _ida_hexrays.hx_block_chains_find

hx_block_chains_insert = _ida_hexrays.hx_block_chains_insert

hx_block_chains_erase = _ida_hexrays.hx_block_chains_erase

hx_block_chains_clear = _ida_hexrays.hx_block_chains_clear

hx_block_chains_size = _ida_hexrays.hx_block_chains_size

hx_block_chains_free = _ida_hexrays.hx_block_chains_free

hx_block_chains_new = _ida_hexrays.hx_block_chains_new

hx_hexrays_alloc = _ida_hexrays.hx_hexrays_alloc

hx_hexrays_free = _ida_hexrays.hx_hexrays_free

hx_valrng_t_clear = _ida_hexrays.hx_valrng_t_clear

hx_valrng_t_copy = _ida_hexrays.hx_valrng_t_copy

hx_valrng_t_assign = _ida_hexrays.hx_valrng_t_assign

hx_valrng_t_compare = _ida_hexrays.hx_valrng_t_compare

hx_valrng_t_set_eq = _ida_hexrays.hx_valrng_t_set_eq

hx_valrng_t_set_cmp = _ida_hexrays.hx_valrng_t_set_cmp

hx_valrng_t_reduce_size = _ida_hexrays.hx_valrng_t_reduce_size

hx_valrng_t_intersect_with = _ida_hexrays.hx_valrng_t_intersect_with

hx_valrng_t_unite_with = _ida_hexrays.hx_valrng_t_unite_with

hx_valrng_t_inverse = _ida_hexrays.hx_valrng_t_inverse

hx_valrng_t_has = _ida_hexrays.hx_valrng_t_has

hx_valrng_t_print = _ida_hexrays.hx_valrng_t_print

hx_valrng_t_dstr = _ida_hexrays.hx_valrng_t_dstr

hx_valrng_t_cvt_to_single_value = _ida_hexrays.hx_valrng_t_cvt_to_single_value

hx_valrng_t_cvt_to_cmp = _ida_hexrays.hx_valrng_t_cvt_to_cmp

hx_get_merror_desc = _ida_hexrays.hx_get_merror_desc

hx_must_mcode_close_block = _ida_hexrays.hx_must_mcode_close_block

hx_is_mcode_propagatable = _ida_hexrays.hx_is_mcode_propagatable

hx_negate_mcode_relation = _ida_hexrays.hx_negate_mcode_relation

hx_swap_mcode_relation = _ida_hexrays.hx_swap_mcode_relation

hx_get_signed_mcode = _ida_hexrays.hx_get_signed_mcode

hx_get_unsigned_mcode = _ida_hexrays.hx_get_unsigned_mcode

hx_mcode_modifies_d = _ida_hexrays.hx_mcode_modifies_d

hx_operand_locator_t_compare = _ida_hexrays.hx_operand_locator_t_compare

hx_vd_printer_t_print = _ida_hexrays.hx_vd_printer_t_print

hx_file_printer_t_print = _ida_hexrays.hx_file_printer_t_print

hx_qstring_printer_t_print = _ida_hexrays.hx_qstring_printer_t_print

hx_dstr = _ida_hexrays.hx_dstr

hx_is_type_correct = _ida_hexrays.hx_is_type_correct

hx_is_small_udt = _ida_hexrays.hx_is_small_udt

hx_is_nonbool_type = _ida_hexrays.hx_is_nonbool_type

hx_is_bool_type = _ida_hexrays.hx_is_bool_type

hx_partial_type_num = _ida_hexrays.hx_partial_type_num

hx_get_float_type = _ida_hexrays.hx_get_float_type

hx_get_int_type_by_width_and_sign = _ida_hexrays.hx_get_int_type_by_width_and_sign

hx_get_unk_type = _ida_hexrays.hx_get_unk_type

hx_dummy_ptrtype = _ida_hexrays.hx_dummy_ptrtype

hx_get_member_type = _ida_hexrays.hx_get_member_type

hx_make_pointer = _ida_hexrays.hx_make_pointer

hx_create_typedef = _ida_hexrays.hx_create_typedef

hx_get_type = _ida_hexrays.hx_get_type

hx_set_type = _ida_hexrays.hx_set_type

hx_vdloc_t_dstr = _ida_hexrays.hx_vdloc_t_dstr

hx_vdloc_t_compare = _ida_hexrays.hx_vdloc_t_compare

hx_vdloc_t_is_aliasable = _ida_hexrays.hx_vdloc_t_is_aliasable

hx_print_vdloc = _ida_hexrays.hx_print_vdloc

hx_arglocs_overlap = _ida_hexrays.hx_arglocs_overlap

hx_lvar_locator_t_compare = _ida_hexrays.hx_lvar_locator_t_compare

hx_lvar_locator_t_dstr = _ida_hexrays.hx_lvar_locator_t_dstr

hx_lvar_t_dstr = _ida_hexrays.hx_lvar_t_dstr

hx_lvar_t_is_promoted_arg = _ida_hexrays.hx_lvar_t_is_promoted_arg

hx_lvar_t_accepts_type = _ida_hexrays.hx_lvar_t_accepts_type

hx_lvar_t_set_lvar_type = _ida_hexrays.hx_lvar_t_set_lvar_type

hx_lvar_t_set_width = _ida_hexrays.hx_lvar_t_set_width

hx_lvar_t_append_list = _ida_hexrays.hx_lvar_t_append_list

hx_lvar_t_append_list_ = _ida_hexrays.hx_lvar_t_append_list_

hx_lvars_t_find_stkvar = _ida_hexrays.hx_lvars_t_find_stkvar

hx_lvars_t_find = _ida_hexrays.hx_lvars_t_find

hx_lvars_t_find_lvar = _ida_hexrays.hx_lvars_t_find_lvar

hx_restore_user_lvar_settings = _ida_hexrays.hx_restore_user_lvar_settings

hx_save_user_lvar_settings = _ida_hexrays.hx_save_user_lvar_settings

hx_modify_user_lvars = _ida_hexrays.hx_modify_user_lvars

hx_modify_user_lvar_info = _ida_hexrays.hx_modify_user_lvar_info

hx_locate_lvar = _ida_hexrays.hx_locate_lvar

hx_restore_user_defined_calls = _ida_hexrays.hx_restore_user_defined_calls

hx_save_user_defined_calls = _ida_hexrays.hx_save_user_defined_calls

hx_parse_user_call = _ida_hexrays.hx_parse_user_call

hx_convert_to_user_call = _ida_hexrays.hx_convert_to_user_call

hx_install_microcode_filter = _ida_hexrays.hx_install_microcode_filter

hx_udc_filter_t_cleanup = _ida_hexrays.hx_udc_filter_t_cleanup

hx_udc_filter_t_init = _ida_hexrays.hx_udc_filter_t_init

hx_udc_filter_t_apply = _ida_hexrays.hx_udc_filter_t_apply

hx_bitset_t_bitset_t = _ida_hexrays.hx_bitset_t_bitset_t

hx_bitset_t_copy = _ida_hexrays.hx_bitset_t_copy

hx_bitset_t_add = _ida_hexrays.hx_bitset_t_add

hx_bitset_t_add_ = _ida_hexrays.hx_bitset_t_add_

hx_bitset_t_add__ = _ida_hexrays.hx_bitset_t_add__

hx_bitset_t_sub = _ida_hexrays.hx_bitset_t_sub

hx_bitset_t_sub_ = _ida_hexrays.hx_bitset_t_sub_

hx_bitset_t_sub__ = _ida_hexrays.hx_bitset_t_sub__

hx_bitset_t_cut_at = _ida_hexrays.hx_bitset_t_cut_at

hx_bitset_t_shift_down = _ida_hexrays.hx_bitset_t_shift_down

hx_bitset_t_has = _ida_hexrays.hx_bitset_t_has

hx_bitset_t_has_all = _ida_hexrays.hx_bitset_t_has_all

hx_bitset_t_has_any = _ida_hexrays.hx_bitset_t_has_any

hx_bitset_t_dstr = _ida_hexrays.hx_bitset_t_dstr

hx_bitset_t_empty = _ida_hexrays.hx_bitset_t_empty

hx_bitset_t_count = _ida_hexrays.hx_bitset_t_count

hx_bitset_t_count_ = _ida_hexrays.hx_bitset_t_count_

hx_bitset_t_last = _ida_hexrays.hx_bitset_t_last

hx_bitset_t_fill_with_ones = _ida_hexrays.hx_bitset_t_fill_with_ones

hx_bitset_t_fill_gaps = _ida_hexrays.hx_bitset_t_fill_gaps

hx_bitset_t_has_common = _ida_hexrays.hx_bitset_t_has_common

hx_bitset_t_intersect = _ida_hexrays.hx_bitset_t_intersect

hx_bitset_t_is_subset_of = _ida_hexrays.hx_bitset_t_is_subset_of

hx_bitset_t_compare = _ida_hexrays.hx_bitset_t_compare

hx_bitset_t_goup = _ida_hexrays.hx_bitset_t_goup

hx_ivl_t_dstr = _ida_hexrays.hx_ivl_t_dstr

hx_ivl_t_compare = _ida_hexrays.hx_ivl_t_compare

hx_ivlset_t_add = _ida_hexrays.hx_ivlset_t_add

hx_ivlset_t_add_ = _ida_hexrays.hx_ivlset_t_add_

hx_ivlset_t_addmasked = _ida_hexrays.hx_ivlset_t_addmasked

hx_ivlset_t_sub = _ida_hexrays.hx_ivlset_t_sub

hx_ivlset_t_sub_ = _ida_hexrays.hx_ivlset_t_sub_

hx_ivlset_t_has_common = _ida_hexrays.hx_ivlset_t_has_common

hx_ivlset_t_print = _ida_hexrays.hx_ivlset_t_print

hx_ivlset_t_dstr = _ida_hexrays.hx_ivlset_t_dstr

hx_ivlset_t_count = _ida_hexrays.hx_ivlset_t_count

hx_ivlset_t_has_common_ = _ida_hexrays.hx_ivlset_t_has_common_

hx_ivlset_t_contains = _ida_hexrays.hx_ivlset_t_contains

hx_ivlset_t_includes = _ida_hexrays.hx_ivlset_t_includes

hx_ivlset_t_intersect = _ida_hexrays.hx_ivlset_t_intersect

hx_ivlset_t_compare = _ida_hexrays.hx_ivlset_t_compare

hx_rlist_t_print = _ida_hexrays.hx_rlist_t_print

hx_rlist_t_dstr = _ida_hexrays.hx_rlist_t_dstr

hx_mlist_t_addmem = _ida_hexrays.hx_mlist_t_addmem

hx_mlist_t_print = _ida_hexrays.hx_mlist_t_print

hx_mlist_t_dstr = _ida_hexrays.hx_mlist_t_dstr

hx_mlist_t_compare = _ida_hexrays.hx_mlist_t_compare

hx_get_temp_regs = _ida_hexrays.hx_get_temp_regs

hx_is_kreg = _ida_hexrays.hx_is_kreg

hx_reg2mreg = _ida_hexrays.hx_reg2mreg

hx_mreg2reg = _ida_hexrays.hx_mreg2reg

hx_get_mreg_name = _ida_hexrays.hx_get_mreg_name

hx_install_optinsn_handler = _ida_hexrays.hx_install_optinsn_handler

hx_remove_optinsn_handler = _ida_hexrays.hx_remove_optinsn_handler

hx_install_optblock_handler = _ida_hexrays.hx_install_optblock_handler

hx_remove_optblock_handler = _ida_hexrays.hx_remove_optblock_handler

hx_simple_graph_t_compute_dominators = _ida_hexrays.hx_simple_graph_t_compute_dominators

hx_simple_graph_t_compute_immediate_dominators = _ida_hexrays.hx_simple_graph_t_compute_immediate_dominators

hx_simple_graph_t_depth_first_preorder = _ida_hexrays.hx_simple_graph_t_depth_first_preorder

hx_simple_graph_t_depth_first_postorder = _ida_hexrays.hx_simple_graph_t_depth_first_postorder

hx_simple_graph_t_goup = _ida_hexrays.hx_simple_graph_t_goup

hx_mutable_graph_t_resize = _ida_hexrays.hx_mutable_graph_t_resize

hx_mutable_graph_t_goup = _ida_hexrays.hx_mutable_graph_t_goup

hx_mutable_graph_t_del_edge = _ida_hexrays.hx_mutable_graph_t_del_edge

hx_lvar_ref_t_compare = _ida_hexrays.hx_lvar_ref_t_compare

hx_lvar_ref_t_var = _ida_hexrays.hx_lvar_ref_t_var

hx_stkvar_ref_t_compare = _ida_hexrays.hx_stkvar_ref_t_compare

hx_stkvar_ref_t_get_stkvar = _ida_hexrays.hx_stkvar_ref_t_get_stkvar

hx_fnumber_t_print = _ida_hexrays.hx_fnumber_t_print

hx_fnumber_t_dstr = _ida_hexrays.hx_fnumber_t_dstr

hx_mop_t_copy = _ida_hexrays.hx_mop_t_copy

hx_mop_t_assign = _ida_hexrays.hx_mop_t_assign

hx_mop_t_swap = _ida_hexrays.hx_mop_t_swap

hx_mop_t_erase = _ida_hexrays.hx_mop_t_erase

hx_mop_t_print = _ida_hexrays.hx_mop_t_print

hx_mop_t_dstr = _ida_hexrays.hx_mop_t_dstr

hx_mop_t_create_from_mlist = _ida_hexrays.hx_mop_t_create_from_mlist

hx_mop_t_create_from_ivlset = _ida_hexrays.hx_mop_t_create_from_ivlset

hx_mop_t_create_from_vdloc = _ida_hexrays.hx_mop_t_create_from_vdloc

hx_mop_t_create_from_scattered_vdloc = _ida_hexrays.hx_mop_t_create_from_scattered_vdloc

hx_mop_t_create_from_insn = _ida_hexrays.hx_mop_t_create_from_insn

hx_mop_t_make_number = _ida_hexrays.hx_mop_t_make_number

hx_mop_t_make_fpnum = _ida_hexrays.hx_mop_t_make_fpnum

hx_mop_t__make_gvar = _ida_hexrays.hx_mop_t__make_gvar

hx_mop_t_make_gvar = _ida_hexrays.hx_mop_t_make_gvar

hx_mop_t_make_reg_pair = _ida_hexrays.hx_mop_t_make_reg_pair

hx_mop_t_make_helper = _ida_hexrays.hx_mop_t_make_helper

hx_mop_t_is_bit_reg = _ida_hexrays.hx_mop_t_is_bit_reg

hx_mop_t_may_use_aliased_memory = _ida_hexrays.hx_mop_t_may_use_aliased_memory

hx_mop_t_is01 = _ida_hexrays.hx_mop_t_is01

hx_mop_t_is_sign_extended_from = _ida_hexrays.hx_mop_t_is_sign_extended_from

hx_mop_t_is_zero_extended_from = _ida_hexrays.hx_mop_t_is_zero_extended_from

hx_mop_t_equal_mops = _ida_hexrays.hx_mop_t_equal_mops

hx_mop_t_lexcompare = _ida_hexrays.hx_mop_t_lexcompare

hx_mop_t_for_all_ops = _ida_hexrays.hx_mop_t_for_all_ops

hx_mop_t_for_all_scattered_submops = _ida_hexrays.hx_mop_t_for_all_scattered_submops

hx_mop_t_is_constant = _ida_hexrays.hx_mop_t_is_constant

hx_mop_t_get_stkoff = _ida_hexrays.hx_mop_t_get_stkoff

hx_mop_t_make_low_half = _ida_hexrays.hx_mop_t_make_low_half

hx_mop_t_make_high_half = _ida_hexrays.hx_mop_t_make_high_half

hx_mop_t_make_first_half = _ida_hexrays.hx_mop_t_make_first_half

hx_mop_t_make_second_half = _ida_hexrays.hx_mop_t_make_second_half

hx_mop_t_shift_mop = _ida_hexrays.hx_mop_t_shift_mop

hx_mop_t_change_size = _ida_hexrays.hx_mop_t_change_size

hx_mop_t_preserve_side_effects = _ida_hexrays.hx_mop_t_preserve_side_effects

hx_mop_t_apply_ld_mcode = _ida_hexrays.hx_mop_t_apply_ld_mcode

hx_mcallarg_t_print = _ida_hexrays.hx_mcallarg_t_print

hx_mcallarg_t_dstr = _ida_hexrays.hx_mcallarg_t_dstr

hx_mcallarg_t_set_regarg = _ida_hexrays.hx_mcallarg_t_set_regarg

hx_mcallinfo_t_lexcompare = _ida_hexrays.hx_mcallinfo_t_lexcompare

hx_mcallinfo_t_set_type = _ida_hexrays.hx_mcallinfo_t_set_type

hx_mcallinfo_t_get_type = _ida_hexrays.hx_mcallinfo_t_get_type

hx_mcallinfo_t_print = _ida_hexrays.hx_mcallinfo_t_print

hx_mcallinfo_t_dstr = _ida_hexrays.hx_mcallinfo_t_dstr

hx_mcases_t_compare = _ida_hexrays.hx_mcases_t_compare

hx_mcases_t_print = _ida_hexrays.hx_mcases_t_print

hx_mcases_t_dstr = _ida_hexrays.hx_mcases_t_dstr

hx_vivl_t_extend_to_cover = _ida_hexrays.hx_vivl_t_extend_to_cover

hx_vivl_t_intersect = _ida_hexrays.hx_vivl_t_intersect

hx_vivl_t_print = _ida_hexrays.hx_vivl_t_print

hx_vivl_t_dstr = _ida_hexrays.hx_vivl_t_dstr

hx_chain_t_print = _ida_hexrays.hx_chain_t_print

hx_chain_t_dstr = _ida_hexrays.hx_chain_t_dstr

hx_chain_t_append_list = _ida_hexrays.hx_chain_t_append_list

hx_chain_t_append_list_ = _ida_hexrays.hx_chain_t_append_list_

hx_block_chains_t_get_chain = _ida_hexrays.hx_block_chains_t_get_chain

hx_block_chains_t_print = _ida_hexrays.hx_block_chains_t_print

hx_block_chains_t_dstr = _ida_hexrays.hx_block_chains_t_dstr

hx_graph_chains_t_for_all_chains = _ida_hexrays.hx_graph_chains_t_for_all_chains

hx_graph_chains_t_release = _ida_hexrays.hx_graph_chains_t_release

hx_minsn_t_init = _ida_hexrays.hx_minsn_t_init

hx_minsn_t_copy = _ida_hexrays.hx_minsn_t_copy

hx_minsn_t_set_combined = _ida_hexrays.hx_minsn_t_set_combined

hx_minsn_t_swap = _ida_hexrays.hx_minsn_t_swap

hx_minsn_t_print = _ida_hexrays.hx_minsn_t_print

hx_minsn_t_dstr = _ida_hexrays.hx_minsn_t_dstr

hx_minsn_t_setaddr = _ida_hexrays.hx_minsn_t_setaddr

hx_minsn_t_optimize_subtree = _ida_hexrays.hx_minsn_t_optimize_subtree

hx_minsn_t_for_all_ops = _ida_hexrays.hx_minsn_t_for_all_ops

hx_minsn_t_for_all_insns = _ida_hexrays.hx_minsn_t_for_all_insns

hx_minsn_t__make_nop = _ida_hexrays.hx_minsn_t__make_nop

hx_minsn_t_equal_insns = _ida_hexrays.hx_minsn_t_equal_insns

hx_minsn_t_lexcompare = _ida_hexrays.hx_minsn_t_lexcompare

hx_minsn_t_is_noret_call = _ida_hexrays.hx_minsn_t_is_noret_call

hx_minsn_t_is_helper = _ida_hexrays.hx_minsn_t_is_helper

hx_minsn_t_find_call = _ida_hexrays.hx_minsn_t_find_call

hx_minsn_t_has_side_effects = _ida_hexrays.hx_minsn_t_has_side_effects

hx_minsn_t_find_opcode = _ida_hexrays.hx_minsn_t_find_opcode

hx_minsn_t_find_ins_op = _ida_hexrays.hx_minsn_t_find_ins_op

hx_minsn_t_find_num_op = _ida_hexrays.hx_minsn_t_find_num_op

hx_minsn_t_modifies_d = _ida_hexrays.hx_minsn_t_modifies_d

hx_minsn_t_is_between = _ida_hexrays.hx_minsn_t_is_between

hx_minsn_t_may_use_aliased_memory = _ida_hexrays.hx_minsn_t_may_use_aliased_memory

hx_minsn_t_serialize = _ida_hexrays.hx_minsn_t_serialize

hx_minsn_t_deserialize = _ida_hexrays.hx_minsn_t_deserialize

hx_getf_reginsn = _ida_hexrays.hx_getf_reginsn

hx_getb_reginsn = _ida_hexrays.hx_getb_reginsn

hx_mblock_t_init = _ida_hexrays.hx_mblock_t_init

hx_mblock_t_print = _ida_hexrays.hx_mblock_t_print

hx_mblock_t_dump = _ida_hexrays.hx_mblock_t_dump

hx_mblock_t_vdump_block = _ida_hexrays.hx_mblock_t_vdump_block

hx_mblock_t_insert_into_block = _ida_hexrays.hx_mblock_t_insert_into_block

hx_mblock_t_remove_from_block = _ida_hexrays.hx_mblock_t_remove_from_block

hx_mblock_t_for_all_insns = _ida_hexrays.hx_mblock_t_for_all_insns

hx_mblock_t_for_all_ops = _ida_hexrays.hx_mblock_t_for_all_ops

hx_mblock_t_for_all_uses = _ida_hexrays.hx_mblock_t_for_all_uses

hx_mblock_t_optimize_insn = _ida_hexrays.hx_mblock_t_optimize_insn

hx_mblock_t_optimize_block = _ida_hexrays.hx_mblock_t_optimize_block

hx_mblock_t_build_lists = _ida_hexrays.hx_mblock_t_build_lists

hx_mblock_t_optimize_useless_jump = _ida_hexrays.hx_mblock_t_optimize_useless_jump

hx_mblock_t_append_use_list = _ida_hexrays.hx_mblock_t_append_use_list

hx_mblock_t_append_def_list = _ida_hexrays.hx_mblock_t_append_def_list

hx_mblock_t_build_use_list = _ida_hexrays.hx_mblock_t_build_use_list

hx_mblock_t_build_def_list = _ida_hexrays.hx_mblock_t_build_def_list

hx_mblock_t_find_first_use = _ida_hexrays.hx_mblock_t_find_first_use

hx_mblock_t_find_redefinition = _ida_hexrays.hx_mblock_t_find_redefinition

hx_mblock_t_is_rhs_redefined = _ida_hexrays.hx_mblock_t_is_rhs_redefined

hx_mblock_t_find_access = _ida_hexrays.hx_mblock_t_find_access

hx_mblock_t_get_valranges = _ida_hexrays.hx_mblock_t_get_valranges

hx_mblock_t_get_valranges_ = _ida_hexrays.hx_mblock_t_get_valranges_

hx_mblock_t_get_reginsn_qty = _ida_hexrays.hx_mblock_t_get_reginsn_qty

hx_mba_ranges_t_range_contains = _ida_hexrays.hx_mba_ranges_t_range_contains

hx_mba_t_stkoff_vd2ida = _ida_hexrays.hx_mba_t_stkoff_vd2ida

hx_mba_t_stkoff_ida2vd = _ida_hexrays.hx_mba_t_stkoff_ida2vd

hx_mba_t_idaloc2vd = _ida_hexrays.hx_mba_t_idaloc2vd

hx_mba_t_idaloc2vd_ = _ida_hexrays.hx_mba_t_idaloc2vd_

hx_mba_t_vd2idaloc = _ida_hexrays.hx_mba_t_vd2idaloc

hx_mba_t_vd2idaloc_ = _ida_hexrays.hx_mba_t_vd2idaloc_

hx_mba_t_term = _ida_hexrays.hx_mba_t_term

hx_mba_t_get_curfunc = _ida_hexrays.hx_mba_t_get_curfunc

hx_mba_t_set_maturity = _ida_hexrays.hx_mba_t_set_maturity

hx_mba_t_optimize_local = _ida_hexrays.hx_mba_t_optimize_local

hx_mba_t_build_graph = _ida_hexrays.hx_mba_t_build_graph

hx_mba_t_get_graph = _ida_hexrays.hx_mba_t_get_graph

hx_mba_t_analyze_calls = _ida_hexrays.hx_mba_t_analyze_calls

hx_mba_t_optimize_global = _ida_hexrays.hx_mba_t_optimize_global

hx_mba_t_alloc_lvars = _ida_hexrays.hx_mba_t_alloc_lvars

hx_mba_t_dump = _ida_hexrays.hx_mba_t_dump

hx_mba_t_vdump_mba = _ida_hexrays.hx_mba_t_vdump_mba

hx_mba_t_print = _ida_hexrays.hx_mba_t_print

hx_mba_t_verify = _ida_hexrays.hx_mba_t_verify

hx_mba_t_mark_chains_dirty = _ida_hexrays.hx_mba_t_mark_chains_dirty

hx_mba_t_insert_block = _ida_hexrays.hx_mba_t_insert_block

hx_mba_t_remove_block = _ida_hexrays.hx_mba_t_remove_block

hx_mba_t_copy_block = _ida_hexrays.hx_mba_t_copy_block

hx_mba_t_remove_empty_and_unreachable_blocks = _ida_hexrays.hx_mba_t_remove_empty_and_unreachable_blocks

hx_mba_t_merge_blocks = _ida_hexrays.hx_mba_t_merge_blocks

hx_mba_t_for_all_ops = _ida_hexrays.hx_mba_t_for_all_ops

hx_mba_t_for_all_insns = _ida_hexrays.hx_mba_t_for_all_insns

hx_mba_t_for_all_topinsns = _ida_hexrays.hx_mba_t_for_all_topinsns

hx_mba_t_find_mop = _ida_hexrays.hx_mba_t_find_mop

hx_mba_t_create_helper_call = _ida_hexrays.hx_mba_t_create_helper_call

hx_mba_t_get_func_output_lists = _ida_hexrays.hx_mba_t_get_func_output_lists

hx_mba_t_arg = _ida_hexrays.hx_mba_t_arg

hx_mba_t_alloc_fict_ea = _ida_hexrays.hx_mba_t_alloc_fict_ea

hx_mba_t_map_fict_ea = _ida_hexrays.hx_mba_t_map_fict_ea

hx_mba_t_serialize = _ida_hexrays.hx_mba_t_serialize

hx_mba_t_deserialize = _ida_hexrays.hx_mba_t_deserialize

hx_mba_t_save_snapshot = _ida_hexrays.hx_mba_t_save_snapshot

hx_mba_t_alloc_kreg = _ida_hexrays.hx_mba_t_alloc_kreg

hx_mba_t_free_kreg = _ida_hexrays.hx_mba_t_free_kreg

hx_mba_t_inline_func = _ida_hexrays.hx_mba_t_inline_func

hx_mba_t_locate_stkpnt = _ida_hexrays.hx_mba_t_locate_stkpnt

hx_mba_t_set_lvar_name = _ida_hexrays.hx_mba_t_set_lvar_name

hx_mbl_graph_t_is_accessed_globally = _ida_hexrays.hx_mbl_graph_t_is_accessed_globally

hx_mbl_graph_t_get_ud = _ida_hexrays.hx_mbl_graph_t_get_ud

hx_mbl_graph_t_get_du = _ida_hexrays.hx_mbl_graph_t_get_du

hx_cdg_insn_iterator_t_next = _ida_hexrays.hx_cdg_insn_iterator_t_next

hx_codegen_t_clear = _ida_hexrays.hx_codegen_t_clear

hx_codegen_t_emit = _ida_hexrays.hx_codegen_t_emit

hx_codegen_t_emit_ = _ida_hexrays.hx_codegen_t_emit_

hx_change_hexrays_config = _ida_hexrays.hx_change_hexrays_config

hx_get_hexrays_version = _ida_hexrays.hx_get_hexrays_version

hx_open_pseudocode = _ida_hexrays.hx_open_pseudocode

hx_close_pseudocode = _ida_hexrays.hx_close_pseudocode

hx_get_widget_vdui = _ida_hexrays.hx_get_widget_vdui

hx_decompile_many = _ida_hexrays.hx_decompile_many

hx_hexrays_failure_t_desc = _ida_hexrays.hx_hexrays_failure_t_desc

hx_send_database = _ida_hexrays.hx_send_database

hx_gco_info_t_append_to_list = _ida_hexrays.hx_gco_info_t_append_to_list

hx_get_current_operand = _ida_hexrays.hx_get_current_operand

hx_remitem = _ida_hexrays.hx_remitem

hx_negated_relation = _ida_hexrays.hx_negated_relation

hx_swapped_relation = _ida_hexrays.hx_swapped_relation

hx_get_op_signness = _ida_hexrays.hx_get_op_signness

hx_asgop = _ida_hexrays.hx_asgop

hx_asgop_revert = _ida_hexrays.hx_asgop_revert

hx_cnumber_t_print = _ida_hexrays.hx_cnumber_t_print

hx_cnumber_t_value = _ida_hexrays.hx_cnumber_t_value

hx_cnumber_t_assign = _ida_hexrays.hx_cnumber_t_assign

hx_cnumber_t_compare = _ida_hexrays.hx_cnumber_t_compare

hx_var_ref_t_compare = _ida_hexrays.hx_var_ref_t_compare

hx_ctree_visitor_t_apply_to = _ida_hexrays.hx_ctree_visitor_t_apply_to

hx_ctree_visitor_t_apply_to_exprs = _ida_hexrays.hx_ctree_visitor_t_apply_to_exprs

hx_ctree_parentee_t_recalc_parent_types = _ida_hexrays.hx_ctree_parentee_t_recalc_parent_types

hx_cfunc_parentee_t_calc_rvalue_type = _ida_hexrays.hx_cfunc_parentee_t_calc_rvalue_type

hx_citem_locator_t_compare = _ida_hexrays.hx_citem_locator_t_compare

hx_citem_t_contains_expr = _ida_hexrays.hx_citem_t_contains_expr

hx_citem_t_contains_label = _ida_hexrays.hx_citem_t_contains_label

hx_citem_t_find_parent_of = _ida_hexrays.hx_citem_t_find_parent_of

hx_citem_t_find_closest_addr = _ida_hexrays.hx_citem_t_find_closest_addr

hx_cexpr_t_assign = _ida_hexrays.hx_cexpr_t_assign

hx_cexpr_t_compare = _ida_hexrays.hx_cexpr_t_compare

hx_cexpr_t_replace_by = _ida_hexrays.hx_cexpr_t_replace_by

hx_cexpr_t_cleanup = _ida_hexrays.hx_cexpr_t_cleanup

hx_cexpr_t_put_number = _ida_hexrays.hx_cexpr_t_put_number

hx_cexpr_t_print1 = _ida_hexrays.hx_cexpr_t_print1

hx_cexpr_t_calc_type = _ida_hexrays.hx_cexpr_t_calc_type

hx_cexpr_t_equal_effect = _ida_hexrays.hx_cexpr_t_equal_effect

hx_cexpr_t_is_child_of = _ida_hexrays.hx_cexpr_t_is_child_of

hx_cexpr_t_contains_operator = _ida_hexrays.hx_cexpr_t_contains_operator

hx_cexpr_t_get_high_nbit_bound = _ida_hexrays.hx_cexpr_t_get_high_nbit_bound

hx_cexpr_t_get_low_nbit_bound = _ida_hexrays.hx_cexpr_t_get_low_nbit_bound

hx_cexpr_t_requires_lvalue = _ida_hexrays.hx_cexpr_t_requires_lvalue

hx_cexpr_t_has_side_effects = _ida_hexrays.hx_cexpr_t_has_side_effects

hx_cexpr_t_maybe_ptr = _ida_hexrays.hx_cexpr_t_maybe_ptr

hx_cexpr_t_dstr = _ida_hexrays.hx_cexpr_t_dstr

hx_cif_t_assign = _ida_hexrays.hx_cif_t_assign

hx_cif_t_compare = _ida_hexrays.hx_cif_t_compare

hx_cloop_t_assign = _ida_hexrays.hx_cloop_t_assign

hx_cfor_t_compare = _ida_hexrays.hx_cfor_t_compare

hx_cwhile_t_compare = _ida_hexrays.hx_cwhile_t_compare

hx_cdo_t_compare = _ida_hexrays.hx_cdo_t_compare

hx_creturn_t_compare = _ida_hexrays.hx_creturn_t_compare

hx_cthrow_t_compare = _ida_hexrays.hx_cthrow_t_compare

hx_cgoto_t_compare = _ida_hexrays.hx_cgoto_t_compare

hx_casm_t_compare = _ida_hexrays.hx_casm_t_compare

hx_cinsn_t_assign = _ida_hexrays.hx_cinsn_t_assign

hx_cinsn_t_compare = _ida_hexrays.hx_cinsn_t_compare

hx_cinsn_t_replace_by = _ida_hexrays.hx_cinsn_t_replace_by

hx_cinsn_t_cleanup = _ida_hexrays.hx_cinsn_t_cleanup

hx_cinsn_t_new_insn = _ida_hexrays.hx_cinsn_t_new_insn

hx_cinsn_t_create_if = _ida_hexrays.hx_cinsn_t_create_if

hx_cinsn_t_print = _ida_hexrays.hx_cinsn_t_print

hx_cinsn_t_print1 = _ida_hexrays.hx_cinsn_t_print1

hx_cinsn_t_is_ordinary_flow = _ida_hexrays.hx_cinsn_t_is_ordinary_flow

hx_cinsn_t_contains_insn = _ida_hexrays.hx_cinsn_t_contains_insn

hx_cinsn_t_collect_free_breaks = _ida_hexrays.hx_cinsn_t_collect_free_breaks

hx_cinsn_t_collect_free_continues = _ida_hexrays.hx_cinsn_t_collect_free_continues

hx_cinsn_t_dstr = _ida_hexrays.hx_cinsn_t_dstr

hx_cblock_t_compare = _ida_hexrays.hx_cblock_t_compare

hx_carglist_t_compare = _ida_hexrays.hx_carglist_t_compare

hx_ccase_t_compare = _ida_hexrays.hx_ccase_t_compare

hx_ccases_t_compare = _ida_hexrays.hx_ccases_t_compare

hx_cswitch_t_compare = _ida_hexrays.hx_cswitch_t_compare

hx_ccatch_t_compare = _ida_hexrays.hx_ccatch_t_compare

hx_ctry_t_compare = _ida_hexrays.hx_ctry_t_compare

hx_ctree_item_t_get_udm = _ida_hexrays.hx_ctree_item_t_get_udm

hx_ctree_item_t_get_edm = _ida_hexrays.hx_ctree_item_t_get_edm

hx_ctree_item_t_get_lvar = _ida_hexrays.hx_ctree_item_t_get_lvar

hx_ctree_item_t_get_ea = _ida_hexrays.hx_ctree_item_t_get_ea

hx_ctree_item_t_get_label_num = _ida_hexrays.hx_ctree_item_t_get_label_num

hx_ctree_item_t_print = _ida_hexrays.hx_ctree_item_t_print

hx_ctree_item_t_dstr = _ida_hexrays.hx_ctree_item_t_dstr

hx_lnot = _ida_hexrays.hx_lnot

hx_new_block = _ida_hexrays.hx_new_block

hx_vcreate_helper = _ida_hexrays.hx_vcreate_helper

hx_vcall_helper = _ida_hexrays.hx_vcall_helper

hx_make_num = _ida_hexrays.hx_make_num

hx_make_ref = _ida_hexrays.hx_make_ref

hx_dereference = _ida_hexrays.hx_dereference

hx_save_user_labels = _ida_hexrays.hx_save_user_labels

hx_save_user_cmts = _ida_hexrays.hx_save_user_cmts

hx_save_user_numforms = _ida_hexrays.hx_save_user_numforms

hx_save_user_iflags = _ida_hexrays.hx_save_user_iflags

hx_save_user_unions = _ida_hexrays.hx_save_user_unions

hx_restore_user_labels = _ida_hexrays.hx_restore_user_labels

hx_restore_user_cmts = _ida_hexrays.hx_restore_user_cmts

hx_restore_user_numforms = _ida_hexrays.hx_restore_user_numforms

hx_restore_user_iflags = _ida_hexrays.hx_restore_user_iflags

hx_restore_user_unions = _ida_hexrays.hx_restore_user_unions

hx_cfunc_t_build_c_tree = _ida_hexrays.hx_cfunc_t_build_c_tree

hx_cfunc_t_verify = _ida_hexrays.hx_cfunc_t_verify

hx_cfunc_t_print_dcl = _ida_hexrays.hx_cfunc_t_print_dcl

hx_cfunc_t_print_func = _ida_hexrays.hx_cfunc_t_print_func

hx_cfunc_t_get_func_type = _ida_hexrays.hx_cfunc_t_get_func_type

hx_cfunc_t_get_lvars = _ida_hexrays.hx_cfunc_t_get_lvars

hx_cfunc_t_get_stkoff_delta = _ida_hexrays.hx_cfunc_t_get_stkoff_delta

hx_cfunc_t_find_label = _ida_hexrays.hx_cfunc_t_find_label

hx_cfunc_t_remove_unused_labels = _ida_hexrays.hx_cfunc_t_remove_unused_labels

hx_cfunc_t_get_user_cmt = _ida_hexrays.hx_cfunc_t_get_user_cmt

hx_cfunc_t_set_user_cmt = _ida_hexrays.hx_cfunc_t_set_user_cmt

hx_cfunc_t_get_user_iflags = _ida_hexrays.hx_cfunc_t_get_user_iflags

hx_cfunc_t_set_user_iflags = _ida_hexrays.hx_cfunc_t_set_user_iflags

hx_cfunc_t_has_orphan_cmts = _ida_hexrays.hx_cfunc_t_has_orphan_cmts

hx_cfunc_t_del_orphan_cmts = _ida_hexrays.hx_cfunc_t_del_orphan_cmts

hx_cfunc_t_get_user_union_selection = _ida_hexrays.hx_cfunc_t_get_user_union_selection

hx_cfunc_t_set_user_union_selection = _ida_hexrays.hx_cfunc_t_set_user_union_selection

hx_cfunc_t_save_user_labels = _ida_hexrays.hx_cfunc_t_save_user_labels

hx_cfunc_t_save_user_cmts = _ida_hexrays.hx_cfunc_t_save_user_cmts

hx_cfunc_t_save_user_numforms = _ida_hexrays.hx_cfunc_t_save_user_numforms

hx_cfunc_t_save_user_iflags = _ida_hexrays.hx_cfunc_t_save_user_iflags

hx_cfunc_t_save_user_unions = _ida_hexrays.hx_cfunc_t_save_user_unions

hx_cfunc_t_get_line_item = _ida_hexrays.hx_cfunc_t_get_line_item

hx_cfunc_t_get_warnings = _ida_hexrays.hx_cfunc_t_get_warnings

hx_cfunc_t_get_eamap = _ida_hexrays.hx_cfunc_t_get_eamap

hx_cfunc_t_get_boundaries = _ida_hexrays.hx_cfunc_t_get_boundaries

hx_cfunc_t_get_pseudocode = _ida_hexrays.hx_cfunc_t_get_pseudocode

hx_cfunc_t_refresh_func_ctext = _ida_hexrays.hx_cfunc_t_refresh_func_ctext

hx_cfunc_t_gather_derefs = _ida_hexrays.hx_cfunc_t_gather_derefs

hx_cfunc_t_find_item_coords = _ida_hexrays.hx_cfunc_t_find_item_coords

hx_cfunc_t_cleanup = _ida_hexrays.hx_cfunc_t_cleanup

hx_close_hexrays_waitbox = _ida_hexrays.hx_close_hexrays_waitbox

hx_decompile = _ida_hexrays.hx_decompile

hx_gen_microcode = _ida_hexrays.hx_gen_microcode

hx_create_cfunc = _ida_hexrays.hx_create_cfunc

hx_mark_cfunc_dirty = _ida_hexrays.hx_mark_cfunc_dirty

hx_clear_cached_cfuncs = _ida_hexrays.hx_clear_cached_cfuncs

hx_has_cached_cfunc = _ida_hexrays.hx_has_cached_cfunc

hx_get_ctype_name = _ida_hexrays.hx_get_ctype_name

hx_create_field_name = _ida_hexrays.hx_create_field_name

hx_install_hexrays_callback = _ida_hexrays.hx_install_hexrays_callback

hx_remove_hexrays_callback = _ida_hexrays.hx_remove_hexrays_callback

hx_vdui_t_set_locked = _ida_hexrays.hx_vdui_t_set_locked

hx_vdui_t_refresh_view = _ida_hexrays.hx_vdui_t_refresh_view

hx_vdui_t_refresh_ctext = _ida_hexrays.hx_vdui_t_refresh_ctext

hx_vdui_t_switch_to = _ida_hexrays.hx_vdui_t_switch_to

hx_vdui_t_get_number = _ida_hexrays.hx_vdui_t_get_number

hx_vdui_t_get_current_label = _ida_hexrays.hx_vdui_t_get_current_label

hx_vdui_t_clear = _ida_hexrays.hx_vdui_t_clear

hx_vdui_t_refresh_cpos = _ida_hexrays.hx_vdui_t_refresh_cpos

hx_vdui_t_get_current_item = _ida_hexrays.hx_vdui_t_get_current_item

hx_vdui_t_ui_rename_lvar = _ida_hexrays.hx_vdui_t_ui_rename_lvar

hx_vdui_t_rename_lvar = _ida_hexrays.hx_vdui_t_rename_lvar

hx_vdui_t_ui_set_call_type = _ida_hexrays.hx_vdui_t_ui_set_call_type

hx_vdui_t_ui_set_lvar_type = _ida_hexrays.hx_vdui_t_ui_set_lvar_type

hx_vdui_t_set_lvar_type = _ida_hexrays.hx_vdui_t_set_lvar_type

hx_vdui_t_set_noptr_lvar = _ida_hexrays.hx_vdui_t_set_noptr_lvar

hx_vdui_t_ui_edit_lvar_cmt = _ida_hexrays.hx_vdui_t_ui_edit_lvar_cmt

hx_vdui_t_set_lvar_cmt = _ida_hexrays.hx_vdui_t_set_lvar_cmt

hx_vdui_t_ui_map_lvar = _ida_hexrays.hx_vdui_t_ui_map_lvar

hx_vdui_t_ui_unmap_lvar = _ida_hexrays.hx_vdui_t_ui_unmap_lvar

hx_vdui_t_map_lvar = _ida_hexrays.hx_vdui_t_map_lvar

hx_vdui_t_set_udm_type = _ida_hexrays.hx_vdui_t_set_udm_type

hx_vdui_t_rename_udm = _ida_hexrays.hx_vdui_t_rename_udm

hx_vdui_t_set_global_type = _ida_hexrays.hx_vdui_t_set_global_type

hx_vdui_t_rename_global = _ida_hexrays.hx_vdui_t_rename_global

hx_vdui_t_rename_label = _ida_hexrays.hx_vdui_t_rename_label

hx_vdui_t_jump_enter = _ida_hexrays.hx_vdui_t_jump_enter

hx_vdui_t_ctree_to_disasm = _ida_hexrays.hx_vdui_t_ctree_to_disasm

hx_vdui_t_calc_cmt_type = _ida_hexrays.hx_vdui_t_calc_cmt_type

hx_vdui_t_edit_cmt = _ida_hexrays.hx_vdui_t_edit_cmt

hx_vdui_t_edit_func_cmt = _ida_hexrays.hx_vdui_t_edit_func_cmt

hx_vdui_t_del_orphan_cmts = _ida_hexrays.hx_vdui_t_del_orphan_cmts

hx_vdui_t_set_num_radix = _ida_hexrays.hx_vdui_t_set_num_radix

hx_vdui_t_set_num_enum = _ida_hexrays.hx_vdui_t_set_num_enum

hx_vdui_t_set_num_stroff = _ida_hexrays.hx_vdui_t_set_num_stroff

hx_vdui_t_invert_sign = _ida_hexrays.hx_vdui_t_invert_sign

hx_vdui_t_invert_bits = _ida_hexrays.hx_vdui_t_invert_bits

hx_vdui_t_collapse_item = _ida_hexrays.hx_vdui_t_collapse_item

hx_vdui_t_collapse_lvars = _ida_hexrays.hx_vdui_t_collapse_lvars

hx_vdui_t_split_item = _ida_hexrays.hx_vdui_t_split_item

hx_select_udt_by_offset = _ida_hexrays.hx_select_udt_by_offset

hx_catchexpr_t_compare = _ida_hexrays.hx_catchexpr_t_compare

hx_mba_t_split_block = _ida_hexrays.hx_mba_t_split_block

hx_mba_t_remove_blocks = _ida_hexrays.hx_mba_t_remove_blocks

class user_numforms_iterator_t(object):
    r"""
    Proxy of C++ user_numforms_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.user_numforms_iterator_t_x_get, _ida_hexrays.user_numforms_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "user_numforms_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: user_numforms_iterator_t const &
        """
        return _ida_hexrays.user_numforms_iterator_t___eq__(self, p)

    def __ne__(self, p: "user_numforms_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: user_numforms_iterator_t const &
        """
        return _ida_hexrays.user_numforms_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> user_numforms_iterator_t
        """
        _ida_hexrays.user_numforms_iterator_t_swiginit(self, _ida_hexrays.new_user_numforms_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_user_numforms_iterator_t

# Register user_numforms_iterator_t in _ida_hexrays:
_ida_hexrays.user_numforms_iterator_t_swigregister(user_numforms_iterator_t)

def user_numforms_first(p: "user_numforms_iterator_t") -> "operand_locator_t const &":
    r"""
    user_numforms_first(p) -> operand_locator_t
    Get reference to the current map key.

    @param p: (C++: user_numforms_iterator_t)
    """
    return _ida_hexrays.user_numforms_first(p)

def user_numforms_second(p: "user_numforms_iterator_t") -> "number_format_t &":
    r"""
    user_numforms_second(p) -> number_format_t
    Get reference to the current map value.

    @param p: (C++: user_numforms_iterator_t)
    """
    return _ida_hexrays.user_numforms_second(p)

def user_numforms_find(map: "user_numforms_t", key: "operand_locator_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_find(map, key) -> user_numforms_iterator_t
    Find the specified key in user_numforms_t.

    @param map: (C++: const user_numforms_t *) user_numforms_t const *
    @param key: (C++: const operand_locator_t &) operand_locator_t const &
    """
    return _ida_hexrays.user_numforms_find(map, key)

def user_numforms_insert(map: "user_numforms_t", key: "operand_locator_t", val: "number_format_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_insert(map, key, val) -> user_numforms_iterator_t
    Insert new (operand_locator_t, number_format_t) pair into user_numforms_t.

    @param map: (C++: user_numforms_t *)
    @param key: (C++: const operand_locator_t &) operand_locator_t const &
    @param val: (C++: const number_format_t &) number_format_t const &
    """
    return _ida_hexrays.user_numforms_insert(map, key, val)

def user_numforms_begin(map: "user_numforms_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_begin(map) -> user_numforms_iterator_t
    Get iterator pointing to the beginning of user_numforms_t.

    @param map: (C++: const user_numforms_t *) user_numforms_t const *
    """
    return _ida_hexrays.user_numforms_begin(map)

def user_numforms_end(map: "user_numforms_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_end(map) -> user_numforms_iterator_t
    Get iterator pointing to the end of user_numforms_t.

    @param map: (C++: const user_numforms_t *) user_numforms_t const *
    """
    return _ida_hexrays.user_numforms_end(map)

def user_numforms_next(p: "user_numforms_iterator_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_next(p) -> user_numforms_iterator_t
    Move to the next element.

    @param p: (C++: user_numforms_iterator_t)
    """
    return _ida_hexrays.user_numforms_next(p)

def user_numforms_prev(p: "user_numforms_iterator_t") -> "user_numforms_iterator_t":
    r"""
    user_numforms_prev(p) -> user_numforms_iterator_t
    Move to the previous element.

    @param p: (C++: user_numforms_iterator_t)
    """
    return _ida_hexrays.user_numforms_prev(p)

def user_numforms_erase(map: "user_numforms_t", p: "user_numforms_iterator_t") -> "void":
    r"""
    user_numforms_erase(map, p)
    Erase current element from user_numforms_t.

    @param map: (C++: user_numforms_t *)
    @param p: (C++: user_numforms_iterator_t)
    """
    return _ida_hexrays.user_numforms_erase(map, p)

def user_numforms_clear(map: "user_numforms_t") -> "void":
    r"""
    user_numforms_clear(map)
    Clear user_numforms_t.

    @param map: (C++: user_numforms_t *)
    """
    return _ida_hexrays.user_numforms_clear(map)

def user_numforms_size(map: "user_numforms_t") -> "size_t":
    r"""
    user_numforms_size(map) -> size_t
    Get size of user_numforms_t.

    @param map: (C++: user_numforms_t *)
    """
    return _ida_hexrays.user_numforms_size(map)

def user_numforms_free(map: "user_numforms_t") -> "void":
    r"""
    user_numforms_free(map)
    Delete user_numforms_t instance.

    @param map: (C++: user_numforms_t *)
    """
    return _ida_hexrays.user_numforms_free(map)

def user_numforms_new() -> "user_numforms_t *":
    r"""
    user_numforms_new() -> user_numforms_t
    Create a new user_numforms_t instance.
    """
    return _ida_hexrays.user_numforms_new()
class lvar_mapping_iterator_t(object):
    r"""
    Proxy of C++ lvar_mapping_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.lvar_mapping_iterator_t_x_get, _ida_hexrays.lvar_mapping_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "lvar_mapping_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: lvar_mapping_iterator_t const &
        """
        return _ida_hexrays.lvar_mapping_iterator_t___eq__(self, p)

    def __ne__(self, p: "lvar_mapping_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: lvar_mapping_iterator_t const &
        """
        return _ida_hexrays.lvar_mapping_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> lvar_mapping_iterator_t
        """
        _ida_hexrays.lvar_mapping_iterator_t_swiginit(self, _ida_hexrays.new_lvar_mapping_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_lvar_mapping_iterator_t

# Register lvar_mapping_iterator_t in _ida_hexrays:
_ida_hexrays.lvar_mapping_iterator_t_swigregister(lvar_mapping_iterator_t)

def lvar_mapping_first(p: "lvar_mapping_iterator_t") -> "lvar_locator_t const &":
    r"""
    lvar_mapping_first(p) -> lvar_locator_t
    Get reference to the current map key.

    @param p: (C++: lvar_mapping_iterator_t)
    """
    return _ida_hexrays.lvar_mapping_first(p)

def lvar_mapping_second(p: "lvar_mapping_iterator_t") -> "lvar_locator_t &":
    r"""
    lvar_mapping_second(p) -> lvar_locator_t
    Get reference to the current map value.

    @param p: (C++: lvar_mapping_iterator_t)
    """
    return _ida_hexrays.lvar_mapping_second(p)

def lvar_mapping_find(map: "lvar_mapping_t", key: "lvar_locator_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_find(map, key) -> lvar_mapping_iterator_t
    Find the specified key in lvar_mapping_t.

    @param map: (C++: const lvar_mapping_t *) lvar_mapping_t const *
    @param key: (C++: const lvar_locator_t &) lvar_locator_t const &
    """
    return _ida_hexrays.lvar_mapping_find(map, key)

def lvar_mapping_insert(map: "lvar_mapping_t", key: "lvar_locator_t", val: "lvar_locator_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_insert(map, key, val) -> lvar_mapping_iterator_t
    Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t.

    @param map: (C++: lvar_mapping_t *)
    @param key: (C++: const lvar_locator_t &) lvar_locator_t const &
    @param val: (C++: const lvar_locator_t &) lvar_locator_t const &
    """
    return _ida_hexrays.lvar_mapping_insert(map, key, val)

def lvar_mapping_begin(map: "lvar_mapping_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_begin(map) -> lvar_mapping_iterator_t
    Get iterator pointing to the beginning of lvar_mapping_t.

    @param map: (C++: const lvar_mapping_t *) lvar_mapping_t const *
    """
    return _ida_hexrays.lvar_mapping_begin(map)

def lvar_mapping_end(map: "lvar_mapping_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_end(map) -> lvar_mapping_iterator_t
    Get iterator pointing to the end of lvar_mapping_t.

    @param map: (C++: const lvar_mapping_t *) lvar_mapping_t const *
    """
    return _ida_hexrays.lvar_mapping_end(map)

def lvar_mapping_next(p: "lvar_mapping_iterator_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_next(p) -> lvar_mapping_iterator_t
    Move to the next element.

    @param p: (C++: lvar_mapping_iterator_t)
    """
    return _ida_hexrays.lvar_mapping_next(p)

def lvar_mapping_prev(p: "lvar_mapping_iterator_t") -> "lvar_mapping_iterator_t":
    r"""
    lvar_mapping_prev(p) -> lvar_mapping_iterator_t
    Move to the previous element.

    @param p: (C++: lvar_mapping_iterator_t)
    """
    return _ida_hexrays.lvar_mapping_prev(p)

def lvar_mapping_erase(map: "lvar_mapping_t", p: "lvar_mapping_iterator_t") -> "void":
    r"""
    lvar_mapping_erase(map, p)
    Erase current element from lvar_mapping_t.

    @param map: (C++: lvar_mapping_t *)
    @param p: (C++: lvar_mapping_iterator_t)
    """
    return _ida_hexrays.lvar_mapping_erase(map, p)

def lvar_mapping_clear(map: "lvar_mapping_t") -> "void":
    r"""
    lvar_mapping_clear(map)
    Clear lvar_mapping_t.

    @param map: (C++: lvar_mapping_t *)
    """
    return _ida_hexrays.lvar_mapping_clear(map)

def lvar_mapping_size(map: "lvar_mapping_t") -> "size_t":
    r"""
    lvar_mapping_size(map) -> size_t
    Get size of lvar_mapping_t.

    @param map: (C++: lvar_mapping_t *)
    """
    return _ida_hexrays.lvar_mapping_size(map)

def lvar_mapping_free(map: "lvar_mapping_t") -> "void":
    r"""
    lvar_mapping_free(map)
    Delete lvar_mapping_t instance.

    @param map: (C++: lvar_mapping_t *)
    """
    return _ida_hexrays.lvar_mapping_free(map)

def lvar_mapping_new() -> "lvar_mapping_t *":
    r"""
    lvar_mapping_new() -> lvar_mapping_t
    Create a new lvar_mapping_t instance.
    """
    return _ida_hexrays.lvar_mapping_new()
class udcall_map_iterator_t(object):
    r"""
    Proxy of C++ udcall_map_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.udcall_map_iterator_t_x_get, _ida_hexrays.udcall_map_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "udcall_map_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: udcall_map_iterator_t const &
        """
        return _ida_hexrays.udcall_map_iterator_t___eq__(self, p)

    def __ne__(self, p: "udcall_map_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: udcall_map_iterator_t const &
        """
        return _ida_hexrays.udcall_map_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> udcall_map_iterator_t
        """
        _ida_hexrays.udcall_map_iterator_t_swiginit(self, _ida_hexrays.new_udcall_map_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_udcall_map_iterator_t

# Register udcall_map_iterator_t in _ida_hexrays:
_ida_hexrays.udcall_map_iterator_t_swigregister(udcall_map_iterator_t)

def udcall_map_first(p: "udcall_map_iterator_t") -> "ea_t const &":
    r"""
    udcall_map_first(p) -> ea_t const &
    Get reference to the current map key.

    @param p: (C++: udcall_map_iterator_t)
    """
    return _ida_hexrays.udcall_map_first(p)

def udcall_map_second(p: "udcall_map_iterator_t") -> "udcall_t &":
    r"""
    udcall_map_second(p) -> udcall_t
    Get reference to the current map value.

    @param p: (C++: udcall_map_iterator_t)
    """
    return _ida_hexrays.udcall_map_second(p)

def udcall_map_find(map: "udcall_map_t const *", key: "ea_t const &") -> "udcall_map_iterator_t":
    r"""
    udcall_map_find(map, key) -> udcall_map_iterator_t
    Find the specified key in udcall_map_t.

    @param map: (C++: const udcall_map_t *) udcall_map_t const *
    @param key: (C++: const ea_t &) ea_t const &
    """
    return _ida_hexrays.udcall_map_find(map, key)

def udcall_map_insert(map: "udcall_map_t *", key: "ea_t const &", val: "udcall_t") -> "udcall_map_iterator_t":
    r"""
    udcall_map_insert(map, key, val) -> udcall_map_iterator_t
    Insert new (ea_t, udcall_t) pair into udcall_map_t.

    @param map: (C++: udcall_map_t *)
    @param key: (C++: const ea_t &) ea_t const &
    @param val: (C++: const udcall_t &) udcall_t const &
    """
    return _ida_hexrays.udcall_map_insert(map, key, val)

def udcall_map_begin(map: "udcall_map_t const *") -> "udcall_map_iterator_t":
    r"""
    udcall_map_begin(map) -> udcall_map_iterator_t
    Get iterator pointing to the beginning of udcall_map_t.

    @param map: (C++: const udcall_map_t *) udcall_map_t const *
    """
    return _ida_hexrays.udcall_map_begin(map)

def udcall_map_end(map: "udcall_map_t const *") -> "udcall_map_iterator_t":
    r"""
    udcall_map_end(map) -> udcall_map_iterator_t
    Get iterator pointing to the end of udcall_map_t.

    @param map: (C++: const udcall_map_t *) udcall_map_t const *
    """
    return _ida_hexrays.udcall_map_end(map)

def udcall_map_next(p: "udcall_map_iterator_t") -> "udcall_map_iterator_t":
    r"""
    udcall_map_next(p) -> udcall_map_iterator_t
    Move to the next element.

    @param p: (C++: udcall_map_iterator_t)
    """
    return _ida_hexrays.udcall_map_next(p)

def udcall_map_prev(p: "udcall_map_iterator_t") -> "udcall_map_iterator_t":
    r"""
    udcall_map_prev(p) -> udcall_map_iterator_t
    Move to the previous element.

    @param p: (C++: udcall_map_iterator_t)
    """
    return _ida_hexrays.udcall_map_prev(p)

def udcall_map_erase(map: "udcall_map_t *", p: "udcall_map_iterator_t") -> "void":
    r"""
    udcall_map_erase(map, p)
    Erase current element from udcall_map_t.

    @param map: (C++: udcall_map_t *)
    @param p: (C++: udcall_map_iterator_t)
    """
    return _ida_hexrays.udcall_map_erase(map, p)

def udcall_map_clear(map: "udcall_map_t *") -> "void":
    r"""
    udcall_map_clear(map)
    Clear udcall_map_t.

    @param map: (C++: udcall_map_t *)
    """
    return _ida_hexrays.udcall_map_clear(map)

def udcall_map_size(map: "udcall_map_t *") -> "size_t":
    r"""
    udcall_map_size(map) -> size_t
    Get size of udcall_map_t.

    @param map: (C++: udcall_map_t *)
    """
    return _ida_hexrays.udcall_map_size(map)

def udcall_map_free(map: "udcall_map_t *") -> "void":
    r"""
    udcall_map_free(map)
    Delete udcall_map_t instance.

    @param map: (C++: udcall_map_t *)
    """
    return _ida_hexrays.udcall_map_free(map)

def udcall_map_new() -> "udcall_map_t *":
    r"""
    udcall_map_new() -> udcall_map_t *
    Create a new udcall_map_t instance.
    """
    return _ida_hexrays.udcall_map_new()
class user_cmts_iterator_t(object):
    r"""
    Proxy of C++ user_cmts_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.user_cmts_iterator_t_x_get, _ida_hexrays.user_cmts_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "user_cmts_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: user_cmts_iterator_t const &
        """
        return _ida_hexrays.user_cmts_iterator_t___eq__(self, p)

    def __ne__(self, p: "user_cmts_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: user_cmts_iterator_t const &
        """
        return _ida_hexrays.user_cmts_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> user_cmts_iterator_t
        """
        _ida_hexrays.user_cmts_iterator_t_swiginit(self, _ida_hexrays.new_user_cmts_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_user_cmts_iterator_t

# Register user_cmts_iterator_t in _ida_hexrays:
_ida_hexrays.user_cmts_iterator_t_swigregister(user_cmts_iterator_t)

def user_cmts_first(p: "user_cmts_iterator_t") -> "treeloc_t const &":
    r"""
    user_cmts_first(p) -> treeloc_t
    Get reference to the current map key.

    @param p: (C++: user_cmts_iterator_t)
    """
    return _ida_hexrays.user_cmts_first(p)

def user_cmts_second(p: "user_cmts_iterator_t") -> "citem_cmt_t &":
    r"""
    user_cmts_second(p) -> citem_cmt_t
    Get reference to the current map value.

    @param p: (C++: user_cmts_iterator_t)
    """
    return _ida_hexrays.user_cmts_second(p)

def user_cmts_find(map: "user_cmts_t", key: "treeloc_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_find(map, key) -> user_cmts_iterator_t
    Find the specified key in user_cmts_t.

    @param map: (C++: const user_cmts_t *) user_cmts_t const *
    @param key: (C++: const treeloc_t &) treeloc_t const &
    """
    return _ida_hexrays.user_cmts_find(map, key)

def user_cmts_insert(map: "user_cmts_t", key: "treeloc_t", val: "citem_cmt_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_insert(map, key, val) -> user_cmts_iterator_t
    Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t.

    @param map: (C++: user_cmts_t *)
    @param key: (C++: const treeloc_t &) treeloc_t const &
    @param val: (C++: const citem_cmt_t &) citem_cmt_t const &
    """
    return _ida_hexrays.user_cmts_insert(map, key, val)

def user_cmts_begin(map: "user_cmts_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_begin(map) -> user_cmts_iterator_t
    Get iterator pointing to the beginning of user_cmts_t.

    @param map: (C++: const user_cmts_t *) user_cmts_t const *
    """
    return _ida_hexrays.user_cmts_begin(map)

def user_cmts_end(map: "user_cmts_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_end(map) -> user_cmts_iterator_t
    Get iterator pointing to the end of user_cmts_t.

    @param map: (C++: const user_cmts_t *) user_cmts_t const *
    """
    return _ida_hexrays.user_cmts_end(map)

def user_cmts_next(p: "user_cmts_iterator_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_next(p) -> user_cmts_iterator_t
    Move to the next element.

    @param p: (C++: user_cmts_iterator_t)
    """
    return _ida_hexrays.user_cmts_next(p)

def user_cmts_prev(p: "user_cmts_iterator_t") -> "user_cmts_iterator_t":
    r"""
    user_cmts_prev(p) -> user_cmts_iterator_t
    Move to the previous element.

    @param p: (C++: user_cmts_iterator_t)
    """
    return _ida_hexrays.user_cmts_prev(p)

def user_cmts_erase(map: "user_cmts_t", p: "user_cmts_iterator_t") -> "void":
    r"""
    user_cmts_erase(map, p)
    Erase current element from user_cmts_t.

    @param map: (C++: user_cmts_t *)
    @param p: (C++: user_cmts_iterator_t)
    """
    return _ida_hexrays.user_cmts_erase(map, p)

def user_cmts_clear(map: "user_cmts_t") -> "void":
    r"""
    user_cmts_clear(map)
    Clear user_cmts_t.

    @param map: (C++: user_cmts_t *)
    """
    return _ida_hexrays.user_cmts_clear(map)

def user_cmts_size(map: "user_cmts_t") -> "size_t":
    r"""
    user_cmts_size(map) -> size_t
    Get size of user_cmts_t.

    @param map: (C++: user_cmts_t *)
    """
    return _ida_hexrays.user_cmts_size(map)

def user_cmts_free(map: "user_cmts_t") -> "void":
    r"""
    user_cmts_free(map)
    Delete user_cmts_t instance.

    @param map: (C++: user_cmts_t *)
    """
    return _ida_hexrays.user_cmts_free(map)

def user_cmts_new() -> "user_cmts_t *":
    r"""
    user_cmts_new() -> user_cmts_t
    Create a new user_cmts_t instance.
    """
    return _ida_hexrays.user_cmts_new()
class user_iflags_iterator_t(object):
    r"""
    Proxy of C++ user_iflags_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.user_iflags_iterator_t_x_get, _ida_hexrays.user_iflags_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "user_iflags_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: user_iflags_iterator_t const &
        """
        return _ida_hexrays.user_iflags_iterator_t___eq__(self, p)

    def __ne__(self, p: "user_iflags_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: user_iflags_iterator_t const &
        """
        return _ida_hexrays.user_iflags_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> user_iflags_iterator_t
        """
        _ida_hexrays.user_iflags_iterator_t_swiginit(self, _ida_hexrays.new_user_iflags_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_user_iflags_iterator_t

# Register user_iflags_iterator_t in _ida_hexrays:
_ida_hexrays.user_iflags_iterator_t_swigregister(user_iflags_iterator_t)

def user_iflags_first(p: "user_iflags_iterator_t") -> "citem_locator_t const &":
    r"""
    user_iflags_first(p) -> citem_locator_t
    Get reference to the current map key.

    @param p: (C++: user_iflags_iterator_t)
    """
    return _ida_hexrays.user_iflags_first(p)

def user_iflags_find(map: "user_iflags_t", key: "citem_locator_t") -> "user_iflags_iterator_t":
    r"""
    user_iflags_find(map, key) -> user_iflags_iterator_t
    Find the specified key in user_iflags_t.

    @param map: (C++: const user_iflags_t *) user_iflags_t const *
    @param key: (C++: const citem_locator_t &) citem_locator_t const &
    """
    return _ida_hexrays.user_iflags_find(map, key)

def user_iflags_insert(map: "user_iflags_t", key: "citem_locator_t", val: "int32 const &") -> "user_iflags_iterator_t":
    r"""
    user_iflags_insert(map, key, val) -> user_iflags_iterator_t
    Insert new (citem_locator_t, int32) pair into user_iflags_t.

    @param map: (C++: user_iflags_t *)
    @param key: (C++: const citem_locator_t &) citem_locator_t const &
    @param val: (C++: const int32 &) int32 const &
    """
    return _ida_hexrays.user_iflags_insert(map, key, val)

def user_iflags_begin(map: "user_iflags_t") -> "user_iflags_iterator_t":
    r"""
    user_iflags_begin(map) -> user_iflags_iterator_t
    Get iterator pointing to the beginning of user_iflags_t.

    @param map: (C++: const user_iflags_t *) user_iflags_t const *
    """
    return _ida_hexrays.user_iflags_begin(map)

def user_iflags_end(map: "user_iflags_t") -> "user_iflags_iterator_t":
    r"""
    user_iflags_end(map) -> user_iflags_iterator_t
    Get iterator pointing to the end of user_iflags_t.

    @param map: (C++: const user_iflags_t *) user_iflags_t const *
    """
    return _ida_hexrays.user_iflags_end(map)

def user_iflags_next(p: "user_iflags_iterator_t") -> "user_iflags_iterator_t":
    r"""
    user_iflags_next(p) -> user_iflags_iterator_t
    Move to the next element.

    @param p: (C++: user_iflags_iterator_t)
    """
    return _ida_hexrays.user_iflags_next(p)

def user_iflags_prev(p: "user_iflags_iterator_t") -> "user_iflags_iterator_t":
    r"""
    user_iflags_prev(p) -> user_iflags_iterator_t
    Move to the previous element.

    @param p: (C++: user_iflags_iterator_t)
    """
    return _ida_hexrays.user_iflags_prev(p)

def user_iflags_erase(map: "user_iflags_t", p: "user_iflags_iterator_t") -> "void":
    r"""
    user_iflags_erase(map, p)
    Erase current element from user_iflags_t.

    @param map: (C++: user_iflags_t *)
    @param p: (C++: user_iflags_iterator_t)
    """
    return _ida_hexrays.user_iflags_erase(map, p)

def user_iflags_clear(map: "user_iflags_t") -> "void":
    r"""
    user_iflags_clear(map)
    Clear user_iflags_t.

    @param map: (C++: user_iflags_t *)
    """
    return _ida_hexrays.user_iflags_clear(map)

def user_iflags_size(map: "user_iflags_t") -> "size_t":
    r"""
    user_iflags_size(map) -> size_t
    Get size of user_iflags_t.

    @param map: (C++: user_iflags_t *)
    """
    return _ida_hexrays.user_iflags_size(map)

def user_iflags_free(map: "user_iflags_t") -> "void":
    r"""
    user_iflags_free(map)
    Delete user_iflags_t instance.

    @param map: (C++: user_iflags_t *)
    """
    return _ida_hexrays.user_iflags_free(map)

def user_iflags_new() -> "user_iflags_t *":
    r"""
    user_iflags_new() -> user_iflags_t
    Create a new user_iflags_t instance.
    """
    return _ida_hexrays.user_iflags_new()
class user_unions_iterator_t(object):
    r"""
    Proxy of C++ user_unions_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.user_unions_iterator_t_x_get, _ida_hexrays.user_unions_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "user_unions_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: user_unions_iterator_t const &
        """
        return _ida_hexrays.user_unions_iterator_t___eq__(self, p)

    def __ne__(self, p: "user_unions_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: user_unions_iterator_t const &
        """
        return _ida_hexrays.user_unions_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> user_unions_iterator_t
        """
        _ida_hexrays.user_unions_iterator_t_swiginit(self, _ida_hexrays.new_user_unions_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_user_unions_iterator_t

# Register user_unions_iterator_t in _ida_hexrays:
_ida_hexrays.user_unions_iterator_t_swigregister(user_unions_iterator_t)

def user_unions_first(p: "user_unions_iterator_t") -> "ea_t const &":
    r"""
    user_unions_first(p) -> ea_t const &
    Get reference to the current map key.

    @param p: (C++: user_unions_iterator_t)
    """
    return _ida_hexrays.user_unions_first(p)

def user_unions_second(p: "user_unions_iterator_t") -> "intvec_t &":
    r"""
    user_unions_second(p) -> intvec_t
    Get reference to the current map value.

    @param p: (C++: user_unions_iterator_t)
    """
    return _ida_hexrays.user_unions_second(p)

def user_unions_find(map: "user_unions_t", key: "ea_t const &") -> "user_unions_iterator_t":
    r"""
    user_unions_find(map, key) -> user_unions_iterator_t
    Find the specified key in user_unions_t.

    @param map: (C++: const user_unions_t *) user_unions_t const *
    @param key: (C++: const ea_t &) ea_t const &
    """
    return _ida_hexrays.user_unions_find(map, key)

def user_unions_insert(map: "user_unions_t", key: "ea_t const &", val: "intvec_t") -> "user_unions_iterator_t":
    r"""
    user_unions_insert(map, key, val) -> user_unions_iterator_t
    Insert new (ea_t, intvec_t) pair into user_unions_t.

    @param map: (C++: user_unions_t *)
    @param key: (C++: const ea_t &) ea_t const &
    @param val: (C++: const intvec_t &) intvec_t const &
    """
    return _ida_hexrays.user_unions_insert(map, key, val)

def user_unions_begin(map: "user_unions_t") -> "user_unions_iterator_t":
    r"""
    user_unions_begin(map) -> user_unions_iterator_t
    Get iterator pointing to the beginning of user_unions_t.

    @param map: (C++: const user_unions_t *) user_unions_t const *
    """
    return _ida_hexrays.user_unions_begin(map)

def user_unions_end(map: "user_unions_t") -> "user_unions_iterator_t":
    r"""
    user_unions_end(map) -> user_unions_iterator_t
    Get iterator pointing to the end of user_unions_t.

    @param map: (C++: const user_unions_t *) user_unions_t const *
    """
    return _ida_hexrays.user_unions_end(map)

def user_unions_next(p: "user_unions_iterator_t") -> "user_unions_iterator_t":
    r"""
    user_unions_next(p) -> user_unions_iterator_t
    Move to the next element.

    @param p: (C++: user_unions_iterator_t)
    """
    return _ida_hexrays.user_unions_next(p)

def user_unions_prev(p: "user_unions_iterator_t") -> "user_unions_iterator_t":
    r"""
    user_unions_prev(p) -> user_unions_iterator_t
    Move to the previous element.

    @param p: (C++: user_unions_iterator_t)
    """
    return _ida_hexrays.user_unions_prev(p)

def user_unions_erase(map: "user_unions_t", p: "user_unions_iterator_t") -> "void":
    r"""
    user_unions_erase(map, p)
    Erase current element from user_unions_t.

    @param map: (C++: user_unions_t *)
    @param p: (C++: user_unions_iterator_t)
    """
    return _ida_hexrays.user_unions_erase(map, p)

def user_unions_clear(map: "user_unions_t") -> "void":
    r"""
    user_unions_clear(map)
    Clear user_unions_t.

    @param map: (C++: user_unions_t *)
    """
    return _ida_hexrays.user_unions_clear(map)

def user_unions_size(map: "user_unions_t") -> "size_t":
    r"""
    user_unions_size(map) -> size_t
    Get size of user_unions_t.

    @param map: (C++: user_unions_t *)
    """
    return _ida_hexrays.user_unions_size(map)

def user_unions_free(map: "user_unions_t") -> "void":
    r"""
    user_unions_free(map)
    Delete user_unions_t instance.

    @param map: (C++: user_unions_t *)
    """
    return _ida_hexrays.user_unions_free(map)

def user_unions_new() -> "user_unions_t *":
    r"""
    user_unions_new() -> user_unions_t
    Create a new user_unions_t instance.
    """
    return _ida_hexrays.user_unions_new()
class user_labels_iterator_t(object):
    r"""
    Proxy of C++ user_labels_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.user_labels_iterator_t_x_get, _ida_hexrays.user_labels_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "user_labels_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: user_labels_iterator_t const &
        """
        return _ida_hexrays.user_labels_iterator_t___eq__(self, p)

    def __ne__(self, p: "user_labels_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: user_labels_iterator_t const &
        """
        return _ida_hexrays.user_labels_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> user_labels_iterator_t
        """
        _ida_hexrays.user_labels_iterator_t_swiginit(self, _ida_hexrays.new_user_labels_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_user_labels_iterator_t

# Register user_labels_iterator_t in _ida_hexrays:
_ida_hexrays.user_labels_iterator_t_swigregister(user_labels_iterator_t)

def user_labels_first(p: "user_labels_iterator_t") -> "int const &":
    r"""
    user_labels_first(p) -> int const &
    Get reference to the current map key.

    @param p: (C++: user_labels_iterator_t)
    """
    return _ida_hexrays.user_labels_first(p)

def user_labels_second(p: "user_labels_iterator_t") -> "qstring &":
    r"""
    user_labels_second(p) -> qstring &
    Get reference to the current map value.

    @param p: (C++: user_labels_iterator_t)
    """
    return _ida_hexrays.user_labels_second(p)

def user_labels_find(map: "user_labels_t", key: "int const &") -> "user_labels_iterator_t":
    r"""
    user_labels_find(map, key) -> user_labels_iterator_t
    Find the specified key in user_labels_t.

    @param map: (C++: const user_labels_t *) user_labels_t const *
    @param key: (C++: const int &) int const &
    """
    return _ida_hexrays.user_labels_find(map, key)

def user_labels_insert(map: "user_labels_t", key: "int const &", val: "qstring const &") -> "user_labels_iterator_t":
    r"""
    user_labels_insert(map, key, val) -> user_labels_iterator_t
    Insert new (int, qstring) pair into user_labels_t.

    @param map: (C++: user_labels_t *)
    @param key: (C++: const int &) int const &
    @param val: (C++: const qstring &) qstring const &
    """
    return _ida_hexrays.user_labels_insert(map, key, val)

def user_labels_begin(map: "user_labels_t") -> "user_labels_iterator_t":
    r"""
    user_labels_begin(map) -> user_labels_iterator_t
    Get iterator pointing to the beginning of user_labels_t.

    @param map: (C++: const user_labels_t *) user_labels_t const *
    """
    return _ida_hexrays.user_labels_begin(map)

def user_labels_end(map: "user_labels_t") -> "user_labels_iterator_t":
    r"""
    user_labels_end(map) -> user_labels_iterator_t
    Get iterator pointing to the end of user_labels_t.

    @param map: (C++: const user_labels_t *) user_labels_t const *
    """
    return _ida_hexrays.user_labels_end(map)

def user_labels_next(p: "user_labels_iterator_t") -> "user_labels_iterator_t":
    r"""
    user_labels_next(p) -> user_labels_iterator_t
    Move to the next element.

    @param p: (C++: user_labels_iterator_t)
    """
    return _ida_hexrays.user_labels_next(p)

def user_labels_prev(p: "user_labels_iterator_t") -> "user_labels_iterator_t":
    r"""
    user_labels_prev(p) -> user_labels_iterator_t
    Move to the previous element.

    @param p: (C++: user_labels_iterator_t)
    """
    return _ida_hexrays.user_labels_prev(p)

def user_labels_erase(map: "user_labels_t", p: "user_labels_iterator_t") -> "void":
    r"""
    user_labels_erase(map, p)
    Erase current element from user_labels_t.

    @param map: (C++: user_labels_t *)
    @param p: (C++: user_labels_iterator_t)
    """
    return _ida_hexrays.user_labels_erase(map, p)

def user_labels_clear(map: "user_labels_t") -> "void":
    r"""
    user_labels_clear(map)
    Clear user_labels_t.

    @param map: (C++: user_labels_t *)
    """
    return _ida_hexrays.user_labels_clear(map)

def user_labels_size(map: "user_labels_t") -> "size_t":
    r"""
    user_labels_size(map) -> size_t
    Get size of user_labels_t.

    @param map: (C++: user_labels_t *)
    """
    return _ida_hexrays.user_labels_size(map)

def user_labels_free(map: "user_labels_t") -> "void":
    r"""
    user_labels_free(map)
    Delete user_labels_t instance.

    @param map: (C++: user_labels_t *)
    """
    return _ida_hexrays.user_labels_free(map)

def user_labels_new() -> "user_labels_t *":
    r"""
    user_labels_new() -> user_labels_t
    Create a new user_labels_t instance.
    """
    return _ida_hexrays.user_labels_new()
class eamap_iterator_t(object):
    r"""
    Proxy of C++ eamap_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.eamap_iterator_t_x_get, _ida_hexrays.eamap_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "eamap_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: eamap_iterator_t const &
        """
        return _ida_hexrays.eamap_iterator_t___eq__(self, p)

    def __ne__(self, p: "eamap_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: eamap_iterator_t const &
        """
        return _ida_hexrays.eamap_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> eamap_iterator_t
        """
        _ida_hexrays.eamap_iterator_t_swiginit(self, _ida_hexrays.new_eamap_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_eamap_iterator_t

# Register eamap_iterator_t in _ida_hexrays:
_ida_hexrays.eamap_iterator_t_swigregister(eamap_iterator_t)

def eamap_first(p: "eamap_iterator_t") -> "ea_t const &":
    r"""
    eamap_first(p) -> ea_t const &
    Get reference to the current map key.

    @param p: (C++: eamap_iterator_t)
    """
    return _ida_hexrays.eamap_first(p)

def eamap_second(p: "eamap_iterator_t") -> "cinsnptrvec_t &":
    r"""
    eamap_second(p) -> cinsnptrvec_t
    Get reference to the current map value.

    @param p: (C++: eamap_iterator_t)
    """
    return _ida_hexrays.eamap_second(p)

def eamap_find(map: "eamap_t", key: "ea_t const &") -> "eamap_iterator_t":
    r"""
    eamap_find(map, key) -> eamap_iterator_t
    Find the specified key in eamap_t.

    @param map: (C++: const eamap_t *) eamap_t const *
    @param key: (C++: const ea_t &) ea_t const &
    """
    return _ida_hexrays.eamap_find(map, key)

def eamap_insert(map: "eamap_t", key: "ea_t const &", val: "cinsnptrvec_t") -> "eamap_iterator_t":
    r"""
    eamap_insert(map, key, val) -> eamap_iterator_t
    Insert new (ea_t, cinsnptrvec_t) pair into eamap_t.

    @param map: (C++: eamap_t *)
    @param key: (C++: const ea_t &) ea_t const &
    @param val: (C++: const cinsnptrvec_t &) cinsnptrvec_t const &
    """
    return _ida_hexrays.eamap_insert(map, key, val)

def eamap_begin(map: "eamap_t") -> "eamap_iterator_t":
    r"""
    eamap_begin(map) -> eamap_iterator_t
    Get iterator pointing to the beginning of eamap_t.

    @param map: (C++: const eamap_t *) eamap_t const *
    """
    return _ida_hexrays.eamap_begin(map)

def eamap_end(map: "eamap_t") -> "eamap_iterator_t":
    r"""
    eamap_end(map) -> eamap_iterator_t
    Get iterator pointing to the end of eamap_t.

    @param map: (C++: const eamap_t *) eamap_t const *
    """
    return _ida_hexrays.eamap_end(map)

def eamap_next(p: "eamap_iterator_t") -> "eamap_iterator_t":
    r"""
    eamap_next(p) -> eamap_iterator_t
    Move to the next element.

    @param p: (C++: eamap_iterator_t)
    """
    return _ida_hexrays.eamap_next(p)

def eamap_prev(p: "eamap_iterator_t") -> "eamap_iterator_t":
    r"""
    eamap_prev(p) -> eamap_iterator_t
    Move to the previous element.

    @param p: (C++: eamap_iterator_t)
    """
    return _ida_hexrays.eamap_prev(p)

def eamap_erase(map: "eamap_t", p: "eamap_iterator_t") -> "void":
    r"""
    eamap_erase(map, p)
    Erase current element from eamap_t.

    @param map: (C++: eamap_t *)
    @param p: (C++: eamap_iterator_t)
    """
    return _ida_hexrays.eamap_erase(map, p)

def eamap_clear(map: "eamap_t") -> "void":
    r"""
    eamap_clear(map)
    Clear eamap_t.

    @param map: (C++: eamap_t *)
    """
    return _ida_hexrays.eamap_clear(map)

def eamap_size(map: "eamap_t") -> "size_t":
    r"""
    eamap_size(map) -> size_t
    Get size of eamap_t.

    @param map: (C++: eamap_t *)
    """
    return _ida_hexrays.eamap_size(map)

def eamap_free(map: "eamap_t") -> "void":
    r"""
    eamap_free(map)
    Delete eamap_t instance.

    @param map: (C++: eamap_t *)
    """
    return _ida_hexrays.eamap_free(map)

def eamap_new() -> "eamap_t *":
    r"""
    eamap_new() -> eamap_t
    Create a new eamap_t instance.
    """
    return _ida_hexrays.eamap_new()
class boundaries_iterator_t(object):
    r"""
    Proxy of C++ boundaries_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.boundaries_iterator_t_x_get, _ida_hexrays.boundaries_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "boundaries_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: boundaries_iterator_t const &
        """
        return _ida_hexrays.boundaries_iterator_t___eq__(self, p)

    def __ne__(self, p: "boundaries_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: boundaries_iterator_t const &
        """
        return _ida_hexrays.boundaries_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> boundaries_iterator_t
        """
        _ida_hexrays.boundaries_iterator_t_swiginit(self, _ida_hexrays.new_boundaries_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_boundaries_iterator_t

# Register boundaries_iterator_t in _ida_hexrays:
_ida_hexrays.boundaries_iterator_t_swigregister(boundaries_iterator_t)

def boundaries_first(p: "boundaries_iterator_t") -> "cinsn_t *const &":
    r"""
    boundaries_first(p) -> cinsn_t
    Get reference to the current map key.

    @param p: (C++: boundaries_iterator_t)
    """
    return _ida_hexrays.boundaries_first(p)

def boundaries_second(p: "boundaries_iterator_t") -> "rangeset_t &":
    r"""
    boundaries_second(p) -> rangeset_t
    Get reference to the current map value.

    @param p: (C++: boundaries_iterator_t)
    """
    return _ida_hexrays.boundaries_second(p)

def boundaries_begin(map: "boundaries_t") -> "boundaries_iterator_t":
    r"""
    boundaries_begin(map) -> boundaries_iterator_t
    Get iterator pointing to the beginning of boundaries_t.

    @param map: (C++: const boundaries_t *) boundaries_t const *
    """
    return _ida_hexrays.boundaries_begin(map)

def boundaries_end(map: "boundaries_t") -> "boundaries_iterator_t":
    r"""
    boundaries_end(map) -> boundaries_iterator_t
    Get iterator pointing to the end of boundaries_t.

    @param map: (C++: const boundaries_t *) boundaries_t const *
    """
    return _ida_hexrays.boundaries_end(map)

def boundaries_next(p: "boundaries_iterator_t") -> "boundaries_iterator_t":
    r"""
    boundaries_next(p) -> boundaries_iterator_t
    Move to the next element.

    @param p: (C++: boundaries_iterator_t)
    """
    return _ida_hexrays.boundaries_next(p)

def boundaries_prev(p: "boundaries_iterator_t") -> "boundaries_iterator_t":
    r"""
    boundaries_prev(p) -> boundaries_iterator_t
    Move to the previous element.

    @param p: (C++: boundaries_iterator_t)
    """
    return _ida_hexrays.boundaries_prev(p)

def boundaries_erase(map: "boundaries_t", p: "boundaries_iterator_t") -> "void":
    r"""
    boundaries_erase(map, p)
    Erase current element from boundaries_t.

    @param map: (C++: boundaries_t *)
    @param p: (C++: boundaries_iterator_t)
    """
    return _ida_hexrays.boundaries_erase(map, p)

def boundaries_clear(map: "boundaries_t") -> "void":
    r"""
    boundaries_clear(map)
    Clear boundaries_t.

    @param map: (C++: boundaries_t *)
    """
    return _ida_hexrays.boundaries_clear(map)

def boundaries_size(map: "boundaries_t") -> "size_t":
    r"""
    boundaries_size(map) -> size_t
    Get size of boundaries_t.

    @param map: (C++: boundaries_t *)
    """
    return _ida_hexrays.boundaries_size(map)

def boundaries_free(map: "boundaries_t") -> "void":
    r"""
    boundaries_free(map)
    Delete boundaries_t instance.

    @param map: (C++: boundaries_t *)
    """
    return _ida_hexrays.boundaries_free(map)

def boundaries_new() -> "boundaries_t *":
    r"""
    boundaries_new() -> boundaries_t
    Create a new boundaries_t instance.
    """
    return _ida_hexrays.boundaries_new()
class block_chains_iterator_t(object):
    r"""
    Proxy of C++ block_chains_iterator_t class.
    """

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    x: "iterator_word" = property(_ida_hexrays.block_chains_iterator_t_x_get, _ida_hexrays.block_chains_iterator_t_x_set, doc=r"""x""")

    def __eq__(self, p: "block_chains_iterator_t") -> "bool":
        r"""
        __eq__(self, p) -> bool

        @param p: block_chains_iterator_t const &
        """
        return _ida_hexrays.block_chains_iterator_t___eq__(self, p)

    def __ne__(self, p: "block_chains_iterator_t") -> "bool":
        r"""
        __ne__(self, p) -> bool

        @param p: block_chains_iterator_t const &
        """
        return _ida_hexrays.block_chains_iterator_t___ne__(self, p)

    def __init__(self):
        r"""
        __init__(self) -> block_chains_iterator_t
        """
        _ida_hexrays.block_chains_iterator_t_swiginit(self, _ida_hexrays.new_block_chains_iterator_t())
    __swig_destroy__ = _ida_hexrays.delete_block_chains_iterator_t

# Register block_chains_iterator_t in _ida_hexrays:
_ida_hexrays.block_chains_iterator_t_swigregister(block_chains_iterator_t)

def block_chains_get(p: "block_chains_iterator_t") -> "chain_t &":
    r"""
    block_chains_get(p) -> chain_t
    Get reference to the current set value.

    @param p: (C++: block_chains_iterator_t)
    """
    return _ida_hexrays.block_chains_get(p)

def block_chains_find(set: "block_chains_t", val: "chain_t") -> "block_chains_iterator_t":
    r"""
    block_chains_find(set, val) -> block_chains_iterator_t
    Find the specified key in set block_chains_t.

    @param set: (C++: const block_chains_t *) block_chains_t const *
    @param val: (C++: const chain_t &) chain_t const &
    """
    return _ida_hexrays.block_chains_find(set, val)

def block_chains_insert(set: "block_chains_t", val: "chain_t") -> "block_chains_iterator_t":
    r"""
    block_chains_insert(set, val) -> block_chains_iterator_t
    Insert new (chain_t) into set block_chains_t.

    @param set: (C++: block_chains_t *)
    @param val: (C++: const chain_t &) chain_t const &
    """
    return _ida_hexrays.block_chains_insert(set, val)

def block_chains_begin(set: "block_chains_t") -> "block_chains_iterator_t":
    r"""
    block_chains_begin(set) -> block_chains_iterator_t
    Get iterator pointing to the beginning of block_chains_t.

    @param set: (C++: const block_chains_t *) block_chains_t const *
    """
    return _ida_hexrays.block_chains_begin(set)

def block_chains_end(set: "block_chains_t") -> "block_chains_iterator_t":
    r"""
    block_chains_end(set) -> block_chains_iterator_t
    Get iterator pointing to the end of block_chains_t.

    @param set: (C++: const block_chains_t *) block_chains_t const *
    """
    return _ida_hexrays.block_chains_end(set)

def block_chains_next(p: "block_chains_iterator_t") -> "block_chains_iterator_t":
    r"""
    block_chains_next(p) -> block_chains_iterator_t
    Move to the next element.

    @param p: (C++: block_chains_iterator_t)
    """
    return _ida_hexrays.block_chains_next(p)

def block_chains_prev(p: "block_chains_iterator_t") -> "block_chains_iterator_t":
    r"""
    block_chains_prev(p) -> block_chains_iterator_t
    Move to the previous element.

    @param p: (C++: block_chains_iterator_t)
    """
    return _ida_hexrays.block_chains_prev(p)

def block_chains_erase(set: "block_chains_t", p: "block_chains_iterator_t") -> "void":
    r"""
    block_chains_erase(set, p)
    Erase current element from block_chains_t.

    @param set: (C++: block_chains_t *)
    @param p: (C++: block_chains_iterator_t)
    """
    return _ida_hexrays.block_chains_erase(set, p)

def block_chains_clear(set: "block_chains_t") -> "void":
    r"""
    block_chains_clear(set)
    Clear block_chains_t.

    @param set: (C++: block_chains_t *)
    """
    return _ida_hexrays.block_chains_clear(set)

def block_chains_size(set: "block_chains_t") -> "size_t":
    r"""
    block_chains_size(set) -> size_t
    Get size of block_chains_t.

    @param set: (C++: block_chains_t *)
    """
    return _ida_hexrays.block_chains_size(set)

def block_chains_free(set: "block_chains_t") -> "void":
    r"""
    block_chains_free(set)
    Delete block_chains_t instance.

    @param set: (C++: block_chains_t *)
    """
    return _ida_hexrays.block_chains_free(set)

def block_chains_new() -> "block_chains_t *":
    r"""
    block_chains_new() -> block_chains_t
    Create a new block_chains_t instance.
    """
    return _ida_hexrays.block_chains_new()

#<pycode(py_hexrays)>
import ida_funcs
import ida_idaapi

hexrays_failure_t.__str__ = lambda self: str("%x: %s" % (self.errea, self.desc()))

# ---------------------------------------------------------------------
# Renamings
is_allowed_on_small_struni = accepts_small_udts
is_small_struni = is_small_udt
mbl_array_t = mba_t

# NOTE: Strictly for backward-compatibily reasons (i.e., not
# to break existing scripts), and will never be thrown.
class DecompilationFailure(Exception):
    pass

# NOTE: We need to keep this `decompile` prototype because some
# scripts might be passing arguments by keyword
def decompile(ea, hf=None, flags=0):
    """
    Decompile a function.

    @param ea an address belonging to the function, or an ida_funcs.func_t object
    @param hf extended error information (if failed)
    @param flags decomp_flags bitwise combination of `DECOMP_...` bits
    @return the decompilation result (a `ida_hexrays.cfunc_t` wrapper), or None
    """
    return decompile_func(ea, hf, flags)

# ---------------------------------------------------------------------
# listify all list types
import ida_idaapi
ida_idaapi._listify_types(
        cinsnptrvec_t,
        ctree_items_t,
        qvector_lvar_t,
        qvector_carg_t,
        qvector_ccase_t,
        hexwarns_t,
        history_t,
        lvar_saved_infos_t,
        ui_stroff_ops_t)

def citem_to_specific_type(self):
    r"""
    cast the citem_t object to its more specific type, either cexpr_t or cinsn_t. 
    """

    if self.op >= cot_empty and self.op <= cot_last:
        return self.cexpr
    elif self.op >= cit_empty and self.op < cit_end:
        return self.cinsn

    raise RuntimeError('unknown op type %s' % (repr(self.op), ))
citem_t.to_specific_type = property(citem_to_specific_type)

""" array used for translating cinsn_t->op type to their names. """
cinsn_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cit_'):
        cinsn_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

""" array used for translating cexpr_t->op type to their names. """
cexpr_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cot_'):
        cexpr_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

def property_op_to_typename(self):
    return self.op_to_typename[self.op]
cinsn_t.opname = property(property_op_to_typename)
cexpr_t.opname = property(property_op_to_typename)

def cexpr_operands(self):
    r"""
    return a dictionary with the operands of a cexpr_t. 
    """

    if self.op >= cot_comma and self.op <= cot_asgumod or \
        self.op >= cot_lor and self.op <= cot_fdiv or \
        self.op == cot_idx:
        return {'x': self.x, 'y': self.y}

    elif self.op == cot_tern:
        return {'x': self.x, 'y': self.y, 'z': self.z}

    elif self.op in [cot_fneg, cot_neg, cot_sizeof] or \
        self.op >= cot_lnot and self.op <= cot_predec:
        return {'x': self.x}

    elif self.op == cot_cast:
        return {'type': self.type, 'x': self.x}

    elif self.op == cot_call:
        return {'x': self.x, 'a': self.a}

    elif self.op in [cot_memref, cot_memptr]:
        return {'x': self.x, 'm': self.m}

    elif self.op == cot_num:
        return {'n': self.n}

    elif self.op == cot_fnum:
        return {'fpc': self.fpc}

    elif self.op == cot_str:
        return {'string': self.string}

    elif self.op == cot_obj:
        return {'obj_ea': self.obj_ea}

    elif self.op == cot_var:
        return {'v': self.v}

    elif self.op == cot_helper:
        return {'helper': self.helper}

    raise RuntimeError('unknown op type %s' % self.opname)
cexpr_t.operands = property(cexpr_operands)

def cinsn_details(self):
    r"""
    return the details pointer for the cinsn_t object depending on the value of its op member.     this is one of the cblock_t, cif_t, etc. objects.
    """

    if self.op not in self.op_to_typename:
        raise RuntimeError('unknown item->op type')

    opname = self.opname
    if opname == 'empty':
        return self

    if opname in ['break', 'continue']:
        return None

    return getattr(self, 'c' + opname)
cinsn_t.details = property(cinsn_details)

cfuncptr_t.__str__ = lambda self: str(self.__deref__())
cfuncptr_t.__eq__ = lambda self, other: self.__ptrval__() == other.__ptrval__() if isinstance(other, cfuncptr_t) else False

import ida_typeinf
def cfunc_type(self):
    r"""
    Get the function's return type tinfo_t object. 
    """
    tif = ida_typeinf.tinfo_t()
    result = self.get_func_type(tif)
    if not result:
        return
    return tif
cfunc_t.type = property(cfunc_type)
cfuncptr_t.type = property(lambda self: self.__deref__().type)

cfunc_t.arguments = property(lambda self: [self.lvars[i] for i in self.argidx])
cfuncptr_t.arguments = property(lambda self: self.__deref__().arguments)

cfunc_t.lvars = property(cfunc_t.get_lvars)
cfuncptr_t.lvars = property(lambda self: self.__deref__().lvars)
cfunc_t.warnings = property(cfunc_t.get_warnings)
cfuncptr_t.warnings = property(lambda self: self.__deref__().warnings)
cfunc_t.pseudocode = property(cfunc_t.get_pseudocode)
cfuncptr_t.pseudocode = property(lambda self: self.__deref__().get_pseudocode())
cfunc_t.eamap = property(cfunc_t.get_eamap)
cfuncptr_t.eamap = property(lambda self: self.__deref__().get_eamap())
cfunc_t.boundaries = property(cfunc_t.get_boundaries)
cfuncptr_t.boundaries = property(lambda self: self.__deref__().get_boundaries())

#pragma SWIG nowarn=+503

lvar_t.used = property(lvar_t.used)
lvar_t.typed = property(lvar_t.typed)
lvar_t.mreg_done = property(lvar_t.mreg_done)
lvar_t.has_nice_name = property(lvar_t.has_nice_name)
lvar_t.is_unknown_width = property(lvar_t.is_unknown_width)
lvar_t.has_user_info = property(lvar_t.has_user_info)
lvar_t.has_user_name = property(lvar_t.has_user_name)
lvar_t.has_user_type = property(lvar_t.has_user_type)
lvar_t.is_result_var = property(lvar_t.is_result_var)
lvar_t.is_arg_var = property(lvar_t.is_arg_var)
lvar_t.is_fake_var = property(lvar_t.is_fake_var)
lvar_t.is_overlapped_var = property(lvar_t.is_overlapped_var)
lvar_t.is_floating_var = property(lvar_t.is_floating_var)
lvar_t.is_spoiled_var = property(lvar_t.is_spoiled_var)
lvar_t.is_mapdst_var = property(lvar_t.is_mapdst_var)

# dictify all dict-like types
def _map_as_dict(maptype, name, keytype, valuetype):

    maptype.keytype = keytype
    maptype.valuetype = valuetype

    for fctname in ['begin', 'end', 'first', 'second', 'next', \
                        'find', 'insert', 'erase', 'clear', 'size']:
        fct = getattr(_ida_hexrays, name + '_' + fctname)
        setattr(maptype, '__' + fctname, fct)

    maptype.__len__ = maptype.size
    maptype.__getitem__ = maptype.at

    maptype.begin = lambda self, *args: self.__begin(self, *args)
    maptype.end = lambda self, *args: self.__end(self, *args)
    maptype.first = lambda self, *args: self.__first(*args)
    maptype.second = lambda self, *args: self.__second(*args)
    maptype.next = lambda self, *args: self.__next(*args)
    maptype.find = lambda self, *args: self.__find(self, *args)
    maptype.insert = lambda self, *args: self.__insert(self, *args)
    maptype.erase = lambda self, *args: self.__erase(self, *args)
    maptype.clear = lambda self, *args: self.__clear(self, *args)
    maptype.size = lambda self, *args: self.__size(self, *args)

    def _map___iter__(self):
        """ Iterate over dictionary keys. """
        return self.iterkeys()
    maptype.__iter__ = _map___iter__

    def _map___getitem__(self, key):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        return self.second(self.find(key))
    maptype.__getitem__ = _map___getitem__

    def _map___setitem__(self, key, value):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if not isinstance(value, self.valuetype):
            raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
        self.insert(key, value)
        return
    maptype.__setitem__ = _map___setitem__

    def _map___delitem__(self, key):
        """ Removes the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        self.erase(self.find(key))
        return
    maptype.__delitem__ = _map___delitem__

    def _map___contains__(self, key):
        """ Returns true if the specified key exists in the . """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if self.find(key) != self.end():
            return True
        return False
    maptype.__contains__ = _map___contains__

    def _map_clear(self):
        self.clear()
        return
    maptype.clear = _map_clear

    def _map_copy(self):
        ret = {}
        for k in self.iterkeys():
            ret[k] = self[k]
        return ret
    maptype.copy = _map_copy

    def _map_get(self, key, default=None):
        if key in self:
            return self[key]
        return default
    maptype.get = _map_get

    def _map_iterkeys(self):
        iter = self.begin()
        while iter != self.end():
            yield self.first(iter)
            iter = self.next(iter)
        return
    maptype.iterkeys = _map_iterkeys

    def _map_itervalues(self):
        iter = self.begin()
        while iter != self.end():
            yield self.second(iter)
            iter = self.next(iter)
        return
    maptype.itervalues = _map_itervalues

    def _map_iteritems(self):
        iter = self.begin()
        while iter != self.end():
            yield (self.first(iter), self.second(iter))
            iter = self.next(iter)
        return
    maptype.iteritems = _map_iteritems

    def _map_keys(self):
        return list(self.iterkeys())
    maptype.keys = _map_keys

    def _map_values(self):
        return list(self.itervalues())
    maptype.values = _map_values

    def _map_items(self):
        return list(self.iteritems())
    maptype.items = _map_items

    def _map_has_key(self, key):
        return key in self
    maptype.has_key = _map_has_key

    def _map_pop(self, key):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        ret = self[key]
        del self[key]
        return ret
    maptype.pop = _map_pop

    def _map_popitem(self):
        """ Sets the value associated with the provided key. """
        if len(self) == 0:
            raise KeyError('key not found')
        key = self.keys()[0]
        return (key, self.pop(key))
    maptype.popitem = _map_popitem

    def _map_setdefault(self, key, default=None):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key in self:
            return self[key]
        self[key] = default
        return default
    maptype.setdefault = _map_setdefault

_map_as_dict(user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(user_iflags_t, 'user_iflags', citem_locator_t, int)
import ida_pro
_map_as_dict(user_unions_t, 'user_unions', ida_idaapi.integer_types, ida_pro.intvec_t)
_map_as_dict(eamap_t, 'eamap', ida_idaapi.long_type, cinsnptrvec_t)
import ida_range
_map_as_dict(boundaries_t, 'boundaries', cinsn_t, ida_range.rangeset_t)

#
# Object ownership
#
def _call_with_transferrable_ownership(fun, *args):
    e = args[0]
    was_owned = e.thisown
    res = fun(e, *args[1:])
# ATM, 'res' doesn't own the resulting cexpr_t.
# In case 'fun'
#   - created a new object: we want to own that one in case 'e' was owned
#   - didn't create a new object: we will remove & re-gain ownership on
#                                 the same underlying cexpr_t. No biggie.
    if was_owned:
        if res:
            e._maybe_disown_and_deregister()
            res._own_and_register()
    else:
        debug_hexrays_ctree("NOTE: call_with_transferrable_ownership() called with non-IDAPython-owned object. Is this intentional?")
    return res

def lnot(e):
    r"""
    Logically negate the specified expression. The specified expression will be
    logically negated. For example, "x == y" is converted into "x != y" by this
    function.

    @return: logically negated expression.
    """
    return _call_with_transferrable_ownership(_ll_lnot, e)

def make_ref(e):
    r"""
    Create a reference. This function performs the following conversion: "obj" =>
    "&obj". It can handle casts, annihilate "&*", and process other special cases.
    """
    return _call_with_transferrable_ownership(_ll_make_ref, e)

def dereference(e, ptrsize, is_float=False):
    r"""
    Dereference a pointer. This function dereferences a pointer expression. It
    performs the following conversion: "ptr" => "*ptr" It can handle discrepancies
    in the pointer type and the access size.

    @return: dereferenced expression
    """
    return _call_with_transferrable_ownership(_ll_dereference, e, ptrsize, is_float)

def call_helper(rettype, args, *rest):
    r"""
    Create a helper call.
    """
    res = _ll_call_helper(rettype, args, *rest)
    if res:
        res._own_and_register()
        if type(args) == carglist_t:
            args.thisown = False
    return res

def new_block():
    r"""
    Create a new block-statement.
    """
    res = _ll_new_block()
    if res:
        res._own_and_register()
    return res

def make_num(*args):
    r"""
    Create a number expression
    """
    res = _ll_make_num(*args)
    if res:
        res._own_and_register()
    return res

def create_helper(*args):
    r"""
    Create a helper object..
    """
    res = _ll_create_helper(*args)
    if res:
        res._own_and_register()
    return res

# ----------------

class __cbhooks_t(Hexrays_Hooks):

    instances = []

    def __init__(self, callback):
        self.callback = callback
        self.instances.append(self)
        Hexrays_Hooks.__init__(self)

    def maturity(self, *args): return self.callback(hxe_maturity, *args)
    def interr(self, *args): return self.callback(hxe_interr, *args)
    def print_func(self, *args): return self.callback(hxe_print_func, *args)
    def func_printed(self, *args): return self.callback(hxe_func_printed, *args)
    def open_pseudocode(self, *args): return self.callback(hxe_open_pseudocode, *args)
    def switch_pseudocode(self, *args): return self.callback(hxe_switch_pseudocode, *args)
    def refresh_pseudocode(self, *args): return self.callback(hxe_refresh_pseudocode, *args)
    def close_pseudocode(self, *args): return self.callback(hxe_close_pseudocode, *args)
    def keyboard(self, *args): return self.callback(hxe_keyboard, *args)
    def right_click(self, *args): return self.callback(hxe_right_click, *args)
    def double_click(self, *args): return self.callback(hxe_double_click, *args)
    def curpos(self, *args): return self.callback(hxe_curpos, *args)
    def create_hint(self, *args): return self.callback(hxe_create_hint, *args)
    def text_ready(self, *args): return self.callback(hxe_text_ready, *args)
    def populating_popup(self, *args): return self.callback(hxe_populating_popup, *args)
# NOTE: Do not add support for new notifications here;
# non-Hexrays_Hooks callbacks are deprecated.

def install_hexrays_callback(callback):
    r"""
    Deprecated. Please use Hexrays_Hooks instead
    Install handler for decompiler events.

    @return: false if failed
    """
    h = __cbhooks_t(callback)
    h.hook()
    return True

def remove_hexrays_callback(callback):
    r"""
    Deprecated. Please use Hexrays_Hooks instead
    Uninstall handler for decompiler events.

    @return: number of uninstalled handlers.
    """
    for inst in __cbhooks_t.instances:
        if inst.callback == callback:
            inst.unhook()
            __cbhooks_t.instances.remove(inst)
            return 1
    return 0

#</pycode(py_hexrays)>


