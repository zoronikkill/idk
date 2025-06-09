r"""
Merge functionality for modules.

NOTE: this functionality is available in IDA Teams (not IDA Pro)

This file contains helper classes and convenience functions for module (plugin
or processor module) merging.

Each module is responsible for merging the data it owns (the module data). At
the very beginning, the merging engine generates the ev_create_merge_handlers
event. Modules should hook to this event to create merge handlers (mergers) that
are responsible for the module data.

We assume that each module may have:

* its data structure, derived from plugmod_t or procmod_t. we call this
structure moddata.
* a dedicated netnode (module node), modnode for short.

Moddata is registered with the IDA kernel using the set_module_data() function,
which returns an integer, moddata_id. moddata_id is used to access the module
data structure during merging, so it is mandatory for all modules that support
merging.

The following sources of mergeable data are supported:

1. Data fields inside moddata 2. Values (scalar or binary, including blobs)
stored in the module node 3. Values (scalar or binary, including blobs) stored
in arbitrary netnodes 4. Data fields inside an auxiliary structure (provided by
a special helper) 5. Indexed arrays of data stored in netnodes

Usually the sources #1-4 are handled by a single merger, which can be
parameterized using the folowing information:

* moddata_id
* module name
* module node name
* array of field descriptors (idbattr_info_t idpopts_info[], see ida.hpp)

See plugins/mex1 for an example of such a merger.

These parameters are stored in a helper class (moddata_diff_helper_t or
derived). The helper class can override the following virtual methods:

merge_starting - prepare module data for merging (e.g. load data from idb)
merge_ending - opposite to merge_starting (e.g. save merged data to idb)
get_struc_ptr - get pointer to the auxiliary structure (to handle source #4);
this method will be called only if the fields with the IDI_HLPSTRUC bit are
present in the idpopts_info[] array

For most plugins, the default implementation of moddata_diff_helper_t or the
std_moddata_diff_helper_t helper (presented below) is sufficient. You can find
examples of non-standard helpers in plugins/mex2 and plugins/callgraph.

The source #5 is handled by a different set of mergers described by an array of
merge_node_info_t entries: a merger per entry. A non-trivial example can be
found in plugins/mex3 and plugins/ex_merge_ldrdata.

A module can use the create_std_modmerge_handlers() function to create necessary
merge handlers. Please pay attention to the following arguments:

helper - a helper class responsible for access to the internal module data for
the sources #1-4. It can be used to prepare a pointer to the internal module
structure and load/save data before/after merging (example: plugins/mex2). Im
most cases the default helper class moddata_diff_helper_t can be used.
merge_node_info - array of descriptions for the source #5. Note that the same
module node is used for all array elements. If you need this kind of mergers for
other netnodes, you should add them manually using the
create_nodeval_merge_handler() function (example: plugins/mex3)

See also module/mergecmn.cpp for procmod-specific functions and macros.

Glossary:

modmerger = module merger moddata = module data moddata_id = module data id"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_mergemod
else:
    import _ida_mergemod

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

SWIG_PYTHON_LEGACY_BOOL = _ida_mergemod.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi


def create_std_modmerge_handlers(mhp: "merge_handler_params_t &", helper: "moddata_diff_helper_t &", merge_node_info: "merge_node_info2_t const *"=None) -> "void":
    r"""
    create_std_modmerge_handlers(mhp, helper, merge_node_info=None)
    convinience function to create merge handlers for modules/plugins

    @param mhp: (C++: merge_handler_params_t &)
    @param helper: (C++: moddata_diff_helper_t &)
    @param merge_node_info: (C++: const merge_node_info_t *) merge_node_info2_t const *
    """
    return _ida_mergemod.create_std_modmerge_handlers(mhp, helper, merge_node_info)


