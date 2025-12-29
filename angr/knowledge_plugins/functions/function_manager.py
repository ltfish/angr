# pylint:disable=raise-missing-from
from __future__ import annotations

from typing import TypeVar, Generic, cast, TYPE_CHECKING, overload
from collections.abc import Iterator
from collections import OrderedDict
import contextlib
from collections.abc import Generator
import logging
import collections.abc
import re
import weakref
import bisect
import os
import pickle
import tempfile
import uuid
import atexit

import lmdb
import networkx

from archinfo.arch_soot import SootMethodDescriptor
import cle

from angr.errors import SimEngineError
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from .function import Function
from .soot_function import SootFunction

K = TypeVar("K", int, SootMethodDescriptor)
T = TypeVar("T")

if TYPE_CHECKING:
    from angr import KnowledgeBase

    class SortedDict(Generic[K, T], dict[K, T]):
        def irange(self, *args, **kwargs) -> Iterator[K]: ...

else:
    from sortedcontainers import SortedDict


QUERY_PATTERN = re.compile(r"^(::(.+?))?::(.+)$")
ADDR_PATTERN = re.compile(r"^(0x[\dA-Fa-f]+)|(\d+)$")

l = logging.getLogger(name=__name__)
_missing = object()

# Default maximum number of functions to keep in memory (None means unlimited)
DEFAULT_MAX_CACHED_FUNCTIONS: int | None = None


class FunctionDict(Generic[K], SortedDict[K, Function]):
    """
    FunctionDict is a dict where the keys are function starting addresses and
    map to the associated :class:`Function`.

    This class works with FunctionManager's LRU cache to keep only the most
    recently accessed functions in memory, spilling others to LMDB.
    """

    def __init__(self, backref: FunctionManager[K] | None, *args, key_types: type = int, **kwargs):
        self._backref = (
            cast(FunctionManager[K], backref if isinstance(backref, weakref.ProxyType) else weakref.proxy(backref))
            if backref is not None
            else None
        )
        self._key_types = key_types
        super().__init__(*args, **kwargs)

    def copy(self) -> FunctionDict[K]:
        return FunctionDict(self._backref, self, key_types=self._key_types)

    def __getitem__(self, addr: K) -> Function:
        # First try to get from in-memory cache
        try:
            func = super().__getitem__(addr)
            # Touch to update LRU order
            if self._backref is not None:
                self._backref._touch(addr)
            return func
        except KeyError as ex:
            if isinstance(addr, bool) or not isinstance(addr, self._key_types):
                raise TypeError(f"FunctionDict only supports {self._key_types} as key type") from ex

            # Try to load from LMDB if it's spilled (but not if we're already loading)
            if (
                self._backref is not None
                and addr in self._backref._spilled_addrs
                and not self._backref._loading_from_lmdb
            ):
                func = self._backref._load_from_lmdb(addr)
                if func is not None:
                    return func

            # Create a new function
            if isinstance(addr, SootMethodDescriptor):
                t = SootFunction(self._backref, addr)
            else:
                t = Function(self._backref, addr)
            with contextlib.suppress(Exception):
                self[addr] = t
            if self._backref is not None:
                self._backref._function_added(t)
            return t

    def __setitem__(self, key: K, value: Function) -> None:
        super().__setitem__(key, value)
        # Notify the manager to potentially evict LRU entries
        if self._backref is not None:
            self._backref._on_function_stored(key)

    def __delitem__(self, key: K) -> None:
        super().__delitem__(key)

    @overload
    def get(self, key: K, default: None = None, /) -> Function: ...
    @overload
    def get(self, key: K, default: Function, /) -> Function: ...
    @overload
    def get(self, key: K, default: T, /) -> Function | T: ...

    def get(self, addr, default=_missing, /):
        # First check in-memory
        try:
            func = super().__getitem__(addr)
            if self._backref is not None:
                self._backref._touch(addr)
            return func
        except KeyError:
            pass

        # Check if spilled to LMDB (but not if we're already loading)
        if (
            self._backref is not None
            and addr in self._backref._spilled_addrs
            and not self._backref._loading_from_lmdb
        ):
            func = self._backref._load_from_lmdb(addr)
            if func is not None:
                return func

        if default is _missing:
            raise KeyError(addr)
        return default

    def floor_addr(self, addr):
        try:
            return next(self.irange(maximum=addr, reverse=True))
        except StopIteration as err:
            raise KeyError(addr) from err

    def ceiling_addr(self, addr):
        try:
            return next(self.irange(minimum=addr, reverse=False))
        except StopIteration as err:
            raise KeyError(addr) from err

    def __setstate__(self, state):
        for v, k in state.items():
            self[k] = v

    def __getstate__(self):
        return dict(self.items())


class FunctionManager(Generic[K], KnowledgeBasePlugin, collections.abc.Mapping[K, Function]):
    """
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.

    The FunctionManager implements an LRU cache that keeps only the most recently
    accessed N functions in memory, spilling others to an LMDB database on disk.
    This allows working with binaries that have more functions than can fit in memory.

    :param max_cached_functions: Maximum number of functions to keep in memory.
                                 None means unlimited (no eviction). Default is None.
    """

    def __init__(self, kb: KnowledgeBase, max_cached_functions: int | None = DEFAULT_MAX_CACHED_FUNCTIONS):
        super().__init__(kb=kb)
        self.function_address_types = self._kb._project.arch.function_address_types
        self.address_types = self._kb._project.arch.address_types
        self._function_map: FunctionDict[K] = FunctionDict(self, key_types=self.function_address_types)
        self.function_addrs_set: set = set()
        self.callgraph = networkx.MultiDiGraph()
        self.block_map = {}

        # Registers used for passing arguments around
        self._arg_registers = kb._project.arch.argument_registers

        # local PLT dictionary cache
        self._rplt_cache_ranges: None | list[tuple[int, int]] = None
        self._rplt_cache: None | set[int] = None
        # local binary name cache: min_addr -> (max_addr, binary_name)
        self._binname_cache: None | SortedDict[int, tuple[int, str | None]] = None

        # LRU cache configuration
        self._max_cached_functions: int | None = max_cached_functions
        # OrderedDict to track access order (most recent at end)
        self._lru_order: OrderedDict[K, None] = OrderedDict()
        # Set of function addresses that have been spilled to LMDB
        self._spilled_addrs: set[K] = set()
        # LMDB environment and path (lazily initialized)
        self._lmdb_env: lmdb.Environment | None = None
        self._lmdb_path: str | None = None
        self._lmdb_functions_db = None
        # Flag to prevent eviction during bulk operations
        self._eviction_enabled: bool = True
        # Flag to prevent recursive loading from LMDB
        self._loading_from_lmdb: bool = False
        # Set of addresses currently being loaded (to prevent recursion)
        self._currently_loading: set[K] = set()

        # Register cleanup on exit
        atexit.register(self._cleanup_lmdb)

    def __setstate__(self, state):
        self._kb = state["_kb"]
        self.function_address_types = state["function_address_types"]
        self.address_types = state["address_types"]
        self._function_map = state["_function_map"]
        self.callgraph = state["callgraph"]
        self.block_map = state["block_map"]

        self._function_map._backref = weakref.proxy(self)
        for func in self._function_map.values():
            func._function_manager = self

        # Initialize LRU cache state
        self._max_cached_functions = state.get("_max_cached_functions", DEFAULT_MAX_CACHED_FUNCTIONS)
        self._lru_order = OrderedDict()
        for addr in self._function_map.keys():
            self._lru_order[addr] = None
        self._spilled_addrs = set()
        self._lmdb_env = None
        self._lmdb_path = None
        self._lmdb_functions_db = None
        self._eviction_enabled = True
        self._loading_from_lmdb = False
        self._currently_loading = set()
        atexit.register(self._cleanup_lmdb)

    def __getstate__(self):
        # Before pickling, bring all spilled functions back to memory
        self._load_all_spilled()
        return {
            "_kb": self._kb,
            "function_address_types": self.function_address_types,
            "address_types": self.address_types,
            "_function_map": self._function_map,
            "callgraph": self.callgraph,
            "block_map": self.block_map,
            "_max_cached_functions": self._max_cached_functions,
        }

    def __del__(self):
        self._cleanup_lmdb()

    def _cleanup_lmdb(self):
        """Clean up LMDB resources."""
        if self._lmdb_env is not None:
            try:
                self._lmdb_env.close()
            except Exception:
                pass
            self._lmdb_env = None
            self._lmdb_functions_db = None

    def copy(self):
        fm = FunctionManager(self._kb, max_cached_functions=self._max_cached_functions)
        # Temporarily disable eviction during copy
        fm._eviction_enabled = False
        # Load all spilled functions for copying
        self._load_all_spilled()
        fm._function_map = self._function_map.copy()
        for address, function in fm._function_map.items():
            fm._function_map[address] = function.copy()
        fm.callgraph = networkx.MultiDiGraph(self.callgraph)
        fm._arg_registers = self._arg_registers.copy()
        fm.function_addrs_set = self.function_addrs_set.copy()
        fm._lru_order = OrderedDict(self._lru_order)
        fm._eviction_enabled = True

        return fm

    def clear(self):
        self._function_map = FunctionDict(self, key_types=self.function_address_types)
        self.callgraph = networkx.MultiDiGraph()
        self.block_map.clear()
        self.function_addrs_set = set()
        # cache
        self._rplt_cache = None
        self._rplt_cache_ranges = None
        self._binname_cache = None
        # LRU cache state
        self._lru_order.clear()
        self._spilled_addrs.clear()
        # Close and cleanup LMDB
        self._cleanup_lmdb()
        self._lmdb_path = None

    def _genenate_callmap_sif(self, filepath):
        """
        Generate a sif file from the call map.

        :param filepath:    Path of the sif file
        :return:            None
        """
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(f"{src:#x}\tDirectEdge\t{dst:#x}\n" for src, dst in self.callgraph.edges())

    def _addr_in_plt_cached_ranges(self, addr: int) -> bool:
        if self._rplt_cache_ranges is None:
            return False
        pos = bisect.bisect_left(self._rplt_cache_ranges, addr, key=lambda x: x[0])
        return pos > 0 and self._rplt_cache_ranges[pos - 1][0] <= addr < self._rplt_cache_ranges[pos - 1][1]

    def is_plt_cached(self, addr: int) -> bool:
        # check if the addr is in the cache range
        if not self._addr_in_plt_cached_ranges(addr):
            # find the object containing this addr
            obj = self._kb._project.loader.find_object_containing(addr, membership_check=False)
            if obj is None:
                return False
            if self._rplt_cache_ranges is None:
                self._rplt_cache_ranges = []
            obj_range = obj.min_addr, obj.max_addr
            idx = bisect.bisect_left(self._rplt_cache_ranges, obj_range)
            if not (idx < len(self._rplt_cache_ranges) and self._rplt_cache_ranges[idx] == obj_range):
                self._rplt_cache_ranges.insert(idx, obj_range)
            if isinstance(obj, (cle.MetaELF, cle.MachO)):
                if self._rplt_cache is None:
                    self._rplt_cache = set()
                self._rplt_cache |= set(obj.reverse_plt)

        return addr in self._rplt_cache if self._rplt_cache is not None else False

    def _binname_cache_get_addr_base(self, addr: int) -> int | None:
        if self._binname_cache is None:
            return None
        try:
            base_addr = next(self._binname_cache.irange(maximum=addr, reverse=True))
        except StopIteration:
            return None
        return base_addr if base_addr <= addr < self._binname_cache[base_addr][0] else None

    def get_binary_name_cached(self, addr: int) -> str | None:
        base_addr = self._binname_cache_get_addr_base(addr)
        if base_addr is None:
            # not cached; cache it first
            obj = self._kb._project.loader.find_object_containing(addr, membership_check=False)
            if obj is None:
                return None
            if self._binname_cache is None:
                self._binname_cache = SortedDict()
            binary_basename = os.path.basename(obj.binary) if obj.binary else None
            self._binname_cache[obj.min_addr] = obj.max_addr, binary_basename
            base_addr = obj.min_addr
        return self._binname_cache[base_addr][1] if self._binname_cache is not None else None

    def _add_node(self, function_addr, node, syscall=None, size=None):
        if isinstance(node, self.address_types):
            node = self._kb._project.factory.snippet(node, size=size)
        dst_func = self._function_map[function_addr]
        if syscall in (True, False):
            dst_func.is_syscall = syscall
        dst_func._register_node(True, node)
        self.block_map[node.addr] = node

    def _add_call_to(
        self,
        function_addr,
        from_node,
        to_addr,
        retn_node=None,
        syscall=None,
        stmt_idx=None,
        ins_addr=None,
        return_to_outside: bool = False,
    ):
        """
        Add a call to a function.

        :param int function_addr:   Address of the current function where this call happens.
        :param from_node:           The source node.
        :param to_addr:             Address of the target function, or None if unknown.
        :param retn_node:           The node where the target function will return to if it returns.
        :param bool syscall:        If this is a call to a syscall or not.
        :param int stmt_idx:        ID of the statement where this call happens.
        :param int ins_addr:        Address of the instruction where this call happens.
        :param return_to_outside:  True if the return of the call is considered going to outside of the current
                                        function.
        :return:                    None
        """

        if isinstance(from_node, self.address_types):
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(retn_node, self.address_types):
            retn_node = self._kb._project.factory.snippet(retn_node)
        func = self._function_map[function_addr]
        func._add_call_site(from_node.addr, to_addr, retn_node.addr if retn_node else None)

        if to_addr is not None:
            dest_func = self._function_map[to_addr]
            if syscall in (True, False):
                dest_func.is_syscall = syscall
            func._call_to(
                from_node,
                dest_func,
                retn_node,
                stmt_idx=stmt_idx,
                ins_addr=ins_addr,
                return_to_outside=return_to_outside,
            )

        if return_to_outside:
            func.add_retout_site(from_node)

        # is there any existing edge on the callgraph?
        edge_data = {"type": "call"}
        if to_addr is not None and (
            function_addr not in self.callgraph
            or to_addr not in self.callgraph[function_addr]
            or edge_data not in self.callgraph[function_addr][to_addr].values()
        ):
            self.callgraph.add_edge(function_addr, to_addr, **edge_data)

    def _add_fakeret_to(
        self, function_addr, from_node, to_node, confirmed=None, syscall=None, to_outside=False, to_function_addr=None
    ):
        if isinstance(from_node, self.address_types):
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(to_node, self.address_types):
            to_node = self._kb._project.factory.snippet(to_node)
        src_func = self._function_map[function_addr]

        if syscall in (True, False):
            src_func.is_syscall = syscall

        src_func._fakeret_to(from_node, to_node, confirmed=confirmed, to_outside=to_outside)

        if to_outside and to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {"type": "fakeret"}
            if (
                function_addr not in self.callgraph
                or to_function_addr not in self.callgraph[function_addr]
                or edge_data not in self.callgraph[function_addr][to_function_addr].values()
            ):
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _remove_fakeret(self, function_addr, from_node, to_node):
        if type(from_node) is int:  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._remove_fakeret(from_node, to_node)

    def _add_return_from(self, function_addr, from_node, to_node=None):  # pylint:disable=unused-argument
        if isinstance(from_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        self._function_map[function_addr]._add_return_site(from_node)

    def _add_transition_to(self, function_addr, from_node, to_node, ins_addr=None, stmt_idx=None, is_exception=False):
        if isinstance(from_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(to_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._transit_to(
            from_node, to_node, ins_addr=ins_addr, stmt_idx=stmt_idx, is_exception=is_exception
        )

    def _add_outside_transition_to(
        self, function_addr, from_node, to_node, to_function_addr=None, ins_addr=None, stmt_idx=None, is_exception=False
    ):
        if type(from_node) is int:  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            try:
                to_node = self._kb._project.factory.snippet(to_node)
            except SimEngineError:
                # we cannot get the snippet, but we should at least tell the function that it's going to jump out here
                self._function_map[function_addr].add_jumpout_site(from_node)
                return
        self._function_map[function_addr]._transit_to(
            from_node,
            to_node,
            outside=True,
            ins_addr=ins_addr,
            stmt_idx=stmt_idx,
            is_exception=is_exception,
        )

        if to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {"type": "transition" if not is_exception else "exception"}
            if (
                function_addr not in self.callgraph
                or to_function_addr not in self.callgraph[function_addr]
                or edge_data not in self.callgraph[function_addr][to_function_addr].values()
            ):
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _add_return_from_call(self, function_addr, src_function_addr, to_node, to_outside=False):
        # Note that you will never return to a syscall

        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        func = self._function_map[function_addr]
        src_func = self._function_map[src_function_addr]
        func._return_from_call(src_func, to_node, to_outside=to_outside)

    #
    # Dict methods
    #

    def __contains__(self, item):
        if type(item) is int:
            # this is an address - check both in-memory and spilled
            return item in self._function_map or item in self._spilled_addrs

        try:
            _ = self[item]
            return True
        except (KeyError, TypeError):
            return False

    def __getitem__(self, k) -> Function:
        if isinstance(k, self.function_address_types):
            f = self.function(addr=k)
        elif type(k) is str:
            f = self.function(name=k) or self.function(name=k, check_previous_names=True)
        else:
            raise ValueError(f"FunctionManager.__getitem__ does not support keys of type {type(k)}")

        if f is None:
            raise KeyError(k)

        return f

    def __setitem__(self, k, v):
        if isinstance(k, self.function_address_types):
            self._function_map[k] = v
            self._function_added(v)
        else:
            raise ValueError("FunctionManager.__setitem__ keys must be an int")

    def __delitem__(self, k):
        if isinstance(k, self.function_address_types):
            # Remove from in-memory map if present
            if k in self._function_map:
                del self._function_map[k]
            # Remove from spilled set if present
            self._spilled_addrs.discard(k)
            # Remove from LRU order
            if k in self._lru_order:
                del self._lru_order[k]
            if k in self.callgraph:
                self.callgraph.remove_node(k)
            self.function_addrs_set.discard(k)
        else:
            raise ValueError(
                f"FunctionManager.__delitem__ only accepts the following address types: "
                f"{self.function_address_types}"
            )

    def __len__(self):
        # Total count includes both in-memory and spilled functions
        return len(self._function_map) + len(self._spilled_addrs)

    def __iter__(self):
        # Iterate over all function addresses (in-memory + spilled)
        all_addrs = set(self._function_map.keys()) | self._spilled_addrs
        yield from sorted(all_addrs)

    def get_by_addr(self, addr) -> Function:
        return self._function_map.get(addr)

    def get_by_name(self, name: str, check_previous_names: bool = False) -> Generator[Function]:
        # First check in-memory functions
        for f in self._function_map.values():
            if f.name == name or (check_previous_names and name in f.previous_names):
                yield f

        # Then check spilled functions (need to load them to check name)
        # This is expensive but necessary for correctness
        for addr in list(self._spilled_addrs):
            func = self._load_from_lmdb(addr)
            if func is not None:
                if func.name == name or (check_previous_names and name in func.previous_names):
                    yield func

    def _function_added(self, func: Function):
        """
        A callback method for adding a new function instance to the manager.

        :param func:   The Function instance being added.
        :return:       None
        """

        # Add the function address to the set of function addresses
        self.function_addrs_set.add(func.addr)

        # make sure all functions exist in the call graph
        self.callgraph.add_node(func.addr)

    def contains_addr(self, addr):
        """
        Decide if an address is handled by the function manager.

        Note: this function is non-conformant with python programming idioms, but its needed for performance reasons.

        :param int addr: Address of the function.
        """
        return addr in self._function_map or addr in self._spilled_addrs

    def ceiling_func(self, addr):
        """
        Return the function who has the least address that is greater than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function after `addr`.
        :rtype:          Function or None
        """

        try:
            next_addr = self._function_map.ceiling_addr(addr)
            return self._function_map.get(next_addr)

        except KeyError:
            return None

    def floor_func(self, addr):
        """
        Return the function who has the greatest address that is less than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function before `addr`.
        :rtype:          Function or None
        """

        try:
            prev_addr = self._function_map.floor_addr(addr)
            return self._function_map.get(prev_addr)

        except KeyError:
            return None

    def query(self, query: str, check_previous_names: bool = False) -> Function | None:
        """
        Query for a function using selectors to disambiguate. Supported variations:

            ::<name>           Function <name> in the main object
            ::<addr>::<name>   Function <name> at <addr>
            ::<obj>::<name>    Function <name> in <obj>

        """
        # FIXME: Proper mangle handling
        matches = QUERY_PATTERN.match(query)
        if matches:
            selector = matches.group(2)
            name = matches.group(3)

            if selector is not None and ADDR_PATTERN.fullmatch(selector):
                addr = cast(K, int(matches.group(2), 0))
                try:
                    func = self._function_map.get(addr)
                    if func.name == name or (check_previous_names and name in func.previous_names):
                        return func
                except KeyError:
                    pass

            obj_name = selector or self._kb._project.loader.main_object.binary_basename
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if func.binary_name == obj_name:
                    return func

        return None

    def function(
        self, addr=None, name=None, check_previous_names=False, create=False, syscall=False, plt=None
    ) -> Function | None:
        """
        Get a function object from the function manager.

        Pass either `addr` or `name` with the appropriate values.

        :param int addr: Address of the function.
        :param str name: Name of the function.
        :param bool create: Whether to create the function or not if the function does not exist.
        :param bool syscall: True to create the function as a syscall, False otherwise.
        :param bool or None plt: True to find the PLT stub, False to find a non-PLT stub, None to disable this
                                 restriction.
        :return: The Function instance, or None if the function is not found and create is False.
        :rtype: Function or None
        """
        if name is not None and name.startswith("sub_"):
            # first check if a function with the specified name exists
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func

            # then enter the syntactic sugar mode
            try:
                addr = cast(K, int(name.split("_")[-1], 16))
                name = None
            except ValueError:
                pass

        if addr is not None:
            try:
                f = self._function_map.get(addr)
                if plt is None or f.is_plt == plt:
                    return f
            except KeyError:
                if create:
                    # the function is not found
                    f = self._function_map[addr]
                    if name is not None:
                        f.name = name
                    if syscall:
                        f.is_syscall = True
                    return f
        elif name is not None:
            func = self.query(name, check_previous_names=check_previous_names)
            if func is not None:
                return func

            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func

        return None

    def dbg_draw(self, prefix="dbg_function_"):
        for func_addr, func in self._function_map.items():
            filename = f"{prefix}{func_addr:#08x}.png"
            func.dbg_draw(filename)

    def rebuild_callgraph(self):
        self.callgraph = networkx.MultiDiGraph()
        cfg = self._kb.cfgs.get_most_accurate()
        for func_addr in self._function_map:
            self.callgraph.add_node(func_addr)
        for func in self._function_map.values():
            if func.block_addrs_set:
                for node in func.transition_graph.nodes():
                    if isinstance(node, Function):
                        self.callgraph.add_edge(func.addr, node.addr)
                    else:
                        cfgnode = cfg.get_any_node(node.addr)
                        if (
                            cfgnode is not None
                            and cfgnode.function_address is not None
                            and cfgnode.function_address != func.addr
                        ):
                            self.callgraph.add_edge(func.addr, cfgnode.function_address)

    #
    # LRU Cache Management
    #

    @property
    def max_cached_functions(self) -> int | None:
        """
        Get the maximum number of functions to keep in memory.
        None means unlimited (no eviction).
        """
        return self._max_cached_functions

    @max_cached_functions.setter
    def max_cached_functions(self, value: int | None) -> None:
        """
        Set the maximum number of functions to keep in memory.
        If the new limit is lower than the current number of cached functions,
        excess functions will be evicted to LMDB.
        """
        self._max_cached_functions = value
        if value is not None:
            # Evict excess functions, but stop if eviction fails
            while len(self._function_map) > value:
                if not self._evict_lru():
                    # Can't evict any more functions
                    break

    @property
    def cached_function_count(self) -> int:
        """Return the number of functions currently in memory."""
        return len(self._function_map)

    @property
    def spilled_function_count(self) -> int:
        """Return the number of functions currently spilled to LMDB."""
        return len(self._spilled_addrs)

    @property
    def total_function_count(self) -> int:
        """Return the total number of functions (in memory + spilled)."""
        return len(self._function_map) + len(self._spilled_addrs)

    def _init_lmdb(self) -> None:
        """Lazily initialize the LMDB database for spilling functions."""
        if self._lmdb_env is not None:
            return

        self._lmdb_path = os.path.join(tempfile.gettempdir(), f"angr_lru_cache_{uuid.uuid4().hex}.lmdb")
        self._lmdb_env = lmdb.open(self._lmdb_path, map_size=1024 * 1024 * 1024, max_dbs=1)
        self._lmdb_functions_db = self._lmdb_env.open_db(b"functions")
        l.debug("Initialized LRU cache LMDB at %s", self._lmdb_path)

    def _touch(self, addr: K) -> None:
        """Update the LRU order for a function (move to end = most recently used)."""
        if addr in self._lru_order:
            self._lru_order.move_to_end(addr)

    def _on_function_stored(self, addr: K) -> None:
        """Called when a function is stored in the function map."""
        # Add to LRU order if not already there
        if addr not in self._lru_order:
            self._lru_order[addr] = None
        else:
            self._lru_order.move_to_end(addr)

        # Remove from spilled set if it was there
        self._spilled_addrs.discard(addr)

        # Check if we need to evict (but not during loading, as functions may be partially initialized)
        if (
            self._eviction_enabled
            and not self._loading_from_lmdb
            and self._max_cached_functions is not None
            and len(self._function_map) > self._max_cached_functions
        ):
            self._evict_lru()

    def _evict_lru(self) -> bool:
        """
        Evict the least recently used function to LMDB.

        :return: True if a function was successfully evicted, False otherwise.
        """
        if not self._lru_order:
            return False

        # Try to find a function that can be evicted (is serializable)
        evicted = False
        checked_addrs = []

        for lru_addr in self._lru_order:
            # Don't evict if it's not in memory
            if lru_addr not in self._function_map:
                checked_addrs.append(lru_addr)
                continue

            # Get the function
            func = dict.__getitem__(self._function_map, lru_addr)  # Direct access to avoid touching LRU

            # Check if function can be serialized (has returning set)
            # Functions created as shells during loading may have returning=None
            if func.returning is None:
                continue

            # Save to LMDB before evicting
            try:
                self._save_to_lmdb(func)
            except Exception as e:
                l.warning("Failed to serialize function %s for eviction: %s",
                         hex(lru_addr) if isinstance(lru_addr, int) else lru_addr, e)
                continue

            # Remove from in-memory map (use parent class method to avoid recursion)
            SortedDict.__delitem__(self._function_map, lru_addr)

            # Remove from LRU order
            del self._lru_order[lru_addr]

            # Add to spilled set
            self._spilled_addrs.add(lru_addr)

            l.debug("Evicted function %s to LMDB", hex(lru_addr) if isinstance(lru_addr, int) else lru_addr)
            evicted = True
            break

        # Clean up any LRU entries that aren't in memory
        for addr in checked_addrs:
            if addr in self._lru_order and addr not in self._function_map:
                del self._lru_order[addr]

        if not evicted:
            l.debug("Could not find any function to evict (all may be non-serializable)")

        return evicted

    def _save_to_lmdb(self, func: Function) -> None:
        """Save a single function to LMDB."""
        self._init_lmdb()

        cmsg = func.serialize_to_cmessage()
        key = str(func.addr).encode("utf-8")

        with self._lmdb_env.begin(write=True, db=self._lmdb_functions_db) as txn:
            txn.put(key, cmsg.SerializeToString())

    def _load_from_lmdb(self, addr: K) -> Function | None:
        """Load a function from LMDB and bring it back into memory."""
        if self._lmdb_env is None:
            return None

        # Prevent recursive loading
        if addr in self._currently_loading:
            return None

        self._currently_loading.add(addr)
        old_loading_state = self._loading_from_lmdb
        self._loading_from_lmdb = True

        try:
            key = str(addr).encode("utf-8")

            with self._lmdb_env.begin(db=self._lmdb_functions_db) as txn:
                value = txn.get(key)
                if value is None:
                    return None

                # Deserialize protobuf
                from angr.protos import function_pb2

                cmsg = function_pb2.Function()
                cmsg.ParseFromString(value)

                # Reconstruct function
                func = Function.parse_from_cmessage(
                    cmsg,
                    function_manager=self,
                    project=self._kb._project,
                    all_func_addrs=self.function_addrs_set,
                )

            # Remove from spilled set
            self._spilled_addrs.discard(addr)

            # Add to in-memory map (this will trigger _on_function_stored)
            # Use parent class method to store without triggering our __setitem__
            SortedDict.__setitem__(self._function_map, addr, func)
            self._on_function_stored(addr)

            l.debug("Loaded function %s from LMDB", hex(addr) if isinstance(addr, int) else addr)
            return func
        finally:
            self._currently_loading.discard(addr)
            self._loading_from_lmdb = old_loading_state

            # After loading is complete (and we're back to not loading), evict if needed
            if (
                not self._loading_from_lmdb
                and self._eviction_enabled
                and self._max_cached_functions is not None
                and len(self._function_map) > self._max_cached_functions
            ):
                # Evict excess functions, but stop if eviction fails
                while len(self._function_map) > self._max_cached_functions:
                    if not self._evict_lru():
                        # Can't evict any more functions (all may be non-serializable)
                        break

    def _load_all_spilled(self) -> None:
        """Load all spilled functions back into memory (disables eviction temporarily)."""
        if not self._spilled_addrs:
            return

        # Temporarily disable eviction
        old_eviction_state = self._eviction_enabled
        self._eviction_enabled = False

        try:
            # Make a copy of spilled_addrs since _load_from_lmdb modifies it
            addrs_to_load = list(self._spilled_addrs)
            for addr in addrs_to_load:
                self._load_from_lmdb(addr)
        finally:
            self._eviction_enabled = old_eviction_state

    def save_all(self, db_path: str | None = None) -> str:
        """
        Save all functions to an LMDB database.

        This method saves both in-memory and spilled functions to the destination database.

        :param db_path: Optional path for the LMDB database. If not provided, an automatically
                        generated filename in the system temporary directory will be used.
        :return: The path to the LMDB database file.
        """
        if db_path is None:
            db_path = os.path.join(tempfile.gettempdir(), f"angr_functions_{uuid.uuid4().hex}.lmdb")

        # Create LMDB environment with a reasonable map size (1GB default)
        env = lmdb.open(db_path, map_size=1024 * 1024 * 1024, max_dbs=2)

        try:
            # Create separate databases for functions and metadata
            functions_db = env.open_db(b"functions")
            metadata_db = env.open_db(b"metadata")

            with env.begin(write=True) as txn:
                # Save in-memory functions
                for func_addr, func in self._function_map.items():
                    # Serialize function to protobuf
                    cmsg = func.serialize_to_cmessage()
                    key = str(func_addr).encode("utf-8")
                    txn.put(key, cmsg.SerializeToString(), db=functions_db)

                # Copy spilled functions from LRU cache LMDB to the destination
                if self._lmdb_env is not None and self._spilled_addrs:
                    with self._lmdb_env.begin(db=self._lmdb_functions_db) as src_txn:
                        for addr in self._spilled_addrs:
                            key = str(addr).encode("utf-8")
                            value = src_txn.get(key)
                            if value is not None:
                                txn.put(key, value, db=functions_db)

                # Save metadata
                metadata = {
                    "callgraph": networkx.node_link_data(self.callgraph),
                    "function_addrs_set": list(self.function_addrs_set),
                    "block_map_keys": list(self.block_map.keys()),
                    "max_cached_functions": self._max_cached_functions,
                }
                txn.put(b"metadata", pickle.dumps(metadata), db=metadata_db)

        finally:
            env.close()

        total_count = len(self._function_map) + len(self._spilled_addrs)
        l.info("Saved %d functions to %s", total_count, db_path)
        return db_path

    def load_all(self, db_path: str) -> None:
        """
        Load all functions from an LMDB database.

        If max_cached_functions is set, only the most recently stored functions
        will be loaded into memory, with the rest remaining in LMDB for lazy loading.

        :param db_path: Path to the LMDB database to load from.
        """
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"LMDB database not found: {db_path}")

        # Clear existing data
        self.clear()

        env = lmdb.open(db_path, readonly=True, max_dbs=2)

        try:
            functions_db = env.open_db(b"functions")
            metadata_db = env.open_db(b"metadata")

            # First pass: collect all function addresses
            all_func_addrs = set()
            with env.begin(db=functions_db) as txn:
                cursor = txn.cursor()
                for key, _ in cursor:
                    func_addr = int(key.decode("utf-8"))
                    all_func_addrs.add(func_addr)

            # Load metadata first
            with env.begin() as txn:
                metadata_bytes = txn.get(b"metadata", db=metadata_db)
                if metadata_bytes:
                    metadata = pickle.loads(metadata_bytes)
                    self.callgraph = networkx.node_link_graph(metadata["callgraph"], directed=True, multigraph=True)
                    # Restore max_cached_functions if saved
                    if "max_cached_functions" in metadata and self._max_cached_functions is None:
                        self._max_cached_functions = metadata["max_cached_functions"]

            # Temporarily disable eviction during bulk load
            old_eviction_state = self._eviction_enabled
            self._eviction_enabled = False

            # Second pass: load functions
            # If we have a cache limit, we need to be smart about what we load
            func_addrs_list = sorted(all_func_addrs)

            with env.begin() as txn:
                for func_addr in func_addrs_list:
                    key = str(func_addr).encode("utf-8")
                    value = txn.get(key, db=functions_db)
                    if value is None:
                        continue

                    # Deserialize protobuf
                    from angr.protos import function_pb2

                    cmsg = function_pb2.Function()
                    cmsg.ParseFromString(value)

                    # Reconstruct function
                    func = Function.parse_from_cmessage(
                        cmsg,
                        function_manager=self,
                        project=self._kb._project,
                        all_func_addrs=all_func_addrs,
                    )

                    # Add to function map using parent class method
                    SortedDict.__setitem__(self._function_map, func_addr, func)
                    self.function_addrs_set.add(func_addr)
                    self._lru_order[func_addr] = None

            # Re-enable eviction
            self._eviction_enabled = old_eviction_state

            # If we have a cache limit and loaded more than the limit,
            # evict excess functions
            if self._max_cached_functions is not None:
                while len(self._function_map) > self._max_cached_functions:
                    if not self._evict_lru():
                        # Can't evict any more functions
                        break

        finally:
            env.close()

        # Reconnect function manager references for in-memory functions
        for func in self._function_map.values():
            func._function_manager = self

        total_count = len(self._function_map) + len(self._spilled_addrs)
        l.info("Loaded %d functions from %s (%d in memory, %d spilled)",
               total_count, db_path, len(self._function_map), len(self._spilled_addrs))


KnowledgeBasePlugin.register_default("functions", FunctionManager)
