#!/usr/bin/env python3
"""Test cases for FunctionManager LMDB save/load and LRU cache functionality."""
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import shutil
import tempfile
import unittest

import angr

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestFunctionManagerLMDB(unittest.TestCase):
    """Test cases for FunctionManager LMDB serialization."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_save_all_auto_path(self):
        """Test save_all() with automatically generated path."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        original_count = len(fm)
        assert original_count > 0, "No functions found"

        # Save to auto-generated path
        db_path = fm.save_all()

        try:
            assert os.path.exists(db_path), f"LMDB database not created at {db_path}"
            assert db_path.endswith(".lmdb"), "Path should end with .lmdb"
            assert "angr_functions_" in db_path, "Path should contain 'angr_functions_'"
        finally:
            if os.path.exists(db_path):
                shutil.rmtree(db_path)

    def test_save_all_custom_path(self):
        """Test save_all() with custom path."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = os.path.join(tmpdir, "custom_functions.lmdb")
            returned_path = fm.save_all(db_path=custom_path)

            assert returned_path == custom_path, f"Expected {custom_path}, got {returned_path}"
            assert os.path.exists(custom_path), "Database not created at custom path"

    def test_load_all(self):
        """Test loading functions from LMDB database."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        original_count = len(fm)
        original_addrs = set(fm.function_addrs_set)

        # Store some function details for comparison
        sample_funcs = {}
        for i, (addr, func) in enumerate(fm._function_map.items()):
            if i >= 5:
                break
            sample_funcs[addr] = {
                "name": func.name,
                "is_syscall": func.is_syscall,
                "is_plt": func.is_plt,
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.lmdb")
            fm.save_all(db_path)

            # Create new project and load functions
            proj2 = angr.Project(self.bin_path, auto_load_libs=False)
            fm2 = proj2.kb.functions
            fm2.clear()
            assert len(fm2) == 0, "Function manager should be empty after clear"

            fm2.load_all(db_path)

            # Verify counts match
            assert len(fm2) == original_count, f"Count mismatch: {len(fm2)} != {original_count}"

            # Verify addresses match
            assert set(fm2.function_addrs_set) == original_addrs, "Function addresses mismatch"

            # Verify function properties
            for addr, props in sample_funcs.items():
                loaded_func = fm2[addr]
                assert loaded_func.name == props["name"], f"Name mismatch for {hex(addr)}"
                assert loaded_func.is_syscall == props["is_syscall"], f"is_syscall mismatch for {hex(addr)}"
                assert loaded_func.is_plt == props["is_plt"], f"is_plt mismatch for {hex(addr)}"

    def test_load_all_nonexistent_path(self):
        """Test load_all() with nonexistent path raises FileNotFoundError."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        fm = proj.kb.functions

        with self.assertRaises(FileNotFoundError):
            fm.load_all("/nonexistent/path/to/database.lmdb")


class TestFunctionManagerLRUCache(unittest.TestCase):
    """Test cases for FunctionManager LRU cache functionality."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_default_unlimited_cache(self):
        """Test that default cache is unlimited (no eviction)."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        assert fm.max_cached_functions is None, "Default should be None (unlimited)"
        assert fm.spilled_function_count == 0, "No functions should be spilled by default"
        assert fm.cached_function_count == fm.total_function_count, "All functions should be in memory"

    def test_set_cache_limit(self):
        """Test setting cache limit triggers eviction."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_count = len(fm)

        # Set cache limit
        cache_limit = 5
        fm.max_cached_functions = cache_limit

        assert fm.cached_function_count <= cache_limit, f"Cache limit not respected: {fm.cached_function_count} > {cache_limit}"
        assert fm.total_function_count == total_count, "Total function count should be preserved"
        assert fm.spilled_function_count == total_count - fm.cached_function_count, "Spilled count incorrect"

    def test_cache_properties(self):
        """Test cache monitoring properties."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        # Verify properties
        assert fm.cached_function_count <= 3
        assert fm.spilled_function_count >= 0
        assert fm.total_function_count == total
        assert fm.cached_function_count + fm.spilled_function_count == fm.total_function_count

    def test_access_spilled_function(self):
        """Test that accessing a spilled function loads it from LMDB."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        # Set small cache limit
        fm.max_cached_functions = 3

        # Find a spilled function
        if fm.spilled_function_count == 0:
            self.skipTest("No spilled functions to test")

        spilled_addr = next(iter(fm._spilled_addrs))

        # Access the spilled function
        func = fm[spilled_addr]

        # Verify it was loaded
        assert func is not None, "Failed to load spilled function"
        assert func.addr == spilled_addr, "Loaded function has wrong address"

    def test_dynamic_cache_limit_decrease(self):
        """Test decreasing cache limit dynamically."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Start with larger limit
        fm.max_cached_functions = 10
        assert fm.cached_function_count <= 10

        # Decrease limit
        fm.max_cached_functions = 5
        assert fm.cached_function_count <= 5

        # Further decrease
        fm.max_cached_functions = 2
        assert fm.cached_function_count <= 2

        # Total should be preserved
        assert fm.total_function_count == total

    def test_dynamic_cache_limit_increase(self):
        """Test increasing cache limit dynamically."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Start with small limit
        fm.max_cached_functions = 3
        cached_before = fm.cached_function_count

        # Increase limit (shouldn't auto-load more)
        fm.max_cached_functions = 10
        assert fm.cached_function_count >= cached_before  # May increase due to access

        # Total preserved
        assert fm.total_function_count == total

    def test_set_unlimited_cache(self):
        """Test setting cache to unlimited (None)."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Set small limit first
        fm.max_cached_functions = 3

        # Set to unlimited
        fm.max_cached_functions = None

        assert fm.max_cached_functions is None
        # Note: Setting to None doesn't auto-load spilled functions
        assert fm.total_function_count == total

    def test_contains_with_spilled(self):
        """Test __contains__ checks both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        all_addrs = set(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        # All addresses should still be "in" the function manager
        for addr in all_addrs:
            assert addr in fm, f"Address {hex(addr)} should be in function manager"

    def test_iter_with_spilled(self):
        """Test __iter__ includes both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        all_addrs_before = set(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        # Iteration should still include all addresses
        all_addrs_after = set(fm)
        assert all_addrs_before == all_addrs_after, "Iteration should include all functions"

    def test_len_with_spilled(self):
        """Test __len__ returns total count including spilled."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        # Length should still return total count
        assert len(fm) == total_before, "len() should return total count"


class TestFunctionManagerLRUCacheSaveLoad(unittest.TestCase):
    """Test cases for save/load with LRU cache enabled."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_save_with_spilled_functions(self):
        """Test save_all() saves both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_count = len(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.lmdb")
            fm.save_all(db_path)

            # Load into new project (without cache limit)
            proj2 = angr.Project(self.bin_path, auto_load_libs=False)
            fm2 = proj2.kb.functions
            fm2.load_all(db_path)

            # All functions should be loaded
            assert len(fm2) == total_count, f"Not all functions saved: {len(fm2)} != {total_count}"

    def test_load_with_cache_limit(self):
        """Test load_all() respects cache limit."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_count = len(fm)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.lmdb")
            fm.save_all(db_path)

            # Load into new project with cache limit
            proj2 = angr.Project(self.bin_path, auto_load_libs=False)
            fm2 = proj2.kb.functions
            fm2.max_cached_functions = 3
            fm2.load_all(db_path)

            # Total count should match
            assert fm2.total_function_count == total_count

            # Cache limit should be respected
            assert fm2.cached_function_count <= 3

            # Can still access some functions (don't iterate all to keep test fast)
            accessed_count = 0
            for addr in fm2:
                func = fm2[addr]
                assert func is not None
                accessed_count += 1
                if accessed_count >= 5:
                    break


class TestFunctionManagerLRUCacheEdgeCases(unittest.TestCase):
    """Test edge cases for LRU cache."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_delete_spilled_function(self):
        """Test deleting a spilled function."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set small cache limit
        fm.max_cached_functions = 3

        if fm.spilled_function_count == 0:
            self.skipTest("No spilled functions to test")

        # Get a spilled address
        spilled_addr = next(iter(fm._spilled_addrs))

        # Delete it
        del fm[spilled_addr]

        # Verify it's removed
        assert spilled_addr not in fm
        assert len(fm) == total_before - 1

    def test_delete_cached_function(self):
        """Test deleting a cached (in-memory) function."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set cache limit
        fm.max_cached_functions = 5

        # Get a cached address
        cached_addr = next(iter(fm._function_map.keys()))

        # Delete it
        del fm[cached_addr]

        # Verify it's removed
        assert cached_addr not in fm
        assert len(fm) == total_before - 1

    def test_clear_with_spilled(self):
        """Test clear() removes both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        # Set cache limit
        fm.max_cached_functions = 3

        # Clear
        fm.clear()

        assert len(fm) == 0
        assert fm.cached_function_count == 0
        assert fm.spilled_function_count == 0

    def test_copy_with_spilled(self):
        """Test copy() works with spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Set cache limit
        fm.max_cached_functions = 5

        # Copy
        fm_copy = fm.copy()

        # Verify copy has all functions
        assert fm_copy.total_function_count == total


if __name__ == "__main__":
    unittest.main()
