# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Orchestrator for semantic variable naming patterns.

This module coordinates multiple naming patterns and applies them in priority order.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import networkx

from angr import ailment
from angr.sim_variable import SimVariable

from .naming_base import SemanticNamingBase
from .loop_counter_naming import LoopCounterNaming
from .array_index_naming import ArrayIndexNaming
from .call_result_naming import CallResultNaming
from .size_naming import SizeNaming
from .boolean_naming import BooleanNaming
from .pointer_naming import PointerNaming

if TYPE_CHECKING:
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

l = logging.getLogger(name=__name__)

# All available naming patterns, will be sorted by priority
NAMING_PATTERNS: list[type[SemanticNamingBase]] = [
    LoopCounterNaming,
    PointerNaming,
    ArrayIndexNaming,
    CallResultNaming,
    SizeNaming,
    BooleanNaming,
]


class SemanticNamingOrchestrator:
    """
    Orchestrates multiple semantic naming patterns.

    Runs each pattern in priority order (lower PRIORITY value = runs first).
    Variables named by higher-priority patterns are not renamed by lower-priority ones.
    """

    def __init__(
        self,
        ail_graph: networkx.DiGraph,
        variable_manager: VariableManagerInternal,
        entry_node: ailment.Block | None = None,
        patterns: list[type[SemanticNamingBase]] | None = None,
    ):
        self._graph = ail_graph
        self._variable_manager = variable_manager
        self._entry_node = entry_node
        self._patterns = patterns or NAMING_PATTERNS

        # Track all renamed variables
        self._renamed_vars: set[SimVariable] = set()
        self._var_to_pattern: dict[SimVariable, str] = {}

    def run(self) -> dict[SimVariable, str]:
        """
        Run all semantic naming patterns in priority order.

        :return: Combined mapping of all renamed variables to their new names
        """
        all_renames: dict[SimVariable, str] = {}

        # Sort patterns by priority (lower = higher priority)
        sorted_patterns = sorted(self._patterns, key=lambda p: p.PRIORITY)

        for pattern_class in sorted_patterns:
            try:
                pattern = pattern_class(
                    self._graph,
                    self._variable_manager,
                    entry_node=self._entry_node,
                )

                # Analyze to get suggested renames
                var_names = pattern.analyze()

                if not var_names:
                    continue

                # Apply names, excluding already-renamed variables
                renamed = pattern.apply_names(exclude_vars=self._renamed_vars)

                # Track what was renamed
                for var in renamed:
                    if var in var_names:
                        all_renames[var] = var_names[var]
                        self._var_to_pattern[var] = pattern_class.__name__

                self._renamed_vars.update(renamed)

                l.debug(
                    "Pattern %s renamed %d variables",
                    pattern_class.__name__,
                    len(renamed)
                )

            except Exception:  # pylint:disable=broad-except
                l.warning(
                    "Semantic naming pattern %s failed",
                    pattern_class.__name__,
                    exc_info=True
                )

        return all_renames

    @property
    def renamed_variables(self) -> set[SimVariable]:
        """Return the set of all renamed variables."""
        return self._renamed_vars

    @property
    def variable_patterns(self) -> dict[SimVariable, str]:
        """Return mapping of variables to the pattern that renamed them."""
        return self._var_to_pattern
