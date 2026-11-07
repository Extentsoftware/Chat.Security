"""Importing this package registers every tool (the ToolLoader.EnsureLoadedAsync equivalent).

Left out on purpose: GoogleSheetPlugin, DiaryImportPlugin and ChemicalMasterImportPlugin,
which read the legacy Google Sheets.
"""
from . import activities, farm_reads, resources  # noqa: F401
