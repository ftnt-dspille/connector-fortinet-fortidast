# -*- coding: utf-8 -*-
"""Test stubs for running outside a FortiSOAR appliance.

Stubs the FortiSOAR connector SDK (`connectors.core.connector`) so the
connector imports standalone, and registers the hyphenated connector
directory as the importable package `fortidast` (module names cannot carry
hyphens).
"""
import logging
import pathlib
import sys
import types

CONNECTOR_DIR = pathlib.Path(__file__).resolve().parents[1]

if "connectors" not in sys.modules:
    _connectors = types.ModuleType("connectors")
    _connectors.__path__ = []
    _core = types.ModuleType("connectors.core")
    _core.__path__ = []
    _connector_mod = types.ModuleType("connectors.core.connector")

    class ConnectorError(Exception):
        pass

    def get_logger(name):
        return logging.getLogger(name)

    class Connector(object):
        pass

    _connector_mod.ConnectorError = ConnectorError
    _connector_mod.get_logger = get_logger
    _connector_mod.Connector = Connector
    _core.connector = _connector_mod
    _connectors.core = _core
    sys.modules["connectors"] = _connectors
    sys.modules["connectors.core"] = _core
    sys.modules["connectors.core.connector"] = _connector_mod

if "fortidast" not in sys.modules:
    _pkg = types.ModuleType("fortidast")
    _pkg.__path__ = [str(CONNECTOR_DIR)]
    sys.modules["fortidast"] = _pkg
