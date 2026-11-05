"""Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end

FortiDAST connector entry point.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import OpHandler, _check_health, operations

logger = get_logger("fortinet-fortidast")


class FortiDAST(Connector):
    """FortiDAST connector entry point."""

    def execute(
        self,
        config: Mapping[str, Any],
        operation: str,
        operation_params: Mapping[str, Any],
        **kwargs: Any,
    ) -> Any:
        op: OpHandler | None = operations.get(operation)
        if not op:
            raise ConnectorError(f"Unknown operation {operation!r}")
        try:
            return op(config, operation_params)
        except ConnectorError:
            raise
        except Exception as err:
            logger.exception("FortiDAST operation failed [%s]", err)
            raise ConnectorError(f"FortiDAST operation failed [{err}]") from err

    def check_health(self, config: Mapping[str, Any]) -> bool:
        try:
            return _check_health(config)
        except ConnectorError:
            raise
        except Exception as err:
            raise ConnectorError(str(err)) from err
