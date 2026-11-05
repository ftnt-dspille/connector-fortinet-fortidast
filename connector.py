# -*- coding: utf-8 -*-
""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError

from .operations import operations, _check_health

logger = get_logger("fortinet-fortidast")


class FortiDAST(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            op = operations.get(operation)
            if not op:
                raise ConnectorError("Unknown operation '{0}'".format(operation))
            return op(config, operation_params)
        except ConnectorError:
            raise
        except Exception as err:
            logger.exception("FortiDAST operation failed [%s]", err)
            raise ConnectorError("FortiDAST operation failed [{0}]".format(err))

    def check_health(self, config):
        try:
            _check_health(config)
        except ConnectorError:
            raise
        except Exception as e:
            raise ConnectorError(str(e))
