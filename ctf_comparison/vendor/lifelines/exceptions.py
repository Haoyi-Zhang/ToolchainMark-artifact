# -*- coding: utf-8 -*-

class StatError(Exception):
    pass

class ProportionalHazardAssumptionError(Exception):
    pass

class ConvergenceError(ValueError):
    def __init__(self, msg, original_exception=""):
        super().__init__(msg + "%s" % original_exception)
        self.original_exception = original_exception

class ConvergenceWarning(RuntimeWarning):
    pass

class StatisticalWarning(RuntimeWarning):
    pass

class ApproximationWarning(RuntimeWarning):
    pass
