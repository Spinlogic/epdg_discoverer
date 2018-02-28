# -*- coding: utf-8 -*-

# 
# (c) Spinlogic, Albacete, Spain, 2018.

"""
This module defines exceptions used in ikev2_class
"""

class PRFError(BaseException):
    """
    Thrown when PRF could not be obtained.
    """

    def __str__(self):
        return "PRF could not be obtained. This module currently only works with Python 3."