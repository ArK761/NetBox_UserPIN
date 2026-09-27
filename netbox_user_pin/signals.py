"""
Signals other plugins can subscribe to (e.g. to write the events into their own audit log).

Every signal is sent with ``sender=UserPin`` and the keyword arguments ``user``, ``request`` (may be None),
``scope`` (may be empty) and, for admin actions, ``actor``.
"""
from django.dispatch import Signal

__all__ = (
    'pin_changed',
    'pin_failed',
    'pin_locked',
    'pin_locked_out',
    'pin_reset',
    'pin_set',
    'pin_unlocked',
)

pin_set = Signal()          # user set a PIN for the first time
pin_changed = Signal()      # user changed an existing PIN
pin_reset = Signal()        # administrator removed a user's PIN (actor=admin)
pin_unlocked = Signal()     # correct PIN entered, scope unlocked in the session
pin_failed = Signal()       # wrong PIN entered (kwarg: remaining_attempts)
pin_locked_out = Signal()   # too many failed attempts, user locked out (kwarg: until)
pin_locked = Signal()       # user locked the scope(s) manually
