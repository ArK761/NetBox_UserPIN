"""
PIN format and strength rules.
"""
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

__all__ = (
    'is_weak_pin',
    'validate_pin',
)


def _is_sequence(pin):
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in zip(digits, digits[1:])}
    return steps in ({1}, {-1})


def _is_repeating_pattern(pin):
    # 111111, 121212, 123123, 12341234 ...
    for period in range(1, len(pin) // 2 + 1):
        if len(pin) % period == 0 and pin[:period] * (len(pin) // period) == pin:
            return True
    return False


def is_weak_pin(pin, blocked=()):
    return _is_repeating_pattern(pin) or _is_sequence(pin) or pin in blocked


def parse_blocked_pins(text):
    return {line.strip() for line in (text or '').replace(',', '\n').splitlines() if line.strip()}


def validate_pin(pin, settings):
    """
    Validate a new PIN against the current PinSettings. Raises ValidationError.
    """
    if not pin or not pin.isdigit() or not pin.isascii():
        raise ValidationError(_('The PIN must contain digits only.'), code='digits')
    if len(pin) != settings.pin_length:
        raise ValidationError(
            _('The PIN must be exactly %(length)d digits long.'), code='length',
            params={'length': settings.pin_length},
        )
    if settings.block_weak_pins and is_weak_pin(pin, parse_blocked_pins(settings.blocked_pins)):
        raise ValidationError(
            _('This PIN is too easy to guess (repeated digits, sequences or a blocked PIN). Choose another one.'),
            code='weak',
        )
