"""
Working time of the PIN-only accesses: the working days, the hours and the public holidays of a country.

The general rules live on the PIN-only page; every access may have its own (a Hungarian technician gets the Hungarian
holidays whatever the language of the interface is) or none at all. Outside the working time the person cannot sign
in; when the time ends while they work, they have ``GRACE_MINUTES`` and one save, then they are signed out.
"""
import datetime
import functools
from collections import namedtuple

from django.utils import timezone
from django.utils.dates import WEEKDAYS_ABBR
from django.utils.translation import gettext as _

try:  # the public holidays of the countries (pip install holidays); without it only days and hours are checked
    import holidays
except ImportError:  # pragma: no cover - depends on the installation
    holidays = None

GRACE_MINUTES = 30

Rules = namedtuple('Rules', 'country days start end')

# the countries offered (the library knows more; these are the ones a company is likely to work with)
COUNTRY_NAMES = {
    'SK': 'Slovakia', 'CZ': 'Czechia', 'HU': 'Hungary', 'AT': 'Austria', 'PL': 'Poland', 'DE': 'Germany',
    'UA': 'Ukraine', 'HR': 'Croatia', 'SI': 'Slovenia', 'RO': 'Romania', 'BG': 'Bulgaria', 'RS': 'Serbia',
    'GB': 'United Kingdom', 'IE': 'Ireland', 'FR': 'France', 'ES': 'Spain', 'IT': 'Italy', 'NL': 'Netherlands',
    'BE': 'Belgium', 'CH': 'Switzerland', 'SE': 'Sweden', 'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland',
    'PT': 'Portugal', 'GR': 'Greece', 'LT': 'Lithuania', 'LV': 'Latvia', 'EE': 'Estonia', 'US': 'United States',
    'CA': 'Canada',
}


def available():
    """Is the library of public holidays installed?"""
    return holidays is not None


def country_choices():
    """[(code, name)] of the countries whose holidays are known (all of them when the library is missing)."""
    known = set(holidays.list_supported_countries()) if holidays is not None else set(COUNTRY_NAMES)
    return sorted(((code, _(name)) for code, name in COUNTRY_NAMES.items() if code in known), key=lambda r: r[1])


@functools.lru_cache(maxsize=64)
def _calendar(country, year):
    return holidays.country_holidays(country, years=year)


def holiday_name(country, day):
    """The name of the public holiday of ``country`` on ``day`` ('' = none, or the library is missing)."""
    if holidays is None or not country:
        return ''
    try:
        return _calendar(country, day.year).get(day) or ''
    except Exception:  # noqa: BLE001 - an unknown country: no holidays rather than no sign-in
        return ''


def clean_days(days):
    """'01234' / ['0', '1'] -> the sorted weekdays as a string; at least one day."""
    chosen = sorted({int(d) for d in str(days if isinstance(days, str) else ''.join(days)) if d.isdigit() and int(d) < 7})
    return ''.join(str(d) for d in chosen)


def parse_time(text):
    """'06:00' -> datetime.time; a time object passes."""
    if isinstance(text, datetime.time):
        return text.replace(second=0, microsecond=0)
    try:
        hour, _sep, minute = str(text).strip().partition(':')
        return datetime.time(int(hour), int(minute or 0))
    except (TypeError, ValueError):
        return None


def rules_of(guest, settings=None):
    """The rules that apply to the access, or ``None`` when there is no limit."""
    from . import service
    settings = settings or service.get_settings()
    if guest.work_mode == 'none':
        return None
    if guest.work_mode == 'own':
        return Rules(guest.work_country or settings.guest_work_country,
                     clean_days(guest.work_days or settings.guest_work_days),
                     guest.work_from or settings.guest_work_from, guest.work_to or settings.guest_work_to)
    if not settings.guest_work_on:
        return None
    return Rules(settings.guest_work_country, clean_days(settings.guest_work_days),
                 settings.guest_work_from, settings.guest_work_to)


def is_workday(rules, day):
    return str(day.weekday()) in rules.days and not holiday_name(rules.country, day)


def state(guest, now=None, settings=None):
    """
    ``'ok'`` (inside the working time, or no limit), ``'grace'`` (the time just ended: the last minutes and one save),
    ``'before'``, ``'after'`` or ``'off'`` (a day off or a public holiday).
    """
    rules = rules_of(guest, settings)
    if rules is None:
        return 'ok'
    now = timezone.localtime(now or timezone.now())
    if not is_workday(rules, now.date()):
        return 'off'
    clock = now.time().replace(tzinfo=None)
    if rules.start <= clock < rules.end:
        return 'ok'
    if clock < rules.start:
        return 'before'
    end = now.replace(hour=rules.end.hour, minute=rules.end.minute, second=0, microsecond=0)
    return 'grace' if now < end + datetime.timedelta(minutes=GRACE_MINUTES) else 'after'


def seconds_until_cut(guest, now=None, settings=None):
    """In the grace period: how many seconds are left (0 when it is over or there is no limit)."""
    rules = rules_of(guest, settings)
    if rules is None:
        return 0
    now = timezone.localtime(now or timezone.now())
    end = now.replace(hour=rules.end.hour, minute=rules.end.minute, second=0, microsecond=0)
    return max(0, int((end + datetime.timedelta(minutes=GRACE_MINUTES) - now).total_seconds()))


def days_text(days):
    """'01234' -> 'Mon–Fri' (the shortest form: a run of days, else the list)."""
    days = sorted(int(d) for d in days)
    if not days:
        return ''
    names = [str(WEEKDAYS_ABBR[d]) for d in days]
    if len(days) > 2 and days == list(range(days[0], days[-1] + 1)):
        return f'{names[0]}–{names[-1]}'
    return ', '.join(names)


def describe(rules):
    """'Mon–Fri 06:00–16:00 (Slovakia)'."""
    names = dict(country_choices())
    where = names.get(rules.country, rules.country)
    return '%s %s–%s%s' % (days_text(rules.days), rules.start.strftime('%H:%M'), rules.end.strftime('%H:%M'),
                           f' ({where})' if where else '')


def message(guest, now=None):
    """What the person is told when the working time keeps them out (or is about to end)."""
    rules = rules_of(guest)
    if rules is None:
        return ''
    now = timezone.localtime(now or timezone.now())
    holiday = holiday_name(rules.country, now.date())
    text = _('You work from %(rules)s. The access is closed outside this time.') % {'rules': describe(rules)}
    if holiday:
        text = _('Today is a public holiday (%(name)s).') % {'name': holiday} + ' ' + text
    return text


SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


def write_state(guest, now=None, settings=None):
    """
    May the person change anything now? ``'free'`` (inside the working time, or no limit), ``'once'`` (the time just
    ended: one save) or ``'blocked'`` (outside the working time: reading only).
    """
    value = state(guest, now, settings)
    return 'free' if value == 'ok' else ('once' if value == 'grace' else 'blocked')


def read_only_text(guest, now=None):
    """'Outside your working time (Mon–Fri 06:00–16:00) you can only read.' (in the language that is active)."""
    rules = rules_of(guest)
    now = timezone.localtime(now or timezone.now())
    holiday = holiday_name(rules.country, now.date()) if rules else ''
    text = _('Outside your working time (%(rules)s) you can only read: nothing can be changed or saved.') % {
        'rules': describe(rules) if rules else ''}
    if holiday:
        text = _('Today is a public holiday (%(name)s).') % {'name': holiday} + ' ' + text
    return text
