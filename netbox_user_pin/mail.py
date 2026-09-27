"""
Sending e-mails for the plugin.

When an SMTP server is set on the Mail page, the plugin sends through it with the service account the
administrator configured there (users never enter any mail credentials). Otherwise NetBox's own e-mail
configuration (EMAIL in configuration.py) is used.
"""
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from django.conf import settings as django_settings
from django.core.mail import send_mail

from . import crypto

__all__ = (
    'configured',
    'decrypt_password',
    'encrypt_password',
    'send',
    'sender',
    'source',
    'test_connection',
)

SMTP_AAD = b'netbox_user_pin:smtp'


def encrypt_password(password):
    return crypto.encrypt(password, SMTP_AAD) if password else ''


def decrypt_password(token):
    return crypto.decrypt(token, SMTP_AAD) if token else ''


def _netbox_email():
    return getattr(django_settings, 'EMAIL', {}) or {}


def source(settings):
    """'plugin' (own SMTP settings), 'netbox' (configuration.py) or '' (nothing usable)."""
    if settings.smtp_server and settings.mail_from_address:
        return 'plugin'
    email = _netbox_email()
    if email.get('SERVER') and (email.get('FROM_EMAIL') or settings.mail_from_address):
        return 'netbox'
    return ''


def configured(settings):
    return bool(source(settings))


def sender(settings):
    address = settings.mail_from_address or _netbox_email().get('FROM_EMAIL', '')
    return formataddr((settings.mail_from_name, address)) if settings.mail_from_name and address else address


def _connect(settings):
    context = ssl.create_default_context()
    if settings.smtp_security == 'ssl':
        connection = smtplib.SMTP_SSL(settings.smtp_server, settings.smtp_port, timeout=settings.smtp_timeout,
                                      context=context)
        connection.ehlo()
    else:
        connection = smtplib.SMTP(settings.smtp_server, settings.smtp_port, timeout=settings.smtp_timeout)
        connection.ehlo()
        if settings.smtp_security == 'starttls' or (settings.smtp_auto_tls and connection.has_extn('starttls')):
            connection.starttls(context=context)
            connection.ehlo()
    if settings.smtp_auth:
        connection.login(settings.smtp_username, decrypt_password(settings.smtp_password))
    return connection


def send(settings, recipients, subject, body):
    """Send a plain text e-mail. Raises on failure."""
    if source(settings) == 'plugin':
        message = EmailMessage()
        message['Subject'] = subject
        message['From'] = sender(settings)
        message['To'] = ', '.join(recipients)
        message['Message-ID'] = make_msgid(domain=settings.mail_from_address.rsplit('@', 1)[-1])
        message.set_content(body)
        connection = _connect(settings)
        try:
            connection.send_message(message)
        finally:
            try:
                connection.quit()
            except smtplib.SMTPException:
                pass
        return
    send_mail(subject=subject, message=body, from_email=sender(settings), recipient_list=list(recipients))


def test_connection(settings):
    """Connect (and log in) to the configured SMTP server. Returns (ok, message)."""
    if source(settings) != 'plugin':
        return False, 'No SMTP server is set on this page.'
    try:
        connection = _connect(settings)
        connection.noop()
        connection.quit()
    except (OSError, smtplib.SMTPException, crypto.DecryptionError) as exc:
        return False, f'{type(exc).__name__}: {exc}'
    return True, f'Connected to {settings.smtp_server}:{settings.smtp_port}.'
