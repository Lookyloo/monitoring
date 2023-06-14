import logging
import smtplib
import ssl

from email.message import EmailMessage

from .default import get_config


class Mail:
    @staticmethod
    def send(email: EmailMessage) -> bool:
        """
        Try to send a mail.
        """
        email_config = get_config('generic', 'email')
        smtp_auth = get_config('generic', 'email_smtp_auth')
        logger = logging.getLogger('Mail')
        logger.setLevel(get_config('generic', 'loglevel'))

        try:
            with smtplib.SMTP(host=email_config['smtp_host'], port=email_config['smtp_port']) as server:
                if smtp_auth['auth']:
                    if smtp_auth['smtp_use_starttls']:
                        if smtp_auth['verify_certificate'] is False:
                            ssl_context = ssl.create_default_context()
                            ssl_context.check_hostname = False
                            ssl_context.verify_mode = ssl.CERT_NONE
                            server.starttls(context=ssl_context)
                        else:
                            server.starttls()
                        server.login(smtp_auth['smtp_user'], smtp_auth['smtp_pass'])
                server.send_message(email)
        except (ConnectionRefusedError, smtplib.SMTPException) as e:
            logger.critical(f'Unable to send mail: {e}\n{email}')
            return False
        return True
