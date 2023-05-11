import logging
import smtplib

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
            server = smtplib.SMTP(host=email_config['smtp_host'], port=email_config['smtp_port'])
            if smtp_auth['auth']:
                server.login(smtp_auth['smtp_user'], smtp_auth['smtp_pass'])
                if smtp_auth['smtp_use_tls']:
                    server.starttls()
            server.send_message(email)
            server.quit()
        except (ConnectionRefusedError, smtplib.SMTPException) as e:
            logger.critical(f'Unable to send mail: {e}\n{email}')
            return False
        return True
