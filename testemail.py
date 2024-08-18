import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_password"  # MailHog does not require authentication by default
SMTP_SERVER = "localhost"
SMTP_PORT = 1025  # Default MailHog port for SMTP

def send_test_email():
    try:
        msg = MIMEMultipart()
        msg['From'] = "darrenswk0@gmail.com"
        msg['To'] = "darrenswk0@gmail.com"
        msg['Subject'] = "Test Email"

        body = "This is a test email."
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(msg)

        print("Test email sent successfully.")
    except Exception as e:
        print(f"Failed to send test email: {e}")

send_test_email()
