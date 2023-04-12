import os
from dotenv import load_dotenv
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#---LOAD ENV VARS---#
load_dotenv()

#---MAIL VARS---#
#SMTP_SERVER = "send.one.com"
SMTP_SERVER = "smtp.sendgrid.net"
SMTP_PORT = 465
SENDER = os.environ.get("EMAIL_SENDER")
PASSWORD = os.environ.get("EMAIL_PASS")
USERNAME = os.environ.get("EMAIL_USERNAME")
url = 'https://peerbrain.teckhawk.be/'
#url = 'http://127.0.0.1:8000/'
account_creation_link_text = 'CONFIRM ACCOUNT'
reset_password_link_text = 'RESET PASSWORD'
RESET_PASSWORD_ROUTE = os.environ.get("RESET_PASSWORD_ROUTE")


#---FUNCTIONS---#
def confirmation_mail(receiver:str, username:str, token:str):
        
    message = MIMEMultipart("alternative")
    message["Subject"] = f"Confirm your email for your Peerbrain account"
    message["From"] = SENDER
    message["To"] = receiver

    # Create the plain-text and HTML version of your message
    text = f"""\
    Dear {username}, \n
    
    Please click the link below to confirm your account: \n \n
    
    {url}confirm-email?token={token}&username={username}
        
    Sincerely,
    
    Team Peerbrain
    """
    html = f"""\
    <html>
    <body>
        <p>Dear {username},<br><br>
        Please click the link below to confirm your account: <br>
        <br>
        
        <b><a href="{url}confirm-email?token={token}&username={username}">{account_creation_link_text}</a></b>
        
        <br>  <br> 
        Sincerely,<br>
        <br>
        Team Peerbrain
        </p>
    </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT , context=context) as server:
        server.login(USERNAME, PASSWORD)
        server.sendmail(
            SENDER, receiver, message.as_string()
        )
    
    print(f"Account creation mail sent to {receiver}")

def password_reset_mail(receiver:str, username:str, token:str):
        
    message = MIMEMultipart("alternative")
    message["Subject"] = f"Reset the password for your Peerbrain account"
    message["From"] = SENDER
    message["To"] = receiver

    # Create the plain-text and HTML version of your message
    text = f"""\
    Dear {username}, \n
    
    Please click the link below to reset your password: \n \n
    
    {url}{RESET_PASSWORD_ROUTE}/reset-password?token={token}&username={username}
    
    \n 
    Please be aware that this link will expire in 5 minutes!
    \n    
    Sincerely,
    
    Team Peerbrain
    """
    html = f"""\
    <html>
    <body>
        <p>Dear {username},<br><br>
        Please click the link below to reset your password: <br>
        <br>
        
        <b><a href="{url}{RESET_PASSWORD_ROUTE}/reset-password?token={token}&username={username}">{reset_password_link_text}</a></b>
        
        <br>
        <br> 
        <b>Please be aware that this link will expire in 5 minutes!</b>
        <br> 
        <br>
        Sincerely,<br>
        <br>
        Team Peerbrain
        </p>
    </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT , context=context) as server:
        server.login(USERNAME, PASSWORD)
        server.sendmail(
            SENDER, receiver, message.as_string()
        )
    
    print(f"Password reset mail sent to {receiver}")