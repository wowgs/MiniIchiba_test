import smtplib
import jwt
import datetime
import hashlib
import uuid
from cassandra.cluster import Cluster
from cassandra import ConsistencyLevel
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_PORT = 465
SMTP_ADDR = "smtp.gmail.com"
EMAIL_PASS = "membership"
EMAIL_FROM = "miniichiba@gmail.com"

SECRET_KEY = "qwertyuiopasdfghjklzxcvbnm123456"
EXP_ACCESS_DELTA = datetime.timedelta(minutes=30)
EXP_REFRESH_DELTA = datetime.timedelta(days=60)
EXP_RESET_DELTA = datetime.timedelta(days=3)


class MyJwt:
    def __init__(self, userid, email, name):
        my_userid = str(userid)

        access_exp = datetime.datetime.utcnow() + EXP_ACCESS_DELTA
        access_jti = str(uuid.uuid4())
        access_payload = {'userId': my_userid, 'exp': access_exp, 'jti': access_jti, 'name': name, 'email': email}
        self.access_token = jwt.encode(payload=access_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')

        refresh_exp = datetime.datetime.utcnow() + EXP_REFRESH_DELTA
        refresh_jti = str(uuid.uuid4())
        refresh_payload = {'userId': my_userid, 'exp': refresh_exp, 'jti': refresh_jti, 'name': name, 'email': email}
        self.refresh_token = jwt.encode(payload=refresh_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')


class MyJwtReset:
    def __init__(self, email):
        iat = datetime.datetime.now()
        exp = iat + EXP_RESET_DELTA
        reset_payload = {'email': email, 'exp': exp, 'iat': iat}
        self.reset_token = jwt.encode(payload=reset_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')


class CassandraClient:
    def __init__(self):
        self.cluster = Cluster(['cassandra0'], port=9042)
        self.session = self.cluster.connect('membership')

        self.pr_user_lookup = self.session.prepare("SELECT userid, name, email, password, refresh_token FROM users WHERE email=?")
        self.pr_user_lookup.consistency_level = ConsistencyLevel.ONE

        self.pr_new_user = self.session.prepare("INSERT INTO users (userid, name, email, password, last_modified) VALUES (?, ?, ?, ?, ?)")
        self.pr_new_user.consistency_level = ConsistencyLevel.ALL

        self.pr_new_token = self.session.prepare("UPDATE users SET refresh_token=? WHERE email=?")
        self.pr_new_token.consistency_level = ConsistencyLevel.ALL

        self.pr_cur_token = self.session.prepare("SELECT refresh_token FROM users WHERE email=?")
        self.pr_cur_token.consistency_level = ConsistencyLevel.ONE

        self.pr_upd_pass = self.session.prepare("UPDATE users SET password=?, last_modified=? WHERE email=?")
        self.pr_upd_pass.consistency_level = ConsistencyLevel.ALL

    def execute(self, *args):
        return self.session.execute(*args)


# class MailConnect:
#     def __init__(self):
#         self.context = ssl.create_default_context()
#         self.server = smtplib.SMTP_SSL(SMTP_ADDR, SMTP_PORT, context=self.context)
#         self.server.login(EMAIL_FROM, EMAIL_PASS)
#
#     def login(self):
#         self.server.login(EMAIL_FROM, EMAIL_PASS)
#
#     def send_token(self, to, token):
#         message = 'http://52.243.bla.bla/resetPassword?token=' + token
#         try:
#             self.server.sendmail(EMAIL_FROM, to, message)
#         except:
#             self.login()
#             self.server.sendmail(EMAIL_FROM, to, message)


def send_mail(e_to, token, e_from="miniichiba@gmail.com", smtp="smtp.gmail.com", port=587, password="membership"):
    link = 'http://52.243.1.1/resetpassword?token=%s' % token

    subject = 'Resetting password at Miniichiba'
    message_html = ('<p>Somebody wants to reset password of your account '
                    '<a href="%s">http://52.243.1.1/resetpassword<a><p>' % link)
    message_plain = "Somebody wants to reset password of your account http://52.243.1.1/resetpassword"

    msg = MIMEMultipart('alternative')
    msg['From'] = e_from
    msg['To'] = e_to
    msg['Subject'] = subject

    msg.attach(MIMEText(message_plain, 'plain'))
    msg.attach(MIMEText(message_html, 'html'))

    server = smtplib.SMTP(smtp, port)
    server.starttls()
    server.login(e_from, password)
    text = msg.as_string()
    server.sendmail(e_from, e_to, text)
    server.quit()


def md5_verify(password, my_hash):
    return md5(password) == my_hash


def md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()
