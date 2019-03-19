import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from exchangelib import ServiceAccount, Configuration, Account, DELEGATE
from exchangelib import Message, Mailbox, FileAttachment, HTMLBody

import smtplib,ssl,pathlib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import formatdate
from email import encoders

input_file_1 = '../properties.txt'
f_in = open(input_file_1, 'r')
properties_dict = {}
for line in f_in:
    properties_dict[line.partition('=')[0]] = line.partition('=')[2].strip()
f_in.close()

def encrypt(source, encode=True):
    key = SHA256.new(b"['7h~;692'{C@zj'&+6]z;28Sh+<xB=~=)/|6+~o").digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(b"['7h~;692'{C@zj'&+6]z;28Sh+<xB=~=)/|6+~o").digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

def send_email(subject, body, recipients, attachments=None, html=False):
    credentials = ServiceAccount(username=properties_dict["email_uid"], password=decrypt(properties_dict["email_pwd"]).decode("latin-1"))
    config = Configuration(server='mail.mskcc.org', credentials=credentials)
    account = Account(primary_smtp_address='{}@mskcc.org'.format(properties_dict["email_uid"]), config=config, autodiscover=False, access_type=DELEGATE)

##    credentials = ServiceAccount(username="darwin", password="***")
##    config = Configuration(server='mail.mskcc.org', credentials=credentials)
##    account = Account(primary_smtp_address='darwin@mskcc.org', config=config, autodiscover=False, access_type=DELEGATE)

    to_recipients = []
    for recipient in recipients:
        to_recipients.append(Mailbox(email_address=recipient))

    if html:
        body = HTMLBody(body)
        
    # Create message
    m = Message(account=account,
                #folder=account.sent,
                #author="darwin@mskcc.org",
                subject=subject,
                body=body,
                to_recipients=to_recipients)

    # attach files
    for attachment_name, attachment_content in attachments or []:
        file = FileAttachment(name=attachment_name, content=attachment_content)
        m.attach(file)
    #m.send_and_save()
    m.send()



# https://stackoverflow.com/questions/25346001/add-excel-file-attachment-when-sending-python-email
def send_mail(send_from, send_to, subject, body, attachments=None, html=False):
    mime_text_type = 'plain'
    if html:
        mime_text_type = 'html'
    
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime = True)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, mime_text_type))

    if attachments:
        for attachment in attachments:
            if pathlib.Path(attachment).is_file():
                part = MIMEBase('application', "octet-stream")
                part.set_payload(open("{}".format(attachment), "rb").read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(attachment.split('\\')[-1]))
                msg.attach(part)
            else:
                return "Error: attachment not found"

    smtp = smtplib.SMTP('exchange2007.mskcc.org', 25)

    smtp.send_message(msg)

    smtp.quit()

    return "success"


##my_password = b"secret_AES_key_string_to_encrypt/decrypt_with"
##my_data = b"input_string_to_encrypt/decrypt"
##
##password = b"password"
##key = b"key"
##
##enc = encrypt(key, password)
##
##print("pass enc: {}".format(enc))
##print("pass dec: {}".format(decrypt(key, enc)))
##
##print("key:  {}".format(my_password))
##print("data: {}".format(my_data))
##encrypted = encrypt(my_password, my_data)
##print("\nenc:  {}".format(encrypted))
##decrypted = decrypt(my_password, encrypted)
##print("dec:  {}".format(decrypted))
##print("\ndata match: {}".format(my_data == decrypted))
##print("\nSecond round....")
##encrypted = encrypt(my_password, my_data)
##print("\nenc:  {}".format(encrypted))
##decrypted = decrypt(my_password, encrypted)
##print("dec:  {}".format(decrypted))
##print("\ndata match: {}".format(my_data == decrypted))
