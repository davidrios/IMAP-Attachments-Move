#!/usr/bin/env python3
import base64
import imaplib
import logging
import quopri
import re
import uuid
from configparser import SafeConfigParser
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser

log = logging.getLogger(__name__)

IMAP_CLS = {True: imaplib.IMAP4_SSL, False: imaplib.IMAP4}


class IMAPDestinationItem(object):
    def __init__(self, connection, mailbox, identifier, body_text):
        self._connection = connection
        self._mailbox = mailbox

        message = MIMEMultipart()
        message['Subject'] = 'attachments backup [{}]'.format(identifier)
        message.attach(MIMEText(body_text, 'plain', 'utf8'))
        self._message = message

    def save(self):
        res = self._connection.append(self._mailbox, '', datetime.now(timezone.utc), self._message.as_bytes())
        if res[0] != 'OK':
            raise Exception(res[1])

    def add(self, attachment):
        self._message.attach(attachment)


class IMAPDestination(object):
    def __init__(self, config):
        self._mailbox = config.get('mailbox')

        connection = IMAP_CLS[config.getboolean('ssl')](config.get('server'), config.getint('port'))
        connection.login(config.get('login'), config.get('password'))
        self._connection = connection

    def new(self, identifier, body_text):
        return IMAPDestinationItem(self._connection, self._mailbox, identifier, body_text)

    def finalize(self):
        self._connection.logout()


DESTINATIONS = {
    'imap': IMAPDestination
}


def add_saved_notice(message, destination_name, bkp_identifier):
    content_type = message['Content-Type'].lower()
    content_encoding = message['Content-Transfer-Encoding']

    if 'text/plain' in content_type:
        notice = '++++ attachments saved to {}, identifier: [{}] ++++\n\n'.format(destination_name, bkp_identifier)
    elif 'text/html' in content_type:
        notice = '<p>++++ attachments saved to {}, identifier: [{}] ++++</p>\n'.format(destination_name, bkp_identifier)
    else:
        raise NotImplementedError

    if content_encoding is None:
        message.set_payload(notice + message.get_payload())
    else:
        content_encoding = content_encoding.lower()

        if 'base64' in content_encoding:
            message_text = base64.b64decode(message.get_payload())
            message.set_payload(base64.b64encode(notice + message_text).decode('ascii'))
        elif 'quoted-printable' in content_encoding:
            message.set_payload(quopri.encodestring(notice.encode('ascii')).decode('ascii') + message.get_payload())
        else:
            raise NotImplementedError


RELEVANT_HEADERS = (
    'date',
    'message-id',
    'subject',
    'from',
    'to',
    'cc'
)
def format_relevant_headers(message):
    return '\n'.join(': '.join(i) for i in message.items() if i[0].lower() in RELEVANT_HEADERS)


def process(config_ini, limit=None):
    config = SafeConfigParser()
    config.read(config_ini)

    destination_name = config.get('destination', 'name')

    log.info('connecting to source server')
    connection = IMAP_CLS[config.getboolean('source', 'ssl')](config.get('source', 'server'), config.getint('source', 'port'))
    connection.login(config.get('source', 'login'), config.get('source', 'password'))

    mailbox = config.get('source', 'mailbox')
    log.debug('selecting mailbox %s', mailbox)
    res = connection.select('"{}"'.format(mailbox))
    if res[0] != 'OK':
        raise Exception(res[1])

    log.debug('searching messages')
    if config.has_option('source', 'imap_search'):
        res = connection.uid('search', None, config.get('source', 'imap_search'))
    else:
        res = connection.uid('search', None, 'LARGER', str(config.getint('source', 'email_min_size')))

    message_uids = res[1][0].split()
    total_messages = total_process = len(message_uids)
    if limit is not None:
        total_process = min([total_messages, limit])

    parser = BytesParser()
    processed_mailbox = config.get('source', 'processed_mailbox')
    destination = DESTINATIONS[config.get('destination', 'type')](config['destination'])

    log.info('found %s messages to process', total_messages)
    for idx, uid in enumerate(message_uids):
        if idx >= total_process:
            break

        log.info('processing %s/%s...', idx + 1, total_process)

        log.debug('downloading and parsing message...')
        res = connection.uid('fetch', uid, '(FLAGS BODY.PEEK[])')
        message = parser.parsebytes(res[1][0][1])
        flags = re.findall(r'FLAGS (\(.*?\))', res[1][0][0].decode('utf8'))[0]

        payload = message.get_payload()
        textmsg = payload[0]

        bkp_identifier = str(uuid.uuid4())

        content_type = textmsg['Content-Type'].lower()
        if 'multipart/related' in content_type:
            log.warn('multipart/related not supported, skipping...')
            continue
        elif 'multipart/alternative' in content_type:
            text, html = textmsg.get_payload()
            add_saved_notice(text, destination_name, bkp_identifier)
            add_saved_notice(html, destination_name, bkp_identifier)
        elif 'text/plain' in content_type or 'text/html' in content_type:
            add_saved_notice(textmsg, destination_name, bkp_identifier)
        else:
            raise NotImplementedError

        log.debug('backup identifier: %s', bkp_identifier)

        destitem = destination.new(bkp_identifier, format_relevant_headers(message))

        attachments = payload[1:]
        if not len(attachments):
            log.debug('no attachments to save')
            continue

        for attachment in attachments:
            destitem.add(attachment)
            del payload[1]

        log.debug('saving attachments to destination...')
        destitem.save()

        log.debug('moving processed message to mailbox %s', processed_mailbox)
        res = connection.xatom('UID MOVE', '{} "{}"'.format(uid.decode('utf8'), processed_mailbox))
        if res[0] != 'OK':
            raise Exception(res[1])

        log.debug('storing stripped message')
        connection.append(mailbox, flags, datetime.now(timezone.utc), message.as_bytes())

    destination.finalize()
    log.debug('logging out')
    connection.logout()

    log.info('done')


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('config_ini')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--limit', '-l', type=int, help='Maximum number of messages processed.')
    args = parser.parse_args()

    level = {
        None: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }.get(args.verbose, logging.DEBUG)

    logging.basicConfig(level=level, format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')

    try:
        process(args.config_ini, limit=args.limit)
    finally:
        logging.shutdown()

if __name__ == '__main__':
    main()
