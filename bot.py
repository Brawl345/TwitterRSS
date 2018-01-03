#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import logging
import re
import sched
import sqlite3
import sys
import time
from configparser import ConfigParser
from json import loads
from json.decoder import JSONDecodeError

import feedparser
import tweepy

# Logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s: %(message)s",
    datefmt="%d.%m.%Y %H:%M:%S",
    level=logging.INFO
)
logger = logging.getLogger(__name__)
logging.getLogger('tweepy.binder').setLevel('WARNING')

# Config
config = ConfigParser()
try:
    config.read_file(open('config.ini'))
except FileNotFoundError:
    logger.critical('config.ini not found')
    sys.exit(1)

try:
    consumer_key = config['DEFAULT']['consumer_key']
    consumer_secret = config['DEFAULT']['consumer_secret']
    access_token = config['DEFAULT']['access_token']
    access_token_secret = config['DEFAULT']['access_token_secret']
    feeds = config['DEFAULT']['feeds']
except KeyError as exception:
    logger.error('Config.ini is wrong')
    sys.exit(1)
if not (feeds, consumer_key, consumer_key, consumer_secret, access_token, access_token_secret):
    logger.error('Some config keys are missing, check your config.ini')
    sys.exit(1)

try:
    feeds = loads(feeds)
except JSONDecodeError as exception:
    logger.error('Feeds list is invalid: ' + str(exception))
    sys.exit(1)

# Check feed validity
if not isinstance(feeds, list):
    logger.error('Feeds list is not a list!')
    sys.exit(1)

if len(feeds) == 0:
    logger.error('Feeds list is empty.')
    sys.exit(1)

for feed in feeds:
    if not isinstance(feed, str):
        logger.error('Feeds must be strings!')
        sys.exit(1)
    if not re.match("^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&~+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$", feed):
        logger.error('"' + feed + '" is not a valid URL.')
        sys.exit(1)

# Connect to database
conn = sqlite3.connect('data.db')
db = conn.cursor()
try:
    db.execute('''CREATE TABLE IF NOT EXISTS feed_data
             (url text, last_entry text)''')
except Exception as e:
    logger.error(e)
    sys.exit(1)

# Scheduler
cron = sched.scheduler(time.time, time.sleep)


def twitter_login():
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    return tweepy.API(auth)


def save_last_entry(last_entry, feed_url):
    db.execute("UPDATE feed_data SET last_entry = ? WHERE url = ?", (last_entry, feed_url))


def fresh_feed(data, feed_url):
    db.execute("SELECT EXISTS(SELECT 1 FROM feed_data WHERE url=? LIMIT 1)", (feed_url,))
    if not db.fetchone()[0]:  # row does not exist
        db.execute("INSERT INTO feed_data VALUES (?,'')", (feed_url,))
    if data.entries:
        if 'id' not in data.entries[0]:
            last_entry = data.entries[0]['link']
        else:
            last_entry = data.entries[0]['id']
        save_last_entry(last_entry, feed_url)


def get_last_entry(feed_url):
    db.execute('SELECT last_entry FROM feed_data WHERE url = ?', (feed_url,))
    result = db.fetchone()
    if not result:
        return None
    else:
        return result[0]


def get_new_entries(entries, last_entry):
    """Returns all new entries from an entries dict up to the last new article"""
    new_entries = []
    for entry in entries:
        if 'id' in entry:
            if entry['id'] == last_entry:
                return new_entries
            else:
                new_entries.append(entry)
        else:
            if entry['link'] == last_entry:
                return new_entries
            else:
                new_entries.append(entry)
    return new_entries


def remove_html_tags(rawhtml):
    """Removes HTML tags"""
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', rawhtml)
    return cleantext


def get_texts(feed_url):
    logger.info('RSS: ' + feed_url)
    texts = []
    data = feedparser.parse(feed_url)
    if 'link' not in data.feed:
        if 'status' in data and data["status"] != 200:
            logger.warning('Kein gültiger Feed, HTTP-Status-Code ' + str(data["status"]))
        else:
            logger.warning('Kein gültiger Feed: ' + str(data.bozo_exception))
        return None
    last_entry = get_last_entry(feed_url)
    new_entries = get_new_entries(data.entries, last_entry)
    if not last_entry:
        fresh_feed(data, feed_url)
        return None
    for entry in reversed(new_entries):
        if 'title' not in entry:
            post_title = 'New entry'
        else:
            post_title = remove_html_tags(entry['title']).strip()
            post_title = post_title.replace('<', '&lt;').replace('>', '&gt;')
        if 'link' not in entry:
            post_link = data.link
        else:
            post_link = entry.link

        texts.append(post_title + ' ' + post_link)
    if new_entries:
        if 'id' not in new_entries[0]:
            new_last_entry = new_entries[0].link
        else:
            new_last_entry = new_entries[0].id
        save_last_entry(new_last_entry, feed_url)
    return texts


def tweet(api):
    # Tweet it!
    for feed in feeds:
        texts = get_texts(feed)
        if not texts:
            continue
        for text in texts:
            try:
                status = api.update_status(status=text)
            except tweepy.error.TweepError as err:
                logger.error('Status could not be posted: ' + str(err))
                continue
            logger.info('POSTED: https://twitter.com/' + status.author.screen_name + '/status/' + status.id_str)
    conn.commit()
    cron.enter(60, 1, tweet, (api,))


def save_db():
    logger.info('Saving DB and exiting...')
    conn.commit()
    conn.close()


atexit.register(save_db)


def main():
    # Twitter login
    api = twitter_login()
    try:
        logger.info('Logged in as @' + api.me().screen_name)
    except tweepy.error.TweepError:
        logger.error('Error while logging in - check your credentials.')
        return
    cron.enter(1, 1, tweet, (api,))
    cron.run()


if __name__ == '__main__':
    main()
