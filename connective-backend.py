#!/usr/bin/python

# -*- coding: utf-8 -*-

import sys
import struct
import json
import time

import tkinter.messagebox
import tkinter as tk
import tkinter.font as font

import smartcard
import smartcard.util

DEBUG = True

APPLET_AID = [ 0x00, 0xA4, 0x04, 0x00, 0x0F, 0xA0, 0x00, 0x00, 0x00, 0x30, 0x29, 0x05,
               0x70, 0x00, 0xAD, 0x13, 0x10, 0x01, 0x01, 0xFF ]
BELPIC_AID = [ 0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xA0, 0x00, 0x00, 0x01, 0x77, 0x50, 0x4B,
               0x43, 0x53, 0x2D, 0x31, 0x35 ]

if sys.platform == "darwin":
    MAX_APDU_READ_LEN = 248
else:
    MAX_APDU_READ_LEN = 252

CCID_VERIFY_START = 0x01
CCID_VERIFY_FINISH = 0x02
CCID_VERIFY_DIRECT = 0x06
CCID_CHANGE_START = 0x03
CCID_CHANGE_FINISH = 0x04
CCID_CHANGE_DIRECT = 0x07

MAX_PIN_LENGTH = 12

class NumpadWindow(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        self.master = master
        self.pack(fill=tk.BOTH, expand=1)

        self.master.wm_title("Connective")
        self.master.resizable(False, False)

        text_large_font = font.Font(size=16)
        self.text_pincode = tk.Label(self, font=text_large_font, width=12)
        self.text_pincode.grid(row=1, column=1 ,columnspan=3)
        self.pincode = ''

        button_large_font = font.Font(size=24, weight='bold')
        button_1 = tk.Button(self, text="1", font=button_large_font, width=3, height=2, \
                             command=self.click_button_1)
        button_1.grid(row=2, column=1)
        button_2 = tk.Button(self, text="2", font=button_large_font, width=3, height=2, \
                             command=self.click_button_2)
        button_2.grid(row=2, column=2)
        button_3 = tk.Button(self, text="3", font=button_large_font, width=3, height=2, \
                             command=self.click_button_3)
        button_3.grid(row=2, column=3)
        button_4 = tk.Button(self, text="4", font=button_large_font, width=3, height=2, \
                             command=self.click_button_4)
        button_4.grid(row=3, column=1)
        button_5 = tk.Button(self, text="5", font=button_large_font, width=3, height=2, \
                             command=self.click_button_5)
        button_5.grid(row=3, column=2)
        button_6 = tk.Button(self, text="6", font=button_large_font, width=3, height=2, \
                             command=self.click_button_6)
        button_6.grid(row=3, column=3)
        button_7 = tk.Button(self, text="7", font=button_large_font, width=3, height=2, \
                             command=self.click_button_7)
        button_7.grid(row=4, column=1)
        button_8 = tk.Button(self, text="8", font=button_large_font, width=3, height=2, \
                             command=self.click_button_8)
        button_8.grid(row=4, column=2)
        button_9 = tk.Button(self, text="9", font=button_large_font, width=3, height=2, \
                             command=self.click_button_9)
        button_9.grid(row=4, column=3)
        button_c = tk.Button(self, text="C", font=button_large_font, width=3, height=2, \
                             command=self.click_button_c)
        button_c.grid(row=5, column=1)
        button_0 = tk.Button(self, text="0", font=button_large_font, width=3, height=2, \
                             command=self.click_button_0)
        button_0.grid(row=5, column=2)
        button_ok = tk.Button(self, text="Ok", font=button_large_font, width=3, height=2, \
                             command=self.click_button_ok)
        button_ok.grid(row=5, column=3)

        self.master.bind("<Key>", self.key_pressed)


    def __add_code(self, char):
        if len(self.pincode) < MAX_PIN_LENGTH and char in '1234567890':
            self.pincode += char
            self.text_pincode.config(text='*' * len(self.pincode))
        elif len(self.pincode) > 0 and char in [ chr(8), 'c', 'C' ]:
            self.pincode = self.pincode[:-1]
            self.text_pincode.config(text='*' * len(self.pincode))
        elif char in [ chr(27), 'q', 'Q' ]:
            self.pincode = ''
            self.master.destroy()
        elif char == chr(13):
            self.master.destroy()


    def click_button_1(self):
        self.__add_code('1')


    def click_button_2(self):
        self.__add_code('2')


    def click_button_3(self):
        self.__add_code('3')


    def click_button_4(self):
        self.__add_code('4')


    def click_button_5(self):
        self.__add_code('5')


    def click_button_6(self):
        self.__add_code('6')


    def click_button_7(self):
        self.__add_code('7')


    def click_button_8(self):
        self.__add_code('8')


    def click_button_9(self):
        self.__add_code('9')


    def click_button_0(self):
        self.__add_code('0')


    def click_button_c(self):
        self.__add_code('c')


    def click_button_ok(self):
        self.__add_code(chr(13))


    def key_pressed(self, event):
        self.__add_code(event.char)


    def get_pincode(self):
        return self.pincode


    def get_pincode_as_hex(self):
        pincode_list = [ ]
        # add pincode in high and low nibbles
        for index, digit in enumerate(numpad.pincode):
            if index % 2 == 0:
                pincode_list.append(int(digit) * 16 + 15)
            else:
                pincode_list[int(index / 2)] += int(digit) - 15
        # pad with 0xFF
        while len(pincode_list) < 6:
            pincode_list.append(0xFF)

        return pincode_list



class CardReaders:
    def __init__(self):
        self.card_readers = smartcard.System.readers()


    def find_reader(self, reader_name):
        card_reader_list = [ r for r in self.card_readers if r.name == reader_name]
        return card_reader_list[0] if len(card_reader_list) > 0 else None


    def amount_readers(self):
        return len(self.card_readers)


    def __card_is_be_id(self, atr):
        # Belgium Electronic ID card or Belgian Eid virtual test card
        # ref: http://ludovic.rousseau.free.fr/softwares/pcsc-tools/smartcard_list.txt
        return atr in ['3B9894400AA503010101AD1310',
                       '3B9813400AA503010101AD1311',
                       '3B989540FFD000480101AD1321']


    def get_reader_as_json(self, index):
        card_present = False
        card_type = 0
        atr = None

        connection = self.card_readers[index].createConnection()
        try:
            connection.connect()
            card_present = True
            atr = smartcard.util.toHexString(connection.getATR()).replace(' ', '')
            if self.__card_is_be_id(atr):
                card_type = 1
            connection.disconnect()
        except smartcard.Exceptions.NoCardException:
            pass

        response = {}
        response['index'] = index
        response['library'] = '__cardcomm__' # modify to pyscard?
        response['name'] = self.card_readers[index].name
        if card_present:
            response['atr'] = atr
        response['cardPresent'] = card_present
        response['cardType'] = card_type

        return response



# ref https://github.com/Fedict/eid-mw/blob/master/doc/sdk/documentation/Applet%201.7%20eID%20Cards/Public_Belpic_Applet_v1%207_Ref_Manual%20-%20A01.pdf
class BeIdCard:
    def __init__(self, card_reader):
        self.card_reader = card_reader
        self.connection = None
        self.__connect()
        self.applet_selected = self.__select_applet()
        self.get_instance = self.__get_instance()

        # Card data
        self.__serialnr = None
        self.__appletversion = None
        self.__6c_delay = 0
        self.card_data = self.__get_card_data()

        if self.card_data:
            log('Card serial nr: %s' % smartcard.util.toHexString(self.__serialnr).replace(' ', ''))
            log('Card applet version: %x' % self.__appletversion)
            log('Card 0x6C delay required: %d ms' % self.__6c_delay)

        # Card reader ioctls, to be detected
        self.__ioctls_detected = False
        self.__ioctl_verify_start = None
        self.__ioctl_verify_finish = None
        self.__ioctl_verify_direct = None
        self.__ioctl_change_start = None
        self.__ioctl_change_finish = None
        self.__ioctl_change_direct = None


    def __del__(self):
        if self.connection:
            self.connection.disconnect()


    def __connect(self):
        if self.card_reader:
            try:
                self.connection = self.card_reader.createConnection()
                self.connection.connect()
            except smartcard.Exceptions.NoCardException:
                self.connection = None


    def __send_apdu(self, apdu):
        data, sw1, sw2 = self.connection.transmit(apdu)
        if len(data) == 0:
            if sw1 == 0x61:
                while sw1 == 0x61:
                    extra_data, sw1, sw2 = self.connection.transmit([ 0x00, 0xC0, 0x00, 0x00, sw2 ])
                    data.extend(extra_data)
            if sw1 == 0x6C:
                time.sleep(self.__6c_delay / 1000)
                data, sw1, sw2 = self.connection.transmit(apdu[0:4] + [ sw2 ] + apdu[5:])
        return data, sw1, sw2


    def __select_applet(self):
        if self.connection:
            data, sw1, sw2 = self.connection.transmit(APPLET_AID)
            if sw1 in [ 0x61, 0x90 ] and sw2 == 0x00:
                return True
            else:
                return False
        else:
            return False


    def __get_instance(self):
        if self.connection:
            data, sw1, sw2 = self.__send_apdu(BELPIC_AID)
            if sw1 == 0x6A and sw2 in [ 0x82, 0x86 ]:
                # Perhaps the applet is no longer selected
                self.applet_selected = self.__select_applet()
                if self.applet_selected:
                    data, sw1, sw2 = self.__send_apdu(BELPIC_AID)
            if sw1 == 0x90 and sw2 == 0x00:
                return True
            else:
                return False
        else:
            return False


    def __get_card_data(self):
        if self.connection:
            # Get Card Data (compatible with all applets)
            data, sw1, sw2 = self.__send_apdu([ 0x80, 0xE4, 0x00, 0x00, 0x1C ])
            if sw1 == 0x90 and sw2 == 0x00 and len(data) > 23:
                self.__serialnr = data[0:16]
                self.__appletversion = data[21]

                if self.__appletversion >= 0x18:
                    # Use applet 1.8-specific extended card data
                    data, sw1, sw2 = self.__send_apdu([ 0x80, 0xE4, 0x00, 0x01, 0x1F ])

                if data[22] == 0x00 and data[23] == 0x01:
                    self.__6c_delay = 50
            else:
                return None

            return data
        else:
            return None


    def select_file(self, file_id):
        '''
        Selects the file at absolute path file_id in preparation of a call to read_selected_file()
        '''
        bin_file_id = smartcard.util.toBytes(file_id)
        request_data = [ 0x00, 0xA4, 0x08, 0x0C, len(bin_file_id) ] + bin_file_id
        data, sw1, sw2 = self.__send_apdu(request_data)
        if sw1 == 0x90 and sw2 == 0x00:
            return True
        else:
            return False


    def read_selected_file(self):
        '''
        Read the contents of the selected file. select_file() should have been called before.
        '''
        file_contents = []
        offset = 0
        is_eof = False
        while not is_eof:
            request_data = [ 0x00, 0xB0, int(offset / 256), offset % 256, MAX_APDU_READ_LEN ]
            data, sw1, sw2 = self.__send_apdu(request_data)
            if sw1 == 0x90 and sw2 == 0x00:
                file_contents.extend(data)
                offset += len(data)
            elif sw1 == 0x6B and sw2 == 0x00:
                # offset beyond eof
                is_eof = True
            else:
                # general error
                is_eof = True
                file_contents = None

            if len(data) < MAX_APDU_READ_LEN:
                is_eof = True
        return file_contents


    def __verify_feature(self, feature, feature_ccid, ioctl_value):
        if feature[0] == feature_ccid:
            return 256 * (256 * ((256 * feature[2]) + feature[3]) + feature[4]) + feature[5]
        else:
            return ioctl_value


    def __get_reader_features(self):
        if self.__ioctls_detected:
            return

        features = self.connection.control(smartcard.scard.SCARD_CTL_CODE(3400), [])
        i = 0
        while i < len(features):
            feature = features[i:i+6]
            self.__ioctl_verify_start = \
                self.__verify_feature(feature, CCID_VERIFY_START, self.__ioctl_verify_start)
            self.__ioctl_verify_finish = \
                self.__verify_feature(feature, CCID_VERIFY_FINISH, self.__ioctl_verify_finish)
            self.__ioctl_verify_direct = \
                self.__verify_feature(feature, CCID_VERIFY_DIRECT, self.__ioctl_verify_direct)
            self.__ioctl_change_start = \
                self.__verify_feature(feature, CCID_CHANGE_START, self.__ioctl_change_start)
            self.__ioctl_change_finish = \
                self.__verify_feature(feature, CCID_CHANGE_FINISH, self.__ioctl_change_finish)
            self.__ioctl_change_direct = \
                self.__verify_feature(feature, CCID_CHANGE_DIRECT, self.__ioctl_change_direct)
            i += 6

        self.__ioctls_detected = True


    def authenticate_pin(self):
        '''
        This function requests the user to authenticate using their PIN code.
        Result is a tuple containing a boolean indicating succesful authentication and an integer
        containing the amount of retries left.
        '''
        self.__get_reader_features()

        control_request = []
        control_request.append(0x1E) # timeout in seconds (0: default timeout)
        control_request.append(0x1E) # timeout in seconds after first key stroke
        control_request.append(0x89) # formatting options
        control_request.append(0x47) # length (in bytes) of the PIN block
        control_request.append(0x04) # where (if needed) to put the PIN length
        control_request.append(0x0C) # max number of PIN digits
        control_request.append(0x04) # min number of PIN digits
        control_request.append(0x02) # e.g. 0x02: "OK" button pressed
        control_request.append(0x01) # number of messages to display
        control_request.append(0x04) # LANG_ID code (english = 0x0409)
        control_request.append(0x09)
        control_request.append(0x00) # Message index (should be 00)
        control_request.append(0x00) # T=1 block prologue field to use (fill with 00)
        control_request.append(0x00)
        control_request.append(0x00)
        control_request.append(0x0D) # length of the following field
        control_request.append(0x00)
        control_request.append(0x00)
        control_request.append(0x00)
        # APDU to send to the card (to be completed by the reader)
        control_request += [ 0x00, 0x20, 0x00, 0x01, 0x08, 0x20, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]
        
        sw1 = 0x00
        sw2 = 0x00
        if self.__ioctl_verify_direct:
            tkinter.messagebox.showinfo(title='Connective', \
                                        message='The Connective Browser Plugin requests your ' + \
                                                'eID PIN code on the secure pinpad reader [%s]' \
                                                % self.card_reader.name)

            data = self.connection.control(self.__ioctl_verify_direct, control_request)
            sw1 = data[0]
            sw2 = data[1]
        elif self.__ioctl_verify_start and self.__ioctl_verify_finish:
            tkinter.messagebox.showinfo(title='Connective', \
                                        message='The Connective Browser Plugin requests your ' + \
                                                'eID PIN code on the secure pinpad reader [%s]' \
                                                % self.card_reader.name)

            data = self.connection.control(self.__ioctl_verify_start, control_request)
            data = self.connection.control(self.__ioctl_verify_finish, [ ])
            sw1 = data[0]
            sw2 = data[1]
        else:
            root = tk.Tk()
            numpad = NumpadWindow(root)
            root.mainloop()

            if len(numpad.pincode) > 0:
                # verify pincode
                data, sw1, sw2 = self.__send_apdu([ 0x00, 0x20, 0x00, 0x01, 0x08,
                                                    0x20 + len(numpad.pincode) ] + \
                                                    numpad.get_pincode_as_hex() + [ 0xFF ])

        if sw1 == 0x63 and sw2 >= 0xC0 and sw2 <= 0xCF:
            # PIN incorrect - untested
            return (False, sw2 - 0xC0)
        elif sw1 == 0x69 and sw2 == 0x83:
            # PIN blocked - untested
            return (False, 0)
        elif sw1 == 0x90 and sw2 == 0x00:
            # PIN correct
            return (True, -1)
        else:
            # Card reader or card returned any other error - unrecoverable
            return (False, 0)


    def sign(self, data_to_sign):
        '''
        Signs the given data using the connected card. A call to authenticate_pin() is required
        first to fulfill the access conditions.
        '''
        # select RSASSA-PKCS1_v15 SHA256 algorithm (0x08) and authentication once (0x82)
        data, sw1, sw2 = self.__send_apdu([ 0x00, 0x22, 0x41, 0xB6, 0x05,
                                            0x04, 0x80, 0x08, 0x84, 0x82 ])
        if sw1 == 0x90 and sw2 == 0x00:
            bin_data_to_sign = smartcard.util.toBytes(data_to_sign)
            request_data = [ 0x00, 0x2A, 0x9E, 0x9A, len(bin_data_to_sign) ] + \
                             bin_data_to_sign + [ 0x00 ]
            data, sw1, sw2 = self.__send_apdu(request_data)
            if sw1 == 0x90 and sw2 == 0x00:
                return smartcard.util.toHexString(data).replace(' ', '')
            else:
                return None
        else:
            return None


    def log_off(self):
        data, sw1, sw2 = self.__send_apdu([ 0x80, 0xE6, 0x00, 0x00 ])
        if sw1 == 0x90 and sw2 == 0x00:
            return True
        else:
            return False



def log(message):
    if DEBUG:
        sys.stderr.write(message + '\n')


def read_native_message():
    text_length_bytes = sys.stdin.buffer.read(4)

    if len(text_length_bytes) == 0:
        return None

    text_length = struct.unpack('@I', text_length_bytes)[0]
    text = str(sys.stdin.buffer.read(text_length), 'utf-8')
    log('IN ' + text)

    return text


def send_native_message(response):
    log('OUT ' + response)
    response_bytes = bytes(response, 'utf-8')
    sys.stdout.buffer.write(struct.pack('@I', len(response_bytes)))
    sys.stdout.buffer.write(response_bytes)
    sys.stdout.buffer.flush()


def get_error(error_code, message):
    response = {}
    response['error'] = {}
    response['error']['code'] = error_code
    response['error']['id'] = error_code
    response['error']['message'] = message
    return response


def process_get_info():
    response = {}
    response['version'] = '2.0.2'
    response['binVersion'] = '2.0.9'
    return response


def process_get_readers():
    card_readers = CardReaders()
    if card_readers.amount_readers() == 0:
        return get_error(2, 'Error getting readers (Comm 0x80100001) (0)')
    else:
        response = {}
        response['readerList'] = []
        for index in range(card_readers.amount_readers()):
            response['readerList'].append(card_readers.get_reader_as_json(index))
        return response


def process_read_file(request_json):
    request_reader = request_json['reader'] if 'reader' in request_json else None
    request_file_id = request_json['fileId'] if 'fileId' in request_json else None
    if not request_reader or not request_file_id:
        return get_error(99, 'No request received after 10 seconds')

    card_readers = CardReaders()
    card_reader = card_readers.find_reader(request_reader)
    beid_card = BeIdCard(card_reader)
    if not beid_card.card_reader:
        return get_error(0, 'Card reader %s not found' % request_reader)
    elif not beid_card.connection or not beid_card.applet_selected or not beid_card.get_instance:
        return get_error(99, 'error calling SCardConnect (0x80100069) (0x0)')
    elif not beid_card.select_file(request_file_id):
        return get_error(5, 'Error reading file (Comm 0x6a87) (0xa4080c)')
    else:
        data = beid_card.read_selected_file()
        if data:
            response = {}
            response['data'] = smartcard.util.toHexString(data).replace(' ', '')
            return response
        else:
            return get_error(5, 'Error reading file (Comm 0x6a87) (0xa4080c)')


def process_compute_authentication(request_json):
    request_reader = request_json['reader'] if 'reader' in request_json else None
    request_hash = request_json['hash'] if 'hash' in request_json else None
    if not request_reader or not request_hash:
        return get_error(99, 'No request received after 10 seconds')

    card_readers = CardReaders()
    card_reader = card_readers.find_reader(request_reader)
    beid_card = BeIdCard(card_reader)
    if not beid_card.card_reader:
        return get_error(0, 'Card reader %s not found' % request_reader)
    elif not beid_card.connection or not beid_card.applet_selected or not beid_card.get_instance:
        return get_error(99, 'error calling SCardConnect (0x80100069) (0x0)')
    else:
        (is_authenticated, retries_left) = beid_card.authenticate_pin()
        signature = None
        if is_authenticated:
            signature = beid_card.sign(request_hash)
            ignore_result = beid_card.log_off()

        # TODO not sure about this section, not tested with wrong or blocked PIN code
        response = {}
        response['pinRemainingAttempts'] = retries_left
        response['pinValid'] = is_authenticated
        if signature:
            response['valid'] = True
            response['signature'] = signature
        else:
            response['valid'] = False

        return response



request = read_native_message()
response_json = {}

try:
    request_json = json.loads(request)

    if 'activationToken' in request_json:
        # TODO request_json['activationToken'] must be checked, but it is not clear what it
        # contains. If it is not correct the application should stop here immediately and send
        # response_json = get_error(10, 'Activation required')
        pass

    if 'cmd' not in request_json:
        # the browser extension blocks this case
        response_json = get_error(99, 'No request received after 10 seconds')
    elif request_json['cmd'] == 'GET_INFO':
        response_json = process_get_info()
    elif request_json['cmd'] == 'GET_READERS':
        response_json = process_get_readers()
    elif request_json['cmd'] == 'READ_FILE':
        response_json = process_read_file(request_json)
    elif request_json['cmd'] == 'COMPUTE_AUTHENTICATION':
        response_json = process_compute_authentication(request_json)
    else:
        response_json = get_error(99, 'Error handling JSON message [%s]. Unknown command [%s]' \
                                                        % (request, request_json['cmd']))
except json.decoder.JSONDecodeError:
    response_json = get_error(99, 'No request received after 10 seconds')
except Exception as e:
    log(str(e))
    # any other exception - exit gracefully
    response_json = get_error(99, 'No request received after 10 seconds')

send_native_message(json.dumps(response_json))

