#!/usr/bin/env python3

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

AUTHENTICATION_KEY = 0x82
NON_REPUDIATION_KEY = 0x83

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
        for i in range(10):
            if i == 0:
                button_r = 5
                button_c = 2
            else:
                button_r = (i - 1) // 3 + 2
                button_c = (i - 1) % 3 + 1
            b = tk.Button(self, text=i, font=button_large_font, \
                          width=3, height=2, \
                          command=lambda i=i: self.click_button(i))
            b.grid(row=button_r, column=button_c)

        button_c = tk.Button(self, text="C", font=button_large_font, width=3, height=2, \
                             command=self.click_button_c)
        button_c.grid(row=5, column=1)
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


    def click_button(self, c):
        self.__add_code('%d' % c)


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
        for index, digit in enumerate(self.pincode):
            if index % 2 == 0:
                pincode_list.append(int(digit) * 16 + 15)
            else:
                pincode_list[int(index / 2)] += int(digit) - 15
        # pad with 0xFF
        while len(pincode_list) < 6:
            pincode_list.append(0xFF)

        return pincode_list



class CardReaderFactory:
    def __init__(self):
        self.card_readers = smartcard.System.readers()


    def __detect_card(self, card_reader):
        # do we have a be-eid card?
        beid_card = BeIdCard(card_reader)
        if beid_card.is_card_present():
            return beid_card
        # do we have a maestro card?
        maestro_card = MaestroCard(card_reader)
        if maestro_card.is_card_present():
            return maestro_card
        # otherwise we have either an unsupported card or no card at all
        return BaseCard(card_reader)


    def get_reader_list(self):
        reader_list = []
        for index, card_reader in enumerate(self.card_readers):
            card = self.__detect_card(card_reader)

            reader = {}
            reader['index'] = index
            reader['library'] = '__cardcomm__' # modify to pyscard?
            reader['name'] = card_reader.name
            if card.is_card_present():
                reader['atr'] = card.get_atr()
            reader['cardPresent'] = card.is_card_present()
            reader['cardType'] = card.get_connective_card_type()

            reader_list.append(reader)

        return reader_list


    def find_reader(self, reader_name):
        card_reader_list = [ r for r in self.card_readers if r.name == reader_name]
        if len(card_reader_list) > 0:
            card_reader = card_reader_list[0]
            return self.__detect_card(card_reader)
        else:
            return None



class BaseCard:
    def __init__(self, card_reader):
        self.card_reader = card_reader
        self._connection = None
        self._atr = None


    def __del__(self):
        if self._connection:
            self._connection.disconnect()


    def get_atr(self):
        return self._atr


    def is_card_present(self):
        return (self._connection is not None)


    def get_connective_card_type(self):
        return 0



# ref https://github.com/Fedict/eid-mw/blob/master/doc/sdk/documentation/Applet%201.7%20eID%20Cards/Public_Belpic_Applet_v1%207_Ref_Manual%20-%20A01.pdf
class BeIdCard(BaseCard):
    def __init__(self, card_reader):
        super().__init__(card_reader)
        self.__connect()
        self.applet_selected = self.__select_applet()
        self.get_instance = self.__get_instance()

        # Card data
        self.__serialnr = None
        self.__appletversion = None
        self.__6c_delay = 0
        self.card_data = self.__get_card_data()

        if self.card_data:
            # disabled to maximally protect privacy
            #log('Card serial nr: %s' % smartcard.util.toHexString(self.__serialnr).replace(' ', ''))
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


    def is_card_present(self):
        return (self._connection and self.applet_selected and self.get_instance)


    def get_connective_card_type(self):
        return 1


    def __card_is_be_id(self):
        # Belgium Electronic ID card or Belgian Eid virtual test card
        # ref: http://ludovic.rousseau.free.fr/softwares/pcsc-tools/smartcard_list.txt
        return self._atr in ['3B9894400AA503010101AD1310',
                             '3B9813400AA503010101AD1311',
                             '3B989540FFD000480101AD1321']


    def __connect(self):
        if self.card_reader:
            try:
                self._connection = self.card_reader.createConnection()
                self._connection.connect()
                self._atr = smartcard.util.toHexString(self._connection.getATR()).replace(' ', '')
                if not self.__card_is_be_id():
                    self._connection.disconnect()
                    self._connection = None
            except smartcard.Exceptions.NoCardException:
                self._connection = None


    def __send_apdu(self, apdu):
        data, sw1, sw2 = self._connection.transmit(apdu)
        if len(data) == 0:
            if sw1 == 0x61:
                while sw1 == 0x61:
                    extra_data, sw1, sw2 = self._connection.transmit([ 0x00, 0xC0, 0x00, 0x00, sw2 ])
                    data.extend(extra_data)
            if sw1 == 0x6C:
                time.sleep(self.__6c_delay / 1000)
                data, sw1, sw2 = self._connection.transmit(apdu[0:4] + [ sw2 ] + apdu[5:])
        return data, sw1, sw2


    def __select_applet(self):
        if self._connection:
            data, sw1, sw2 = self._connection.transmit(APPLET_AID)
            if sw1 in [ 0x61, 0x90 ] and sw2 == 0x00:
                return True
            else:
                return False
        else:
            return False


    def __get_instance(self):
        if self._connection:
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
        if self._connection:
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


    def get_card_version(self):
        return self.__appletversion


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

        features = self._connection.control(smartcard.scard.SCARD_CTL_CODE(3400), [])
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


    def is_pin_pad_available(self):
        '''
        This function returns True if a pinpad is available on the card reader. Contrary to the
        Connective application a card is required to be present here.
        '''
        # Is this hardcoded on model number in the Connective application?
        # VASCO DIGIPASS 850, VASCO DIGIPASS 870, VASCO DIGIPASS 875, VASCO DIGIPASS 920, APG8201
        self.__get_reader_features()

        if self.__ioctl_verify_direct:
            return True
        elif self.__ioctl_verify_start and self.__ioctl_verify_finish:
            return True
        else:
            return False


    def EMSA_PKCS1_V1_5_ENCODE(self, sha256hash):
        '''
        Implement the EMSA-PKCS1-V1_5-ENCODE function, as defined in PKCS#1 v2.1 (RFC3447, 9.2).
        EMSA-PKCS1-V1_5-ENCODE actually accepts the message M as input, and hash it internally.
        Here, we expect that the message has already been hashed instead.

        ref: https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_v1_5.py#L173
        '''
        # requires pycryptodome
        # from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString, DerObjectId
        # from Crypto.Util.py3compat import bchr
        '''
        # SHA256 Identifier OID for use with PKCS#1 v1.5.
        digestAlgo  = DerSequence([
                        DerObjectId('2.16.840.1.101.3.4.2.1').encode(),
                        DerNull().encode()
                        ])

        digest = DerOctetString(sha256hash)
        digestInfo  = DerSequence([
                        digestAlgo.encode(),
                        digest.encode()
                        ]).encode()

        return digestInfo
        '''
        pass


    def select_coding_algorithm(self, key_selector):
        '''
        Select RSASSA-PKCS1_v15 SHA256 algorithm (0x08) with either the authentication or
        the non repudiation private key.
        '''
        # RSASSA-PKCS1_v15 without predefined padding algorithm (0x01) can also be selected but then
        # the data to sign must be EMSA-PKCS1-v1_5 encoded first. See EMSA_PKCS1_V1_5_ENCODE above.
        data, sw1, sw2 = self.__send_apdu([ 0x00, 0x22, 0x41, 0xB6, 0x05,
                                            0x04, 0x80, 0x08, 0x84, key_selector ])
        if sw1 == 0x90 and sw2 == 0x00:
            return True
        else:
            return False


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

            data = self._connection.control(self.__ioctl_verify_direct, control_request)
            sw1 = data[0]
            sw2 = data[1]
        elif self.__ioctl_verify_start and self.__ioctl_verify_finish:
            tkinter.messagebox.showinfo(title='Connective', \
                                        message='The Connective Browser Plugin requests your ' + \
                                                'eID PIN code on the secure pinpad reader [%s]' \
                                                % self.card_reader.name)

            data = self._connection.control(self.__ioctl_verify_start, control_request)
            data = self._connection.control(self.__ioctl_verify_finish, [ ])
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
        bin_data_to_sign = smartcard.util.toBytes(data_to_sign)
        request_data = [ 0x00, 0x2A, 0x9E, 0x9A, len(bin_data_to_sign) ] + \
                         bin_data_to_sign #+ [ 0x00 ]
        data, sw1, sw2 = self.__send_apdu(request_data)
        if sw1 == 0x90 and sw2 == 0x00:
            return smartcard.util.toHexString(data).replace(' ', '')
        else:
            return None


    def log_off(self):
        data, sw1, sw2 = self.__send_apdu([ 0x80, 0xE6, 0x00, 0x00 ])
        if sw1 == 0x90 and sw2 == 0x00:
            return True
        else:
            return False



class MaestroCard(BaseCard):
    def __init__(self, card_reader):
        super().__init__(card_reader)


    def is_card_present(self):
        return (self._connection is not None)


    def get_connective_card_type(self):
        return 2



class Parameters:
    def __init__(self, message):
        self.message = message
        self.error_code = None
        self.error = None


    def __verify_field_exists(self, field):
        if field not in self.message:
            self.error_code = 99
            self.error = 'Message [%s] misses a field named [%s]' % (json.dumps(self.message), field)


    def __verify_field_is_hex(self, field, maxlen):
        value = self.message[field]
        if len(value) > maxlen or any([ c for c in value if (c not in '0123456789ABCDEF') ]):
            if field == 'fileId':
                self.error_code = 3
            else:
                self.error_code = 7
            self.error = 'Invalid data [%s]. Should be maximum %d hex characters' % (value, maxlen)


    def __verify_field_is_valid_hash(self, field):
        value = self.message[field]
        validlen = [ 40, 64, 128 ]
        if len(value) not in validlen or any([ c for c in value if (c not in '0123456789ABCDEF') ]):
            self.error_code = 7
            self.error = 'Invalid hash [%s]; should be either 20, 32 or 64 bytes' % value


    def contains(self, field):
        if not self.error_code:
            self.__verify_field_exists(field)
        return self


    def contains_hex(self, field, maxlen):
        if not self.error_code:
            self.__verify_field_exists(field)
        if not self.error_code:
            self.__verify_field_is_hex(field, maxlen)
        return self


    def contains_hash(self, field):
        if not self.error_code:
            self.__verify_field_exists(field)
        if not self.error_code:
            self.__verify_field_is_valid_hash(field)
        return self



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


def verify_activation_token(token):
    '''
    Verify if the given token is valid.
    '''
    #TODO Not clear what the token contains or how it must be verified. For now always return valid.
    return True


def process_get_info():
    response = {}
    response['version'] = '2.0.2'
    response['binVersion'] = '2.0.9'
    return response


def process_get_readers():
    card_reader_factory = CardReaderFactory()
    reader_list = card_reader_factory.get_reader_list()
    if len(reader_list) == 0:
        return get_error(2, 'Error getting readers (Comm 0x80100001) (0)')
    else:
        response = {}
        response['readerList'] = reader_list
        return response


def process_read_file(request_json):
    params = Parameters(request_json).contains('reader').contains_hex('fileId', 64)
    if params.error_code:
        return get_error(params.error_code, params.error)

    request_reader = request_json['reader']
    request_file_id = request_json['fileId']

    card_reader_factory = CardReaderFactory()
    card_reader = card_reader_factory.find_reader(request_reader)
    sys.stderr.write('==> %s <==\n' % type(card_reader))
    if not card_reader:
        return get_error(0, 'Card reader %s not found' % request_reader)
    elif not isinstance(card_reader, BeIdCard) or not card_reader.is_card_present():
        return get_error(99, 'error calling SCardConnect (0x80100069) (0x0)')
    elif not card_reader.select_file(request_file_id):
        return get_error(5, 'Error reading file (Comm 0x6a87) (0xa4080c)')
    else:
        data = card_reader.read_selected_file()
        if data:
            response = {}
            response['data'] = smartcard.util.toHexString(data).replace(' ', '')
            return response
        else:
            return get_error(5, 'Error reading file (Comm 0x6a87) (0xa4080c)')


def compute_signature(request_reader, request_hash, key_selector):
    card_reader_factory = CardReaderFactory()
    card_reader = card_reader_factory.find_reader(request_reader)
    if not card_reader:
        return get_error(0, 'Card reader %s not found' % request_reader)
    elif not isinstance(card_reader, BeIdCard) or not card_reader.is_card_present():
        return get_error(99, 'error calling SCardConnect (0x80100069) (0x0)')

    is_authenticated = False
    retries_left = -1
    if not key_selector or card_reader.select_coding_algorithm(key_selector):
        (is_authenticated, retries_left) = card_reader.authenticate_pin()
        signature = None
        if is_authenticated:
            if request_hash and key_selector:
                signature = card_reader.sign(request_hash)
            ignore_result = card_reader.log_off()

    # TODO not sure about this section, not tested with wrong or blocked PIN code
    response = {}
    response['pinRemainingAttempts'] = retries_left
    response['pinValid'] = is_authenticated
    if request_hash and key_selector:
        if signature:
            response['valid'] = True
            response['signature'] = signature
        else:
            response['valid'] = False
    else:
        response['valid'] = True

    return response


def process_compute_authentication(request_json):
    params = Parameters(request_json).contains('reader').contains_hash('hash')
    if params.error_code:
        return get_error(params.error_code, params.error)

    return compute_signature(request_json['reader'], request_json['hash'], AUTHENTICATION_KEY)


def process_pin_pad_available(request_json):
    params = Parameters(request_json).contains('reader')
    if params.error_code:
        return get_error(params.error_code, params.error)

    request_reader = request_json['reader']

    card_reader_factory = CardReaderFactory()
    card_reader = card_reader_factory.find_reader(request_reader)
    if not card_reader:
        return get_error(0, 'Card reader %s not found' % request_reader)
    elif not isinstance(card_reader, BeIdCard) or not card_reader.is_card_present():
        return get_error(99, 'error calling SCardConnect (0x80100069) (0x0)')

    response = {}
    response['available'] = card_reader.is_pin_pad_available()

    return response


def process_verify_pin(request_json):
    params = Parameters(request_json).contains('reader')
    if params.error_code:
        return get_error(params.error_code, params.error)

    return compute_signature(request_json['reader'], None, None)


def process_compute_signature(request_json):
    params = Parameters(request_json).contains('reader').contains_hash('hash')
    if params.error_code:
        return get_error(params.error_code, params.error)

    return compute_signature(request_json['reader'], request_json['hash'], NON_REPUDIATION_KEY)


def process_compute_sign_challenge(request_json):
    params = Parameters(request_json) \
        .contains('reader') \
        .contains('language') \
        .contains('transaction') \
        .contains_hex('hash', 100)
    if params.error_code:
        return get_error(params.error_code, params.error)

    # TODO implement

    return get_error(99, 'Error handling JSON message [%s]. Unknown command [%s]' \
                                                        % (request_json, request_json['cmd']))


def process_select_maestro(request_json):
    # TODO implement

    return get_error(99, 'Error handling JSON message [%s]. Unknown command [%s]' \
                                                        % (request_json, request_json['cmd']))


def process_get_processing_options(request_json):
    params = Parameters(request_json).contains('reader').contains_hex('data', 256)
    if params.error_code:
        return get_error(params.error_code, params.error)

    # TODO implement

    return get_error(99, 'Error handling JSON message [%s]. Unknown command [%s]' \
                                                        % (request_json, request_json['cmd']))


def process_read_record(request_json):
    params = Parameters(request_json).contains('reader').contains('record').contains('sfi')
    if params.error_code:
        return get_error(params.error_code, params.error)

    # TODO implement

    return get_error(99, 'Error handling JSON message [%s]. Unknown command [%s]' \
                                                        % (request_json, request_json['cmd']))


def main():
    request = read_native_message()
    response_json = {}

    try:
        request_json = json.loads(request)

        if 'activationToken' in request_json and \
           not verify_activation_token(request_json['activationToken']):
            response_json = get_error(10, 'Activation required')
        elif 'cmd' not in request_json:
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
        elif request_json['cmd'] == 'PIN_PAD_AVAILABLE':
            response_json = process_pin_pad_available(request_json)
        elif request_json['cmd'] == 'VERIFY_PIN':
            response_json = process_verify_pin(request_json)
        elif request_json['cmd'] == 'COMPUTE_SIGNATURE':
            response_json = process_compute_signature(request_json)
        elif request_json['cmd'] == 'COMPUTE_SIGN_CHALLENGE':
            response_json = process_compute_sign_challenge(request_json)
        elif request_json['cmd'] == 'SELECT_MAESTRO':
            response_json = process_select_maestro(request_json)
        elif request_json['cmd'] == 'GET_PROCESSING_OPTIONS':
            response_json = process_get_processing_options(request_json)
        elif request_json['cmd'] == 'READ_RECORD':
            response_json = process_read_record(request_json)
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


if __name__ == "__main__":
    main()
