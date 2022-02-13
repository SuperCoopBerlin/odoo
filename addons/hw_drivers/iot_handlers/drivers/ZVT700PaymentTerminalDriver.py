import logging
import json
import time
import curses.ascii
from threading import Lock
from queue import Queue
import traceback
import requests
import werkzeug
import datetime

from odoo import http

from odoo.addons.hw_drivers.controllers.proxy import proxy_drivers
from odoo.addons.hw_drivers.event_manager import event_manager
from odoo.addons.hw_drivers.driver import Driver

from ecrterm.ecr import ECR
from ecrterm.packets.base_packets import Registration

#For transport debug logging
from ecrterm.common import (
    TERMINAL_STATUS_CODES, INTERMEDIATE_STATUS_CODES, ERRORCODES,
    INTERMEDIATE_STATUS_CODES_DE, ERRORCODES_DE)
from ecrterm.conv import bs2hl, toBytes, toHexString
from ecrterm.packets.base_packets import (
    Authorisation, Completion, DisplayText, EndOfDay, Packet, PrintLine,
    Registration, ResetTerminal, StatusEnquiry, StatusInformation)
from ecrterm.packets.tlv import TLV
from ecrterm.utils import is_stringlike
from ecrterm.ecr import parse_represented_data
from ecrterm.exceptions import TransportLayerException

from ecrterm.transmission.transport_serial import SerialMessage

ECR_TRANSPORT_DEBUG = False
ECR_DEBUG = False

# Only needed to ensure compatibility with older versions of Odoo
ACTIVE_TERMINAL = None

_logger = logging.getLogger(__name__)

# Remove later
try:
    import pycountry

    EUR_CY_NBR = False
except (ImportError, IOError) as err:
    _logger.debug(err)
    _logger.warning(
        'Unable to import pycountry, only EUR currency is supported')
    EUR_CY_NBR = 978


def ecr_log(data, incoming=False, **kwargs):

    if 'raw' in kwargs:
        _logger.debug("Ecrterm debug log: %s" % data)
        return

    """Logger stub for the ecrterm transport layer log"""
    try:
        if incoming:
            incoming = '<'
        else:
            incoming = '>'
        if is_stringlike(data):
            data = bs2hl(data)
        try:
            _logger.debug('%s %s\n' % (incoming, toHexString(data)))
        except Exception:
            pass
        if len(data):
            try:
                data = repr(parse_represented_data(data))
                _logger.debug('= %s\n' % data)
            except Exception as e:
                _logger.debug('Cannot be represented: %s, %s' % (data, e))
                data = toHexString(data)
        _logger.debug('%s %s' % (incoming, data))
    except Exception:
        _logger.debug("Error in log: %s" % traceback.format_exc())

# Ensures compatibility with older versions of Odoo
class ZVT700PaymentTerminalControllerOldRoute(http.Controller):
    @http.route(
        '/hw_proxy/payment_terminal_transaction_start',
        type='json', auth='none', cors='*')
    def payment_terminal_transaction_start(self, payment_info):
        _logger.debug(
            'Call payment_terminal_transaction_start via old route with '
            'payment_info=%s' % (payment_info))
        answer = False
        if ACTIVE_TERMINAL and ACTIVE_TERMINAL._status['status'] != 'disconnected':
            answer = ACTIVE_TERMINAL._start_transaction_old_route(payment_info)

        _logger.debug('Result of payment_terminal_transaction_start: %s' % answer)
        return answer

    @http.route(
        '/hw_proxy/payment_terminal_transaction_start_with_return',
        type='json', auth='none', cors='*')
    def payment_terminal_transaction_start_with_return(self, payment_info):
        _logger.debug(
            'Call payment_terminal_transaction_start_with_return via old route with '
            'payment_info=%s' % (payment_info))
        answer = False
        if ACTIVE_TERMINAL and ACTIVE_TERMINAL._status['status'] != 'disconnected':
            answer = ACTIVE_TERMINAL._start_transaction_old_route(payment_info)

        _logger.debug('Result of payment_terminal_transaction_start_with_return: %s' % answer)
        return answer

    @http.route(
        '/hw_proxy/payment_terminal_turnover_totals',
        type='json', auth='none', cors='*')
    def payment_terminal_turnover_totals(self, print_receipt):
        _logger.debug(
            'Call payment_terminal_turnover_totals via old route')
        answer = False
        if ACTIVE_TERMINAL and ACTIVE_TERMINAL._status['status'] != 'disconnected':
            answer = ACTIVE_TERMINAL._start_turnover_totals_old_route(print_receipt)

        _logger.debug('Result of payment_terminal_turnover_totals: %s' % answer)
        return answer

    @http.route(
        '/hw_proxy/payment_terminal_end_of_day',
        type='json', auth='none', cors='*')
    def payment_terminal_end_of_day(self, print_receipt):
        _logger.debug(
            'Call payment_terminal_end_of_day via old route')
        answer = False
        if ACTIVE_TERMINAL:
            answer = ACTIVE_TERMINAL._start_end_of_day_old_route(print_receipt)

        _logger.debug('Result of payment_terminal_end_of_day: %s' % answer)
        return answer

class ZVT700PaymentTerminalDriver(Driver):
    connection_type = 'serial'
    protocol_name = 'ZVT-700'
    priority = 1

    def __init__(self, identifier, device):
        super(ZVT700PaymentTerminalDriver, self).__init__(identifier, device)
        self.device_type = 'payment_terminal'
        self._actions = {
            'get_status': self._push_status,
            'payment_terminal_transaction_start': self._transaction_start,
            'payment_terminal_transaction_start_with_return': self._transaction_start,
            'payment_terminal_turnover_totals': self._turnover_totals_start,
            'payment_terminal_end_of_day': self._end_of_day_start,
        }
        self.device_name = self._set_name()

        self.queue = Queue()
        self.receipt_queue = Queue()
        self._device_lock = Lock()

        self.device_connection = 'serial'

        if self._connect_and_configure(self.device_identifier, enable_ECR_printing=True):
            status = 'connected'
        else:
            status = 'disconnected'

        self._status = {'status': status, 'message_title': '', 'message_body': ''}
        self._push_status()

        global ACTIVE_TERMINAL
        ACTIVE_TERMINAL = self
        proxy_drivers['payment_terminal'] = ACTIVE_TERMINAL

    # Ensures compatibility with older versions of Odoo
    def _start_transaction_old_route(self, payment_info):
        """Used when the iot app is not installed"""
        with self._device_lock:
            return self._transaction_start(payment_info)

    def _start_turnover_totals_old_route(self, print_receipt):
        """Used when the iot app is not installed"""
        with self._device_lock:
            return self._turnover_totals_start(print_receipt)

    def _start_end_of_day_old_route(self, print_receipt):
        """Used when the iot app is not installed"""
        with self._device_lock:
            return self._end_of_day_start(print_receipt)

    def _set_name(self):
        try:
            #Requires SerialInterface.py to search for '/dev/serial/by-id/*' instead of '/dev/serial/by-path/*'
            id_parts = self.device_identifier.split('/')[-1].split('-')[1].split('_')
            manufacturer = id_parts[0]
            product = id_parts[1]
            return ("%s - %s") % (manufacturer, product)
        except IndexError or ValueError as e:
            _logger.warning(e)
            return ('Unknown %s device' % self.protocol_name)

    # Ensures compatibility with older versions of Odoo
    # and allows using the `ProxyDevice` in the point of sale to retrieve the status
    def get_status(self):
        """Allows `hw_proxy.Proxy` to retrieve the status of the terminal"""
        _logger.debug("Old 'get_status()' method called")
        status = self._status
        return {'status': status['status'], 'messages': [status['message_title'], ]}

    def _push_status(self):
        """Updates the current status and pushes it to the frontend."""
        self.data['status'] = self._status
        event_manager.device_changed(self)

    def disconnect(self):
        msg = 'Terminal was disconnected'
        _logger.debug(msg)
        self._status = {'status': "disconnected", 'message_title': msg, 'message_body': ""}
        self._push_status()

        super(ZVT700PaymentTerminalDriver, self).disconnect()
        

    @classmethod
    def supported(cls, device):
        """Checks whether the device, which port info is passed as argument, is supported by the driver.

        :param device: path to the device
        :type device: str
        :return: whether the device is supported by the driver
        :rtype: bool
        """
        res = False
        try:
            _logger.debug("Probing device %s with %s protocol" % (device['identifier'], cls.protocol_name))
            ecr = ECR(device=device['identifier'], password='111111', baudrate=115200)
            # Enable ecrterm logging
            if ECR_TRANSPORT_DEBUG:
                ecr.transport.slog = ecr_log
            if ECR_DEBUG:
                ecr.ecr_log = ecr_log

            # Try multiple times in case the PT is still booting
            attempts_total = 5
            num_attempts = 0

            while num_attempts < attempts_total:
                num_attempts += 1
                try:
                    if ecr.detect_pt():
                        res = True
                        break
                    else:
                        _logger.debug("Device %s does not comply with %s protocol (attempt %d/%d)" % (device['identifier'], cls.protocol_name, num_attempts, attempts_total))
                        time.sleep(5)
                except TransportLayerException as e:
                    _logger.debug("TransportLayerException while detecting %s terminal (%s), attempt %d/%d" % (
                    cls.protocol_name, device['identifier'], num_attempts, attempts_total))
                    time.sleep(5)
                    pass
        except Exception as e:
            _logger.error('Error while probing %s with %s protocol (%s)' % (device, cls.protocol_name, e))
            pass
        return res

    def _connect_and_configure(self, device, enable_ECR_printing=False):
        self._ecr = ECR(device=device, password='111111', baudrate=115200)
        # Enable ecrterm logging
        if ECR_TRANSPORT_DEBUG:
            self._ecr.transport.slog = ecr_log
        if ECR_DEBUG:
            self._ecr.ecr_log = ecr_log

        attempts_total = 5
        num_attempts = 0
        res = False
        with self._device_lock:
            while num_attempts < attempts_total:
                num_attempts += 1
                try:
                    _logger.debug("Configuring %s terminal (%s)" % (self.protocol_name, self.device_identifier))
                    CC_EUR = [0x09, 0x78]

                    self._ecr.register(config_byte=Registration.generate_config(
                        ecr_prints_receipt=enable_ECR_printing,
                        ecr_prints_admin_receipt=enable_ECR_printing,
                        ecr_controls_admin=True,
                        ecr_controls_payment=True,),
                        cc=CC_EUR,
                        tlv={'tlv12': [0x44]}, # Set maximum print line width to 44
                    )

                    code = self._ecr.status()
                    _logger.debug("%s terminal status is: %s" % (self.protocol_name, hex(code)))

                    if code == 0:
                        self._ecr.show_text(lines=['Verbindung', 'zur Kasse', 'erfolgreich', 'hergestellt'], beeps=0)
                        res = True
                        break
                    else:
                        _logger.error("Detecting %s terminal (%s) failed, status: %d, attempt %d/%d" % (self.protocol_name, self.device_identifier, res, num_attempts, attempts_total))
                        time.sleep(5)
                except TransportLayerException as e:
                    _logger.error("TransportLayerException while detecting %s terminal (%s), attempt %d/%d" % (self.protocol_name, self.device_identifier, num_attempts, attempts_total))
                    time.sleep(5)
                    pass
        return res

    def _get_amount(self, payment_info_dict):
        amount = payment_info_dict['amount']
        return int(round(amount*100,0))

    def _get_currency_code(self, payment_info_dict):
        cur_iso_letter = payment_info_dict['currency_iso'].upper()
        try:
            if EUR_CY_NBR:
                cur_numeric = str(EUR_CY_NBR)
            else:
                cur = pycountry.currencies.get(alpha_3=cur_iso_letter)
                cur_numeric = str(cur.numeric)
        except:
            _logger.error("Currency %s is not recognized" % cur_iso_letter)
        return cur_numeric

    def _get_payment_type(self, payment_info_dict):
        if payment_info_dict['payment_mode'] == 'check':
            payment_mode = 'C'
        elif payment_info_dict['payment_mode'] == 'card':
            payment_mode = '1'
        else:
            _logger.error(
                "The payment mode '%s' is not supported"
                % payment_info_dict['payment_mode'])
            return False

    def _terminal_wait_for_status(self, poll_interval=0.5, timeout=5):
        """
        waits until self.status() returns 0 (or False/None)
        or a timeout occurs; wait poll_interval seconds between attempts
        """
        attempt_ctr = timeout // poll_interval
        status = self._ecr.status()
        while status and attempt_ctr > 0:
            if self._ecr.transport.insert_delays:
                time.sleep(poll_interval)
            attempt_ctr += 1
            status = self._ecr.status()
        return status

    def _change_print_config(self, enable_ECR_printing):
        CC_EUR = [0x09, 0x78]

        attempts_total = 5
        num_attempts = 0
        res = False
        while num_attempts < attempts_total:
            if(num_attempts > 0):
                time.sleep(1.5)
                _logger.debug("Attempt %d/%d in _change_print_config" % (num_attempts+1, attempts_total))
            num_attempts += 1
            try:
                self._ecr.register(config_byte=Registration.generate_config(
                    ecr_prints_receipt=enable_ECR_printing,
                    ecr_prints_admin_receipt=enable_ECR_printing,
                    ecr_controls_admin=True,
                    ecr_controls_payment=True,),
                    cc=CC_EUR,
                    tlv={'tlv12': [0x44]},
                )
                code = self._ecr.status()
                if code == 0:
                    res = True
                    break
                else:
                    _logger.warning("Non-zero return code (%d) in _change_print_config" % code)
            except TransportLayerException as e:
                #Potential timeout, terminal not ready, ignore for now
                _logger.error("TransportLayerException in _change_print_config: %s" % traceback.format_exc())
                pass
        return res
    
    def decode_receipt_with_attributes(self, receipt_lines):
        """cp437 decoding, 'if attr <= 80' filters out non-printables
        """
        return [bytearray([ord(t) for t in txt]).decode('cp437') for attr, txt in receipt_lines if attr <= 80 and txt != '']

    def _transaction_start(self, payment_info):
        """This function executes the transaction
        """

        payment_info_dict = json.loads(payment_info)
        assert isinstance(payment_info_dict, dict), \
            'payment_info_dict should be a dict'
        res = False

        _logger.debug("Starting %s transaction: %s" % (self.protocol_name, payment_info_dict))

        amount = self._get_amount(payment_info_dict)

        # Currently not used; assume correctly configured PT
        currency_code = self._get_currency_code(payment_info_dict)
        payment_type = self._get_payment_type(payment_info_dict)

        dummy_transaction = False
        dump_transaction = False

        try:
            if not dummy_transaction:
                #self._change_print_config(enable_ECR_printing=True)
                success = self._ecr.payment(amount_cent=amount)
            else:
                success = True

            if success:
                if not dummy_transaction:
                    last_status = self._ecr.last_status_information()[-1]
                    _logger.debug("Last status (type %s): %s" % (type(last_status), last_status))

                    printout = self._ecr.last_printout_with_attribute()
                    
                    if dump_transaction:
                        import pickle
                        try:
                            with open('/home/pi/last_status_dump.pickle', 'wb') as f:
                                pickle.dump(last_status, f)
                            with open('/home/pi/printout_dump.pickle', 'wb') as f:
                                pickle.dump(printout, f)
                        except Exception as e:
                            _logger.debug("Pickle exception: %s" % e)
                else:
                    import pickle
                    with open('/home/pi/last_status_dump.pickle', 'rb') as f:
                        last_status = pickle.load(f)
                    with open('/home/pi/printout_dump.pickle', 'rb') as f:
                        printout = pickle.load(f)

                    last_status['amount'] = str(amount).zfill(12)

                start_indices = [i + 1 for i, (attr, txt) in enumerate(printout) if txt == '\x00']
                printout_merchant = printout[start_indices[0]:start_indices[1]-1]
                printout_cardholder = printout[start_indices[1]:]

                # cp437 decoding, 'if attr <= 80' filters out non-printables
                printout_cardholder_decoded = self.decode_receipt_with_attributes(printout_cardholder)
                printout_merchant_decoded = self.decode_receipt_with_attributes(printout_merchant)
                _logger.debug("printout_cardholder_decoded: %s" % printout_cardholder_decoded)
                _logger.debug("printout_merchant_decoded: %s" % printout_merchant_decoded)

                res = {
                    'pos_number': last_status['tid'],
                    'transaction_result': last_status['result_code'][0],
                    'amount_msg': last_status['amount'],
                    'payment_mode': last_status['card_name'],
                    'payment_terminal_return_message': last_status,
                    'merchant_receipt': printout_merchant_decoded,
                    'cardholder_receipt': printout_cardholder_decoded,
                }
                
                self.receipt_queue.put({'date': datetime.datetime.now(),
                                        'merchant_receipt': printout_merchant_decoded,
                                        'cardholder_receipt': printout_cardholder_decoded
                                       })
            else:
                _logger.debug("Transaction failed. %s" % payment_info_dict)

                last_intermediate_status = self._ecr.last_intermediate_status_information()
                _logger.debug("Intermediate status information: %s" % last_intermediate_status)
                if len(last_intermediate_status) > 0:
                    intermediate_status = last_intermediate_status[-1]
                    intermediate_status_msg = INTERMEDIATE_STATUS_CODES_DE.get(intermediate_status, 'No intermediate_status')
                    _logger.debug("Last intermediate status: %s, reason: %s" % (str(intermediate_status), intermediate_status_msg))

                last_aborts = self._ecr.last_aborts()
                _logger.debug("Last aborts: %s" % last_aborts)
                if len(last_aborts) > 0:
                    last_abort_error_code = last_aborts[-1]
                    last_abort_error_msg = ERRORCODES_DE.get(last_abort_error_code, 'No error code')
                    _logger.debug("Last abort error code: %s, reason: %s" % (str(last_abort_error_code), last_abort_error_msg))
                    
                    res = {
                        'transaction_result': 1,
                        'error_code': last_abort_error_code,
                        'error_msg': last_abort_error_msg
                    }

                else:
                    last_packet = self._ecr.last_packet()
                    _logger.debug("Unknown transaction error. Last packet: %s" % last_packet)
                    res = {
                        'transaction_result': 1,
                        'error_code': 99, #Unknown error reason
                        'error_msg': 'Unknown transaction error'
                    }
        except Exception as e:
            msg = 'Exception during terminal transaction: %s' % str(e)
            _logger.error("%s %s" % (msg, traceback.format_exc()))
            self._status = {'status': "error", 'message_title': msg, 'message_body': traceback.format_exc()}
            self._push_status()
        #finally:
        #    if not dummy_transaction:
        #        self._change_print_config(enable_ECR_printing=False)
        return res

    def _turnover_totals_start(self, print_receipt=True):
        #self._change_print_config(enable_ECR_printing=True)

        now = datetime.datetime.now()
        result = self._ecr.turnover_totals()
        _logger.debug("Turnover totals result: %s" % (result))
        #self._change_print_config(enable_ECR_printing=False)

        res = {'result': result}
        if result:
            printout = self._ecr.totalslog
            _logger.debug("Turnover totals: %s" % (printout))

            printout_decoded = self.decode_receipt_with_attributes(printout)
            if print_receipt:
                self.print_receipt(printout_decoded)
            self.receipt_queue.put({'date': now,
                                    'turnover_totals_receipt': printout_decoded
                                    })
            res['turnover_totals_receipt'] = printout_decoded

        return res
            
    def _end_of_day_start(self, print_receipt=True):
        #self._change_print_config(enable_ECR_printing=True)

        now = datetime.datetime.now()
        result = self._ecr.end_of_day()
        _logger.debug("End of day result: %s" % (result))
        #self._change_print_config(enable_ECR_printing=False)

        res = {'result': result}
        if result:
            printout = self._ecr.daylog
            _logger.debug("End of day: %s" % (printout))
            
            printout_decoded = self.decode_receipt_with_attributes(printout)
            if print_receipt:
                self.print_receipt(printout_decoded)
            self.receipt_queue.put({'date': now,
                                    'end_of_day_receipt': printout_decoded
                                    })
            res['end_of_day_receipt'] = printout_decoded

        return res


    def action(self, data):
        """Perform a specific action on the device.

        :param data: the `_actions` key mapped to the action method we want to call
        :type data: string
        """
        try:
            with self._device_lock:
                res = self._actions[data['action']](data)
        except Exception:
            msg = 'An error occured while performing action %s on %s' % (data, self.device_name)
            _logger.error(msg)
            self._status = {'status': 'error', 'message_title': msg,
                            'message_body': traceback.format_exc()}
            self._push_status()
        return res

    def dump_receipt(self, receipt_dict):
        date = receipt_dict['date']
        receipt = None
        
        if 'merchant_receipt' in receipt_dict:
            receipt = receipt_dict['merchant_receipt']
            receipt += receipt_dict['cardholder_receipt']
        elif 'turnover_totals_receipt' in receipt_dict:
           receipt = receipt_dict['turnover_totals_receipt']
        elif 'daylog_receipt' in receipt_dict:
            receipt = receipt_dict['daylog_receipt']
        
        if receipt:
            _logger.debug('Receipt to dump (date: %s) %s' % (date, receipt))
            # TODO Save receipt to file/cloud
        else:
            _logger.debug('Unknown receipt to dump %s' % receipt_dict)

    def dump_all_receipts(self):
        if self.receipt_queue.qsize():
            for receipt in iter(self.receipt_queue.get, None):
                _logger.debug('Receipt %s' % receipt)
                if receipt:
                    _logger.debug('Saving receipt %s' % receipt)
                    self.dump_receipt(receipt)
                else:
                    break
                if not self.receipt_queue.qsize():
                    _logger.debug('Receipt queue is now empty')
                    break
        else:
            _logger.debug('Receipt queue empty')

    def print_receipt(self, receipt_lines):
        xml_receipt = "<receipt align=\"center\" value-thousands-separator=\"\" width=\"44\">" + "\n"
        xml_receipt += "<pre>" + "\n"
        xml_receipt += "</pre> \n <pre>".join(receipt_lines)
        xml_receipt += "</pre>" + "\n"
        xml_receipt += "</receipt>"

        data = json.dumps({"id":501563999, "jsonrpc":"2.0","method":"call","params":{"receipt": xml_receipt}})
        req = requests.post('http://localhost:8069/hw_proxy/print_xml_receipt', data=data, 
                            headers={'Content-Type': 'application/json', 'Accept': 'text/plain'}, verify=False)
        req.raise_for_status()
        response = werkzeug.utils.unescape(req.content.decode())
        _logger.debug("RPC response: %s" % (response))

'''
    def run(self):
        """Continuously check for new receipt in the queue so save"""
        date_old = datetime.datetime(year=2000, month=1, day=1, hour=0, minute=0, second=0)

        periodic_turnover_totals = False

        while not self._stopped.isSet():
            try:
                
                #_logger.debug('##################')
                #_logger.debug('##################')
                #_logger.debug('#ZVT-700 run loop#')

                self.dump_all_receipts()

                time.sleep(5)

                if periodic_turnover_totals:
                    date_now = datetime.datetime.now()
                    time_diff = date_now - date_old
                    date_old = date_now
                    if time_diff.total_seconds() > (24*60*60): #Do every day (not needed for production use)
                        with self._device_lock:
                            if self._ecr:
                                try:                           
                                    self._turnover_totals_start()    
                                    
                                except TransportLayerException as e:
                                    _logger.debug('Run loop: TransportLayerException: %s; %s' % (e, traceback.format_exc()))
                                    pass
                                except Exception as e:
                                    _logger.error('Run loop: Exception while receiving message: %s; %s' % (e, traceback.format_exc()))
                                    pass

                #_logger.debug('#ZVT-700 run loop#')
                #_logger.debug('###### end #######')
                #_logger.debug('##################')

            except Exception as e:
                _logger.debug(e, traceback.format_exc()) 
                pass
        _logger.debug('Terminating run loop')
'''
