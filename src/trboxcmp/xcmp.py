import logging
import asyncio
import time
import binascii
from trboxcmp.xnl import XnlListener
from trboxcmp.XcmpByteFactory import XcmpByteFactory
from trboxcmp.XcmpOpCodes import XcmpOpCodes, XcmpConsts, XcmpCallStatus

class Xcmp:
    # op defs for callback
    OP_CALL = 1
    OP_CALL_INFO = 2
    OP_RADIOSTATUS = 3
    OP_VERSTATUS = 4
    OP_BATTLVL = 5
    OP_DISPTXT = 6

    # byte offsets inside a CALL_CTRL_BCAST (0xb41e) message
    CALL_STATUS_POS = 3
    CALL_RID_POS = 6
    CALL_TGID_POS = 12
    # one byte of padding/flag after the tgid, then the sender's alias
    CALL_ALIAS_POS = 16
    #byte order of the UTF-16 alias field, "little" or "big"
    CALL_ALIAS_ENDIAN = "little"

    def __init__(self, keys, delta, kid, callback, ip="192.168.10.1", port=8002):
        self._xnl = XnlListener(keys, delta, kid, self.onXcmpIn, ip, port)
        self._callback = callback
        self._byteFactory = XcmpByteFactory
        self._connected = False

    def sendRaw(self, bytes):
        self._xnl.sendXcmp(bytes)

    @classmethod
    def decodeAlias(cls, data, pos = None, endian = None):
        '''
        Pull the sender's alias (the radio name, e.g. "DEMO 1-1") out of the tail
        of a CALL_CTRL_BCAST message.

        The name rides at the end of the frame as null padded UTF-16:

            ... 00 00 01 | 00 | 44 00 45 00 4d 00 4f 00 20 00 31 00 2d 00 31 | 00 00
                tgid = 1     ?    B     V     ' '   7     -     5

        Little endian, one byte after the talkgroup id, which lines the field up
        with the end of the 32 byte frame exactly. A code unit only counts as
        text while its high byte is 0x00 and its low byte is printable, so the
        zero padding (and any other number that happens to sit there) ends the
        name instead of turning into mojibake. That means names outside of
        Latin-1 are dropped rather than guessed at.

        Radios that use the big endian layout one byte earlier need
        CALL_ALIAS_POS = 15 and CALL_ALIAS_ENDIAN = "big".
        Returns "" when the message carries no alias, which is the case for most
        of the call status updates.
        '''
        if (pos is None):
            pos = cls.CALL_ALIAS_POS
        if (endian is None):
            endian = cls.CALL_ALIAS_ENDIAN

        chars = []
        for i in range(pos, len(data) - 1, 2):
            if (endian == "big"):
                high, low = data[i], data[i + 1]
            else:
                low, high = data[i], data[i + 1]
            #high byte set or a control byte: end of the name / start of padding
            if (high != 0 or low < 0x20):
                break
            chars.append(chr(low))
        return "".join(chars)

    def onXcmpIn(self, data):
        logging.debug("XCMP: Incoming message: {}".format(data))
        result = {}
        payload = {}

        opCode = data[0:2]
        #if we hit an error, don't run the callback
        dontCallBack = False

        if (opCode == XcmpOpCodes.SPKR_CTRL_BCAST):
            #msg
            #b4 07 00 01 00 01
            #first 2 - opcode
            #middle 2 - ??
            #last 2 - call status - on/off
            result['type'] = self.OP_CALL

            #decode call on/off
            payload['callStatus'] = int.from_bytes(data[4:6], "big")

        elif (opCode == XcmpOpCodes.CALL_CTRL_BCAST):
            #msg
            #b4 1e 06 01 01 03 00 7b 96 00 00 03 00 0c 3b
            #b4 1e 06 01 01 03 01 08 4f 00 00 03 00 00 01 00 42 00 56 00 20 00 37 00 2d 00 35 00 00 00 00 00
            #first 2 - opcode
            #2-4 - 06 01 - call decoded
            #      06 02 - call in progress
            #      06 08 - call decoded clear
            #      06 09 - call decoded enc valid key
            #      06 07 - hang time
            #      06 03 - call end
            #6-9 - rid (id of the radio that is talking)
            #12-15 - tgid
            #16.. - alias of the sender, UTF-16, null padded ("DEMO 1-1")
            result['type'] = self.OP_CALL_INFO

            status = int.from_bytes(data[3:4], "big")
            payload['status'] = status
            payload['statusText'] = XcmpCallStatus.text(status)
            #short frames (call end, hang time) stop after the tgid
            if (len(data) >= self.CALL_RID_POS + 3):
                payload['rid'] = int.from_bytes(data[self.CALL_RID_POS:self.CALL_RID_POS + 3], "big")
            if (len(data) >= self.CALL_TGID_POS + 3):
                payload['tgid'] = int.from_bytes(data[self.CALL_TGID_POS:self.CALL_TGID_POS + 3], "big")
            alias = self.decodeAlias(data)
            if (alias):
                payload['alias'] = alias

        elif (opCode == XcmpOpCodes.RADIOSTATUS_RES):
            result['type'] = self.OP_RADIOSTATUS
            # radio status response
            statusCondition = data[3:4]
            # radio model number
            if (statusCondition == b'\x07'):
                modelNo = data[4:17].replace(b'\x00', b'').decode()
                payload['respType'] = "model"
                payload['content'] = modelNo

            # radio serial number
            if (statusCondition == b'\x08'):
                serialNo = data[4:14].replace(b'\x00', b'').decode()
                payload['respType'] = "serial"
                payload['content'] = serialNo

            # radio ID
            if (statusCondition == b'\x0e'):
                rid = data[5:8].replace(b'\x00', b'').decode()
                payload['respType'] = "rid"
                payload['content'] = rid

        elif (opCode == XcmpOpCodes.VERSTATUS_RES):
            result['type'] = self.OP_VERSTATUS
            payload['version'] = data[2:18].replace(b'\x00', b'').decode()

        elif (opCode == XcmpOpCodes.BATTLVL_BCAST):
            result['type'] = self.OP_BATTLVL
            payload['battLevel'] = int.from_bytes(data[3:4], "big")

        elif (opCode == XcmpOpCodes.DISPTXT_BCAST):
            result['type'] = self.OP_DISPTXT
            payload['lineNo'] = int.from_bytes(data[2:3], "big")
            #decode as latin1 so it doesn't kick back errors about bad bytes
            payload['content'] = data[125:].replace(b'\x00', b'').decode('latin1')
            #logging.debug("Raw Text Data: {}".format(data[125:]))

        elif (opCode == XcmpOpCodes.DEVINITSTS_BCAST or opCode == XcmpOpCodes.INDUP_BCAST):
            #drop it on the floor, we don't care
            dontCallBack = True

        else:
            logging.debug("Got unknown XCMP opcode: {}".format(opCode))
            dontCallBack = True

        result['payload'] = payload
        
        if (dontCallBack == False):
            self._callback(result)

    def connect(self):
        #don't attempt reconnection
        if self._connected:
            return True
        else:
            if (self._xnl.connect()):
                #give the connection a few seconds to init before we go blasting data down it
                time.sleep(0.5)
                return True
            else:
                return False

    def close(self):
        self._xnl.close()

    def sendRaw(self, bytesIn):
        self._xnl.sendXcmp(bytesIn)

    def setChannel(self, channel):
        bytes = self._byteFactory.genChZnSel(XcmpConsts.CH_SEL, 0, channel)
        self._xnl.sendXcmp(bytes)

    def setZone(self, zone):
        bytes = self._byteFactory.genChZnSel(XcmpConsts.ZN_SEL, zone, 0)
        self._xnl.sendXcmp(bytes)

    def chUp(self):
        bytes = self._byteFactory.genChZnSel(XcmpConsts.CH_UP)
        self._xnl.sendXcmp(bytes)

    def chDown(self):
        bytes = self._byteFactory.genChZnSel(XcmpConsts.CH_DN)
        self._xnl.sendXcmp(bytes)

    def enterRSSI(self):
        async def buttonPressRoutine():
            #left, left, left, right, right, right
            self.pressButton(XcmpConsts.BTN_LEFT)
            await asyncio.sleep(0.1)

            self.pressButton(XcmpConsts.BTN_LEFT)
            await asyncio.sleep(0.1)

            self.pressButton(XcmpConsts.BTN_LEFT)
            await asyncio.sleep(0.1)

            self.pressButton(XcmpConsts.BTN_RIGHT)
            await asyncio.sleep(0.1)

            self.pressButton(XcmpConsts.BTN_RIGHT)
            await asyncio.sleep(0.1)

            self.pressButton(XcmpConsts.BTN_RIGHT)
        asyncio.run(buttonPressRoutine())

    def setBrightness(self, brightness):
        reqBytes = XcmpByteFactory.genBrightness(4, brightness)
        self._xnl.sendXcmp(reqBytes)

    def incBrightness(self):
        reqBytes = XcmpByteFactory.genBrightness(0)
        self._xnl.sendXcmp(reqBytes)

    def decBrightness(self):
        reqBytes = XcmpByteFactory.genBrightness(1)
        self._xnl.sendXcmp(reqBytes)

    def getVersion(self):
        reqBytes = XcmpByteFactory.genVerReq()
        self._xnl.sendXcmp(reqBytes)

    def getSerial(self):
        reqBytes = XcmpByteFactory.genSerialReq()
        self._xnl.sendXcmp(reqBytes)

    def getModel(self):
        reqBytes = XcmpByteFactory.genModelReq()
        self._xnl.sendXcmp(reqBytes)

    def updateStatus(self):
        logging.debug("XCMP: Updating status")

    def pressButton(self, button):
        butOn = XcmpByteFactory.genUserButton(button, 1)
        self._xnl.sendXcmp(butOn)
        time.sleep(0.1)
        butOff = XcmpByteFactory.genUserButton(button, 0)
        self._xnl.sendXcmp(butOff)

    def sendButton(self, button, state):
        '''Send button with specific state rather than just pressing it'''
        but = XcmpByteFactory.genUserButton(button, state)
        self._xnl.sendXcmp(but)

    def ptt(self, status):
        '''Key up/down the radio. Pass a 1 to key up, 0 to key down'''
        pttBytes = XcmpByteFactory.genPtt(status)
        logging.debug("XCMP: PTT {}".format("on" if status > 0 else "off"))
        self._xnl.sendXcmp(pttBytes)
    
    def selectMic(self, mic):
        '''Select radio mic, 0=internal; 1=external'''
        micBytes = XcmpByteFactory.genMicSelect(mic)
        logging.debug("XCMP: Changing mic to {}".format(mic))
        self._xnl.sendXcmp(micBytes)

    def stunRadio(self, rid):
        '''Stuns radio using OTA interface'''
        ctrlBytes = XcmpByteFactory.genRadioControl(1, rid)
        logging.debug("XCMP: Stunning radio {}".format(rid))
        self._xnl.sendXcmp(ctrlBytes)

    def unstunRadio(self, rid):
        '''Unstuns radio using OTA interface'''
        ctrlBytes = XcmpByteFactory.genRadioControl(2, rid)
        logging.debug("XCMP: Unstunning radio {}".format(rid))
        self._xnl.sendXcmp(ctrlBytes)