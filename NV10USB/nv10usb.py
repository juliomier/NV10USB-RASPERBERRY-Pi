import serial

class NV10USB(object):
    INIT_ERROR = False
    SEND_STATUS = False
    ERROR = None
    SERIAL_NUMBER = None
    CHANNEL_VALUE = None

    # Generic Response
    GENERIC_RESPONSE = {
        0xF0: 'OK',
        0xF2: 'COMMAND NOT KNOWN',
        0xF3: 'WRONG No PARAMETERS',
        0xF4: 'PARAMETERS',
        0xF5: 'COMMAND CANNOT BE PROCESSED',
        0xF6: 'SOFTWARE ERROR',
        0xF8: 'FAIL',
        0xFA: 'KEY NOT SET'
    }

    # Commands
    __Sync = '0x11'  # Generic Commands
    __Reset = '0x01'  # Generic Commands
    __Host_Protocol_Version = '0x06'  # Generic Commands
    __Poll = '0x07'
    __Get_Serial_Number = '0x0C'  # Generic Commands NEED TO FIX
    __Disable = '0x09'  # Generic Commands
    __Enable = '0x0A'  # Generic Commands
    __Get_Firmware_Version = '0x20'  # Generic Commands
    __Get_Dataset_Version = '0x21'  # Generic Commands
    __Set_Inhibits = '0x02'
    __Display_On = '0x03'
    __Display_Off = '0x04'
    __Reject = '0x08'
    __Unit_Data = '0x0D'
    __Channel_Value_Data = '0x0E'
    __Channel_Security_Data = '0x0F'
    __Last_Reject_Code = '0x17'
    __Configure_Bezel = '0x54'
    __Poll_With_Ack = '0x56'
    __Event_Ack = '0x57'
    __Get_Counters = '0x58'
    __Set_Generator = '0x4A'
    __Set_Modulus = '0x4B'
    __Request_Key_Exchange = '0x4C'
    __Ssp_Set_Encryption_Key = '0x60'
    __Ssp_Encryption_Reset_To_Default = '0x61'
    __Hold = '0x18'
    __Setup_Request = '0x05'
    __High_Protocol = '0x19'

    def __init__(self, serialport='COM15'):
        self.__eSSPId = 0
        self.__sequence = '0x80'
        try:
            self.ser = serial.Serial(serialport, 9600, timeout=0.1)
        except serial.SerialException as e:
            self.ERROR = str(e)
            self.INIT_ERROR = True

    def crc(self, command):
        """
        Cálculo del CRC-16 forward usando polinomio 0x8005 (X^16 + X^15 + X^2 + 1)
        Se usa semilla 0xFFFF, calculado antes del byte-stuffing.
        """
        length = len(command)
        seed = int('0xFFFF', 16)
        poly = int('0x8005', 16)
        crc = seed
        for i in range(0, length):
            crc ^= (int(command[i], 16) << 8)
            for j in range(0, 8):
                if (crc & int('0x8000', 16)):
                    crc = ((crc << 1) & int('0xffff', 16)) ^ poly
                else:
                    crc <<= 1
        crc = [hex((crc & 0xFF)), hex(((crc >> 8) & 0xFF))]
        return crc

    def send(self, command):
        seq = self.getseq()
        if type(command) == list:
            crc_val = self.crc([seq] + command)
        else:
            crc_val = self.crc([seq, '0x01', command])

        packet = bytearray()
        packet.append(0x7F)
        packet.append(int(seq, 16))

        if type(command) == list:
            packet.append(int(command[0], 16))
            for i in command[1:]:
                packet.append(int(i, 16))
        else:
            packet.append(0x01)
            packet.append(int(command, 16))

        packet.append(int(crc_val[0], 16))
        packet.append(int(crc_val[1], 16))

        self.ser.write(packet)

        # Lee la respuesta
        bytes_read = []
        expected_bytes = 3
        while True:
            byte = self.ser.read()
            if byte:
                bytes_read.append(byte)
            else:
                self.ERROR = 'Unable to read the expected response'
                return None

            if expected_bytes == 3 and len(bytes_read) >= 3:
                expected_bytes += ord(bytes_read[2]) + 2

            if expected_bytes > 3 and len(bytes_read) == expected_bytes:
                break

        first_data_byte = bytes_read[3]
        length_data_byte = bytes_read[2]

        # Analiza el status
        if ord(first_data_byte) in self.GENERIC_RESPONSE and \
           self.GENERIC_RESPONSE[ord(first_data_byte)] == 'OK':
            self.SEND_STATUS = True
            data = []
            for i in bytes_read[4:3 + ord(length_data_byte)]:
                data.append(i)
            return data
        else:
            # Si la respuesta no es 0xF0 (OK), guarda el error
            self.SEND_STATUS = False
            err_code = ord(first_data_byte)
            if err_code in self.GENERIC_RESPONSE:
                self.ERROR = self.GENERIC_RESPONSE[err_code]
            else:
                self.ERROR = f"Unknown response code: {hex(err_code)}"
            return None

    def getseq(self):
        """
        Alterna la secuencia entre 0x80 y 0x00.
        El slave usa esto para detectar retransmisiones.
        """
        if (self.__sequence == '0x80'):
            self.__sequence = '0x00'
        else:
            self.__sequence = '0x80'

        returnseq = hex(self.__eSSPId | int(self.__sequence, 16))
        return returnseq

    def sync(self):
        """Resetea la secuencia a 0x00."""
        self.__sequence = '0x00'
        result = self.send(self.__Sync)
        if self.SEND_STATUS:
            return 'OK'

    def get_serial_number(self):
        data = self.send(self.__Get_Serial_Number)
        if self.SEND_STATUS and data:
            serial = 0
            # Según ITL, el serial viene en 4 bytes (o 8 bytes) big-endian.
            for i in range(len(data)):
                serial += ord(data[i]) << (8 * (7 - i))
            self.SERIAL_NUMBER = serial
            return serial

    def get_firmware_version(self):
        data = self.send(self.__Get_Firmware_Version)
        if self.SEND_STATUS and data:
            return ''.join(list(map(lambda x: x.decode('ascii'), data)))

    def get_dataset_version(self):
        data = self.send(self.__Get_Dataset_Version)
        if self.SEND_STATUS and data:
            return ''.join(list(map(lambda x: x.decode('ascii'), data)))

    def enable(self):
        """Saca de modo disable."""
        data = self.send(self.__Enable)
        if self.SEND_STATUS:
            return 'OK'

    def disable(self):
        """Pone el dispositivo en modo disable."""
        data = self.send(self.__Disable)
        if self.SEND_STATUS:
            return 'OK'

    def setup_request(self):
        """Obtiene la información principal del billetero (firmware, canales, etc.)."""
        result = self.send(self.__Setup_Request)
        if not self.SEND_STATUS or not result:
            return None
        
        # Byte 0: unit type
        unittype = int(result[0].hex(), 16)

        # Bytes 1..4: firmware
        fwversion = ''
        for i in range(1, 5):
            fwversion += result[i].decode('ascii', errors='ignore')

        # Bytes 5..7: país
        country = ''
        for i in range(5, 8):
            country += result[i].decode('ascii', errors='ignore')

        # Bytes 8..10: value multiplier (3 bytes)
        valuemulti = 0
        for i in range(8, 11):
            valuemulti <<= 8
            valuemulti += int(result[i].hex(), 16)

        # Byte 11: número de canales
        channels = int(result[11].hex(), 16)

        # Bytes 12..(12+channels-1): valores por canal (1 byte cada uno)
        values = []
        for i in range(channels):
            values.append(int(result[12 + i].hex(), 16))

        # Bytes (12+channels)..(12+2*channels-1): seguridad de cada canal
        security = []
        for i in range(channels):
            security.append(int(result[12 + channels + i].hex(), 16))

        # Bytes (12+2*channels)..(12+2*channels+2): real value multiplier (3 bytes)
        real_multiplier = 0
        idx_real_mult = 12 + 2 * channels
        for i in range(idx_real_mult, idx_real_mult + 3):
            real_multiplier <<= 8
            real_multiplier += int(result[i].hex(), 16)

        # Byte (15+2*channels): versión de protocolo
        protocol = int(result[15 + 2 * channels].hex(), 16)

        unit_data = {
            'Unit type': unittype,
            'Firmware version': fwversion,
            'Country code': country,
            'Value Multiplier': valuemulti,
            'Number of channels': channels,
            'Channel Values': values,
            'Channel Security': security,
            'Real value Multiplier': real_multiplier,
            'Protocol version': protocol
        }

        # Si el protocolo >= 6, hay datos extra (expanded channel data)
        if protocol >= 6:
            # Bytes extra: channels*3 para country code expandido
            start_idx = 16 + 2 * channels
            end_idx = start_idx + channels * 3
            Expanded_channel_country_code = ''

            for i in range(start_idx, end_idx):
                Expanded_channel_country_code += result[i].decode('ascii', errors='ignore')

            # Luego channels*4 para el valor expandido de cada canal
            Expanded_channel_value_raw = []
            start_val = end_idx
            end_val = start_val + channels * 4

            for i in range(start_val, end_val):
                Expanded_channel_value_raw.append(result[i])

            Expanded_channel_value = []
            a = 0
            b = 4

            # FIX: se reemplaza range(8) por range(channels)
            for i in range(channels):
                chunk = Expanded_channel_value_raw[a:b]
                # Se invierte cada grupo de 4 bytes
                chunk_reversed = list(reversed(chunk))
                # Los concatenamos en un buffer y convertimos a int
                res = b''.join(chunk_reversed)
                valor = int(res.hex(), 16)
                Expanded_channel_value.append(valor)
                a = b
                b += 4

            unit_data['Expanded channel country code'] = Expanded_channel_country_code
            unit_data['Expanded_channel_value'] = Expanded_channel_value
            # Guardamos un dict {canal: valor_expandido}
            self.CHANNEL_VALUE = dict(zip(range(1, channels + 1), Expanded_channel_value))

        return unit_data

    def display_on(self):
        """Enciende luz bezel."""
        result = self.send(self.__Display_On)
        if self.SEND_STATUS:
            return 'OK'

    def unit_data(self):
        """Comando Unit_Data (similar a setup_request, pero menos completo)."""
        result = self.send(self.__Unit_Data)
        if not self.SEND_STATUS or not result:
            return None
        unittype = int(result[0].hex(), 16)
        fwversion = ''
        for i in range(1, 5):
            fwversion += result[i].decode('ascii', errors='ignore')
        country = ''
        for i in range(5, 8):
            country += result[i].decode('ascii', errors='ignore')
        valuemulti = 0
        for i in range(8, 11):
            valuemulti <<= 8
            valuemulti += int(result[i].hex(), 16)
        protocol = int(result[11].hex(), 16)
        return [unittype, fwversion, country, valuemulti, protocol]

    def display_off(self):
        """Apaga luz bezel."""
        result = self.send(self.__Display_Off)
        if self.SEND_STATUS:
            return 'OK'

    def enable_higher_protocol(self):
        """
        A veces necesario para protocolos >=3, 
        pero dependerá de la implementación en firmware.
        """
        result = self.send(self.__High_Protocol)
        if self.SEND_STATUS:
            return 'OK'

    def host_protocol_version(self, protocol):
        result = self.send(['0x02', self.__Host_Protocol_Version, hex(protocol)])
        if self.SEND_STATUS:
            return 'OK'

    def poll(self):
        """Lee eventos del dispositivo."""
        event_table = {
            0xF1: 'Slave Reset',
            0xEF: 'Read',
            0xEE: 'Note Credit',
            0xED: 'Rejecting',
            0xEC: 'Rejected',
            0xCC: 'Stacking',
            0xEB: 'Stacked',
            0xE9: 'Unsafe Jam',
            0xE8: 'Disabled',
            0xE6: 'Fraud Attempt',
            0xE7: 'Stacker Full',
            0xE2: 'Note Cleared Into Cashbox',
            0xB5: 'Channel Disable'
        }
        result = self.send(self.__Poll)
        if not self.SEND_STATUS or not result:
            return None

        forreturn = []
        for i in result:
            code_hex = int(i.hex(), 16)
            if code_hex in event_table:
                forreturn.append(event_table[code_hex])
            else:
                # Si se maneja como "canal devuelto":
                if self.CHANNEL_VALUE and code_hex in self.CHANNEL_VALUE:
                    forreturn.append(self.CHANNEL_VALUE[code_hex])
                else:
                    # Devuelve el byte en crudo
                    forreturn.append(code_hex)

        return forreturn

    def set_inhibits(self, command):
        result = self.send([self.__Set_Inhibits] + command)
        if self.SEND_STATUS:
            return 'OK'

    def inhibit_channel(self, channel1=1, channel2=1, channel3=1, channel4=1,
                        channel5=1, channel6=1, channel7=1, channel8=1):
        """
        Ejemplo de bits de inhibición.
        channelX = 1 => habilitado, 0 => inhibido.
        """
        # {1: 10, 2: 50, 3: 100, 4: 200, 5: 500, 6: 1000, 7: 2000, 8: 5000}
        bits = '0b{}{}{}{}{}{}{}{}'.format(channel8, channel7, channel6, channel5,
                                          channel4, channel3, channel2, channel1)
        byte_val = hex(int(bits, 2))  # convierte bits en valor hex
        result = self.send([self.__Set_Inhibits, '0x02', byte_val])
        if self.SEND_STATUS:
            return 'OK'

    def __del__(self):
        try:
            if self.ser is not None:
                self.ser.close()
        except AttributeError:
            pass
