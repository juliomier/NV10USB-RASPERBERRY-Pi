from nv10usb import NV10USB
import time

n = NV10USB(serialport='/dev/ttyACM0')
if not n.INIT_ERROR:
    print('Sincronizando... ', n.sync())
    print('Estableciendo versión 7 del protocolo... ', n.host_protocol_version(7))
    print('Obteniendo datos del validador de billetes... ', n.setup_request())
    print('Número de serie... ', n.get_serial_number())
    print('Encuestando... ', n.poll())
    print('Permitiendo recepción de todos los valores... ', n.inhibit_channel())
    print('Habilitando... ', n.enable())
    print(n.display_on())

    while True:
        try:
            poll = n.poll()
            if len(poll) > 0:
                print(poll)
            time.sleep(0.5)
        except KeyboardInterrupt:
            print(n.display_off())
            print('Deshabilitando... ', n.disable())
else:
    print('Error ', n.ERROR)
