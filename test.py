import sys
import time

#agregar tu ruta
sys.path.append('')

from nv10usb import NV10USB

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

    try:
        while True:
            try:
                poll_data = n.poll()
                if poll_data:  # Verifica que poll_data no sea None ni vacío
                    print(poll_data)
                time.sleep(0.5)
            except Exception as e:
                print(f"Error durante la lectura del billetero: {e}")
                time.sleep(1)  # Espera un poco antes de volver a intentar
    except KeyboardInterrupt:
        print(n.display_off())
        print('Deshabilitando... ', n.disable())
        print("Saliendo del programa.")
else:
    print('Error: ', n.ERROR)
