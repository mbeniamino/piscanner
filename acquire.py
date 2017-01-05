import picamera
import io
import sys
import time

offset = 6404096
n_pix = 5
if len(sys.argv) > 1:
        n_pix = int(sys.argv[1])

stream = io.BytesIO()
with picamera.PiCamera() as camera:
        time.sleep(2)
        for i in range(n_pix):
                camera.capture(stream, format='jpeg', bayer=True)
                data = stream.getvalue()[-offset:]
                assert data[:4] == 'BRCM'
                data = data[32768:]
                sys.stdout.write(data)
