# esp-mqtt example:
## Only tls connection allowed

### Installation

1. Add esp-mqtt component by [instruction](https://github.com/256dpi/esp-mqtt).
2. Copy this folder to directory where esp-idf is located.
3. Setup your wifi `ssid` and `pass` in ```main.c```.

### Running

1. In the root directory of this example run `make menuconfig` and setup your `Serial flasher config` and save config.
2. Run `make flash monitor`.