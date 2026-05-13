import asyncio
import json
import re
import sys
from typing import AsyncGenerator

from bleak import BleakScanner, AdvertisementDataCallback, BLEDevice, AdvertisementData

from dataclasses import dataclass, asdict
from typing import Optional, Union

INVALID_U16 = 0xFFFF
INVALID_U8 = 0xFF
INVALID_I16 = 0x8000

def _u16(b, i):
    return (b[i] << 8) | b[i+1]

def _i16(b, i):
    val = _u16(b, i)
    return val - 0x10000 if val & 0x8000 else val

def _u8(b, i):
    return b[i]

@dataclass
class AccelerationData:
    x_mg: Optional[int]
    y_mg: Optional[int]
    z_mg: Optional[int]

    def as_dict(self):
        return asdict(self)


@dataclass
class RuuviTagData:
    data_format: int
    temperature_c: Optional[float]
    humidity_rh: Optional[float]
    pressure_pa: Optional[int]

    acceleration: AccelerationData

    battery_v: Optional[float]
    tx_power_dbm: Optional[int]

    movement_counter: Optional[int]
    measurement_sequence: Optional[int]

    mac: Optional[str]

    def as_dict(self):
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent)

# https://github.com/ruuvi/ruuvi-sensor-protocols/blob/master/dataformat_05.md
def decode_rawv2(data: Union[bytes, str]) -> RuuviTagData:
    """
    Decode RuuviTag RAWv2 (Format 5) payload.
    """

    if isinstance(data, str):
        data = bytes.fromhex(
            data.replace("0x", "").replace(" ", "")
        )

    if len(data) < 24:
        raise ValueError("Invalid payload length")

    fmt = data[0]

    if fmt != 5:
        raise ValueError(f"Unsupported format: {fmt}")

    # Temperature
    t_raw = _i16(data, 1)
    temperature = None if t_raw == INVALID_I16 else t_raw * 0.005

    # Humidity
    h_raw = _u16(data, 3)
    humidity = None if h_raw == INVALID_U16 else h_raw * 0.0025

    # Pressure
    p_raw = _u16(data, 5)
    pressure = None if p_raw == INVALID_U16 else (p_raw + 50000)

    # Acceleration
    ax_raw = _i16(data, 7)
    ay_raw = _i16(data, 9)
    az_raw = _i16(data, 11)

    acceleration = AccelerationData(
        x_mg=None if ax_raw == INVALID_I16 else ax_raw,
        y_mg=None if ay_raw == INVALID_I16 else ay_raw,
        z_mg=None if az_raw == INVALID_I16 else az_raw,
    )

    # Power info
    power = _u16(data, 13)

    batt_raw = (power >> 5) & 0x7FF
    tx_raw = power & 0x1F

    battery_v = (
        None
        if batt_raw == 0x7FF
        else (1600 + batt_raw) / 1000.0
    )

    tx_power = (
        None
        if tx_raw == 0x1F
        else -40 + (tx_raw * 2)
    )

    # Movement counter
    movement = _u8(data, 15)
    movement = None if movement == INVALID_U8 else movement

    # Measurement sequence
    seq = _u16(data, 16)
    seq = None if seq == INVALID_U16 else seq

    # MAC address
    mac_raw = data[18:24]

    mac = (
        None
        if mac_raw == b"\xff\xff\xff\xff\xff\xff"
        else ":".join(f"{b:02X}" for b in mac_raw)
    )

    return RuuviTagData(
        data_format=fmt,
        temperature_c=temperature,
        humidity_rh=humidity,
        pressure_pa=pressure,
        acceleration=acceleration,
        battery_v=battery_v,
        tx_power_dbm=tx_power,
        movement_counter=movement,
        measurement_sequence=seq,
        mac=mac,
    )

def _get_scanner(detection_callback: AdvertisementDataCallback, bt_device: str = ""):
    # NOTE: On Linux - bleak.exc.BleakError: passive scanning mode requires bluez or_patterns
    # NOTE: On macOS - bleak.exc.BleakError: macOS does not support passive scanning
    scanning_mode = "passive" if sys.platform.startswith("win") else "active"

    if bt_device:
        return BleakScanner(
            detection_callback=detection_callback,
            scanning_mode=scanning_mode,  # type: ignore[arg-type]
            bluez={"adapter": bt_device}
        )

    return BleakScanner(detection_callback=detection_callback, scanning_mode=scanning_mode)  # type: ignore[arg-type]

# Looks for known mac addresses, prints and returns all detected
# Ununsed. keeping it for now
async def find_kwon_mac_devices(addresses: [str] = None):
    if addresses is None:
        addresses = []
    addresses_found = []
    devices = await BleakScanner.discover()
    for d in devices:
        print(f"found {d.name}({d.address})")
        if d.address in addresses:
            addresses_found.append(d.address)
    return addresses_found


MAC_REGEX = "[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"


ruuvitags_queue = asyncio.Queue[RuuviTagData]()


async def get_ruuvitags_data(blacklist: list[str] | None = None, bt_device: str = "") -> AsyncGenerator[RuuviTagData]:
    async def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
        mac: str = device.address if re.match(MAC_REGEX, device.address.lower()) else ""
        if blacklist and mac in blacklist:
            print("MAC blacklised: %s", mac)
            return

        # TODO: Do all RuuviTags have data in 1177?
        if 1177 not in advertisement_data.manufacturer_data:
            return

        try:
            await ruuvitags_queue.put(decode_rawv2(advertisement_data.manufacturer_data[1177]))
        except Exception as e:
            print("could not add to queue", e)

    scanner = _get_scanner(detection_callback, bt_device)
    await scanner.start()

    try:
        while True:
            next_item: RuuviTagData = await ruuvitags_queue.get()
            yield next_item
    except KeyboardInterrupt:
        pass
    except GeneratorExit:
        pass
    except Exception as ex:
        print("Exception during async_generation", ex)

    await scanner.stop()


if __name__ == "__main__":
    # example usage
    async def iter_data():
        async for item in get_ruuvitags_data():
            print(item.to_json(4))

    asyncio.run(iter_data())