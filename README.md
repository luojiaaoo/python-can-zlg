# python-can-zlg
用于周立工CAN设备对python-can的支持，支持接收合并设备，已测速USBCANDF-200U
1. 修改python-can路径下的can/interfaces/__init__.py文件, 在BACKENDS字典中添加一行:

   ```
   "zlg": ("can.interfaces.zlg", "ZlgUsbCanBus"),
   ```

2. 将zlg文件夹拷贝到can/interfaces/文件夹下

## example

```python
import can
can_filters = [dict(is_extended=1, filter_start=UDS_PhysicalRequestID, filter_end=UDS_PhysicalRequestID),]
bus = can.interface.Bus(bustype='zlg', channel=0, dev_type=39, fd=True,bitrate=500000,data_bitrate=2000000, receive_own_messages=True, can_filters=can_filters)
msg = can.Message(arbitration_id=0x111,data=[0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],is_extended_id=False, )
bus.send(msg)
while (rec:=bus.recv(timeout=0.1)):
    print(rec)
bus.shutdown()
```
