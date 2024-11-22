# python-can-zlg
用于周立工CAN设备对python-can的支持，支持接收合并设备，已测速USBCANDF-200U
1. 修改python-can路径下的can/interfaces/__init__.py文件, 在BACKENDS字典中添加一行:

   ```
   "zlg": ("can.interfaces.zlg", "ZlgUsbCanBus"),
   ```

2. 将zlg文件夹拷贝到can/interfaces/文件夹下