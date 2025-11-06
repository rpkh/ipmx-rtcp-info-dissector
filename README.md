# ipmx-rtcp-info-dissector
Lua Wireshark post-dissector for extracting IPMX info blocks from RTCP sender reports.

## Supported Media Info Block types
| Media Info Block type |  Specification |  Description |
| :-------------------: | :------------- | :----------- |
|  0x1                  | TR-10-2        | Uncompressed Active Video |
|  0x2                  | TR-10-3        | PCM Digital Audio |
|  0x3                  | TR-10-11       | Constant Bit-Rate Compressed Video |
|  0x4                  | TR-10-12       | AES3 Transparent Transport |
|  0x5                  | TR-10-7        | (VBR) Compressed Video |

## How to install
1. Open Wireshark.
2. Go to **Help** &rarr; **About Wireshark**.
3. Select the **Folders** tab.
4. Double-click the location for the **Personal Lua Plugins** to open the folder.
5. Copy the **ipmx_rtcp_info.lua** file into this folder.
6. Restart Wireshark or go to **Analyze** &rarr; **Reload Lua Plugins**.

## Wireshark coloring rules
Wireshark provides the ability to visually highlight packets based on their properties, making it easier to spot errors or identify specific packet types.  
To highlight IPMX specific errors in Wireshark, follow these steps to create a custom coloring rule.
1. Open Wireshark
2. Go to **View** &rarr; **Coloring Rules**.
3. Click **New** to add a rule.
4. Set the **Name** for the rule (e.g. `IPMX errors`)
5. Set the **Display Filter** &rarr; `ipmx_rtcp_info.block_length.error`
6. Set the **foreground** and **background** (new rule needs to be selected)

## Known issues
- In **Wireshark version 4.2.x and earlier versions**, the built-in RTCP dissector falsely reports RTCP packets containing IPMX info blocks as malformed.  
When RTCP profile specific extension support was added in the dissector, it was made specifically to support the definition used in [MS-RTP](https://learn.microsoft.com/en-us/openspecs/office_protocols/ms-rtp/26056cc7-e6a4-4699-b2a1-67f59d89631a).  
For more info see [Wireshark issue](https://gitlab.com/wireshark/wireshark/-/issues/19393).  
The issue has been fixed starting with **Wireshark version 4.4.0**.

## Release History
### v1.2.0
- Added support for media info block for (VBR) compressed video.
- Added length checks with error handling.
- Added support for multiple embedded media info blocks.
- Cleanup and minor improvements.
### v1.1.0
- Made the post-dissector compatible with both the old version (4.2.x and earlier) and newer version (v4.4.x and newer) of wireshark.
### v1.0.0
- Initial release
