# ipmx-rtcp-info-dissector
Lua Wireshark post-dissector for extracting IPMX info blocks from RTCP sender reports.

## How to install
1. Open Wireshark.
2. Go to **Help** &rarr; **About Wireshark**.
3. Select the **Folders** tab.
4. Double-click the location for the **Personal Lua Plugins** to open the folder.
5. Copy the **ipmx_rtcp_info.lua** file into this folder.
6. Restart Wireshark or go to **Analyze** &rarr; **Reload Lua Plugins**.

## Known issues
- Wireshark's built-in RTCP dissector falsely reports RTCP packets containing IPMX info blocks as malformed.  
When RTCP profile specific extension support was added in the dissector, it was made specifically to support the definition used in [MS-RTP](https://learn.microsoft.com/en-us/openspecs/office_protocols/ms-rtp/26056cc7-e6a4-4699-b2a1-67f59d89631a)

