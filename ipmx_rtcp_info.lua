-------------------------------------------------------------------------------
-- Lua Wireshark post-dissector for extracting IPMX info blocks from RTCP sender reports
-- Copyright (C) 2023  Raymond Hermans (raymond.hermans@gmail.com)
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-------------------------------------------------------------------------------
local plugin_info = {
  version = "1.0.0",
  author = "Raymond Hermans",
  description = "Post-dissector for extracting IPMX info blocks from RTCP sender reports",
  repository = "https://github.com/rpkh/ipmx-rtcp-info-dissector",
}
set_plugin_info(plugin_info)

-------------------------------------------------------------------------------
-- RTCP SR fields interpreted for IPMX
local ipmx_rtcp_sr_ptp_time_msw = ProtoField.uint32("ipmx_rtcp_info.ptp_time_msw", "PTP time MSW", base.DEC_HEX)
local ipmx_rtcp_sr_ptp_time_lsw = ProtoField.uint32("ipmx_rtcp_info.ptp_time_lsw", "PTP time LSW", base.DEC_HEX)
local ipmx_rtcp_sr_ptp_time = ProtoField.absolute_time("ipmx_rtcp_info.ptp_time", "PTP time", base.UTC)
local ipmx_rtcp_sr_rtp_timestamp = ProtoField.uint32("ipmx_rtcp_info.rtp_timestamp", "RTP timestamp", base.DEC_HEX)

-------------------------------------------------------------------------------
-- IPMX tag
local ipmx_profile_extension = 0x5831

-------------------------------------------------------------------------------
-- IPMX Info Block
local ipmx_info_block_version = ProtoField.uint8("ipmx_rtcp_info.version", "version", base.DEC)
local ipmx_info_ts_refclk = ProtoField.string("ipmx_rtcp_info.ts_refclk", "ts_refclk", base.ASCII)
local ipmx_info_mediaclk = ProtoField.string("ipmx_rtcp_info.mediaclk", "mediaclk", base.ASCII)

-------------------------------------------------------------------------------
-- IPMX Media Info Common

-- IPMX Media Info Block types
local media_type_tbl = {
  [1] = "Uncompressed Active Video",
  [2] = "PCM Digital Audio",
  [3] = "Constant Bit-rate Compressed Video",
  [4] = "AES3 Transparent Transport",
}

local media_info_type = ProtoField.uint16("ipmx_rtcp_info.media_info_type", "media info type", base.DEC, media_type_tbl)
local media_info_length = ProtoField.uint16("ipmx_rtcp_info.media_info_length", "media info length", base.DEC)

-------------------------------------------------------------------------------
-- IPMX Media Info: Uncompressed Active Video
local video_info_sampling = ProtoField.string("ipmx_rtcp_info.video_info.sampling", "sampling", base.ASCII)
local video_info_float = ProtoField.bool("ipmx_rtcp_info.video_info.float", "float", 8, {"Yes","No"}, 0x80)
local video_info_depth = ProtoField.uint8("ipmx_rtcp_info.video_info.depth", "depth", base.DEC, nil, 0x7F)
local video_info_packing_mode = ProtoField.bool("ipmx_rtcp_info.video_info.packing_mode", "packing mode", 8, {"GPM", "BPM"}, 0x80)
local video_info_interlace = ProtoField.bool("ipmx_rtcp_info.video_info.interlace", "interlace", 8, {"Interlaced/PsF", "Progressive"}, 0x40)
local video_info_segmented = ProtoField.bool("ipmx_rtcp_info.video_info.segmented", "segmented", 8, {"Segmented", "No"}, 0x20)
local video_info_parw = ProtoField.uint8("ipmx_rtcp_info.video_info.parw", "PARw", base.DEC)
local video_info_parh = ProtoField.uint8("ipmx_rtcp_info.video_info.parh", "PARh", base.DEC)
local video_info_range = ProtoField.string("ipmx_rtcp_info.video_info.range", "range", base.ASCII)
local video_info_colorimetry = ProtoField.string("ipmx_rtcp_info.video_info.colorimetry", "colorimetry", base.ASCII)
local video_info_tcs = ProtoField.string("ipmx_rtcp_info.video_info.tcs", "TCS", base.ASCII)
local video_info_width = ProtoField.uint16("ipmx_rtcp_info.video_info.width", "width", base.DEC)
local video_info_height = ProtoField.uint16("ipmx_rtcp_info.video_info.height", "height", base.DEC)
local video_info_rate_num = ProtoField.uint24("ipmx_rtcp_info.video_info.rate_num", "rate numerator", base.DEC, nil, 0xFFFFFC)
local video_info_rate_denom = ProtoField.uint16("ipmx_rtcp_info.video_info.rate_denom", "rate denominator", base.DEC, nil, 0x3FF)
local video_info_meas_pix_clk = ProtoField.uint64("ipmx_rtcp_info.video_info.meas_pix_clk", "measured pixel clock", base.DEC)
local video_info_htotal = ProtoField.uint16("ipmx_rtcp_info.video_info.htotal", "htotal", base.DEC)
local video_info_vtotal = ProtoField.uint16("ipmx_rtcp_info.video_info.vtotal", "vtotal", base.DEC)

-------------------------------------------------------------------------------
-- IPMX Media Info: PCM Digital Audio
local audio_info_samp_rate = ProtoField.uint32("ipmx_rtcp_info.audio_info.samp_rate", "sampling rate", base.DEC)
local audio_info_samp_size = ProtoField.uint8("ipmx_rtcp_info.audio_info.samp_size", "sample size", base.DEC)
local audio_info_chan_count = ProtoField.uint8("ipmx_rtcp_info.audio_info.chan_count", "channel count", base.DEC)
local audio_info_packet_time = ProtoField.uint16("ipmx_rtcp_info.audio_info.packet_time", "packet time", base.DEC)
local audio_info_meas_samp_rate = ProtoField.uint32("ipmx_rtcp_info.audio_info.meas_samp_rate", "measured sample rate", base.DEC)
local audio_info_chan_order_len = ProtoField.uint32("ipmx_rtcp_info.audio_info.chan_order_len", "channel-order length", base.DEC)
local audio_info_chan_order = ProtoField.string("ipmx_rtcp_info.audio_info.chan_order", "channel-order", base.ASCII)

-------------------------------------------------------------------------------
-- RTCP Fields that are used as helpers for IPMX Info extraction
local rtcp_sr_timestamp_ntp_msw = Field.new("rtcp.timestamp.ntp.msw")
local rtcp_sr_timestamp_ntp_lsw = Field.new("rtcp.timestamp.ntp.lsw")
local rtcp_sr_timestamp_rtp = Field.new("rtcp.timestamp.rtp")

local rtcp_profile_extension = Field.new("rtcp.profile-specific-extension")
local rtcp_profile_extension_type = Field.new("rtcp.profile-specific-extension.type")
local rtcp_profile_extension_length = Field.new("rtcp.profile-specific-extension.length")

-------------------------------------------------------------------------------
-- Wireshark specifics for registering the dissector
ipmx_info = Proto("ipmx_rtcp_info", "IPMX RTCP INFO")

ipmx_info.fields = {
  -- RTCP Sender Report fields
  ipmx_rtcp_sr_ptp_time_msw,
  ipmx_rtcp_sr_ptp_time_lsw,
  ipmx_rtcp_sr_ptp_time,
  ipmx_rtcp_sr_rtp_timestamp,
  -- IPMX Info Block
  ipmx_info_block_version,
  ipmx_info_ts_refclk,
  ipmx_info_mediaclk,
  -- IPMX Media Info Common
  media_info_type,
  media_info_length,
  -- IPMX Media Info: Uncompressed Active Video
  video_info_sampling,
  video_info_float,
  video_info_depth,
  video_info_packing_mode,
  video_info_interlace,
  video_info_segmented,
  video_info_parw,
  video_info_parh,
  video_info_range,
  video_info_colorimetry,
  video_info_tcs,
  video_info_width,
  video_info_height,
  video_info_rate_num,
  video_info_rate_denom,
  video_info_meas_pix_clk,
  video_info_htotal,
  video_info_vtotal,
  -- IPMX Media Info: PCM Digital Audio
  audio_info_samp_rate,
  audio_info_samp_size,
  audio_info_chan_count,
  audio_info_packet_time,
  audio_info_meas_samp_rate,
  audio_info_chan_order_len,
  audio_info_chan_order,
}

register_postdissector(ipmx_info)

-------------------------------------------------------------------------------
-- Function for parsing and displaying the Uncompressed Active Video Info Block
function video_info_parse(buffer, offset, tree, block_len)
  video_tree = tree:add(ipmx_info, buffer(offset,(block_len*4)), "Data: Uncompressed Active Video")
  video_tree:add(video_info_sampling, buffer(offset,16))
  offset = offset + 16
  video_tree:add(video_info_float, buffer(offset,1))
  video_tree:add(video_info_depth, buffer(offset,1))
  offset = offset + 1
  video_tree:add(video_info_packing_mode, buffer(offset,1))
  video_tree:add(video_info_interlace, buffer(offset,1))
  video_tree:add(video_info_segmented, buffer(offset,1))
  offset = offset + 1
  video_tree:add(video_info_parw, buffer(offset,1))
  offset = offset + 1
  video_tree:add(video_info_parh, buffer(offset,1))
  offset = offset + 1
  video_tree:add(video_info_range, buffer(offset,12))
  offset = offset + 12
  video_tree:add(video_info_colorimetry, buffer(offset,20))
  offset = offset + 20
  video_tree:add(video_info_tcs, buffer(offset,16))
  offset = offset + 16
  video_tree:add(video_info_width, buffer(offset,2))
  offset = offset + 2
  video_tree:add(video_info_height, buffer(offset,2))
  offset = offset + 2
  video_tree:add(video_info_rate_num, buffer(offset,3))
  offset = offset + 2
  video_tree:add(video_info_rate_denom, buffer(offset,2))
  offset = offset + 2
  video_tree:add(video_info_meas_pix_clk, buffer(offset,8))
  offset = offset + 8
  video_tree:add(video_info_htotal, buffer(offset,2))
  offset = offset + 2
  video_tree:add(video_info_vtotal, buffer(offset,2))
  offset = offset + 2
end

-- Function for parsing and displaying the PCM Digital Audio Info Block
function audio_info_parse(buffer, offset, tree, block_len)
  audio_tree = tree:add(ipmx_info, buffer(offset,(block_len*4)), "Data: PCM Digital Audio")
  audio_tree:add(audio_info_samp_rate, buffer(offset,4))
  offset = offset + 4
  audio_tree:add(audio_info_samp_size, buffer(offset,1))
  offset = offset + 1
  audio_tree:add(audio_info_chan_count, buffer(offset,1))
  offset = offset + 1
  audio_tree:add(audio_info_packet_time, buffer(offset,2))
  offset = offset + 2
  audio_tree:add(audio_info_meas_samp_rate, buffer(offset,4))
  offset = offset + 4
  audio_tree:add(audio_info_chan_order_len, buffer(offset,4))
  ch_order_len = buffer:range(offset,4):uint()
  offset = offset + 4
  if ch_order_len == 0 then return end
  audio_tree:add(audio_info_chan_order, buffer(offset,(ch_order_len*4)))
end

-- Media Info parse function table.
-- Index should match IPMX Media Info Block types (media_type_tbl)
local media_info_parse_tbl =
{
  [1] = video_info_parse,
  [2] = audio_info_parse,
  [3] = video_info_parse,
  [4] = audio_info_parse,
}

-------------------------------------------------------------------------------
-- Main entry point
function ipmx_info.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  -- Check if an RTCP profile extension has been detected
  ext_type = rtcp_profile_extension_type()
  if not ext_type then return end

  -- Check if it has the IPMX tag
  if ext_type.value ~= ipmx_profile_extension then return end

  -- Easy way to extract the starting offset of the IPMX info block
  profile_extension = rtcp_profile_extension()
  Offset = profile_extension.offset
  -- Easy way to extract the IPMX info block length
  ext_len = rtcp_profile_extension_length()

  -- Create root tree
  ipmx_rtcp_tree = tree:add(ipmx_info, "IPMX RTCP Sender Report")
  -- Extract RTCP sender report NTP field and add to tree
  rtcp_sr_ptp_time = rtcp_sr_timestamp_ntp_msw()
  ipmx_rtcp_tree:add(ipmx_rtcp_sr_ptp_time_msw, buffer(rtcp_sr_ptp_time.offset,4))
  ipmx_rtcp_tree:add(ipmx_rtcp_sr_ptp_time_lsw, buffer(rtcp_sr_ptp_time.offset+4,4))
  ipmx_rtcp_tree:add(ipmx_rtcp_sr_ptp_time, buffer(rtcp_sr_ptp_time.offset,8)):set_generated()
  ipmx_rtcp_tree:add(ipmx_rtcp_sr_rtp_timestamp, buffer(rtcp_sr_ptp_time.offset+8,4))

  -- Create IPMX info block tree and add to root
  ipmx_info_tree = ipmx_rtcp_tree:add(ipmx_info, buffer(Offset,(ext_len.value)*4), "IPMX Info Block")
  ipmx_info_tree:add(ipmx_info_block_version, buffer(Offset,1))
  Offset = Offset + 4
  ipmx_info_tree:add(ipmx_info_ts_refclk, buffer(Offset,64))
  Offset = Offset + 64
  ipmx_info_tree:add(ipmx_info_mediaclk, buffer(Offset,12))
  Offset = Offset + 12

  -- Check if a media info block is expected
  if ext_len.value <= 20 then return end

  -- Extract media info block and add to IPMX info block tree
  media_block_type = buffer:range(Offset,2):uint()
  media_block_len = buffer:range(Offset+2,2):uint()
  media_block_tree = ipmx_info_tree:add(ipmx_info, buffer(Offset,(media_block_len+1)*4), "Media Info Block")
  media_block_tree:add(media_info_type, buffer(Offset,2))
  Offset = Offset + 2
  media_block_tree:add(media_info_length, buffer(Offset,2))
  Offset = Offset + 2

  -- Use the media info block type for selecting the parse function
  parse_func = media_info_parse_tbl[media_block_type]
  if parse_func then
    parse_func(buffer, Offset, media_block_tree, media_block_len)
  else
    print("Unsupported media type")
  end

end
