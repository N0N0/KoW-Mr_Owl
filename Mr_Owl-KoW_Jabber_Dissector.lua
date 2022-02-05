-- Mr. Owl - Kiss of War: Jabber Dissector -  Version 0.97 (2021-04-04, compatible with Game Version 1.39.0)
--
-- This Wireshark dissector will extract information like Player Name + ID from Tap4Fun's "Kiss of War" request data.
--
-- Usage:
-- 	o On Windows this file has to be stored under %APPDATA%/Wireshark/Plugins
--  o The dissector is active for every running analysis
--  o To make it easier to follow the analizes you may use this filter to log KoW Chat Data only:
--    (tcp contains "original_from" || tcp contains "type='chat'")
--	  or tcp.port == 30052 || (tcp contains "original_from" || tcp contains "type='chat'")
--	oo to read all data processed by this dissector filter by protocol: kow
--	o This dissector provides the following custom columns:
--      kow.message_length
--      kow.message_data
--		kow.chat_content
--		kow.chat_guild_rank
--      kow.chat_player_name
--      kow.chat_player_id
--      ... for a complete list, have a look at the lua-table named proto_fields
--
--
-- Known limitations:
--  o Private Chat does not contain PlayerName, ID is the only info available from it
--  o Backlog is split over multiple packets therefore it happens that the player name and ID
--	  are transmitted in different packages - in this case one or both values may not be available.
--  o Unicode character in names are currently not supported
--
--
-- Legal stuff:
--  o This script is provided as is, the author is not to be accounted for any harms caused by using this script.
--  o This Script is done by observating the applications request response behavior only.
--    No disassembling or debugging of the compiled program code has been applied.
--  o This script itself is licensed under the GNU General Public License Version 3.0
--    https://www.gnu.org/licenses/gpl-3.0.en.html
--
--	Copyright (c) 2021 nono
--

-- constants - Configuration: change values if needed
CONST_BUFFER_LENGTH = 1356
CONST_BUFFER_START = 0
-- old KOW_JABBER_PORT = 5223
CONST_KOW_JABBER_PORT = 30052

-- declarations
kow_jabber_protocol = Proto("Kow",  "Kow Jabba Protocol")

-- declaration of protocol fields
local proto_fields = {
	message_length    = ProtoField.int32("kow.message_length",     "messageLength", base.DEC),
	message_data      = ProtoField.string("kow.message_data",      "messageData", base.UNICODE),

	chat_content      = ProtoField.string("kow.chat_content",      "content", base.ASCII),
	chat_alliance_tag = ProtoField.string("kow.chat_alliance_tag", "allianceTag", base.ASCII),
	chat_guild_rank   = ProtoField.string("kow.chat_guild_rank",   "guildRank", base.ASCII),
	chat_player_name  = ProtoField.string("kow.chat_player_name",  "playerName", base.ASCII),
	chat_player_id    = ProtoField.string("kow.chat_player_id",    "playerID", base.ASCII),
	chat_timestamp    = ProtoField.string("kow.chat_timestamp",    "timestamp", base.ASCII),
}

-- register fields to protocol
kow_jabber_protocol.fields = proto_fields


-- functions
function kow_jabber_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then
		return
	end
	
	pinfo.cols.protocol = kow_jabber_protocol.name
	
	local subtree = tree:add(kow_jabber_protocol, buffer(), "Kow Jabba Protocol Data")
	
	-- calls to get desired information
	local encodedStringData = buffer(CONST_BUFFER_START, CONST_BUFFER_LENGTH):string(base.ASCII)
	
	-- prepare data for and register protocol fields
	register_proto_fields(subtree, buffer, encodedStringData)
end


-- part of the dissector initialisation
-- all fields of KoW protocol are registered in here
function register_proto_fields(subtree, buffer, encodedStringData)

	local chatContent     = get_chat_fields(encodedStringData, {"content&#34;:&#34;", "content&quot;:&quot;"}, {"&#34;,&#34;", "&quot;,&quot;"})
	local chatAllianceTag = get_chat_fields(encodedStringData, {"m_abbr&#34;:&#34;", "m_abbr&&quot;:&quot;"}, {"&#34;,&#34;", "&quot;,&quot;"})
	local chatGuildRank   = get_chat_fields(encodedStringData, {"m_rank&#34;:", "&quot;m_rank&quot;:"}, {",&#34;", ",&quot;"})
	local chatTimestamp   = get_chat_fields(encodedStringData, {"timestamp&#34;:", "&quot;timestamp&quot;:"}, {",&#34;", ",&quot;"})
	local chatPlayerName  = get_chat_player_name(encodedStringData)
	local chatPlayerId    = get_chat_player_id(encodedStringData)
	
	-- add gathered info to custom fields
	subtree:add_le(proto_fields.message_length, buffer(CONST_BUFFER_START, CONST_BUFFER_LENGTH))
	subtree:add_le(proto_fields.message_data, buffer(CONST_BUFFER_START, CONST_BUFFER_LENGTH))
	subtree:add_le(proto_fields.chat_content, chatContent)
	
	subtree:add_le(proto_fields.chat_alliance_tag, chatAllianceTag)
	subtree:add_le(proto_fields.chat_guild_rank, chatGuildRank)
	subtree:add_le(proto_fields.chat_timestamp, chatTimestamp)
	
	subtree:add_le(proto_fields.chat_player_name, chatPlayerName)
	subtree:add_le(proto_fields.chat_player_id, chatPlayerId)
end


function get_chat_player_name(stringdata)
	local idxStart
	local idxEnd
	local locPlayerName
	
	-- find playername from groupchat (guild and zone)
	idxStart = string.find(stringdata, "type=\"groupchat\"")
	if(idxStart and 0 < idxStart) then -- idxStart is not nil and greater zero
		-- get username
		-- possible backlog snippet
		idxStart = string.find(stringdata, "sender_name")
		idxEnd = string.find(stringdata, "sender_vip_lv")
		if(idxStart and idxEnd) then
			locPlayerName = string.sub(stringdata, (idxStart + 22), (idxEnd-12))
		end
	end
	
	if(locPlayerName == nil or locPlayerName == '') then
		locPlayerName = "n./a."
	end
	
	return locPlayerName
end


-- returns player id from zone and private chat
function get_chat_player_id(stringdata)
	local addToIdxStart = 28
	
	-- zone chat
	local idxStart = string.find(stringdata, "original_from")
	if(not idxStart) then
	-- private chat
		idxStart = string.find(stringdata, "to='local")
		addToIdxStart = 17
	end
	
	local idxEnd = string.find(stringdata, "@chat.pf.tap4fun.com", idxStart)
	local locPlayerId = string.sub(stringdata, (idxStart+addToIdxStart), idxEnd-1)
	
	if(locPlayerId == nil or locPlayerId == '') then
		locPlayerId = "n./a."
	end
	
	return locPlayerId
end


-- returns data between given tag and delimiter.
--  convenience function to call #get_chat_fields(string, array<string>, array<string>)
function get_chat_field(stringdata, tag, delimiter)
	return get_chat_fields(stringdata, {tag}, {delimiter})
end

-- returns data between given tags and delimiter.
--   used for simple chat data fields
function get_chat_fields(stringdata, tags, delimiter)
	local arrayIndex = 1
	local localData = "n./a."

	local idxStart
	local addToIdxStart
	for i = arrayIndex, #tags do
		idxStart = string.find(stringdata, tags[i])
		if(idxStart) then
			addToIdxStart = string.len(tags[i])
			arrayIndex = i
			break
		end
	end

	if(not idxStart) then
		return localData
	end
	
	local idxEnd = string.find(stringdata, delimiter[arrayIndex], idxStart)
	if(idxEnd == nil or idxEnd <= 0) then
		-- 0 value occurs when T4F emojis are being used e.g.
		return localData
	end
	
	local localData = string.sub(stringdata, (idxStart+addToIdxStart), idxEnd-1)
	if(localData == nil or localData == '') then
		localData = "n./a."
	end
	
	return localData
end


-- register dissector to TCP Port 5223 (default for kiss of war)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(CONST_KOW_JABBER_PORT, kow_jabber_protocol)
