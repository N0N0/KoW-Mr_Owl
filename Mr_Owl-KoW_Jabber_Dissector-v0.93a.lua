-- Mr. Owl - Kiss of War: Jabber Dissector -  Version 0.92 (2020-08-18)
--
-- This Wireshark dissector will extract information like Player Name + ID from Tap4Fun's "Kiss of War" request data.
--
-- Usage:
-- 	o On Windows this file has to be stored under %APPDATA%/Wireshark/Plugins
--  o The dissector is active for every running analysis
--  o To make it easier to follow the analizes you may use this filter to log KoW Chat Data only:
--    (tcp contains "original_from" || tcp contains "type='chat'")
--	o This dissector provides the following custom columns:
--      kow.message_length
--      kow.message_data
--      kow.player_name
--      kow.player_id
--
--
-- Known limitations:
--  o Private Chat does not contain PlayerName, ID only available from that
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
--	Copyright (c) 2020 nono
--

-- constants - Configuration: change values if needed
CONST_BUFFER_LENGTH = 1334
CONST_BUFFER_START = 0
--CONST_KOW_JABBER_PORT = 5223
CONST_KOW_JABBER_PORT = 30052

-- declarations
kow_jabber_protocol = Proto("Kow",  "Kow Jabba Protocol")

message_length = ProtoField.int32("kow.message_length", "messageLength", base.DEC)
message_data = ProtoField.string("kow.message_data", "messageData", base.UNICODE)

player_name = ProtoField.string("kow.player_name", "playerName", base.ASCII)
player_id = ProtoField.string("kow.player_id", "playerID", base.ASCII)

kow_jabber_protocol.fields = { message_length, message_data, player_name, player_id}


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
	local playerName = get_player_name(encodedStringData)
	local playerId = get_player_id(encodedStringData)
	
	-- add gathered info to custom fields
	subtree:add_le(message_length, buffer(CONST_BUFFER_START, CONST_BUFFER_LENGTH))
	subtree:add_le(message_data, buffer(CONST_BUFFER_START, CONST_BUFFER_LENGTH))
	subtree:add_le(player_name, playerName)
	subtree:add_le(player_id, playerId)
end


function get_player_name(stringdata)
--	original regular expression = '^.*original_from=\'local(\\|[\\d\\w]*){3}\\|([\\d]*)@.*(sender_name&quot;:&quot;)(.*)(&quot;,&quot;sender_vip).*$';
	local idxStart
	local idxEnd
	local locPlayerName
	
	-- find playername from groupchat (guild and zone)
	idxStart = string.find(stringdata, "type='groupchat'")
	if(idxStart and 0 < idxStart) then -- idxStart is not nil and greater zero
		-- get username
		
--	commented out because of a slightly change in chat data format
--		
--		idxStart = string.find(stringdata, "muc.chat.pf.tap4fun.com")
--		idxEnd = string.find(stringdata, "' to='local")
--		if(idxStart and idxEnd) then
--			locPlayerName = string.sub(stringdata, (idxStart + 24), (idxEnd-1))
--		end
--		if(locPlayerName == '') then


			-- possible backlog snippet
			idxStart = string.find(stringdata, "sender_name")
			idxEnd = string.find(stringdata, "sender_vip_lv")
			if(idxStart and idxEnd) then
				locPlayerName = string.sub(stringdata, (idxStart + 24), (idxEnd-14))
			end
--		end
	end
	
	if(locPlayerName == nil or locPlayerName == '') then
		locPlayerName = "n./a."
	end
	
	return locPlayerName
end


-- returns player id from zone and private chat
function get_player_id(stringdata)
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

-- register dissectr to TCP Port 5223 (default for kiss of war)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(CONST_KOW_JABBER_PORT, kow_jabber_protocol)
