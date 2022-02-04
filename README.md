Mr. Owl - Kiss of War: Jabber Dissector -  Version 0.92 (2020-08-18)

This Wireshark dissector will extract information like Player Name + ID from Tap4Fun's "Kiss of War" request data.

Usage:
	o On Windows this file has to be stored under %APPDATA%/Wireshark/Plugins
 o The dissector is active for every running analysis
 o To make it easier to follow the analizes you may use this filter to log KoW Chat Data only:
   (tcp contains "original_from" || tcp contains "type='chat'")
o This dissector provides the following custom columns:
     kow.message_length
     kow.message_data
     kow.player_name
     kow.player_id


Known limitations:
 o Private Chat does not contain PlayerName, ID only available from that
 o Backlog is split over multiple packets therefore it happens that the player name and ID
  are transmitted in different packages - in this case one or both values may not be available.
 o Unicode character in names are currently not supported


Legal stuff:
 o This script is provided as is, the author is not to be accounted for any harms caused by using this script.
 o This Script is done by observating the applications request response behavior only.
   No disassembling or debugging of the compiled program code has been applied.
 o This script itself is licensed under the GNU General Public License Version 3.0
   https://www.gnu.org/licenses/gpl-3.0.en.html

Copyright (c) 2020 nono
