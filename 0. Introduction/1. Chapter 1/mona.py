#!/usr/bin/env python2.7
"""
 
U{Corelan<https://www.corelan.be>}

Copyright (c) 2011-2020, Peter Van Eeckhoutte - Corelan Consulting bv
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Corelan nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN CONSULTING BVBA 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
$Revision: 613 $
$Id: mona.py 613 2020-07-13 14:33:00Z corelanc0d3r $ 
"""

__VERSION__ = '2.0'
__REV__ = filter(str.isdigit, '$Revision: 613 $')
__IMM__ = '1.8'
__DEBUGGERAPP__ = ''
arch = 32
win7mode = False

# try:
# 	import debugger
# except:
# 	pass
try:
	import immlib as dbglib
	from immlib import LogBpHook
	__DEBUGGERAPP__ = "Immunity Debugger"
except:		
	try:
		import pykd
		import windbglib as dbglib
		from windbglib import LogBpHook
		dbglib.checkVersion()
		arch = dbglib.getArchitecture()
		__DEBUGGERAPP__ = "WinDBG"
	except SystemExit:
		print("-Exit.")
		import sys
		sys.exit(1)
	except Exception:
		#import traceback
		print("Do not run this script outside of a debugger !")
		#print traceback.format_exc()
		import sys
		sys.exit(1)

import getopt

try:
	#import debugtypes
	#import libdatatype
	from immutils import *
except:
	pass

		
import os
import re
import sys
import types
import random
import shutil
import struct
import string
import types
import urllib
import inspect
import datetime
import binascii
import itertools
import traceback
import pickle
import json

from operator import itemgetter
from collections import defaultdict, namedtuple

import cProfile
import pstats

import copy

DESC = "Corelan Team exploit development swiss army knife"

#---------------------------------------#
#  Global stuff                         #
#---------------------------------------#	

TOP_USERLAND = 0x7fffffff
g_modules={}
MemoryPageACL={}
global CritCache
global vtableCache
global stacklistCache
global segmentlistCache
global VACache
global IATCache
global NtGlobalFlag
global FreeListBitmap
global memProtConstants
global currentArgs
global disasmUpperChecked
global disasmIsUpper
global configFileCache
global configwarningshown

NtGlobalFlag = -1
FreeListBitmap = {}
memProtConstants = {}
CritCache={}
IATCache={}
vtableCache={}
stacklistCache={}
segmentlistCache={}
configFileCache={}
VACache={}
ptr_counter = 0
ptr_to_get = -1
silent = False
ignoremodules = False
noheader = False
dbg = dbglib.Debugger()
disasmUpperChecked = False
disasmIsUpper = False
configwarningshown = False

if __DEBUGGERAPP__ == "WinDBG":
	if pykd.getSymbolPath().replace(" ","") == "":
		dbg.log("")
		dbg.log("** Warning, no symbol path set ! ** ",highlight=1)
		sympath = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
		dbg.log("   I'll set the symbol path to %s" % sympath)
		pykd.setSymbolPath(sympath)
		dbg.log("   Symbol path set, now reloading symbols...")
		dbg.nativeCommand(".reload")
		dbg.log("   All set. Please restart WinDBG.")
		dbg.log("")

osver = dbg.getOsVersion()
if osver in ["6", "7", "8", "vista", "win7", "2008server", "win8", "win8.1", "win10"]:
	win7mode = True

heapgranularity = 8
if arch == 64:
	heapgranularity = 16

offset_categories = ["xp", "vista", "win7", "win8", "win10"]

# offset = [x86,x64]
offsets = {
	"FrontEndHeap" : {
		"xp" : [0x580,0xad8],
		"vista" : [0x0d4,0x178],
		"win8" : [0x0d0,0x170],
		"win10" : {
			14393 : [0x0d4,0x178]
		}
	},
	"FrontEndHeapType" : {
		"xp" : [0x586,0xae2],
		"vista" : [0x0da,0x182],
		"win8" : [0x0d6,0x17a],
		"win10" : {
			14393 : [0x0da,0x182]
		}
	},
	"VirtualAllocdBlocks" : {
		"xp" : [0x050,0x090],
		"vista" : [0x0a0,0x118],
		"win8" : [0x09c,0x110]
	},
	"SegmentList" : {
		"vista" : [0x0a8,0x128],
		"win8" : [0x0a4,0x120]
	}
}

#---------------------------------------#
#  Populate constants                   #
#---------------------------------------#	
memProtConstants["X"] = ["PAGE_EXECUTE",0x10]
memProtConstants["RX"] = ["PAGE_EXECUTE_READ",0x20]
memProtConstants["RWX"] = ["PAGE_EXECUTE_READWRITE",0x40]
memProtConstants["N"] = ["PAGE_NOACCESS",0x1]
memProtConstants["R"] = ["PAGE_READONLY",0x2]
memProtConstants["RW"] = ["PAGE_READWRITE",0x4]
memProtConstants["GUARD"] = ["PAGE_GUARD",0x100]
memProtConstants["NOCACHE"] = ["PAGE_NOCACHE",0x200]
memProtConstants["WC"] = ["PAGE_WRITECOMBINE",0x400]

#---------------------------------------#
#  Utility functions                    #
#---------------------------------------#	

def resetGlobals():
	"""
	Clears all global variables
	"""
	global CritCache
	global vtableCache
	global stacklistCache
	global segmentlistCache
	global VACache
	global NtGlobalFlag
	global FreeListBitmap
	global memProtConstants
	global currentArgs

	CritCache = None
	vtableCache = None
	stacklistCache = None
	segmentlistCache = None
	VACache = None
	NtGlobalFlag = None
	FreeListBitmap = None
	memProtConstants = None
	currentArgs = None
	disasmUpperChecked = False

	return


def getPythonVersion():
	versioninfo = sys.version
	versioninfolines = versioninfo.split('\n')
	return versioninfolines[0]


def toHex(n):
	"""
	Converts a numeric value to hex (pointer to hex)

	Arguments:
	n - the value to convert

	Return:
	A string, representing the value in hex (8 characters long)
	"""
	if arch == 32:
		return "%08x" % n
	if arch == 64:
		return "%016x" % n

def sanitize_module_name(modname):
	"""
	Sanitizes a module name so it can be used as a variable
	"""
	return modname.replace(".", "_")


def DwordToBits(srcDword):
	"""
	Converts a dword into an array of 32 bits
	"""

	bit_array = []
	h_str = "%08x" % srcDword
	h_size = len(h_str) * 4
	bits = (bin(int(h_str,16))[2:]).zfill(h_size)[::-1]
	for bit in bits:
		bit_array.append(int(bit))
	return bit_array


def getDisasmInstruction(disasmentry):
	""" returns instruction string, checks if ASM is uppercase and converts to upper if needed """
	instrline = disasmentry.getDisasm()
	global disasmUpperChecked
	global disasmIsUpper
	if disasmUpperChecked:
		if not disasmIsUpper:
			instrline = instrline.upper()
	else:
		disasmUpperChecked = True
		interim_instr = instrline.upper()
		if interim_instr == instrline:
			disasmIsUpper = True
		else:
			disasmIsUpper = False
			dbg.log("** It looks like you've configured the debugger to produce lowercase disassembly. Got it, all good **", highlight=1)
			instrline = instrline.upper()
	return instrline
	

def multiSplit(thisarg,delimchars):
	""" splits a string into an array, based on provided delimeters"""
	splitparts = []
	thispart = ""
	for c in str(thisarg):
		if c in delimchars:
			thispart = thispart.replace(" ","")
			if thispart != "":
				splitparts.append(thispart)
			splitparts.append(c)
			thispart = ""
		else:
			thispart += c
	if thispart != "":
		splitparts.append(thispart)
	return splitparts


def getAddyArg(argaddy):
	"""
	Tries to extract an address from a specified argument
	addresses and values will be considered hex
	(unless you specify 0n before a value)
	registers are allowed too
	"""
	findaddy = 0
	addyok = True
	addyparts = []
	addypartsint = []
	delimchars = ["-","+","*","/","(",")","&","|",">","<"]
	regs = dbg.getRegs()
	thispart = ""
	for c in str(argaddy):
		if c in delimchars:
			thispart = thispart.replace(" ","")
			if thispart != "":
				addyparts.append(thispart)
			addyparts.append(c)
			thispart = ""
		else:
			thispart += c
	if thispart != "":
		addyparts.append(thispart)

	partok = False
	for part in addyparts:
		cleaned = part
		if not part in delimchars:
			for x in delimchars:
				cleaned = cleaned.replace(x,"")	
			if cleaned.startswith("[") and cleaned.endswith("]"):
				partval,partok = getIntForPart(cleaned.replace("[","").replace("]",""))
				if partok:
					try:
						partval = struct.unpack('<L',dbg.readMemory(partval,4))[0]
					except:
						partval = 0
						partok = False
						break
			else:	
				partval,partok = getIntForPart(cleaned)
				if not partok:
					break
			addypartsint.append(partval)
		else:
			addypartsint.append(part)
		if not partok:
			break

	if not partok:
		addyok = False
		findval = 0
	else:
		calcstr = "".join(str(x) for x in addypartsint)
		try:
			findval = eval(calcstr)
			addyok = True
		except:
			findval = 0
			addyok = False

	return findval, addyok
	


def getIntForPart(part):
	"""
	Returns the int value associated with an input string
	The input string can be a hex value, decimal value, register, modulename, or modulee!functionname
	"""
	partclean = part
	partclean = partclean.upper()
	addyok = True
	partval = 0
	regs = dbg.getRegs()
	if partclean in regs:
		partval = regs[partclean]
	elif partclean.lower() == "heap" or partclean.lower() == "processheap":
		partval = getDefaultProcessHeap()
	else:
		if partclean.lower().startswith("0n"):
			partclean = partclean.lower().replace("0n","")
			try:
				partval = int(partclean)
			except:
				addyok = False
				partval = 0
		else:
			try:
				if not "0x" in partclean.lower():
					partclean = "0x" + partclean
				partval = int(partclean,16)
			except:
				addyok = False
				partval = 0
	if not addyok:
		if not "!" in part:
			m = getModuleObj(part)
			if not m == None:
				partval = m.moduleBase
				addyok = True
		else:
			modparts = part.split("!")
			modname = modparts[0]
			funcname = modparts[1]
			m = getFunctionAddress(modname,funcname)
			if m > 0:
				partval = m
				addyok = True
	return partval,addyok


def getHeapAllocSize(requested_size, granularity = 8):
	"""
	Returns the expected allocated size for a request of X bytes of heap memory
	taking a certain granularity into account
	"""
	
	requested_size_int = to_int(requested_size)
	interimval = (requested_size_int / granularity) * granularity
	interimtimes = (requested_size_int / granularity)
	if (interimval < requested_size_int):
		interimtimes += 1
	allocated_size = granularity * interimtimes
	
	return allocated_size
	


def getFunctionAddress(modname,funcname):
	"""
	Returns the addres of the function inside a given module
	Relies on EAT data
	Returns 0 if nothing found
	"""
	funcaddy = 0
	m = getModuleObj(modname)
	if not m == None:
		eatlist = m.getEAT()
		for f in eatlist:
			if funcname == eatlist[f]:
				return f
		for f in eatlist:
			if funcname.lower() == eatlist[f].lower():
				return f
	return funcaddy

def getFunctionName(addy):
	"""
	Returns symbol name closest to the specified address
	Only works in WinDBG
	Returns function name and optional offset
	"""
	fname = ""
	foffset = ""
	cmd2run = "ln 0x%08x" % addy
	output = dbg.nativeCommand(cmd2run)
	for line in output.split("\n"):
		if "|" in line:
			lineparts = line.split(" ")
			partcnt = 0
			for p in lineparts:
				if not p == "":
					if partcnt == 1:
						fname = p
						break
					partcnt += 1
	if "+" in fname:
		fnameparts = fname.split("+")
		if len(fnameparts) > 1:
			return fnameparts[0],fnameparts[1]
	return fname,foffset


def printDataArray(data,charsperline=16,prefix=""):
	maxlen = len(data)
	charcnt = 0
	charlinecnt = 0
	linecnt = 0
	thisline = prefix
	lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
	thisline += lineprefix
	while charcnt < maxlen:
		thisline += data[charcnt:charcnt+1]
		charlinecnt += 1
		charcnt += 1
		if charlinecnt == charsperline or charlinecnt == maxlen:
			dbg.log(thisline)
			thisline = prefix
			lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
			thisline += lineprefix
			charlinecnt = 0
	return None


def find_all_copies(tofind,data):
	"""
	Finds all occurences of a string in a longer string

	Arguments:
	tofind - the string to find
	data - contains the data to look for all occurences of 'tofind'

	Return:
	An array with all locations
	"""
	position = 0
	positions = []
	searchstringlen = len(tofind)
	maxlen = len(data)
	while position < maxlen:
		position = data.find(tofind,position)
		if position == -1:
			break
		positions.append(position)
		position += searchstringlen
	return positions

def getAllStringOffsets(data,minlen,offsetstart = 0):
	asciistrings = {}
	for match in re.finditer("(([\x20-\x7e]){%d,})" % minlen,data): 
		thisloc = match.start() + offsetstart
		thisend = match.end() + offsetstart
		asciistrings[thisloc] = thisend
	return asciistrings

def getAllUnicodeStringOffsets(data,minlen,offsetstart = 0):
	unicodestrings = {}
	for match in re.finditer("((\x00[\x20-\x7e]){%d,})" % (minlen*2),data):
		unicodestrings[offsetstart + match.start()] = (offsetstart + match.end())
	return unicodestrings


def stripExtension(fullname):
	"""
	Removes extension from a filename
	(will only remove the last extension)

	Arguments :
	fullname - the original string

	Return:
	A string, containing the original string without the last extension
	"""
	nameparts = str(fullname).split(".")
	if len(nameparts) > 1:
		cnt = 0
		modname = ""
		while cnt < len(nameparts)-1:
			modname = modname + nameparts[cnt] + "."
			cnt += 1
		return modname.strip(".")
	return fullname


def toHexByte(n):
	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def toAsciiOnly(inputstr):
	return "".join(i for i in inputstr if ord(i)<128 and ord(i) > 31)

def toAscii(n):
	"""
	Converts a byte to its ascii equivalent. Null byte = space

	Arguments:
	n - A string (2 chars) representing the byte to convert to ascii

	Return:
	A string (one character), representing the ascii equivalent
	"""
	asciiequival = " "
	if n.__class__.__name__ == "int":
		n = "%02x" % n
	try:
		if n != "00":
			asciiequival=binascii.a2b_hex(n)
		else:
			asciiequival = " "
	except TypeError:
		asciiequival=" "
	return asciiequival

def hex2bin(pattern):
	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
	
	return ''.join([binascii.a2b_hex(i+j) for i,j in zip(pattern[0::2],pattern[1::2])])

def cleanHex(hex):
	hex = hex.replace("'","")
	hex = hex.replace('"',"")
	hex = hex.replace("\\x","")
	hex = hex.replace("0x","")
	return hex

def hex2int(hex):
	return int(hex,16)

def getVariantType(typenr):
	varianttypes = {}
	varianttypes[0x0] = "VT_EMPTY"
	varianttypes[0x1] = "VT_NULL"
	varianttypes[0x2] = "VT_I2"
	varianttypes[0x3] = "VT_I4"
	varianttypes[0x4] = "VT_R4"
	varianttypes[0x5] = "VT_R8"
	varianttypes[0x6] = "VT_CY"
	varianttypes[0x7] = "VT_DATE"
	varianttypes[0x8] = "VT_BSTR"
	varianttypes[0x9] = "VT_DISPATCH"
	varianttypes[0xA] = "VT_ERROR"
	varianttypes[0xB] = "VT_BOOL"
	varianttypes[0xC] = "VT_VARIANT"
	varianttypes[0xD] = "VT_UNKNOWN"
	varianttypes[0xE] = "VT_DECIMAL"
	varianttypes[0x10] = "VT_I1"
	varianttypes[0x11] = "VT_UI1"
	varianttypes[0x12] = "VT_UI2"
	varianttypes[0x13] = "VT_UI4"
	varianttypes[0x14] = "VT_I8"
	varianttypes[0x15] = "VT_UI8"
	varianttypes[0x16] = "VT_INT"
	varianttypes[0x17] = "VT_UINT"
	varianttypes[0x18] = "VT_VOID"
	varianttypes[0x19] = "VT_HRESULT"
	varianttypes[0x1A] = "VT_PTR"
	varianttypes[0x1B] = "VT_SAFEARRAY"
	varianttypes[0x1C] = "VT_CARRAY"
	varianttypes[0x1D] = "VT_USERDEFINED"
	varianttypes[0x1E] = "VT_LPSTR"
	varianttypes[0x1F] = "VT_LPWSTR"
	varianttypes[0x24] = "VT_RECORD"
	varianttypes[0x25] = "VT_INT_PTR"
	varianttypes[0x26] = "VT_UINT_PTR"
	varianttypes[0x2000] = "VT_ARRAY"
	varianttypes[0x4000] = "VT_BYREF"

	if typenr in varianttypes:
		return varianttypes[typenr]
	else:
		return ""



def bin2hex(binbytes):
	"""
	Converts a binary string to a string of space-separated hexadecimal bytes.
	"""
	return ' '.join('%02x' % ord(c) for c in binbytes)

def bin2hexstr(binbytes):
	"""
	Converts bytes to a string with hex
	
	Arguments:
	binbytes - the input to convert to hex
	
	Return :
	string with hex
	"""
	return ''.join('\\x%02x' % ord(c) for c in binbytes)

def str2js(inputstring):
	"""
	Converts a string to a javascript string
	
	Arguments:
	inputstring - the input string to convert 

	Return :
	string in javascript format
	"""
	length = len(inputstring)
	if length % 2 == 1:
		jsmsg = "Warning : odd size given, js pattern will be truncated to " + str(length - 1) + " bytes, it's better use an even size\n"
		if not silent:
			dbg.logLines(jsmsg,highlight=1)
	toreturn=""
	for thismatch in re.compile("..").findall(inputstring):
		thisunibyte = ""
		for thisbyte in thismatch:
			thisunibyte = "%02x" % ord(thisbyte) + thisunibyte
		toreturn += "%u" + thisunibyte
	return toreturn		


def readJSONDict(filename):
	"""
	Retrieve stored dict from JSON file
	"""
	jsondict = {}
	with open(filename, 'rb') as infile:
		jsondata = infile.read()
		jsondict = json.loads(jsondata)
	return jsondict


def writeJSONDict(filename, dicttosave):
	"""
	Write dict as JSON to file
	"""
	with open(filename, 'wb') as outfile:
		json.dump(dicttosave, outfile)
	return


def readPickleDict(filename):
	"""
	Retrieve stored dict from file (pickle load)
	"""
	pdict = {}
	pdict = pickle.load( open(filename,"rb"))
	return pdict

def writePickleDict(filename, dicttosave):
	"""
	Write a dict to file as a pickle
	"""
	pickle.dump(dicttosave, open(filename, "wb"))
	return

	
def opcodesToHex(opcodes):
	"""
	Converts pairs of chars (opcode bytes) to hex string notation

	Arguments :
	opcodes : pairs of chars
	
	Return :
	string with hex
	"""
	toreturn = []
	opcodes = opcodes.replace(" ","")
	
	for cnt in range(0, len(opcodes), 2):
		thisbyte = opcodes[cnt:cnt+2]
		toreturn.append("\\x" + thisbyte)
	toreturn = ''.join(toreturn)
	return toreturn
	
	
def rmLeading(input,toremove,toignore=""):
	"""
	Removes leading characters from an input string
	
	Arguments:
	input - the input string
	toremove - the character to remove from the begin of the string
	toignore - ignore this character
	
	Return:
	the input string without the leading character(s)
	"""
	newstring = ""
	cnt = 0
	while cnt < len(input):
		if input[cnt] != toremove and input[cnt] != toignore:
			break
		cnt += 1
	newstring = input[cnt:]
	return newstring

	
def getVersionInfo(filename):
	"""Retrieves version and revision numbers from a mona file
	
	Arguments : filename
	
	Return :
	version - string with version (or empty if not found)
	revision - string with revision (or empty if not found)
	"""

	file = open(filename,"rb")
	content = file.readlines()
	file.close()

	
	revision = ""
	version = ""
	for line in content:
		if line.startswith("$Revision"):
			parts = line.split(" ")
			if len(parts) > 1:
				revision = parts[1].replace("$","")
		if line.startswith("__VERSION__"):
			parts = line.split("=")
			if len(parts) > 1:
				version = parts[1].strip()
	return version,revision

	
def toniceHex(data,size):
	"""
	Converts a series of bytes into a hex string, 
	newline after 'size' nr of bytes
	
	Arguments :
	data - the bytes to convert
	size - the number of bytes to show per linecache
	
	Return :
	a multiline string
	"""
	flip = 1
	thisline = "\""
	block = ""

	try:
   		 # Python 2
		xrange
	except NameError:
		# Python 3, xrange is now named range
		xrange = range
	
	for cnt in xrange(len(data)):
		thisline += "\\x%s" % toHexByte(ord(data[cnt]))				
		if (flip == size) or (cnt == len(data)-1):				
			thisline += "\""
			flip = 0
			block += thisline 
			block += "\n"
			thisline = "\""
		cnt += 1
		flip += 1
	return block.lower()
	
def hexStrToInt(inputstr):
	"""
	Converts a string with hex bytes to a numeric value
	Arguments:
	inputstr - A string representing the bytes to convert. Example : 41414141

	Return:
	the numeric value
	"""
	valtoreturn = 0
	try:
		valtoreturn = int(inputstr, 16)
	except:
		valtoreturn = 0
	return valtoreturn

def to_int(inputstr):
	"""
	Converts a string to int, whether it's hex or decimal
	Arguments:
	    inputstr - A string representation of a number. Example: 0xFFFF, 2345

	Return:
	    the numeric value
	"""
	if str(inputstr).lower().startswith("0x"):
		return hexStrToInt(inputstr)
	else:
		return int(inputstr)
	
def toSize(toPad,size):
	"""
	Adds spaces to a string until the string reaches a certain length

	Arguments:
	input - A string
	size - the destination size of the string 

	Return:
	the expanded string of length <size>
	"""
	padded = toPad + " " * (size - len(toPad))
	return padded.ljust(size," ")

	
def toUnicode(input):
	"""
	Converts a series of bytes to unicode (UTF-16) bytes
	
	Arguments :
	input - the source bytes
	
	Return:
	the unicode expanded version of the input
	"""
	unicodebytes = ""
	# try/except, just in case .encode bails out
	try:
		unicodebytes = input.encode('UTF-16LE')
	except:
		inputlst = list(input)
		for inputchar in inputlst:
			unicodebytes += inputchar + '\x00'
	return unicodebytes
	
def toJavaScript(input):
	"""
	Extracts pointers from lines of text
	and returns a javascript friendly version
	"""
	alllines = input.split("\n")
	javascriptversion = ""
	allbytes = ""
	for eachline in alllines:
		thisline = eachline.replace("\t","").lower().strip()
		if not(thisline.startswith("#")):
			if thisline.startswith("0x"):
				theptr = thisline.split(",")[0].replace("0x","")
				# change order to unescape format
				if arch == 32:
					ptrstr = ""
					byte1 = theptr[0] + theptr[1]
					ptrstr = "\\x" + byte1
					byte2 = theptr[2] + theptr[3]
					ptrstr = "\\x" + byte2 + ptrstr
					try:
						byte3 = theptr[4] + theptr[5]
						ptrstr = "\\x" + byte3 + ptrstr
					except:
						pass
					try:
						byte4 = theptr[6] + theptr[7]
						ptrstr = "\\x" + byte4 + ptrstr
					except:
						pass
					allbytes += hex2bin(ptrstr)
				if arch == 64:
					byte1 = theptr[0] + theptr[1]
					byte2 = theptr[2] + theptr[3]
					byte3 = theptr[4] + theptr[5]
					byte4 = theptr[6] + theptr[7]
					byte5 = theptr[8] + theptr[9]
					byte6 = theptr[10] + theptr[11]
					byte7 = theptr[12] + theptr[13]
					byte8 = theptr[14] + theptr[15]
					allbytes += hex2bin("\\x" + byte8 + "\\x" + byte7 + "\\x" + byte6 + "\\x" + byte5)
					allbytes += hex2bin("\\x" + byte4 + "\\x" + byte3 + "\\x" + byte2 + "\\x" + byte1)
	javascriptversion = str2js(allbytes)			
	return javascriptversion
	

def getSourceDest(instruction):
	"""
	Determines source and destination register for a given instruction
	"""
	src = []
	dst = []
	srcp = []
	dstp = []
	srco = []
	dsto = []
	instr = []
	haveboth = False
	seensep = False
	seeninstr = False

	regs = getAllRegs()

	instructionparts = multiSplit(instruction,[" ",","])
	
	if "," in instructionparts:
		haveboth = True

	delkeys = ["DWORD","PTR","BYTE"]

	for d in delkeys:
		if d in instructionparts:
			instructionparts.remove(d)


	for p in instructionparts:

		regfound = False
		for r in regs:
			if r.upper() in p.upper() and not "!" in p and not len(instr) == 0:
				regfound = True
				seeninstr = True
				break

		if not regfound:
			if not seeninstr and not seensep:
				instr.append(p) 
		
			if "," in p:
				seensep = True
		else:
			for r in regs:
				if r.upper() in p.upper():
					if not seensep or not haveboth:
						dstp.append(p)
						if not r in dsto:
							dsto.append(r)
							break
					else:
						srcp.append(p)
						if not r in srco:
							srco.append(r)
							break

	#dbg.log("dst: %s" % dsto)
	#dbg.log("src: %s" % srco)
	src = srcp
	dst = dstp
	return src,dst

	

def getAllRegs():
	"""
	Return an array with all 32bit, 16bit and 8bit registers
	"""
	regs = ["EAX","EBX","ECX","EDX","ESP","EBP","ESI","EDI","EIP"]
	regs.append("AX")
	regs.append("BX")
	regs.append("CX")
	regs.append("DX")
	regs.append("BP")
	regs.append("SP")
	regs.append("SI")
	regs.append("DI")
	regs.append("AL")
	regs.append("AH")
	regs.append("BL")
	regs.append("BH")
	regs.append("CL")
	regs.append("CH")
	regs.append("DL")
	regs.append("DH")
	return regs

def getSmallerRegs(reg):
	if reg == "EAX":
		return ["AX","AL","AH"]
	if reg == "AX":
		return ["AL","AH"]
	if reg == "EBX":
		return ["BX","BL","BH"]
	if reg == "BX":
		return ["BL","BH"]
	if reg == "ECX":
		return ["CX","CL","CH"]
	if reg == "CX":
		return ["CL","CH"]
	if reg == "EDX":
		return ["DX","DL","DH"]
	if reg == "DX":
		return ["DL","DH"]
	if reg == "ESP":
		return ["SP"]
	if reg == "EBP":
		return ["BP"]
	if reg == "ESI":
		return ["SI"]
	if reg == "EDI":
		return ["DI"]

	return []


def isReg(reg):
	"""
	Checks if a given string is a valid reg
	Argument :
	reg  - the register to check
	
	Return:
	Boolean
	"""
	regs = []
	if arch == 32:
		regs=["eax","ebx","ecx","edx","esi","edi","ebp","esp"]
	if arch == 64:
		regs=["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
	return str(reg).lower() in regs
	

def isAddress(string):
	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	string = string.replace("\\x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0"]:
			return False
	return True
	
def isHexValue(string):
	"""
	Check if a string is a hex value / consists of hex chars only (and - )

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes or - sign
	"""
	string = string.replace("\\x","")
	string = string.replace("0x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0","-"]:
			return False
	return True	

def Poly_ReturnDW(value):
	I = random.randint(1, 3)
	if I == 1:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "SUB EAX, EAX\n ADD EAX, 0x%08x" % value )
		else:
			return dbg.assemble( "SUB EAX, EAX\n ADD EAX, -0x%08x" % value )
	if I == 2:
		return dbg.assemble( "PUSH 0x%08x\n POP EAX\n" % value )
	if I == 3:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "XCHG EAX, EDI\n DB 0xBF\n DD 0x%08x\n XCHG EAX, EDI" % value )
		else:
			return dbg.assemble( "XCHG EAX, EDI\n MOV EDI, 0x%08x\n XCHG EAX, EDI" % value )
	return

def Poly_Return0():
	I = random.randint(1, 4)
	if I == 1:
		return dbg.assemble( "SUB EAX, EAX" )
	if I == 2:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "PUSH 0\n POP EAX" )
		else:
			return dbg.assemble( "DB 0x6A, 0x00\n POP EAX" )
	if I == 3:
		return dbg.assemble( "XCHG EAX, EDI\n SUB EDI, EDI\n XCHG EAX, EDI" )
	if I == 4:
		return Poly_ReturnDW(0)
	return


def addrToInt(string):
	"""
	Convert a textual address to an integer

	Arguments:
	string - the address

	Return:
	int - the address value
	"""
	
	string = string.replace("\\x","")
	return hexStrToInt(string)
	
def splitAddress(address):
	"""
	Splits aa dword/qdword into individual bytes (4 or 8 bytes)

	Arguments:
	address - The string to split

	Return:
	4 or 8 bytes
	"""
	if arch == 32:
		byte1 = address >> 24 & 0xFF
		byte2 = address >> 16 & 0xFF
		byte3 = address >>  8 & 0xFF
		byte4 = address & 0xFF
		return byte1,byte2,byte3,byte4

	if arch == 64:
		byte1 = address >> 56 & 0xFF
		byte2 = address >> 48 & 0xFF
		byte3 = address >> 40 & 0xFF
		byte4 = address >> 32 & 0xFF
		byte5 = address >> 24 & 0xFF
		byte6 = address >> 16 & 0xFF
		byte7 = address >>  8 & 0xFF
		byte8 = address & 0xFF
		return byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8


def bytesInRange(address, range):
	"""
	Checks if all bytes of an address are in a range

	Arguments:
	address - the address to check
	range - a range object containing the values all bytes need to comply with

	Return:
	a boolean
	"""
	if arch == 32:
		byte1,byte2,byte3,byte4 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False

	if arch == 64:
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False
		elif not byte5 in range:
			return False
		elif not byte6 in range:
			return False
		elif not byte7 in range:
			return False
		elif not byte8 in range:
			return False
	
	return True

def readString(address):
	"""
	Reads a string from the given address until it reaches a null bytes

	Arguments:
	address - the base address (integer value)

	Return:
	the string
	"""
	toreturn = dbg.readString(address)
	return toreturn

def getSegmentEnd(segmentstart):
	os = dbg.getOsVersion()
	offset = 0x24
	if win7mode:
		offset = 0x28
	segmentend = struct.unpack('<L',dbg.readMemory(segmentstart + offset,4))[0]
	return segmentend


def getHeapFlag(flag):
	flags = {
	0x0 : "Free",
	0x1 : "Busy",
	0x2 : "Extra present",
	0x4 : "Fill pattern",
	0x8 : "Virtallocd",
	0x10 : "Last",
	0x20 : "FFU-1",
	0x40 : "FFU-2",
	0x80 : "No Coalesce"
	}
	#if win7mode:
	#	flags[0x8] = "Internal"
	if flag in flags:
		return flags[flag]
	else:
		# maybe it's a combination of flags
		values = [0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1]
		flagtext = []
		for val in values:
			if (flag - val) >= 0:
				flagtext.append(flags[val])
				flag -= val
		if len(flagtext) == 0:
			flagtext = "Unknown"
		else:
			flagtext = ','.join(flagtext)
		return flagtext

def decodeHeapHeader(headeraddress,headersize,key):
	# get header and decode first 4 bytes
	blockcnt = 0
	fullheaderbytes = ""
	decodedheader = ""
	fullheaderbytes = ""
	while blockcnt < headersize:
		header = struct.unpack('<L',dbg.readMemory(headeraddress+blockcnt,4))[0]
		if blockcnt == 0:
			decodedheader = header ^ key
		else:
			decodedheader = header
		headerbytes = "%08x" % decodedheader
		bytecnt = 7
		while bytecnt >= 0:
			fullheaderbytes = fullheaderbytes + headerbytes[bytecnt-1] + headerbytes[bytecnt]
			bytecnt -= 2
		blockcnt += 4
	return hex2bin(fullheaderbytes)

def walkSegment(FirstEntry,LastValidEntry,heapbase):
	"""
	Finds all chunks in a given segment

	Arguments : Start and End of segment, and heapbase
	

	Returns a dictionary of MnChunk objects
	Key : chunk pointer

	"""
	mHeap = MnHeap(heapbase)
	mSegment = MnSegment(heapbase,FirstEntry,LastValidEntry)
	return mSegment.getChunks()

	
def getStacks():
	"""
	Retrieves all stacks from all threads in the current application

	Arguments:
	None

	Return:
	a dictionary, with key = threadID. Each entry contains an array with base and top of the stack
	"""
	stacks = {}
	global stacklistCache
	if len(stacklistCache) > 0:
		return stacklistCache
	else:
		threads = dbg.getAllThreads() 
		for thread in threads:
			teb = thread.getTEB()
			tid = thread.getId()
			topStack = 0
			baseStack = 0
			if arch == 32:
				topStack = struct.unpack('<L',dbg.readMemory(teb+4,4))[0]
				baseStack = struct.unpack('<L',dbg.readMemory(teb+8,4))[0]
			if arch == 64:
				topStack = struct.unpack('<Q',dbg.readMemory(teb+8,8))[0]
				baseStack = struct.unpack('<Q',dbg.readMemory(teb+16,8))[0]
			stacks[tid] = [baseStack,topStack]
		stacklistCache = stacks
		return stacks

def meetsAccessLevel(page,accessLevel):
	"""
	Checks if a given page meets a given access level

	Arguments:
	page - a page object
	accesslevel - a string containing one of the following access levels :
	R,W,X,RW,RX,WR,WX,RWX or *

	Return:
	a boolean
	"""
	if "*" in accessLevel:
		return True
	
	pageAccess = page.getAccess(human=True)
	
	if "-R" in accessLevel:
		if "READ" in pageAccess:
			return False
	if "-W" in accessLevel:
		if "WRITE" in pageAccess:
			return False
	if "-X" in accessLevel:
		if "EXECUTE" in pageAccess:
			return False
	if "R" in accessLevel:
		if not "READ" in pageAccess:
			return False
	if "W" in accessLevel:
		if not "WRITE" in pageAccess:
			return False
	if "X" in accessLevel:
		if not "EXECUTE" in pageAccess:
			return False
			
	return True

def splitToPtrInstr(input):
	"""
	Splits a line (retrieved from a mona output file) into a pointer and a string with the instructions in the file

	Arguments:
	input : the line containing pointer and instruction

	Return:
	a pointer - (integer value)
	a string - instruction
	if the input does not contain a valid line, pointer will be set to -1 and string will be empty
	"""	
	
	thispointer = -1
	thisinstruction = ""
	split1 = re.compile(" ")
	split2 = re.compile(":")
	split3 = re.compile("\*\*")
	
	thisline = input.lower()
	if thisline.startswith("0x"):
		#get the pointer
		parts = split1.split(input)
		part1 = parts[0].replace("\n","").replace("\r","")
		if len(part1) != 10:
			return thispointer,thisinstruction
		else:
			thispointer = hexStrToInt(part1)
			if len(parts) > 1:
				subparts = split2.split(input)
				subpartsall = ""
				if len(subparts) > 1:
					cnt = 1
					while cnt < len(subparts):
						subpartsall += subparts[cnt] + ":"
						cnt +=1
					subsubparts = split3.split(subpartsall)
					thisinstruction = subsubparts[0].strip()
			return thispointer,thisinstruction
	else:
		return thispointer,thisinstruction
		
		
def getNrOfDictElements(thisdict):
	"""
	Will get the total number of entries in a given dictionary
	Argument: the source dictionary
	Output : an integer
	"""
	total = 0
	for dicttype in thisdict:
		for dictval in thisdict[dicttype]:
			total += 1
	return total
	
def getModuleObj(modname):
	"""
	Will return a module object if the provided module name exists
	Will perform a case sensitive search first,
	and then a case insensitive search in case nothing was found
	"""
	# Method 1
	mod = dbg.getModule(modname)
	if mod is not None:
		return MnModule(modname)
	# Method 2

	suffixes = ["",".exe",".dll"]
	allmod = dbg.getAllModules()
	for suf in suffixes:
		modname_search = modname + suf	
		
		#WinDBG optimized
		if __DEBUGGERAPP__ == "WinDBG":	
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName() == modname_search:
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName())
					if not imname == None:
						if imname == modname_search:
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName().lower() == modname_search.lower():
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName().lower())
					if not imname == None:
						if imname.lower() == modname_search.lower():
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod_s.lower() == modname_search.lower():
						return MnModule(tmod_s)
		else:
			# Immunity
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname == modname_search:
						return MnModule(mname)
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname.lower() == modname_search.lower():
						return MnModule(mname)
		
	return None
	
		
		
def getPatternLength(startptr,type="normal",args={}):
	"""
	Gets length of a cyclic pattern, starting from a given pointer
	
	Arguments:
	startptr - the start pointer (integer value)
	type - optional string, indicating type of pattern :
		"normal" : normal pattern
		"unicode" : unicode pattern
		"upper" : uppercase pattern
		"lower" : lowercase pattern
	"""
	patternsize = 0
	endofpattern = False
	global silent
	oldsilent=silent
	silent=True
	fullpattern = createPattern(200000,args)
	silent=oldsilent
	if type == "upper":
		fullpattern = fullpattern.upper()
	if type == "lower":
		fullpattern = fullpattern.lower()
	#if type == "unicode":
	#	fullpattern = toUnicode(fullpattern)
	
	if type in ["normal","upper","lower","unicode"]:
		previousloc = -1
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=dbg.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=dbg.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=dbg.readMemory(startptr+patternsize,4)
			if len(sizemeter) == 4:
				thisloc = fullpattern.find(sizemeter)
				if thisloc < 0 or thisloc <= previousloc:
					endofpattern = True
				else:
					patternsize += 4
					previousloc = thisloc
			else:
				return patternsize
		#maybe this is not the end yet
		patternsize -= 8
		endofpattern = False
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=dbg.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=dbg.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=dbg.readMemory(startptr+patternsize,4)
			if fullpattern.find(sizemeter) < 0:
				patternsize += 3
				endofpattern = True
			else:		
				patternsize += 1
	if type == "unicode":
		patternsize = (patternsize / 2) + 1
	return patternsize
	
def getAPointer(modules,criteria,accesslevel):
	"""
	Gets the first pointer from one of the supplied module that meets a set of criteria
	
	Arguments:
	modules - array with module names
	criteria - dictionary describing the criteria the pointer needs to comply with
	accesslevel - the required access level
	
	Return:
	a pointer (integer value) or 0 if nothing was found
	"""
	pointer = 0
	dbg.getMemoryPages()
	for a in dbg.MemoryPages.keys():
			page_start = a
			page_size  = dbg.MemoryPages[a].getSize()
			page_end   = a + page_size
			#page in one of the modules ?
			if meetsAccessLevel(dbg.MemoryPages[a],accesslevel):
				pageptr = MnPointer(a)
				thismodulename = pageptr.belongsTo()
				if thismodulename != "" and thismodulename in modules:
					thismod = MnModule(thismodulename)
					start = thismod.moduleBase
					end = thismod.moduleTop
					random.seed()
					for cnt in xrange(page_size+1):
						#randomize the value
						theoffset = random.randint(0,page_size)
						thispointer = MnPointer(page_start + theoffset)
						if meetsCriteria(thispointer,criteria):
							return page_start + theoffset
	return pointer
	
	
def haveRepetition(string, pos):
	first =  string[pos]
	MIN_REPETITION = 3		
	if len(string) - pos > MIN_REPETITION:
		count = 1
		while ( count < MIN_REPETITION and string[pos+count] ==  first):
			count += 1
		if count >= MIN_REPETITION:
			return True
	return False


def findAllPaths(graph,start_vertex,end_vertex,path=[]):
	path = path + [start_vertex]
	if start_vertex == end_vertex:
		return [path]
	if start_vertex not in graph:
		return []
	paths = []
	for vertex in graph[start_vertex]:
		if vertex not in path:
			extended_paths = findAllPaths(graph,vertex,end_vertex,path)
			for p in extended_paths:
				paths.append(p)
	return paths



def isAsciiString(data):
	"""
	Check if a given string only contains ascii characters
	"""
	return all((ord(c) >= 32 and ord(c) <= 127) for c in data)
	
def isAscii(b):
	"""
	Check if a given hex byte is ascii or not
	
	Argument : the byte
	Returns : Boolean
	"""
	return b == 0x0a or b == 0x0d or (b >= 0x20 and b <= 0x7e)
	
def isAscii2(b):
	"""
	Check if a given hex byte is ascii or not, will not flag newline or carriage return as ascii
	
	Argument : the byte
	Returns : Boolean
	"""
	return b >= 0x20 and b <= 0x7e	
	
def isHexString(input):
	"""
	Checks if all characters in a string are hex (0->9, a->f, A->F)
	Alias for isAddress()
	"""
	return isAddress(input)

def extract_chunks(iterable, size):
	""" Retrieves chunks of the given :size from the :iterable """
	fill = object()
	gen = itertools.izip_longest(fillvalue=fill, *([iter(iterable)] * size))
	return (tuple(x for x in chunk if x != fill) for chunk in gen)

def rrange(x, y = 0):
	""" Creates a reversed range (from x - 1 down to y).
	
	Example:
	>>> rrange(10, 0) # => [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
	"""
	return range(x - 1, y - 1, -1)

def getSkeletonHeader(exploittype,portnr,extension,url,badchars='\x00\x0a\x0d'):

	originalauthor = "insert_name_of_person_who_discovered_the_vulnerability"
	name = "insert name for the exploit"
	cve = "insert CVE number here"
	
	if url == "":
		url = "<insert another link to the exploit/advisory here>"
	else:
		try:
			# connect to url & get author + app description
			u = urllib.urlretrieve(url)
			# extract title
			fh = open(u[0],'r')
			contents = fh.readlines()
			fh.close()
			for line in contents:
				if line.find('<h1') > -1:
					titleline = line.split('>')
					if len(titleline) > 1:
						name = titleline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('Author:') > -1 and line.find('td style') > -1:
					authorline = line.split("Author:")
					if len(authorline) > 1:
						originalauthor = authorline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('CVE:') > -1 and line.find('td style') > -1:
					cveline = line.split("CVE:")
					if len(cveline) > 1:
						tcveparts = cveline[1].split('>')
						if len(tcveparts) > 1:
							tcve = tcveparts[1].split('<')[0].replace("\"","").replace("'","").strip()
							if tcve.upper().strip() != "N//A":
								cve = tcve
					break					
		except:
			dbg.log(" ** Unable to download %s" % url,highlight=1)
			url = "<insert another link to the exploit/advisory here>"
	
	monaConfig = MnConfig()
	thisauthor = monaConfig.get("author")
	if thisauthor == "":
		thisauthor = "<insert your name here>"

	skeletonheader = "##\n"
	skeletonheader += "# This module requires Metasploit: http://metasploit.com/download\n"
	skeletonheader += "# Current source: https://github.com/rapid7/metasploit-framework\n"
	skeletonheader += "##\n\n"
	skeletonheader += "require 'msf/core'\n\n"
	skeletonheader += "class MetasploitModule < Msf::Exploit::Remote\n"
	skeletonheader += "  #Rank definition: https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking\n"
	skeletonheader += "  #ManualRanking/LowRanking/AverageRanking/NormalRanking/GoodRanking/GreatRanking/ExcellentRanking\n"
	skeletonheader += "  Rank = NormalRanking\n\n"
	
	if exploittype == "fileformat":
		skeletonheader += "  include Msf::Exploit::FILEFORMAT\n"
	if exploittype == "network client (tcp)":
		skeletonheader += "  include Msf::Exploit::Remote::Tcp\n"
	if exploittype == "network client (udp)":
		skeletonheader += "  include Msf::Exploit::Remote::Udp\n"
		
	if cve.strip() == "":
		cve = "<insert CVE number here>"
		
	skeletoninit = "  def initialize(info = {})\n"
	skeletoninit += "    super(update_info(info,\n"
	skeletoninit += "      'Name'    => '" + name + "',\n"
	skeletoninit += "      'Description'  => %q{\n"
	skeletoninit += "          Provide information about the vulnerability / explain as good as you can\n"
	skeletoninit += "          Make sure to keep each line less than 100 columns wide\n"
	skeletoninit += "      },\n"
	skeletoninit += "      'License'    => MSF_LICENSE,\n"
	skeletoninit += "      'Author'    =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          '" + originalauthor + "<user[at]domain.com>',  # Original discovery\n"
	skeletoninit += "          '" + thisauthor + "',  # MSF Module\n"		
	skeletoninit += "        ],\n"
	skeletoninit += "      'References'  =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          [ 'OSVDB', '<insert OSVDB number here>' ],\n"
	skeletoninit += "          [ 'CVE', '" + cve + "' ],\n"
	skeletoninit += "          [ 'URL', '" + url + "' ]\n"
	skeletoninit += "        ],\n"
	skeletoninit += "      'DefaultOptions' =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'ExitFunction' => 'process', #none/process/thread/seh\n"
	skeletoninit += "          #'InitialAutoRunScript' => 'migrate -f',\n"	
	skeletoninit += "        },\n"
	skeletoninit += "      'Platform'  => 'win',\n"
	skeletoninit += "      'Payload'  =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'BadChars' => \"" + bin2hexstr(badchars) + "\", # <change if needed>\n"
	skeletoninit += "          'DisableNops' => true,\n"
	skeletoninit += "        },\n"
	
	skeletoninit2 = "      'Privileged'  => false,\n"
	skeletoninit2 += "      #Correct Date Format: \"M D Y\"\n"
	skeletoninit2 += "      #Month format: Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec\n"
	skeletoninit2 += "      'DisclosureDate'  => 'MONTH DAY YEAR',\n"
	skeletoninit2 += "      'DefaultTarget'  => 0))\n"
	
	if exploittype.find("network") > -1:
		skeletoninit2 += "\n    register_options([Opt::RPORT(" + str(portnr) + ")], self.class)\n"
	if exploittype.find("fileformat") > -1:
		skeletoninit2 += "\n    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'msf" + extension + "']),], self.class)\n"
	skeletoninit2 += "\n  end\n\n"
	
	return skeletonheader,skeletoninit,skeletoninit2

def shortJump(sizeofinst, offset):
	"""
	Calculate the parameter for a short relative jump from the size of instruction (which can be JMP, JNZ etc...) and the desired offset
	Arguments:
	sizeofinst - the size of the instruction used to achieve the jump
	offset - the desired offset from the address of the instruction
	Return:
	A binary value which can be used along with the jump instruction
	"""
	if (offset - sizeofinst) < -128 or (offset - sizeofinst) > 127:
		dbg.log(" ** short jump too long",highlight=1)
	return struct.pack("b", offset - sizeofinst)

def archValue(x86, x64):
	if arch == 32:
		return x86
	elif arch == 64:
		return x64

def readPtrSizeBytes(ptr):
	if arch == 32:
		return struct.unpack('<L',dbg.readMemory(ptr,4))[0]
	elif arch == 64:
		return struct.unpack('<Q',dbg.readMemory(ptr,8))[0]

def getOsOffset(name):
	osrelease = dbg.getOsRelease()
	osreleaseparts = osrelease.split(".")
	major = int(osreleaseparts[0])
	minor = int(osreleaseparts[1])
	build = int(osreleaseparts[2])

	offset_category = "xp"
	if major == 6 and minor == 0:
		offset_category = "vista"
	elif major == 6 and minor == 1:
		offset_category = "win7"
	elif major == 6 and minor in [2, 3]:
		offset_category = "win8"
	elif major == 10 and minor == 0:
		offset_category = "win10"

	offset_category_index = offset_categories.index(offset_category)

	offset = 0
	curr_category = "xp"
	for c in offset_categories:
		if not c in offsets[name]:
			continue
		if offset_categories.index(c) > offset_category_index:
			break
		curr_category = c
		if curr_category != "win10":
			offset = offsets[name][c]
		else:
			win10offsets = offsets[name][c]
			for o in sorted(win10offsets):
				if o > build:
					break
				curr_build = o
				offset = win10offsets[o]

	return archValue(offset[0], offset[1])

#---------------------------------------#
#   Class to call commands & parse args #
#---------------------------------------#

class MnCommand:
	"""
	Class to call commands, show usage and parse arguments
	"""
	def __init__(self, name, description, usage, parseProc, alias=""):
		self.name = name
		self.description = description
		self.usage = usage
		self.parseProc = parseProc
		self.alias = alias


#---------------------------------------#
#   Class to encode bytes               #
#---------------------------------------#

class MnEncoder:
	""" 
	Class to encode bytes
	"""

	def __init__(self,bytestoencode):
		self.origbytestoencode = bytestoencode
		self.bytestoencode = bytestoencode

	def encodeAlphaNum(self,badchars = []):
		encodedbytes = {}
		if not silent:
			dbg.log("[+] Using alphanum encoder")
			dbg.log("[+] Received %d bytes to encode" % len(self.origbytestoencode))
			dbg.log("[+] Nr of bad chars: %d" % len(badchars))
		# first, check if there are no bad char conflicts
		nobadchars = "\x25\x2a\x2d\x31\x32\x35\x4a\x4d\x4e\x50\x55"
		badbadchars = False
		for b in badchars:
			if b in nobadchars:
				dbg.log("*** Error: byte \\x%s cannot be a bad char with this encoder" % bin2hex(b))
				badbadchars = True

		if badbadchars:
			return {}				

		# if all is well, explode the input to a multiple of 4
		while True:
			moduloresult = len(self.bytestoencode) % 4
			if moduloresult == 0:
				break
			else:
				self.bytestoencode += '\x90'
		if not len(self.bytestoencode) == len(self.origbytestoencode):
			if not silent:
				dbg.log("[+] Added %d nops to make length of input a multiple of 4" % (len(self.bytestoencode) - len(self.origbytestoencode)))

		# break it down into chunks of 4 bytes
		toencodearray = []
		toencodearray = [self.bytestoencode[max(i-4,0):i] for i in range(len(self.bytestoencode), 0, -4)][::-1]
		blockcnt = 1
		encodedline = 0
		# we have to push the blocks in reverse order
		blockcnt = len(toencodearray)
		nrblocks = len(toencodearray)
		while blockcnt > 0:
			if not silent:
				dbg.log("[+] Processing block %d/%d" % (blockcnt,nrblocks))
			encodedbytes[encodedline] = ["\x25\x4a\x4d\x4e\x55","AND EAX,0x554E4D4A"]
			encodedline += 1
			encodedbytes[encodedline] = ["\x25\x35\x32\x31\x2A","AND EAX,0x2A313235"]
			encodedline += 1
	
			opcodes=[]
			startpos=7
			source = "".join(bin2hex(a) for a in toencodearray[blockcnt-1])
			
			origbytes=source[startpos-7]+source[startpos-6]+source[startpos-5]+source[startpos-4]+source[startpos-3]+source[startpos-2]+source[startpos-1]+source[startpos]
			reversebytes=origbytes[6]+origbytes[7]+origbytes[4]+origbytes[5]+origbytes[2]+origbytes[3]+origbytes[0]+origbytes[1]
			revval=hexStrToInt(reversebytes)			   
			twoval=4294967296-revval
			twobytes=toHex(twoval)
			if not silent:	
				dbg.log("Opcode to produce : %s%s %s%s %s%s %s%s" % (origbytes[0],origbytes[1],origbytes[2],origbytes[3],origbytes[4],origbytes[5],origbytes[6],origbytes[7]))
				dbg.log("         reversed : %s%s %s%s %s%s %s%s" % (reversebytes[0],reversebytes[1],reversebytes[2],reversebytes[3],reversebytes[4],reversebytes[5],reversebytes[6],reversebytes[7]))
				dbg.log("                    -----------")				   
				dbg.log("   2's complement : %s%s %s%s %s%s %s%s" % (twobytes[0],twobytes[1],twobytes[2],twobytes[3],twobytes[4],twobytes[5],twobytes[6],twobytes[7]))
		
			#for each byte, start with last one first
			bcnt=3
			overflow=0		
			while bcnt >= 0:
				currbyte=twobytes[(bcnt*2)]+twobytes[(bcnt*2)+1]
				currval=hexStrToInt(currbyte)-overflow
				testval=currval/3

				if testval < 32:
					#put 1 in front of byte
					currbyte="1"+currbyte
					currval=hexStrToInt(currbyte)-overflow
					overflow=1
				else:
					overflow=0

				val1=currval/3
				val2=currval/3
				val3=currval/3
				sumval=val1+val2+val3
				
				if sumval < currval:
					val3 = val3 + (currval-sumval)

				#validate / fix badchars
				
				fixvals=self.validatebadchars_enc(val1,val2,val3,badchars)
				val1="%02x" % fixvals[0]
				val2="%02x" % fixvals[1]
				val3="%02x" % fixvals[2]			
				opcodes.append(val1)
				opcodes.append(val2)
				opcodes.append(val3)
				bcnt=bcnt-1

			# we should now have 12 bytes in opcodes
			if not silent:
				dbg.log("                    -----------")
				dbg.log("                    %s %s %s %s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0]))
				dbg.log("                    %s %s %s %s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1]))
				dbg.log("                    %s %s %s %s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2]))
				dbg.log("")
			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[0])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[3])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[6])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[9])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0])]
			encodedline += 1

			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[1])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[4])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[7])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[10])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1])]
			encodedline += 1

			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[2])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[5])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[8])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[11])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2])]
			encodedline += 1

			encodedbytes[encodedline] = ["\x50","PUSH EAX"]
			encodedline += 1
			
			blockcnt -= 1
	

		return encodedbytes



	def validatebadchars_enc(self,val1,val2,val3,badchars):
		newvals=[]
		allok=0
		giveup=0
		type=0
		origval1=val1
		origval2=val2
		origval3=val3
		d1=0
		d2=0
		d3=0
		lastd1=0
		lastd2=0
		lastd3=0	
		while allok==0 and giveup==0:
			#check if there are bad chars left
			charcnt=0
			val1ok=1
			val2ok=1
			val3ok=1
			while charcnt < len(badchars):
				if (hex2bin("%02x" % val1) in badchars):
					val1ok=0
				if (hex2bin("%02x" % val2) in badchars):
					val2ok=0
				if (hex2bin("%02x" % val3) in badchars):
					val3ok=0
				charcnt=charcnt+1		
			if (val1ok==0) or (val2ok==0) or (val3ok==0):
				allok=0
			else:
				allok=1
			if allok==0:
				#try first by sub 1 from val1 and val2, and add more to val3
				if type==0:
					val1=val1-1
					val2=val2-1
					val3=val3+2
					if (val1<1) or (val2==0) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=1
				if type==1:			  
				#then try by add 1 to val1 and val2, and sub more from val3
					val1=val1+1
					val2=val2+1
					val3=val3-2
					if (val1>126) or (val2>126) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=2	
				if type==2:
					#try by sub 2 from val1, and add 1 to val2 and val3
					val1=val1-2
					val2=val2+1
					val3=val3+1
					if (val1<1) or (val2>126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=3
				if type==3:
					#try by add 2 to val1, and sub 1 from val2 and val3
					val1=val1+2
					val2=val2-1
					val3=val3-1
					if (val1 > 126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=4
				if type==4:
					if (val1ok==0):
						val1=val1-1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2+1
							val3=origval3+d1-1
							d1=d1-1
						else:
							val1=0					
					if (val1 < 1) or (val2 > 126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						d1=0					
						type=5
				if type==5:
					if (val1ok==0):
						val1=val1+1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2-1
							val3=origval3-d1+1
							d1=d1-1
						else:
							val1=255					
					if (val1>126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						val1ok=0
						val2ok=0
						val3ok=0					
						d1=0
						d2=0
						d3=0					
						type=6
				if type==6:
					if (val1ok==0):
						val1=val1-1
						#d1=d1+1
					if (val2ok==0):
						val2=val2+1
						#d2=d2+1
					d3=origval1-val1+origval2-val2
					val3=origval3+d3
					if (lastd3==d3) and (d3 > 0):
						val1=origval1
						val2=origval2
						val3=origval3				
						giveup=1
					else:
						lastd3=d3			
					if (val1<1) or (val2 < 1) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						giveup=1
		#check results
		charcnt=0
		val1ok=1
		val2ok=1
		val3ok=1	
		val1text="OK"	
		val2text="OK"
		val3text="OK"	
		while charcnt < len(badchars):
			if (val1 == badchars[charcnt]):
				val1ok=0
				val1text="NOK"			
			if (val2 == badchars[charcnt]):
				val2ok=0
				val2text="NOK"						
			if (val3 == badchars[charcnt]):
				val3ok=0
				val3text="NOK"						
			charcnt=charcnt+1	
			
		if (val1ok==0) or (val2ok==0) or (val3ok==0):
			dbg.log("  ** Unable to fix bad char issue !",highlight=1)
			dbg.log("	  -> Values to check : %s(%s) %s(%s) %s(%s) " % (bin2hex(origval1),val1text,bin2hex(origval2),val2text,bin2hex(origval3),val3text),highlight=1)	
			val1=origval1
			val2=origval2
			val3=origval3		
		newvals.append(val1)
		newvals.append(val2)
		newvals.append(val3)
		return newvals		
		
		
#---------------------------------------#
#   Class to perform call tracing       #
#---------------------------------------#

class MnCallTraceHook(LogBpHook):
	def __init__(self, callptr, showargs, instruction, logfile):
		LogBpHook.__init__(self)
		self.callptr = callptr
		self.showargs = showargs
		self.logfile = logfile
		self.instruction = instruction
	
	def run(self,regs):
		# get instruction at this address
		thisaddress = regs["EIP"]
		thisinstruction = self.instruction
		allargs = []
		argstr = ""
		if thisinstruction.startswith("CALL "):
			if self.showargs > 0:
				for cnt in xrange(self.showargs):
					thisarg = 0
					try:
						thisarg = struct.unpack('<L',dbg.readMemory(regs["ESP"]+(cnt*4),4))[0]
					except:
						thisarg = 0
					allargs.append(thisarg)
					argstr += "0x%08x, " % thisarg
				argstr = argstr.strip(" ")
				argstr = argstr.strip(",")
				#dbg.log("CallTrace : 0x%08x : %s (%s)" % (thisaddress,thisinstruction,argstr),address = thisaddress)
			#else:
				#dbg.log("CallTrace : 0x%08x : %s" % (thisaddress,thisinstruction), address = thisaddress)
			# save to file
			try:
				FILE=open(self.logfile,"a")
				textra = ""
				for treg in dbglib.Registers32BitsOrder:
					if thisinstruction.lower().find(treg.lower()) > -1:
						textra += "%s = 0x%08x, " % (treg,regs[treg])
				if textra != "":
					textra = textra.strip(" ")
					textra = textra.strip(",")
					textra = "(" + textra + ")"
				FILE.write("0x%08x : %s %s\n" % (thisaddress, thisinstruction, textra))
				if self.showargs > 0:
					cnt = 0
					while cnt < len(allargs):
						content = ""
						try:
							bytecontent = dbg.readMemory(allargs[cnt],16)
							content = bin2hex(bytecontent)
						except:
							content = ""
						FILE.write("            Arg%d at 0x%08x : 0x%08x : %s\n" % (cnt,regs["ESP"]+(cnt*4),allargs[cnt],content))
						cnt += 1
				FILE.close()
			except:
				#dbg.log("OOPS", highlight=1)
				pass
		if thisinstruction.startswith("RETN"):
			returnto = 0
			try:
				returnto = struct.unpack('<L',dbg.readMemory(regs["ESP"],4))[0]
			except:
				returnto = 0
			#dbg.log("ReturnTrace : 0x%08x : %s - Return To 0x%08x" % (thisaddress,thisinstruction,returnto), address = thisaddress)
			try:
				FILE=open(self.logfile,"a")
				FILE.write("0x%08x : %s \n" % (thisaddress, thisinstruction))
				FILE.write("            ReturnTo at 0x%08x : 0x%08x\n" % (regs["ESP"],returnto))
				FILE.write("            EAX : 0x%08x\n" % regs["EAX"])
				FILE.close()
			except:
				pass
				
#---------------------------------------#
#   Class to set deferred BP Hooks      #
#---------------------------------------#

class MnDeferredHook(LogBpHook):
	def __init__(self, loadlibraryptr, targetptr):
		LogBpHook.__init__(self)
		self.targetptr = targetptr
		self.loadlibraryptr = loadlibraryptr
		
	def run(self,regs):
		#dbg.log("0x%08x - DLL Loaded, checking for %s" % (self.loadlibraryptr,self.targetptr), highlight=1)
		dbg.pause()
		if self.targetptr.find(".") > -1:
			# function name, try to resolve
			functionaddress = dbg.getAddress(self.targetptr)
			if functionaddress > 0:
				dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,functionaddress),highlight=1)
				dbg.setBreakpoint(functionaddress)
				self.UnHook()
				dbg.log("Hook removed")
				dbg.run()
				return
		if self.targetptr.find("+") > -1:
			ptrparts = self.targetptr.split("+")
			modname = ptrparts[0]
			if not modname.lower().endswith(".dll"):
				modname += ".dll" 
			themodule = getModuleObj(modname)
			if themodule != None and len(ptrparts) > 1:
				address = themodule.getBase() + int(ptrparts[1],16)
				if address > 0:
					dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,address),highlight=1)
					dbg.setBreakpoint(address)
					self.UnHook()
					dbg.log("Hook removed")
					dbg.run()
					return
		if self.targetptr.find("+") == -1 and self.targetptr.find(".") == -1:
			address = int(self.targetptr,16)
			thispage = dbg.getMemoryPageByAddress(address)
			if thispage != None:
				dbg.setBreakpoint(address)
				dbg.log("Deferred Breakpoint set at 0x%08x" % address, highlight=1)
				self.UnHook()
				dbg.log("Hook removed")
		dbg.run()

#---------------------------------------#
#   Class to access config file         #
#---------------------------------------#
class MnConfig:
	"""
	Class to perform config file operations
	"""
	def __init__(self):
	
		global configwarningshown
		self.configfile = "mona.ini"
		self.currpath = os.path.dirname(os.path.realpath(self.configfile))
		# first check if we will be saving the file into Immunity folder
		if __DEBUGGERAPP__ == "Immunity Debugger":
			if not os.path.exists(os.path.join(self.currpath,"immunitydebugger.exe")):
				if not configwarningshown:
					dbg.log(" ** Warning: using mona.ini file from %s" % self.currpath, highlight=True)
					configwarningshown = True
	
	def get(self,parameter):
		"""
		Retrieves the contents of a given parameter from the config file
		or from memory if the config file has been read already
		(configFileCache)
		Arguments:
		parameter - the name of the parameter 

		Return:
		A string, containing the contents of that parameter
		"""	
		#read config file
		#format :  parameter=value
		toreturn = ""
		curparam=[]
		global configFileCache
		#first check if parameter already exists in global cache
		if parameter.strip().lower() in configFileCache:
			toreturn = configFileCache[parameter.strip().lower()]
			#dbg.log("Found parameter %s in cache: %s" % (parameter, toreturn))
		else:
			if os.path.exists(self.configfile):
				try:
					configfileobj = open(self.configfile,"rb")
					content = configfileobj.readlines()
					configfileobj.close()
					for thisLine in content:
						if not thisLine[0] == "#":
							currparam = thisLine.split('=')
							if currparam[0].strip().lower() == parameter.strip().lower() and len(currparam) > 1:
								#get value
								currvalue = ""
								i=1
								while i < len(currparam):
									currvalue = currvalue + currparam[i] + "="
									i += 1
								toreturn = currvalue.rstrip("=").replace('\n','').replace('\r','')
								# drop into global cache for next time
								configFileCache[parameter.strip().lower()] = toreturn
								#dbg.log("Read parameter %s from file: %s" % (parameter, toreturn))
				except:
					toreturn=""
		
		return toreturn
	
	def set(self,parameter,paramvalue):
		"""
		Sets/Overwrites the contents of a given parameter in the config file

		Arguments:
		parameter - the name of the parameter 
		paramvalue - the new value of the parameter

		Return:
		nothing
		"""
		global configFileCache
		configFileCache[parameter.strip().lower()] = paramvalue
		if os.path.exists(self.configfile):
			#modify file
			try:
				configfileobj = open(self.configfile,"r")
				content = configfileobj.readlines()
				configfileobj.close()
				newcontent = []
				paramfound = False
				for thisLine in content:
					thisLine = thisLine.replace('\n','').replace('\r','')
					if not thisLine[0] == "#":
						currparam = thisLine.split('=')
						if currparam[0].strip().lower() == parameter.strip().lower():
							newcontent.append(parameter+"="+paramvalue+"\n")
							paramfound = True
						else:
							newcontent.append(thisLine+"\n")
					else:
						newcontent.append(thisLine+"\n")
				if not paramfound:
					newcontent.append(parameter+"="+paramvalue+"\n")
				#save new config file (rewrite)
				dbg.log("[+] Saving config file, modified parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.writelines(newcontent)
				FILE.close()
				dbg.log("     mona.ini saved under %s" % self.currpath)
			except:
				dbg.log("Error writing config file : %s : %s" % (sys.exc_type,sys.exc_value),highlight=1)
				return ""
		else:
			#create new file
			try:
				dbg.log("[+] Creating config file, setting parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write("# !mona.py configuration file                    #\n")
				FILE.write("# Corelan Team - https://www.corelan.be          #\n") 
				FILE.write("# -----------------------------------------------#\n")
				FILE.write(parameter+"="+paramvalue+"\n")
				FILE.close()
			except:
				dbg.log(" ** Error writing config file", highlight=1)
				return ""
		return ""
	
	
#---------------------------------------#
#   Class to log entries to file        #
#---------------------------------------#
class MnLog:
	"""
	Class to perform logfile operations
	"""
	def __init__(self, filename):
		
		self.filename = filename
		
			
	def reset(self,clear=True,showheader=True):
		"""
		Optionally clears a log file, write a header to the log file and return filename

		Optional :
		clear = Boolean. When set to false, the logfile won't be cleared. This method can be
		used to retrieve the full path to the logfile name of the current MnLog class object
		Logfiles are written to the debugger program folder, unless a config value 'workingfolder' is set.

		Return:
		full path to the logfile name.
		"""	
		global noheader
		if clear:
			if not silent:
				dbg.log("[+] Preparing output file '" + self.filename +"'")
		if not showheader:
			noheader = True
		debuggedname = dbg.getDebuggedName()
		thispid = dbg.getDebuggedPid()
		if thispid == 0:
			debuggedname = "_no_name_"
		thisconfig = MnConfig()
		workingfolder = thisconfig.get("workingfolder").rstrip("\\").strip()
		#strip extension from debuggedname
		parts = debuggedname.split(".")
		extlen = len(parts[len(parts)-1])+1
		debuggedname = debuggedname[0:len(debuggedname)-extlen]
		debuggedname = debuggedname.replace(" ","_")
		workingfolder = workingfolder.replace('%p', debuggedname)
		workingfolder = workingfolder.replace('%i', str(thispid))		
		logfile = workingfolder + "\\" + self.filename
		#does working folder exist ?
		if workingfolder != "":
			if not os.path.exists(workingfolder):
				try:
					dbg.log("    - Creating working folder %s" % workingfolder)
					#recursively create folders
					os.makedirs(workingfolder)
					dbg.log("    - Folder created")
				except:
					dbg.log("   ** Unable to create working folder %s, the debugger program folder will be used instead" % workingfolder,highlight=1)
					logfile = self.filename
		else:
			logfile = self.filename
		if clear:
			if not silent:
				dbg.log("    - (Re)setting logfile %s" % logfile)
			try:
				if os.path.exists(logfile):
					try:
						os.delete(logfile+".old")
					except:
						pass
					try:
						os.rename(logfile,logfile+".old")
					except:
						try:
							os.rename(logfile,logfile+".old2")
						except:
							pass
			except:
				pass
			#write header
			if not noheader:
				try:
					with open(logfile,"w") as fh:
						fh.write("=" * 80 + '\n')
						thisversion,thisrevision = getVersionInfo(inspect.stack()[0][1])
						thisversion = thisversion.replace("'","")
						fh.write("  Output generated by mona.py v"+thisversion+", rev "+thisrevision+" - " + __DEBUGGERAPP__ + "\n")
						fh.write("  Corelan Team - https://www.corelan.be\n")
						fh.write("=" * 80 + '\n')
						osver=dbg.getOsVersion()
						osrel=dbg.getOsRelease()
						fh.write("  OS : " + osver + ", release " + osrel + "\n")
						fh.write("  Process being debugged : " + debuggedname +" (pid " + str(thispid) + ")\n")
						currmonaargs = " ".join(x for x in currentArgs)
						fh.write("  Current mona arguments: %s\n" % currmonaargs)
						fh.write("=" * 80 + '\n')
						fh.write("  " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
						fh.write("=" * 80 + '\n')
				except:
					pass
			else:
				try:
					with open(logfile,"w") as fh:
						fh.write("")
				except:
					pass
			#write module table
			try:
				if not ignoremodules:
					showModuleTable(logfile)
			except:
				pass
		return logfile
		
	def write(self,entry,logfile):
		"""
		Write an entry (can be multiline) to a given logfile

		Arguments:
		entry - the data to write to the logfile
		logfile - the full path to the logfile

		Return:
		nothing
		"""		
		towrite = ""
		#check if entry is int 
		if type(entry) == int:
			if entry > 0:
				ptrx = MnPointer(entry)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				towrite = "0x" + toHex(entry) + " : " + ptrx.__str__() + " " + modinfo.__str__()
			else:
				towrite = entry
		else:
			towrite = entry
		# if this fails, we got an unprintable character
		try:
			towrite = str(towrite)
		except:
			# one at a time
			towrite2 = ""
			for c in towrite:
				try:
					towrite2 += str(c)
				except:
					towrite2 += "\\x" + str(hex(ord(c))).replace("0x","")
			towrite = towrite2
		try:
			with open(logfile,"a") as fh:
				if towrite.find('\n') > -1:
					fh.writelines(towrite)
				else:
					fh.write(towrite+"\n")
		except:
			pass
		return True
	

#---------------------------------------#
#  Simple Queue class                   #
#---------------------------------------#
class MnQueue:
	"""
	Simple queue class
	"""
	def __init__(self):
		self.holder = []
		
	def enqueue(self,val):
		self.holder.append(val)
		
	def dequeue(self):
		val = None
		try:
			val = self.holder[0]
			if len(self.holder) == 1:
				self.holder = []
			else:
				self.holder = self.holder[1:]	
		except:
			pass
			
		return val	
		
	def IsEmpty(self):
		result = False
		if len(self.holder) == 0:
			result = True
		return result	


#---------------------------------------#
#  Class to access module properties    #
#---------------------------------------#
	
class MnModule:
	"""
	Class to access module properties
	"""
	def __init__(self, modulename):
		#dbg.log("MnModule(%s)" % modulename)
		modisaslr = True
		modissafeseh = True
		modrebased = True
		modisnx = True
		modisos = True
		self.IAT = {}
		self.EAT = {}
		path = ""
		mzbase = 0
		mzsize = 0
		mztop = 0
		mcodebase = 0
		mcodesize = 0
		mcodetop = 0
		mentry = 0
		mversion = ""
		self.internalname = modulename
		if modulename != "":
			# if info is cached, retrieve from cache
			if ModInfoCached(modulename):
				modisaslr = getModuleProperty(modulename,"aslr")
				modissafeseh = getModuleProperty(modulename,"safeseh")
				modrebased = getModuleProperty(modulename,"rebase")
				modisnx = getModuleProperty(modulename,"nx")
				modisos = getModuleProperty(modulename,"os")
				path = getModuleProperty(modulename,"path")
				mzbase = getModuleProperty(modulename,"base")
				mzsize = getModuleProperty(modulename,"size")
				mztop = getModuleProperty(modulename,"top")
				mversion = getModuleProperty(modulename,"version")
				mentry = getModuleProperty(modulename,"entry")
				mcodebase = getModuleProperty(modulename,"codebase")
				mcodesize = getModuleProperty(modulename,"codesize")
				mcodetop = getModuleProperty(modulename,"codetop")
			else:
				#gather info manually - this code should only get called from populateModuleInfo()
				self.moduleobj = dbg.getModule(modulename)
				modissafeseh = True
				modisaslr = True
				modisnx = True
				modrebased = False
				modisos = False
				#if self.moduleobj == None:
				#	dbg.log("*** Error - self.moduleobj is None, key %s" % modulename, highlight=1)
				mod       = self.moduleobj
				mzbase    = mod.getBaseAddress()
				mzrebase  = mod.getFixupbase()
				mzsize    = mod.getSize()
				mversion  = mod.getVersion()
				mentry    = mod.getEntry() 
				mcodebase = mod.getCodebase()
				mcodesize = mod.getCodesize()
				mcodetop  = mcodebase + mcodesize
				
				mversion=mversion.replace(", ",".")
				mversionfields=mversion.split('(')
				mversion=mversionfields[0].replace(" ","")
								
				if mversion=="":
					mversion="-1.0-"
				path=mod.getPath()
				if mod.getIssystemdll() == 0:
					modisos = "WINDOWS" in path.upper()
				else:
					modisos = True
				mztop = mzbase + mzsize
				if mzbase > 0:
					peoffset=struct.unpack('<L',dbg.readMemory(mzbase+0x3c,4))[0]
					pebase=mzbase+peoffset
					osver=dbg.getOsVersion()
					safeseh_offset = [0x5f, 0x5f, 0x5e]
					safeseh_flag = [0x4, 0x4, 0x400]
					os_index = 0
					# Vista / Win7 / Win8
					if win7mode:
						os_index = 2
					flags=struct.unpack('<H',dbg.readMemory(pebase+safeseh_offset[os_index],2))[0]
					numberofentries=struct.unpack('<L',dbg.readMemory(pebase+0x74,4))[0]
					#safeseh ?
					if (flags&safeseh_flag[os_index])!=0:
						modissafeseh=True
					else:
						if numberofentries>10:
							sectionaddress,sectionsize=struct.unpack('<LL',dbg.readMemory(pebase+0x78+8*10,8))
							sectionaddress+=mzbase
							data=struct.unpack('<L',dbg.readMemory(sectionaddress,4))[0]
							condition = False
							if os_index < 2:
								condition=(sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==data))
							else:
								condition=(sectionsize!=0) and ((sectionsize==0x40))
							if condition==False:
								modissafeseh=False
							else:
								sehlistaddress,sehlistsize=struct.unpack('<LL',dbg.readMemory(sectionaddress+0x40,8))
								if sehlistaddress!=0 and sehlistsize!=0:
									modissafeseh=True
								else:
									modissafeseh=False
				
					#aslr
					if (flags&0x0040)==0:  # 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
						modisaslr=False
					#nx
					if (flags&0x0100)==0:
						modisnx=False
					#rebase
					if mzrebase != mzbase:
						modrebased=True
		else:
			# should never be hit
			#print "No module specified !!!"
			#print "stacktrace : "
			#print traceback.format_exc()
			return None

		#check if module is excluded
		thisconfig = MnConfig()
		allexcluded = []
		excludedlist = thisconfig.get("excluded_modules")
		modfound = False
		if excludedlist:
			allexcluded = excludedlist.split(',')
			for exclentry in allexcluded:
				if exclentry.lower().strip() == modulename.lower().strip():
					modfound = True
		self.isExcluded = modfound
		
		#done - populate variables
		self.isAslr = modisaslr
		
		self.isSafeSEH = modissafeseh
		
		self.isRebase = modrebased
		
		self.isNX = modisnx
		
		self.isOS = modisos
		
		self.moduleKey = modulename
	
		self.modulePath = path
		
		self.moduleBase = mzbase
		
		self.moduleSize = mzsize
		
		self.moduleTop = mztop
		
		self.moduleVersion = mversion
		
		self.moduleEntry = mentry
		
		self.moduleCodesize = mcodesize
		
		self.moduleCodetop = mcodetop
		
		self.moduleCodebase = mcodebase
		
			
	
	def __str__(self):
		#return general info about the module
		#modulename + info
		"""
		Get information about a module (human readable format)

		Arguments:
		None

		Return:
		String with various properties about a module
		"""			
		outstring = ""
		if self.moduleKey != "":
			outstring = "[" + self.moduleKey + "] ASLR: " + str(self.isAslr) + ", Rebase: " + str(self.isRebase) + ", SafeSEH: " + str(self.isSafeSEH) + ", OS: " + str(self.isOS) + ", v" + self.moduleVersion + " (" + self.modulePath + ")"
		else:
			outstring = "[None]"
		return outstring
		
	def isAslr(self):
		return self.isAslr
		
	def isSafeSEH(self):
		return self.isSafeSEH
		
	def isRebase(self):
		return self.isRebase
		
	def isOS(self):
		return self.isOS
	
	def isNX(self):
		return self.isNX
		
	def moduleKey(self):
		return self.moduleKey
		
	def modulePath(self):
		return self.modulePath
	
	def moduleBase(self):
		return self.moduleBase
	
	def moduleSize(self):
		return self.moduleSize
	
	def moduleTop(self):
		return self.moduleTop
	
	def moduleEntry(self):
		return self.moduleEntry
		
	def moduleCodebase(self):
		return self.moduleCodebase
	
	def moduleCodesize(self):
		return self.moduleCodesize
		
	def moduleCodetop(self):
		return self.moduleCodetop
		
	def moduleVersion(self):
		return self.moduleVersion
		
	def isExcluded(self):
		return self.isExcluded
	
	def getFunctionCalls(self,criteria={}):
		funccalls = {}
		sequences = []
		sequences.append(["call","\xff\x15"])
		funccalls = searchInRange(sequences, self.moduleBase, self.moduleTop,criteria)
		return funccalls
		
	def getIAT(self):
		IAT = {}
		global IATCache
		dbg.logLines("    Getting IAT for %s." % (self.moduleKey))
		try:
			if not self.moduleKey in IATCache:  # if len(self.IAT) == 0:
				dbg.log("    Enumerating IAT")          
				try:
					themod = dbg.getModule(self.moduleKey)
					syms = themod.getSymbols()
					thename = ""
					for sym in syms:
						if syms[sym].getType().startswith("Import"):
							thename = syms[sym].getName()
							theaddress = syms[sym].getAddress()
							if not theaddress in IAT:
								IAT[theaddress] = thename
				except:
					import traceback
					dbg.logLines(traceback.format_exc())
					pass
				# merge
				
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L',dbg.readMemory(PEHeader_ref,4))[0]
				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location+0x14,2)
				sizeOfOptionalHeader = struct.unpack('<L',bsizeOfOptionalHeader+"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18
				if sizeOfOptionalHeader > 0:
					# get address of DataDirectory
					DataDirectory_location = OptionalHeader_location + 0x60
					# get size of Import Table
					importtable_size = struct.unpack('<L',dbg.readMemory(DataDirectory_location+0x64,4) )[0]
					importtable_rva = struct.unpack('<L',dbg.readMemory(DataDirectory_location+0x60,4) )[0]
					iatAddr = self.moduleBase + importtable_rva
					max_nr_entries = importtable_size / 4
					iatcnt = 0
					while iatcnt < max_nr_entries:
						thisloc = iatAddr + (4*iatcnt)
						iatEntry = struct.unpack('<L',dbg.readMemory(thisloc,4) )[0]
						if iatEntry > 0:
							ptr = iatEntry
							ptrx = MnPointer(iatEntry)
							modname = ptrx.belongsTo()
							tmod = MnModule(modname)
							thisfunc = dbglib.Function(dbg,ptr)
							thisfuncfullname = thisfunc.getName().lower()
							if thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % ptr):
								if not tmod is None:
									imagename = tmod.getShortName()
									eatlist = tmod.getEAT()
									if iatEntry in eatlist:
										thisfuncfullname =  "." + imagename + "!" + eatlist[iatEntry]	
										thisfuncname = thisfuncfullname.split('.')
										IAT[thisloc] = thisfuncname[1].strip(">")
									else:
										IAT[thisloc] = imagename + "!0x%08x" % iatEntry
							else:	
								IAT[thisloc] = thisfuncfullname.replace(".","!")
						iatcnt += 1
				
				if len(IAT) == 0:
					#search method nr 2, not accurate, but will find *something*
					funccalls = self.getFunctionCalls()
					for functype in funccalls:
						for fptr in funccalls[functype]:
							ptr=struct.unpack('<L',dbg.readMemory(fptr+2,4))[0]
							if ptr >= self.moduleBase and ptr <= self.moduleTop:
								if not ptr in IAT:
									thisfunc = dbglib.Function(dbg,ptr)
									thisfuncfullname = thisfunc.getName().lower()
									thisfuncname = []
									if thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % ptr):
										iatptr = struct.unpack('<L',dbg.readMemory(ptr,4))[0]
										# see if we can find the original function name using the EAT
										tptr = MnPointer(ptr)
										modname = tptr.belongsTo()
										tmod = MnModule(modname)
										ofullname = thisfuncfullname
										
										if not tmod is None:
											imagename = tmod.getShortName()
											eatlist = tmod.getEAT()
											if iatptr in eatlist:
												thisfuncfullname =  "." + imagename + "!" + eatlist[iatptr]
										if thisfuncfullname == ofullname:
											tparts = thisfuncfullname.split('.')
											thisfuncfullname = tparts[0] + (".%08x" % iatptr)
									thisfuncname = thisfuncfullname.split('.')
									IAT[ptr] = thisfuncname[1].strip(">")
									
				self.IAT = IAT
				IATCache[self.moduleKey] = IAT
			else:
				dbg.log("    Retrieving IAT from cache")             
				IAT = IATCache[self.moduleKey] #IAT = self.IAT
		except:
			import traceback
			dbg.logLines(traceback.format_exc())
			return IAT
		return IAT
		
		
	def getEAT(self):
		eatlist = {}
		if len(self.EAT) == 0:
			try:
				# avoid major suckage, let's do it ourselves
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L',dbg.readMemory(PEHeader_ref,4))[0]
				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location+0x14,2)
				sizeOfOptionalHeader = struct.unpack('<L',bsizeOfOptionalHeader+"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18
				if sizeOfOptionalHeader > 0:
					# get address of DataDirectory
					DataDirectory_location = OptionalHeader_location + 0x60
					# get size of Export Table
					exporttable_size = struct.unpack('<L',dbg.readMemory(DataDirectory_location+4,4) )[0]
					exporttable_rva = struct.unpack('<L',dbg.readMemory(DataDirectory_location,4) )[0]
					if exporttable_size > 0:
						# get start of export table
						eatAddr = self.moduleBase + exporttable_rva
						nr_of_names = struct.unpack('<L',dbg.readMemory(eatAddr + 0x18,4))[0]
						rva_of_names = self.moduleBase + struct.unpack('<L',dbg.readMemory(eatAddr + 0x20,4))[0]
						address_of_functions =  self.moduleBase + struct.unpack('<L',dbg.readMemory(eatAddr + 0x1c,4))[0]
						for i in range(0, nr_of_names):
							eatName = dbg.readString(self.moduleBase + struct.unpack('<L',dbg.readMemory(rva_of_names + (4 * i),4))[0])
							eatAddress = self.moduleBase + struct.unpack('<L',dbg.readMemory(address_of_functions + (4 * i),4))[0]
							eatlist[eatAddress] = eatName
				self.EAT = eatlist
			except:
				return eatlist
		else:
			eatlist = self.EAT
		return eatlist
	
	
	def getShortName(self):
		return stripExtension(self.moduleKey)


def getNtGlobalFlag():
	pebaddress = dbg.getPEBAddress()
	global NtGlobalFlag
	if NtGlobalFlag == -1:
		try:
			NtGlobalFlag = struct.unpack('<L',dbg.readMemory(pebaddress+0x068,4))[0]
		except:
			NtGlobalFlag = 0
	return NtGlobalFlag

def getNtGlobalFlagDefinitions():
	definitions = {}
	
	definitions[0x0]		= ["","No GFlags enabled"]
	
	definitions[0x00000001]	= ["soe", "Stop On Execute"]
	definitions[0x00000002]	= ["sls", "Show Loader Snaps"]
	definitions[0x00000004]	= ["dic", "Debug Initial Command"]
	definitions[0x00000008]	= ["shg", "Stop On Hung GUI"]
	
	definitions[0x00000010]	= ["htc", "Enable Heap Tail Checking"]
	definitions[0x00000020]	= ["hfc", "Enable Heap Free Checking"]
	definitions[0x00000040]	= ["hpc", "Enable Heap Parameter Checking"]
	definitions[0x00000080]	= ["hvc", "Enable Heap Validation On Call"]
	
	definitions[0x00000100]	= ["vrf", "Enable Application Verifier"]
	definitions[0x00000200]	= ["   ", "Enable Silent Process Exit Monitoring"]
	if not win7mode:
		definitions[0x00000400]	= ["ptg", "Enable Pool Tagging"]
	definitions[0x00000800]	= ["htg", "Enable Heap Tagging"]
	
	definitions[0x00001000]	= ["ust", "Create User Mode Stack Trace"]
	definitions[0x00002000]	= ["kst", "Create Kernel Mode Stack Trace"]
	definitions[0x00004000]	= ["otl", "Maintain A List Of Objects For Each Type"]
	definitions[0x00008000]	= ["htd", "Enable Heap Tagging By DLL"]
	
	definitions[0x00010000]	= ["dse", "Disable Stack Extension"]
	definitions[0x00020000]	= ["d32", "Enable Debugging Of Win32 Subsystem"]
	definitions[0x00040000]	= ["ksl", "Enable Loading Of Kernel Debugger Symbols"]
	definitions[0x00080000]	= ["dps", "Disable Paging Of Kernel Stacks"]
	
	definitions[0x00100000]	= ["scb", "Enable System Critical Breaks"]
	definitions[0x00200000]	= ["dhc", "Disable Heap Coalesce On Free"]
	definitions[0x00400000]	= ["ece", "Enable Close Exception"]
	definitions[0x00800000]	= ["eel", "Enable Exception Logging"]
	
	definitions[0x01000000]	= ["eot", "Early Object Handle Type Tagging"]
	definitions[0x02000000]	= ["hpa", "Enable Page Heap"]
	definitions[0x04000000]	= ["dwl", "Debug WinLogon"]
	definitions[0x08000000]	= ["ddp", "Buffer DbgPrint Output"]

	definitions[0x10000000] = ["cse", "Early Critical Section Event Creation"]
	definitions[0x40000000] = ["bhd", "Disable Bad Handles Detection"]
	definitions[0x80000000]	= ["dpd", "Disable Protected DLL Verification"]
	
	return definitions



def getNtGlobalFlagValues(flag):
	allvalues = []
	for defvalue in getNtGlobalFlagDefinitions():
		if defvalue > 0:
			allvalues.append(defvalue)
	# sort list descending
	allvalues.sort(reverse=True)
	flagvalues = []
	remaining = flag
	for flagvalue in allvalues:
		if flagvalue <= remaining:
			remaining -= flagvalue
			if remaining >= 0:
				flagvalues.append(flagvalue)
	return flagvalues

def getNtGlobalFlagNames(flag):
	names = []
	allvalues = getNtGlobalFlagDefinitions()
	currentvalues = getNtGlobalFlagValues(flag)
	for defvalue in currentvalues:
		if defvalue > 0:
			names.append(allvalues[defvalue][0])
	return names

def getNtGlobalFlagValueData(flagvalue):
	toreturn = ["",""]
	if flagvalue in getNtGlobalFlagDefinitions():
		toreturn = getNtGlobalFlagDefinitions()[flagvalue]
	return toreturn


def getActiveFlagNames(flagvalue):
	currentflags = getNtGlobalFlagValues(flagvalue)
	flagdefs = getNtGlobalFlagDefinitions()
	flagnames = []
	if len(currentflags) == 0:
		currentflags = [0]
	for flag in currentflags:
		if flag in flagdefs:
			flagdata = flagdefs[flag]
			flagnames.append(flagdata[0])
	return ",".join(flagnames)


def getNtGlobalFlagValueName(flagvalue):
	data = getNtGlobalFlagValueData(flagvalue)
	toreturn = ""
	if data[0] != "":
		toreturn += "+" + data[0]
	else:
		toreturn += "    "
	toreturn += " - "
	toreturn += data[1]
	return toreturn


#---------------------------------------#
#  Class for heap structures            #
#---------------------------------------#		
class MnHeap:
	"""
	Class for heap structures
	"""
	heapbase = 0
	EncodeFlagMask = 0
	Encoding = 0

	# _HEAP
	# Windows XP
	# ----------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 Signature        : Uint4B
	# +0x00c Flags            : Uint4B
	# +0x010 ForceFlags       : Uint4B
	# +0x014 VirtualMemoryThreshold : Uint4B
	# +0x018 SegmentReserve   : Uint4B
	# +0x01c SegmentCommit    : Uint4B
	# +0x020 DeCommitFreeBlockThreshold : Uint4B
	# +0x024 DeCommitTotalFreeThreshold : Uint4B
	# +0x028 TotalFreeSize    : Uint4B
	# +0x02c MaximumAllocationSize : Uint4B
	# +0x030 ProcessHeapsListIndex : Uint2B
	# +0x032 HeaderValidateLength : Uint2B
	# +0x034 HeaderValidateCopy : Ptr32 Void
	# +0x038 NextAvailableTagIndex : Uint2B
	# +0x03a MaximumTagIndex  : Uint2B
	# +0x03c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x040 UCRSegments      : Ptr32 _HEAP_UCR_SEGMENT
	# +0x044 UnusedUnCommittedRanges : Ptr32 _HEAP_UNCOMMMTTED_RANGE
	# +0x048 AlignRound       : Uint4B
	# +0x04c AlignMask        : Uint4B
	# +0x050 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x058 Segments         : [64] Ptr32 _HEAP_SEGMENT
	# +0x158 u                : __unnamed
	# +0x168 u2               : __unnamed
	# +0x16a AllocatorBackTraceIndex : Uint2B
	# +0x16c NonDedicatedListLength : Uint4B
	# +0x170 LargeBlocksIndex : Ptr32 Void
	# +0x174 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x178 FreeLists        : [128] _LIST_ENTRY
	# +0x578 LockVariable     : Ptr32 _HEAP_LOCK
	# +0x57c CommitRoutine    : Ptr32     long 
	# +0x580 FrontEndHeap     : Ptr32 Void
	# +0x584 FrontHeapLockCount : Uint2B
	# +0x586 FrontEndHeapType : UChar
	# +0x587 LastSegmentIndex : UChar

	# Windows 7
	# ---------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 SegmentSignature : Uint4B
	# +0x00c SegmentFlags     : Uint4B
	# +0x010 SegmentListEntry : _LIST_ENTRY
	# +0x018 Heap             : Ptr32 _HEAP
	# +0x01c BaseAddress      : Ptr32 Void
	# +0x020 NumberOfPages    : Uint4B
	# +0x024 FirstEntry       : Ptr32 _HEAP_ENTRY
	# +0x028 LastValidEntry   : Ptr32 _HEAP_ENTRY
	# +0x02c NumberOfUnCommittedPages : Uint4B
	# +0x030 NumberOfUnCommittedRanges : Uint4B
	# +0x034 SegmentAllocatorBackTraceIndex : Uint2B
	# +0x036 Reserved         : Uint2B
	# +0x038 UCRSegmentList   : _LIST_ENTRY
	# +0x040 Flags            : Uint4B
	# +0x044 ForceFlags       : Uint4B
	# +0x048 CompatibilityFlags : Uint4B
	# +0x04c EncodeFlagMask   : Uint4B
	# +0x050 Encoding         : _HEAP_ENTRY
	# +0x058 PointerKey       : Uint4B
	# +0x05c Interceptor      : Uint4B
	# +0x060 VirtualMemoryThreshold : Uint4B
	# +0x064 Signature        : Uint4B
	# +0x068 SegmentReserve   : Uint4B
	# +0x06c SegmentCommit    : Uint4B
	# +0x070 DeCommitFreeBlockThreshold : Uint4B
	# +0x074 DeCommitTotalFreeThreshold : Uint4B
	# +0x078 TotalFreeSize    : Uint4B
	# +0x07c MaximumAllocationSize : Uint4B
	# +0x080 ProcessHeapsListIndex : Uint2B
	# +0x082 HeaderValidateLength : Uint2B
	# +0x084 HeaderValidateCopy : Ptr32 Void
	# +0x088 NextAvailableTagIndex : Uint2B
	# +0x08a MaximumTagIndex  : Uint2B
	# +0x08c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x090 UCRList          : _LIST_ENTRY
	# +0x098 AlignRound       : Uint4B
	# +0x09c AlignMask        : Uint4B
	# +0x0a0 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x0a8 SegmentList      : _LIST_ENTRY
	# +0x0b0 AllocatorBackTraceIndex : Uint2B
	# +0x0b4 NonDedicatedListLength : Uint4B
	# +0x0b8 BlocksIndex      : Ptr32 Void
	# +0x0bc UCRIndex         : Ptr32 Void
	# +0x0c0 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x0c4 FreeLists        : _LIST_ENTRY
	# +0x0cc LockVariable     : Ptr32 _HEAP_LOCK
	# +0x0d0 CommitRoutine    : Ptr32     long 
	# +0x0d4 FrontEndHeap     : Ptr32 Void
	# +0x0d8 FrontHeapLockCount : Uint2B
	# +0x0da FrontEndHeapType : UChar
	# +0x0dc Counters         : _HEAP_COUNTERS
	# +0x130 TuningParameters : _HEAP_TUNING_PARAMETERS	
	
	def __init__(self,address):
		self.heapbase = address
		self.VirtualAllocdBlocks = {}
		self.LookAsideList = {}
		self.SegmentList = {}
		self.lalheads = {}
		self.Encoding = 0
		self.FrontEndHeap = 0
		return None


	def getEncodingKey(self):
		"""
		Retrieves the Encoding key from the current heap

		Return: Int, containing the Encoding key (on Windows 7 and up)
		or zero on older Operating Systems
		"""
		self.Encoding = 0
		if win7mode:
			offset = archValue(0x4c,0x7c)
			self.EncodeFlagMask = struct.unpack('<L',dbg.readMemory(self.heapbase+offset,4))[0]
			if self.EncodeFlagMask == 0x100000:
				if arch == 32:
					self.Encoding = struct.unpack('<L',dbg.readMemory(self.heapbase+0x50,4))[0]
				elif arch == 64:
					self.Encoding = struct.unpack('<L',dbg.readMemory(self.heapbase+0x80+0x8,4))[0]
		return self.Encoding


	def getHeapChunkHeaderAtAddress(self,thischunk,headersize=8,type="chunk"):
		"""
		Will convert the bytes placed at a certain address into an MnChunk object
		"""

		key = self.getEncodingKey()
		fullheaderbin = ""
		if type == "chunk" or type == "lal" or type == "freelist":
			chunktype = "chunk"
			if key == 0 and not win7mode:
				fullheaderbin = dbg.readMemory(thischunk,headersize)
			else:
				fullheaderbin = decodeHeapHeader(thischunk,headersize,key)
			# if we have heap corruption, thischunk may not be a readable address
			# so fullheaderbin would be empty
			if len(fullheaderbin) == headersize:
				sizebytes = fullheaderbin[0:2]
				thissize = struct.unpack('<H',sizebytes)[0]
				prevsize = 0
				segmentid = 0
				flag = 0
				unused = 0
				tag = 0

				if key == 0 and not win7mode:
					prevsize = struct.unpack('<H',fullheaderbin[2:4])[0]
					segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
					flag = struct.unpack('<B',fullheaderbin[5:6])[0]
					unused = struct.unpack('<B',fullheaderbin[6:7])[0]
					tag = struct.unpack('<B',fullheaderbin[7:8])[0]		
				else:
					flag = struct.unpack('<B',fullheaderbin[2:3])[0]
					tag = struct.unpack('<B',fullheaderbin[3:4])[0]
					prevsize = struct.unpack('<H',fullheaderbin[4:6])[0]
					segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
					unused = struct.unpack('<B',fullheaderbin[7:8])[0]

				flink = 0
				blink = 0
				if type == "lal" or type == "freelist":
					flink = struct.unpack('<L',dbg.readMemory(thischunk+headersize,4))[0]
				if type == "freelist":
					blink = struct.unpack('<L',dbg.readMemory(thischunk+headersize+4,4))[0]
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,thissize,prevsize,segmentid,flag,unused,tag,flink,blink)
			else:
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,0,0,0,0,0,0,0,0)

		return None


	def getFrontEndHeap(self):
		"""
		Returns the value of the FrontEndHeap field in the heapbase
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))


	def getFrontEndHeapType(self):
		"""
		Returns the value of the FrontEndHeapType field in the heapbase
		"""
		return struct.unpack('B',dbg.readMemory(self.heapbase+getOsOffset("FrontEndHeapType"),1))[0]

	def getLookAsideHead(self):
		"""
		Returns the LookAside List Head as a dictionary of dictionaries
		"""
		if not win7mode:
			self.FrontEndHeap = self.getFrontEndHeap()
			self.FrontEndHeapType = self.getFrontEndHeapType()
			if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1 and len(self.lalheads) == 0:
				lalindex = 0
				startloc = self.FrontEndHeap
				while lalindex < 128:
					thisptr = self.FrontEndHeap + (0x30 * lalindex)
					lalheadfields = {}
					# read the next 0x30 bytes and break down into lal head elements
					lalheadbin = dbg.readMemory(thisptr,0x30)
					lalheadfields["Next"] = struct.unpack('<L',lalheadbin[0:4])[0]
					lalheadfields["Depth"] = struct.unpack('<H',lalheadbin[4:6])[0]
					lalheadfields["Sequence"] = struct.unpack('<H',lalheadbin[6:8])[0]
					lalheadfields["Depth2"] = struct.unpack('<H',lalheadbin[8:0xa])[0]
					lalheadfields["MaximumDepth"] = struct.unpack('<H',lalheadbin[0xa:0xc])[0]
					lalheadfields["TotalAllocates"] = struct.unpack('<L',lalheadbin[0xc:0x10])[0]
					lalheadfields["AllocateMisses"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0]
					lalheadfields["AllocateHits"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0] 
					lalheadfields["TotalFrees"] = struct.unpack('<L',lalheadbin[0x14:0x18])[0]
					lalheadfields["FreeMisses"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
					lalheadfields["FreeHits"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
					lalheadfields["Type"] = struct.unpack('<L',lalheadbin[0x1c:0x20])[0]
					lalheadfields["Tag"] = struct.unpack('<L',lalheadbin[0x20:0x24])[0]
					lalheadfields["Size"] = struct.unpack('<L',lalheadbin[0x24:0x28])[0]
					lalheadfields["Allocate"] = struct.unpack('<L',lalheadbin[0x28:0x2c])[0]
					lalheadfields["Free"] = struct.unpack('<L',lalheadbin[0x2c:0x30])[0]
					self.lalheads[lalindex] = lalheadfields
					lalindex += 1
		return self.lalheads

	def showLookAsideHead(self,lalindex):
		if len(self.lalheads) == 0:
			self.getLookAsideHead()
		if lalindex in self.lalheads:
			thislalhead = self.lalheads[lalindex]
			dbg.log("  Next: 0x%08x" % thislalhead["Next"])
			dbg.log("  Depth: 0x%04x" % thislalhead["Depth"])
			dbg.log("  Sequence: 0x%04x" % thislalhead["Sequence"])
			dbg.log("  Depth2: 0x%04x" % thislalhead["Depth2"])
			dbg.log("  MaximumDepth: 0x%04x" % thislalhead["MaximumDepth"])
			dbg.log("  TotalAllocates: 0x%08x" % thislalhead["TotalAllocates"])
			dbg.log("  AllocateMisses/AllocateHits: 0x%08x" % thislalhead["AllocateMisses"])
			dbg.log("  TotalFrees: 0x%08x" % thislalhead["TotalFrees"])
			dbg.log("  FreeMisses/FreeHits: 0x%08x" % thislalhead["FreeMisses"])
			dbg.log("  Type 0x%08x" % thislalhead["Type"])
			dbg.log("  Tag: 0x%08x" % thislalhead["Tag"])
			dbg.log("  Size: 0x%08x" % thislalhead["Size"])
			dbg.log("  Allocate: 0x%08x" % thislalhead["Allocate"])
			dbg.log("  Free: 0x%08x" % thislalhead["AllocateMisses"])
		return 

	def getLookAsideList(self):
		"""
		Retrieves the LookAsideList (if enabled) for the current heap
		Returns : a dictionary, key = LAL index
		Each element in the dictionary contains a dictionary, using a sequence nr as key,
		    and each element in this dictionary contains an MnChunk object
		"""
		lal = {}
		if not win7mode:
			self.FrontEndHeap = self.getFrontEndHeap()
			self.FrontEndHeapType = self.getFrontEndHeapType()
			if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1:
				lalindex = 0
				startloc = self.FrontEndHeap
				while lalindex < 128:
					thisptr = self.FrontEndHeap + (0x30 * lalindex)
					lalhead_flink = struct.unpack('<L',dbg.readMemory(thisptr,4))[0]
					if lalhead_flink != 0:
						thissize = (lalindex * 8)
						next_flink = lalhead_flink
						seqnr = 0
						thislal = {} 
						while next_flink != 0 and next_flink != startloc:
							chunk = self.getHeapChunkHeaderAtAddress(next_flink-8,8,"lal")
							next_flink = chunk.flink
							thislal[seqnr] = chunk
							seqnr += 1
						lal[lalindex] = thislal
					lalindex += 1
		return lal

	def getFreeListInUseBitmap(self):
		global FreeListBitmap
		if not self.heapbase in FreeListBitmap:
			FreeListBitmapHeap = []
			cnt = 0
			while cnt < 4:
				fldword = dbg.readLong(self.heapbase+0x158 + (4 * cnt))
				bitmapbits = DwordToBits(fldword)
				#print "0x%08x : %s (%d)" % (fldword,bitmapbits,len(bitmapbits))
				for thisbit in bitmapbits:
					FreeListBitmapHeap.append(thisbit)
				cnt += 1
			FreeListBitmap[self.heapbase] = FreeListBitmapHeap
		return FreeListBitmap[self.heapbase]


	def getFreeList(self):
		"""
		Retrieves the FreeLists (XP/2003) for the current heap
		Returns : a dictionary, key = FreeList table index
		Each element in the dictionary contains a dictionary, using the FreeList position as key
			and each element in this dictionary contains an MnChunk object		
		"""
		freelists = {}
		if not win7mode:
			flindex = 0
			while flindex < 128:
				freelistflink = self.heapbase + 0x178 + (8 * flindex) + 4
				freelistblink = self.heapbase + 0x178 + (8 * flindex)
				endchain = False
				try:
					tblink = struct.unpack('<L',dbg.readMemory(freelistflink,4))[0]
					tflink = struct.unpack('<L',dbg.readMemory(freelistblink,4))[0]
					origblink = freelistblink
					if freelistblink != tblink:
						thisfreelist = {}
						endchain = False
						thisfreelistindex = 0
						pflink = 0
						while not endchain:
							try:
								freelistentry = self.getHeapChunkHeaderAtAddress(tflink-8,8,"freelist")
								thisfreelist[thisfreelistindex] = freelistentry
								thisfreelistindex += 1
								thisblink = struct.unpack('<L',dbg.readMemory(tflink+4,4))[0]
								thisflink = struct.unpack('<L',dbg.readMemory(tflink,4))[0]
								tflink=thisflink
								if (tflink == origblink) or (tflink == pflink):
									endchain = True
								pflink = tflink 
							except:
								endchain = True
						freelists[flindex] = thisfreelist
				except:
					continue
				flindex += 1
		return freelists	


	def getVirtualAllocdBlocks(self):
		"""
		Retrieves the VirtualAllocdBlocks list from the selected heap

		Return: A dictionary, using the start of a virtualallocdblock as key
		Each entry in the dictionary contains a MnChunk object, with chunktype set to "virtualalloc"
		"""
		global VACache
		offset = getOsOffset("VirtualAllocdBlocks")
		encodingkey = 0
		if win7mode:
			encodingkey = self.getEncodingKey()
		if not self.heapbase in VACache:
			try:
				# get virtualallocdBlocks for this heap
				vaptr = self.heapbase + offset
				valistentry = struct.unpack('<L',dbg.readMemory(vaptr,4))[0]
				while valistentry != vaptr:
					# get VA Header info
					# header:
					#            	size    size
					#               (x86)   (x64)
					#               =====   =====
					# FLINK         4       8
					# BLINK      	4       8
					# Normal header 8       16    encoded on Win7+
					# CommitSize    4       8
					# ReserveSize   4       8     = requested size
					# BusyBlock     8       16

					headersize = 0
					heoffset = 0 # HEAP_ENTRY offset (@ BusyBlock)
					vaheader = None
					flink = 0
					blink = 0
					commitsize = 0
					reservesize = 0
					size = 0

					if arch == 32:
						headersize = 32
						heoffset = 24
						vaheader = dbg.readMemory(valistentry,headersize)
						flink = struct.unpack('<L',vaheader[0:4])[0]
						blink = struct.unpack('<L',vaheader[4:8])[0]
						commitsize = struct.unpack('<L',vaheader[16:20])[0]
						reservesize = struct.unpack('<L',vaheader[20:24])[0]
					elif arch == 64:
						headersize = 64
						heoffset = 48
						vaheader = dbg.readMemory(valistentry,headersize)
						flink = struct.unpack('<Q',vaheader[0:8])[0]
						blink = struct.unpack('<Q',vaheader[8:16])[0]
						commitsize = struct.unpack('<Q',vaheader[32:40])[0]
						reservesize = struct.unpack('<Q',vaheader[40:48])[0]

					size_e = struct.unpack('<H',vaheader[heoffset:heoffset+2])[0]
					if win7mode:
						size = (size_e ^ (encodingkey & 0xFFFF))
					else:
						size = size_e

					#prevsize = struct.unpack('<H',vaheader[26:28])[0]
					prevsize = 0
					segmentid = struct.unpack('<B',vaheader[heoffset+4:heoffset+5])[0]
					flag = struct.unpack('<B',vaheader[heoffset+5:heoffset+6])[0]
					if win7mode:
						flag = struct.unpack('<B',vaheader[heoffset+2:heoffset+3])[0]
					unused = struct.unpack('<B',vaheader[heoffset+6:heoffset+7])[0]
					tag = struct.unpack('<B',vaheader[heoffset+7:])[0]

					chunkobj = MnChunk(valistentry,"virtualalloc",headersize,self.heapbase,0,size,prevsize,segmentid,flag,unused,tag,flink,blink,commitsize,reservesize)
					self.VirtualAllocdBlocks[valistentry] = chunkobj
					valistentry = struct.unpack('<L',dbg.readMemory(valistentry,4))[0]
				VACache[self.heapbase] = self.VirtualAllocdBlocks
			except:
				pass
		else:
			self.VirtualAllocdBlocks = VACache[self.heapbase]		
		return self.VirtualAllocdBlocks	

	def getHeapSegmentList(self):
		"""
		Will collect all segments for the current heap object

		Return: A dictionary, using the start of a segment as key
		Each entry in the dictionary has 4 fields :
		start of segment, end of segment, FirstEntry and LastValidEntry
		"""
		self.SegmentList = getSegmentsForHeap(self.heapbase)
		# segstart,segend,firstentry,lastentry
		return self.SegmentList

	def usesLFH(self):
		"""
		Checks if the current heap has LFH enabled

		Return: Boolean
		"""
		if win7mode:
			frontendheaptype = self.getFrontEndHeapType()
			if frontendheaptype == 0x2:
				return True
			else:
				return False
		else:
			return False
			
	def getLFHAddress(self):
		"""
		Retrieves the address of the Low Fragmentation Heap for the current heap

		Return: Int
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))

	def getState(self):
		"""
		Enumerates all segments, chunks and VirtualAllocdBlocks in the current heap

		Return: array of dicts 
			0 : segments  (with segment addy as key), contains list of chunks 
			1 : vablocks 
		Key: Heap
		Contents:
			Segment -> Chunks
			VA Blocks
		"""
		statedata = {}
		segments = getSegmentsForHeap(self.heapbase)
		for seg in segments:
			segstart = segments[seg][0]
			segend = segments[seg][1]
			FirstEntry = segments[seg][2]
			LastValidEntry = segments[seg][3]
			datablocks = walkSegment(FirstEntry,LastValidEntry,self.heapbase)
			statedata[seg] = datablocks
		return statedata

"""
Low Fragmentation Heap
"""
class MnLFH():

   # +0x000 Lock             : _RTL_CRITICAL_SECTION
   # +0x018 SubSegmentZones  : _LIST_ENTRY
   # +0x020 ZoneBlockSize    : Uint4B
   # +0x024 Heap             : Ptr32 Void
   # +0x028 SegmentChange    : Uint4B
   # +0x02c SegmentCreate    : Uint4B
   # +0x030 SegmentInsertInFree : Uint4B
   # +0x034 SegmentDelete    : Uint4B
   # +0x038 CacheAllocs      : Uint4B
   # +0x03c CacheFrees       : Uint4B
   # +0x040 SizeInCache      : Uint4B
   # +0x048 RunInfo          : _HEAP_BUCKET_RUN_INFO
   # +0x050 UserBlockCache   : [12] _USER_MEMORY_CACHE_ENTRY
   # +0x110 Buckets          : [128] _HEAP_BUCKET
   # +0x310 LocalData        : [1] _HEAP_LOCAL_DATA

   # blocks : LocalData->SegmentInfos->SubSegments (Mgmt List)->SubSegs
   
	# class attributes
	Lock = None
	SubSegmentZones = None
	ZoneBlockSize = None
	Heap = None
	SegmentChange = None
	SegmentCreate = None
	SegmentInsertInFree = None
	SegmentDelete = None
	CacheAllocs = None
	CacheFrees = None
	SizeInCache = None
	RunInfo = None
	UserBlockCache = None
	Buckets = None
	LocalData = None
	
	def __init__(self,lfhbase):
		self.lfhbase = lfhbase
		self.populateLFHFields()
		return
		
	def populateLFHFields(self):
		# read 0x310 bytes and split into pieces
		FLHHeader = dbg.readMemory(self.lfhbase,0x310)
		self.Lock = FLHHeader[0:0x18]
		self.SubSegmentZones = []
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x18:0x1c])[0])
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x1c:0x20])[0])
		self.ZoneBlockSize = struct.unpack('<L',FLHHeader[0x20:0x24])[0]
		self.Heap = struct.unpack('<L',FLHHeader[0x24:0x28])[0]
		self.SegmentChange = struct.unpack('<L',FLHHeader[0x28:0x2c])[0]
		self.SegmentCreate = struct.unpack('<L',FLHHeader[0x2c:0x30])[0]
		self.SegmentInsertInFree = struct.unpack('<L',FLHHeader[0x30:0x34])[0]
		self.SegmentDelete = struct.unpack('<L',FLHHeader[0x34:0x38])[0]
		self.CacheAllocs = struct.unpack('<L',FLHHeader[0x38:0x3c])[0]
		self.CacheFrees = struct.unpack('<L',FLHHeader[0x3c:0x40])[0]
		self.SizeInCache = struct.unpack('<L',FLHHeader[0x40:0x44])[0]
		self.RunInfo = []
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x48:0x4c])[0])
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x4c:0x50])[0])
		self.UserBlockCache = []
		cnt = 0
		while cnt < (12*4):
			self.UserBlockCache.append(struct.unpack('<L',FLHHeader[0x50+cnt:0x54+cnt])[0])
			cnt += 4

	def getSegmentInfo(self):
		# input : self.LocalData
		# output : return SubSegment
		return

	def getSubSegmentList(self):
		# input : SubSegment
		# output : subsegment mgmt list
		return

	def getSubSegment(self):
		# input : subsegment list
		# output : subsegments/blocks
		return

"""
MnHeap Childclass
"""
class MnSegment:
	def __init__(self,heapbase,segmentstart,segmentend,firstentry=0,lastvalidentry=0):
		self.heapbase = heapbase
		self.segmentstart = segmentstart
		self.segmentend = segmentend
		self.firstentry = segmentstart
		self.lastvalidentry = segmentend
		if firstentry > 0:
			self.firstentry = firstentry
		if lastvalidentry > 0:
			self.lastvalidentry = lastvalidentry
		self.chunks = {}

	def getChunks(self):
		"""
		Enumerate all chunks in the current segment
		Output : Dictionary, key = chunkptr
		         Values : MnChunk objects
		         chunktype will be set to "chunk"
		"""
		thischunk = self.firstentry
		allchunksfound = False
		allchunks = {}
		nextchunk = thischunk
		cnt = 0
		savedprevsize = 0
		mHeap = MnHeap(self.heapbase)
		key = mHeap.getEncodingKey()
		while not allchunksfound:
			thissize = 0
			prevsize = 0
			flag = 0
			unused = 0
			segmentid = 0
			tag = 0
			headersize = 0x8
			try:
				fullheaderbin = ""
				if key == 0 and not win7mode:
					fullheaderbin = dbg.readMemory(thischunk,headersize)
				else:
					fullheaderbin = decodeHeapHeader(thischunk,headersize,key)

				sizebytes = fullheaderbin[0:2]
				thissize = struct.unpack('<H',sizebytes)[0]
				
				if key == 0 and not win7mode:
					prevsizebytes = struct.unpack('<H',fullheaderbin[2:4])[0]
					segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
					flag = struct.unpack('<B',fullheaderbin[5:6])[0]
					unused = struct.unpack('<B',fullheaderbin[6:7])[0]
					tag = struct.unpack('<B',fullheaderbin[7:8])[0]
						
				else:
					flag = struct.unpack('<B',fullheaderbin[2:3])[0]
					tag = struct.unpack('<B',fullheaderbin[3:4])[0]
					prevsizebytes = struct.unpack('<H',fullheaderbin[4:6])[0]
					segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
					unused = struct.unpack('<B',fullheaderbin[7:8])[0]

				if savedprevsize == 0:
					prevsize = 0
					savedprevsize = thissize
				else:
					prevsize = savedprevsize
					savedprevsize = thissize

				#prevsize = prevsizebytes
					
			except:
				thissize = 0
				prevsize = 0
				flag = 0
				unused = 0

			if thissize > 0:
				nextchunk = thischunk + (thissize * 8)
			else:
				nextchunk += headersize

			chunktype = "chunk"
			if "virtall" in getHeapFlag(flag).lower() or "internal" in getHeapFlag(flag).lower():
				#chunktype = "virtualalloc"
				headersize = 0x20
					
			if not thischunk in allchunks and thissize > 0:
				mChunk = MnChunk(thischunk,chunktype,headersize,self.heapbase,self.segmentstart,thissize,prevsize,segmentid,flag,unused,tag)
				allchunks[thischunk] = mChunk
			
			thischunk = nextchunk

			if nextchunk >= self.lastvalidentry:
				allchunksfound = True
			if "last" in getHeapFlag(flag).lower():
				allchunksfound = True
			
			cnt += 1
		self.chunks = allchunks
		return allchunks

"""
Chunk class
"""
class MnChunk:
	chunkptr = 0
	chunktype = ""
	headersize = 0
	extraheadersize = 0
	heapbase = 0
	segmentbase = 0
	size = 0
	prevsize = 0
	segment = 0
	flag = 0
	flags = 0
	unused = 0
	tag = 0
	flink = 0
	blink = 0
	commitsize = 0
	reservesize = 0
	remaining = 0
	hasust = False
	dph_block_information_startstamp = 0 
	dph_block_information_heap = 0
	dph_block_information_requestedsize = 0 
	dph_block_information_actualsize = 0
	dph_block_information_traceindex = 0
	dph_block_information_stacktrace = 0
	dph_block_information_endstamp = 0	

	def __init__(self,chunkptr,chunktype,headersize,heapbase,segmentbase,size,prevsize,segment,flag,unused,tag,flink=0,blink=0,commitsize=0,reservesize=0):
		self.chunkptr = chunkptr
		self.chunktype = chunktype
		self.extraheadersize = 0
		self.remaining = 0
		self.dph_block_information_startstamp = 0 
		self.dph_block_information_heap = 0
		self.dph_block_information_requestedsize = 0 
		self.dph_block_information_actualsize = 0
		self.dph_block_information_traceindex = 0
		self.dph_block_information_stacktrace = 0
		self.dph_block_information_endstamp = 0
		self.hasust = False
		# if ust/hpa is enabled, the chunk header is followed by 32bytes of DPH_BLOCK_INFORMATION header info
		currentflagnames = getNtGlobalFlagNames(getNtGlobalFlag())
		if "ust" in currentflagnames:
			self.hasust = True
		if "hpa" in currentflagnames:
			# reader header info
			if arch == 32:
				self.extraheadersize = 0x20
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x20)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<L',raw_dph_header[4:8])[0]
					self.dph_block_information_requestedsize = struct.unpack('<L',raw_dph_header[8:12])[0]
					self.dph_block_information_actualsize = struct.unpack('<L',raw_dph_header[12:16])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[16:18])[0]
					self.dph_block_information_stacktrace = struct.unpack('<L',raw_dph_header[24:28])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[28:32])[0]
				except:
					pass
			elif arch == 64:
				self.extraheadersize = 0x40
				# reader header info
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x40)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<Q',raw_dph_header[8:16])[0]
					self.dph_block_information_requestedsize = struct.unpack('<Q',raw_dph_header[16:24])[0]
					self.dph_block_information_actualsize = struct.unpack('<Q',raw_dph_header[24:32])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[32:34])[0]
					self.dph_block_information_stacktrace = struct.unpack('<Q',raw_dph_header[48:56])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[60:64])[0]
				except:
					pass
		self.headersize = headersize
		self.heapbase = heapbase
		self.segmentbase = segmentbase
		self.size = size
		self.prevsize = prevsize
		self.segment = segment
		self.flag = flag
		self.flags = flag
		self.unused = unused
		self.tag = tag
		self.flink = flink
		self.blink = blink
		self.commitsize = commitsize
		self.reservesize = reservesize
		self.userptr = self.chunkptr + self.headersize + self.extraheadersize
		self.usersize = (self.size * heapgranularity) - self.unused - self.extraheadersize
		self.remaining = self.unused - self.headersize - self.extraheadersize
		self.flagtxt = getHeapFlag(self.flag)


	def showChunk(self,showdata = False):
		chunkshown = False
		if self.chunktype == "chunk":
			dbg.log("    _HEAP @ %08x, Segment @ %08x" % (self.heapbase,self.segmentbase))
			if win7mode:
				iHeap = MnHeap(self.heapbase)
				if iHeap.usesLFH():
					dbg.log("    Heap has LFH enabled. LFH Heap starts at 0x%08x" % iHeap.getLFHAddress())
					if "busy" in self.flagtxt.lower() and "virtallocd" in self.flagtxt.lower():
						dbg.log("    ** This chunk may be managed by LFH")
						self.flagtxt = self.flagtxt.replace("Virtallocd","Internal")
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize Remaining - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d  %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if self.chunktype == "virtualalloc":
			dbg.log("    _HEAP @ %08x, VirtualAllocdBlocks" % (self.heapbase))
			dbg.log("      FLINK : 0x%08x, BLINK : 0x%08x" % (self.flink,self.blink))
			dbg.log("      CommitSize : 0x%08x bytes, ReserveSize : 0x%08x bytes" % (self.commitsize*heapgranularity, self.reservesize*heapgranularity))
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if chunkshown:
			requestedsize = self.usersize
			dbg.log("      Chunk header size: 0x%x (%d)" % (self.headersize,self.headersize))
			if self.extraheadersize > 0:
				dbg.log("      Extra header due to GFlags: 0x%x (%d) bytes" % (self.extraheadersize,self.extraheadersize))
			if self.dph_block_information_stacktrace > 0:
				dbg.log("      DPH_BLOCK_INFORMATION Header size: 0x%x (%d)" % (self.extraheadersize,self.extraheadersize))
				dbg.log("         StartStamp    : 0x%08x" % self.dph_block_information_startstamp)
				dbg.log("         Heap          : 0x%08x" % self.dph_block_information_heap)
				dbg.log("         RequestedSize : 0x%08x" % self.dph_block_information_requestedsize)
				requestedsize = self.dph_block_information_requestedsize
				dbg.log("         ActualSize    : 0x%08x" % self.dph_block_information_actualsize)
				dbg.log("         TraceIndex    : 0x%08x" % self.dph_block_information_traceindex)
				dbg.log("         StackTrace    : 0x%08x" % self.dph_block_information_stacktrace)
				dbg.log("         EndStamp      : 0x%08x" % self.dph_block_information_endstamp)	
			dbg.log("      Size initial allocation request: 0x%x (%d)" % (requestedsize,requestedsize))
			dbg.log("      Total space for data: 0x%x (%d)" % (self.usersize + self.unused - self.headersize,self.usersize + self.unused - self.headersize))
			dbg.log("      Delta between initial size and total space for data: 0x%x (%d)" % (self.unused - self.headersize, self.unused-self.headersize))
			if showdata:
				dsize = self.usersize + self.remaining
				if dsize > 0 and dsize < 32:
					contents = bin2hex(dbg.readMemory(self.userptr,self.usersize+self.remaining))
				else:
					contents = bin2hex(dbg.readMemory(self.userptr,32)) + " ..."
				dbg.log("      Data : %s" % contents)
			dbg.log("")
		return

	def showChunkLine(self,showdata = False):
		return


#---------------------------------------#
#  Class to access pointer properties   #
#---------------------------------------#
class MnPointer:
	"""
	Class to access pointer properties
	"""
	def __init__(self,address):
	
		# check that the address is an integer
		if not type(address) == int and not type(address) == long:
			raise Exception("address should be an integer or long")
	
		self.address = address
		
		NullRange 			= [0]
		AsciiRange			= range(1,128)
		AsciiPrintRange		= range(20,127)
		AsciiUppercaseRange = range(65,91)
		AsciiLowercaseRange = range(97,123)
		AsciiAlphaRange     = AsciiUppercaseRange + AsciiLowercaseRange
		AsciiNumericRange   = range(48,58)
		AsciiSpaceRange     = [32]
		
		self.HexAddress = toHex(address)

		# define the characteristics of the pointer
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = (0,)*8

		if arch == 32:
			byte1,byte2,byte3,byte4 = splitAddress(address)
		elif arch == 64:
			byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# Nulls
		self.hasNulls = (byte1 == 0) or (byte2 == 0) or (byte3 == 0) or (byte4 == 0)
		
		# Starts with null
		self.startsWithNull = (byte1 == 0)
		
		# Unicode
		self.isUnicode = ((byte1 == 0) and (byte3 == 0))
		
		# Unicode reversed
		self.isUnicodeRev = ((byte2 == 0) and (byte4 == 0))

		if arch == 64:
			self.hasNulls = self.hasNulls or (byte5 == 0) or (byte6 == 0) or (byte7 == 0) or (byte8 == 0)
			self.isUnicode = self.isUnicode and ((byte5 == 0) and (byte7 == 0))
			self.isUnicodeRev = self.isUnicodeRev and ((byte6 == 0) and (byte8 == 0))
		
		# Unicode transform
		self.unicodeTransform = UnicodeTransformInfo(self.HexAddress) 

		# Ascii
		if not self.isUnicode and not self.isUnicodeRev:			
			self.isAscii = bytesInRange(address, AsciiRange)
		else:
			self.isAscii = bytesInRange(address, NullRange + AsciiRange)
		
		# AsciiPrintable
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAsciiPrintable = bytesInRange(address, AsciiPrintRange)
		else:
			self.isAsciiPrintable = bytesInRange(address, NullRange + AsciiPrintRange)
			
		# Uppercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUppercase = bytesInRange(address, AsciiUppercaseRange)
		else:
			self.isUppercase = bytesInRange(address, NullRange + AsciiUppercaseRange)
		
		# Lowercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowercase = bytesInRange(address, AsciiLowercaseRange)
		else:
			self.isLowercase = bytesInRange(address, NullRange + AsciiLowercaseRange)
			
		# Numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isNumeric = bytesInRange(address, AsciiNumericRange)
		else:
			self.isNumeric = bytesInRange(address, NullRange + AsciiNumericRange)
			
		# Alpha numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAlphaNumeric = bytesInRange(address, AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		else:
			self.isAlphaNumeric = bytesInRange(address, NullRange + AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		
		# Uppercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUpperNum = bytesInRange(address, AsciiUppercaseRange + AsciiNumericRange)
		else:
			self.isUpperNum = bytesInRange(address, NullRange + AsciiUppercaseRange + AsciiNumericRange)
		
		# Lowercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowerNum = bytesInRange(address, AsciiLowercaseRange + AsciiNumericRange)
		else:
			self.isLowerNum = bytesInRange(address, NullRange + AsciiLowercaseRange + AsciiNumericRange)
		
	
	def __str__(self):
		"""
		Get pointer properties (human readable format)

		Arguments:
		None

		Return:
		String with various properties about the pointer
		"""	

		outstring = ""
		if self.startsWithNull:
			outstring += "startnull,"
			
		elif self.hasNulls:
			outstring += "null,"
		
		#check if this pointer is unicode transform
		hexaddr = self.HexAddress
		outstring += UnicodeTransformInfo(hexaddr)

		if self.isUnicode:
			outstring += "unicode,"
		if self.isUnicodeRev:
			outstring += "unicodereverse,"			
		if self.isAsciiPrintable:
			outstring += "asciiprint,"
		if self.isAscii:
			outstring += "ascii,"
		if self.isUppercase:
			outstring == "upper,"
		if self.isLowercase:
			outstring += "lower,"
		if self.isNumeric:
			outstring+= "num,"
			
		if self.isAlphaNumeric and not (self.isUppercase or self.isLowercase or self.isNumeric):
			outstring += "alphanum,"
		
		if self.isUpperNum and not (self.isUppercase or self.isNumeric):
			outstring += "uppernum,"
		
		if self.isLowerNum and not (self.isLowercase or self.isNumeric):
			outstring += "lowernum,"
			
		outstring = outstring.rstrip(",")
		outstring += " {" + getPointerAccess(self.address)+"}"
		return outstring

	def getAddress(self):
		return self.address
	
	def isUnicode(self):
		return self.isUnicode
		
	def isUnicodeRev(self):
		return self.isUnicodeRev		
	
	def isUnicodeTransform(self):
		return self.unicodeTransform != ""
	
	def isAscii(self):
		return self.isAscii
	
	def isAsciiPrintable(self):
		return self.isAsciiPrintable
	
	def isUppercase(self):
		return self.isUppercase
	
	def isLowercase(self):
		return self.isLowercase
		
	def isUpperNum(self):
		return self.isUpperNum
		
	def isLowerNum(self):
		return self.isLowerNum
		
	def isNumeric(self):
		return self.isNumeric
		
	def isAlphaNumeric(self):
		return self.alphaNumeric
	
	def hasNulls(self):
		return self.hasNulls
	
	def startsWithNull(self):
		return self.startsWithNull
		
	def belongsTo(self):
		"""
		Retrieves the module a given pointer belongs to

		Arguments:
		None

		Return:
		String with the name of the module a pointer belongs to,
		or empty if pointer does not belong to a module
		"""		
		if len(g_modules)==0:
			populateModuleInfo()
		for thismodule,modproperties in g_modules.iteritems():
				thisbase = getModuleProperty(thismodule,"base")
				thistop = getModuleProperty(thismodule,"top")
				if (self.address >= thisbase) and (self.address <= thistop):
					return thismodule
		return ""
	
	def isOnStack(self):
		"""
		Checks if the pointer is on one of the stacks of one of the threads in the process

		Arguments:
		None

		Return:
		Boolean - True if pointer is on stack
		"""	
		stacks = getStacks()
		for stack in stacks:
			if (stacks[stack][0] <= self.address) and (self.address < stacks[stack][1]):
				return True
		return False
	
	def isInHeap(self):
		"""
		Checks if the pointer is part of one of the pages associated with process heaps/segments

		Arguments:
		None

		Return:
		Boolean - True if pointer is in heap
		"""	
		segmentcnt = 0

		for heap in dbg.getHeapsAddress():
				# part of a segment ?
				segments = getSegmentsForHeap(heap)
				for segment in segments:
					if segmentcnt == 0:
						# in heap data structure
						if self.address >= heap and self.address <= segment:
							return True
						segmentcnt += 1
					if self.address >= segment:
						last = segments[segment][3]
						if self.address >= segment and self.address <= last:
							return True
		# maybe it's in a VA List ?
		for heap in dbg.getHeapsAddress():
			mHeap = MnHeap(heap)
			valist = mHeap.getVirtualAllocdBlocks()
			if len(valist) > 0:
				for vachunk in valist:
					thischunk = valist[vachunk]
					#dbg.log("self: 0x%08x, vachunk: 0x%08x, commitsize: 0x%08x, vachunk+(thischunk.commitsize)*8: 0x%08x" % (self.address,vachunk,thischunk.commitsize,vachunk+(thischunk.commitsize*8)))
					if self.address >= vachunk and self.address <= (vachunk+(thischunk.commitsize*heapgranularity)):
						return True
		return False
		

	def getHeapInfo(self):
		global silent
		oldsilent = silent
		silent = True
		foundinheap, foundinsegment, foundinva, foundinchunk = self.showHeapBlockInfo()
		silent = oldsilent
		return [foundinheap, foundinsegment, foundinva, foundinchunk]

	def getHeapInfo_old(self):
		"""
		Returns heap related information about a given pointer
		"""
		heapinfo = {}
		heapinfo["heap"] = 0
		heapinfo["segment"] = 0
		heapinfo["chunk"] = 0
		heapinfo["size"] = 0
		allheaps = dbg.getHeapsAddress()
		for heap in allheaps:
			dbg.log("checking heap 0x%08x for 0x%08x" % (heap,self.address))
			theap = dbg.getHeap(heap)
			heapchunks = theap.getChunks(heap)
			if len(heapchunks) > 0 and not silent:
				dbg.log("Querying segment(s) for heap 0x%s" % toHex(heap))
			for hchunk in heapchunks:
				chunkbase = hchunk.get("address")
				chunksize = hchunk.get("size")
				if self.address >= chunkbase and self.address <= (chunkbase+chunksize):
					heapinfo["heap"] = heap
					heapinfo["segment"] = 0
					heapinfo["chunk"] = chunkbase
					heapinfo["size"] = chunksize
					return heapinfo
		return heapinfo


	def showObjectInfo(self):
		# check if chunk is a DOM object
		if __DEBUGGERAPP__ == "WinDBG":
			cmdtorun = "dds 0x%08x L 1" % self.address
			output = dbg.nativeCommand(cmdtorun)
			outputlower = output.lower()
			outputlines = output.split("\n")
			if "vftable" in outputlower:
				# is this Internet Explorer ?
				ieversion = 0
				if isModuleLoadedInProcess('iexplore.exe') and isModuleLoadedInProcess('mshtml.dll'):
					ieversionstr = getModuleProperty('iexplore.exe','version')
					dbg.log("      Internet Explorer v%s detected" % ieversionstr)
					ieversion = 0
					if ieversionstr.startswith("8."):
						ieversion = 8
					if ieversionstr.startswith("9."):
						ieversion = 9
					if ieversionstr.startswith("10."):
						ieversion = 10
				dbg.log("      0x%08x may be the start of an object, vtable pointer: %s" % (self.address,outputlines[0]))
				vtableptr_s = outputlines[0][10:18]
				try:
					vtableptr = hexStrToInt(vtableptr_s)
					dbg.log("      Start of vtable at 0x%08x: (showing first 4 entries only)" % vtableptr)
					cmdtorun = "dds 0x%08x L 4" % vtableptr
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					cnt = 0
					for line in outputlines:
						if line.replace(" ","") != "":
							dbg.log("       +0x%x -> %s" % (cnt,line))
						cnt += 4
					if "mshtml!" in outputlower and ieversion > 7:
						# see if we can find the object type, refcounter, attribute count, parent, etc
						refcounter = None
						attributeptr = None
						try:
							refcounter = dbg.readLong(self.address + 4)
						except:
							pass
						try:
							if ieversion == 8:
								attributeptr = dbg.readLong(self.address + 0xc)
							if ieversion == 9:
								attributeptr = dbg.readLong(self.address + 0x10)
						except:
							pass
						if not refcounter is None and not attributeptr is None:
							dbg.log("      Refcounter: 0x%x (%d)" % (refcounter,refcounter))
							if refcounter > 0x20000:
								dbg.log("      Note: a huge refcounter value may indicate this is not a real DOM object")
							if attributeptr == 0:
								dbg.log("      No attributes found")
							else:
								ptrx = MnPointer(attributeptr)
								if ptrx.isInHeap():
									dbg.log("      Attribute info structure stored at 0x%08x" % attributeptr)
									offset_nr = 0x4
									nr_multiplier = 4
									offset_tableptr = 0xc
									offset_tabledata = 0
									variant_offset = 4
									attname_offset = 8
									attvalue_offset = 0xc
									if ieversion == 9:
										nr_multiplier = 1
										offset_nr = 0x4
										offset_tableptr = 0x8
										offset_tabledata = 4
										variant_offset = 1
										attname_offset = 4
										attvalue_offset = 8

									nr_attributes = dbg.readLong(attributeptr + offset_nr) / nr_multiplier
									attributetableptr = dbg.readLong(attributeptr + offset_tableptr)
									dbg.log("        +0x%02x : Nr of attributes: %d" % (offset_nr,nr_attributes))
									dbg.log("        +0x%02x : Attribute table at 0x%08x" % (offset_tableptr,attributetableptr))
									
									attcnt = 0
									while attcnt < nr_attributes:
										
										try:
											dbg.log("                Attribute %d (at 0x%08x) :" % (attcnt+1,attributetableptr))
											sec_dword = "%08x" % struct.unpack('<L',dbg.readMemory(attributetableptr+4,4))[0]
											variant_type = int(sec_dword[0:2][:-1],16)
											dbg.log("                  Variant Type : 0x%02x (%s)" % (variant_type,getVariantType(variant_type)))
											if variant_type > 0x1:
												att_name = "<n.a.>"
												try:
													att_name_ptr = dbg.readLong(attributetableptr+attname_offset)
													att_name_ptr_value = dbg.readLong(att_name_ptr+4)
													att_name = dbg.readWString(att_name_ptr_value)
												except:
													att_name = "<n.a.>"
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Attribute name : '%s'" % (attributetableptr,attname_offset,attributetableptr+attname_offset,att_name_ptr,att_name))
												att_value_ptr = dbg.readLong(attributetableptr+attvalue_offset)
												ptrx = MnPointer(att_value_ptr)
												if ptrx.isInHeap():
													att_value = ""
													if variant_type == 0x8:
														att_value = dbg.readWString(att_value_ptr)
													if variant_type == 0x16:
														attv = dbg.readLong(att_value_ptr)
														att_value = "0x%08x (%s)" % (attv,int("0x%08x" % attv,16))
													if variant_type == 0x1e:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readString(att_from)
													if variant_type == 0x1f:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readWString(att_from)
												else:
													att_value = "0x%08x (%s)" % (att_value_ptr,int("0x%08x" % att_value_ptr,16))
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Value : %s" % (attributetableptr,attvalue_offset,attributetableptr+attvalue_offset,att_value_ptr,att_value))
										except:
											dbg.logLines(traceback.format_exc(),highlight=True)
											break
										attributetableptr += 0x10 											
										attcnt += 1
								else:
									dbg.log("      Invalid attribute ptr found (0x%08x). This may not be a real DOM object." % attributeptr)


						offset_domtree = 0x14
						if ieversion == 9:
							offset_domtree = 0x1C
						domtreeptr = dbg.readLong(self.address + offset_domtree)
						if not domtreeptr is None:
							dptrx = MnPointer(domtreeptr)
							if dptrx.isInHeap():
								currobj = self.address
								moreparents = True
								parentcnt = 0
								dbg.log("      Object +0x%02x : Ptr to DOM Tree info: 0x%08x" % (offset_domtree,domtreeptr))								
								while moreparents:
									# walk tree, get parents
									parentspaces = " " * parentcnt
									cmdtorun = "dds poi(poi(poi(0x%08x+0x%02x)+4)) L 1" % (currobj,offset_domtree)
									output = dbg.nativeCommand(cmdtorun)
									outputlower = output.lower()
									outputlines = output.split("\n")
									if "vftable" in outputlines[0]:
										dbg.log("      %s Parent : %s" % (parentspaces,outputlines[0]))
										parts = outputlines[0].split(" ")
										try:
											currobj = int(parts[0],16)
										except:
											currobj = 0
									else:
										moreparents = False
									parentcnt += 3
									if currobj == 0:
										moreparents = False

				except:
					dbg.logLines(traceback.format_exc(),highlight=True)
					pass

		return



	def showHeapBlockInfo(self):
		"""
		Find address in heap and print out info about heap, segment, chunk it belongs to
		"""
		allheaps = []
		heapkey = 0
		
		foundinheap = None
		foundinsegment = None
		foundinva = None
		foundinchunk = None
		dumpsize = 0
		dodump = False

		try:
			allheaps = dbg.getHeapsAddress()
		except:
			allheaps = []
		for heapbase in allheaps:
			mHeap = MnHeap(heapbase)
			heapbase_extra = ""
			frontendinfo = []
			frontendheapptr = 0
			frontendheaptype = 0
			if win7mode:
				heapkey = mHeap.getEncodingKey()
				if mHeap.usesLFH():
					frontendheaptype = 0x2
					heapbase_extra = " [LFH] "
					frontendheapptr = mHeap.getLFHAddress()
			frontendinfo = [frontendheaptype,frontendheapptr]

			segments = mHeap.getHeapSegmentList()

			#segments
			for seg in segments:
				segstart = segments[seg][0]
				segend = segments[seg][1]
				FirstEntry = segments[seg][2]
				LastValidEntry = segments[seg][3]								
				allchunks = walkSegment(FirstEntry,LastValidEntry,heapbase)
				for chunkptr in allchunks:
					thischunk = allchunks[chunkptr]
					thissize = thischunk.size*8 
					headersize = thischunk.headersize
					if self.address >= chunkptr and self.address < (chunkptr + thissize):
						# found it !
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in " % self.address)
							thischunk.showChunk(showdata = True)
							self.showObjectInfo()
							self.showHeapStackTrace(thischunk)
							dodump = True
							dumpsize = thissize
						foundinchunk = thischunk
						foundinsegment = seg
						foundinheap = heapbase
						break
				if not foundinchunk == None:
					break

			# VA
			if foundinchunk == None:
				# maybe it's in VirtualAllocdBlocks
				vachunks = mHeap.getVirtualAllocdBlocks()
				for vaptr in vachunks:
					thischunk = vachunks[vaptr]
					if self.address >= vaptr and self.address <= vaptr + (thischunk.commitsize*8):
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in VirtualAllocdBlocks of heap 0x%08x" % (self.address,heapbase))
							thischunk.showChunk(showdata = True)
							self.showObjectInfo()
							self.showHeapStackTrace(thischunk)
							thissize = thischunk.usersize
							dumpsize = thissize
							dodump = True					
						foundinchunk = thischunk
						foundinva = vaptr
						foundinheap = heapbase
						break

			# perhaps chunk is in FEA
			# if it is, it won't be a VA chunk
			if foundinva == None:
				if not win7mode:
					foundinlal = False
					foundinfreelist = False
					FrontEndHeap = mHeap.getFrontEndHeap()
					if FrontEndHeap > 0:
						fea_lal = mHeap.getLookAsideList()
						for lal_table_entry in sorted(fea_lal.keys()):
							nr_of_chunks = len(fea_lal[lal_table_entry])
							lalhead = struct.unpack('<L',dbg.readMemory(FrontEndHeap + (0x30 * lal_table_entry),4))[0]
							for chunkindex in fea_lal[lal_table_entry]:
								lalchunk = fea_lal[lal_table_entry][chunkindex]
								chunksize = lalchunk.size * 8
								flag = getHeapFlag(lalchunk.flag)
								if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
									foundinlal = True
									if not silent:
										dbg.log("Address is part of chunk on LookAsideList[%d], heap 0x%08x" % (lal_table_entry,mHeap.heapbase))
									break
							if foundinlal:
								expectedsize = lal_table_entry * 8
								if not silent:
									dbg.log("     LAL [%d] @0x%08x, Expected Chunksize: 0x%x (%d), %d chunks, Flink: 0x%08x" % (lal_table_entry,FrontEndHeap + (0x30 * lal_table_entry),expectedsize,expectedsize,nr_of_chunks,lalhead))
								for chunkindex in fea_lal[lal_table_entry]:
									lalchunk = fea_lal[lal_table_entry][chunkindex]
									foundchunk = lalchunk
									chunksize = lalchunk.size * 8
									flag = getHeapFlag(lalchunk.flag)
									extra = "       "
									if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
										extra = "   --> "
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, ChunkSize: 0x%x, UserSize: 0x%x, UserSpace: 0x%x (%s)" % (extra,lalchunk.chunkptr,lalchunk.userptr,lalchunk.flink,chunksize,lalchunk.usersize,lalchunk.usersize + lalchunk.remaining,flag))
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break

					if not foundinlal:
						# or maybe in BEA
						thisfreelist = mHeap.getFreeList()
						thisfreelistinusebitmap = mHeap.getFreeListInUseBitmap()				
						for flindex in thisfreelist:
							freelist_addy = heapbase + 0x178 + (8 * flindex)
							expectedsize = ">1016"
							expectedsize2 = ">0x%x" % 1016
							if flindex != 0:
								expectedsize2 = str(8 * flindex)
								expectedsize = "0x%x" % (8 * flindex)
							for flentry in thisfreelist[flindex]:
								freelist_chunk = thisfreelist[flindex][flentry]
								chunksize = freelist_chunk.size * 8
								if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):
									foundinfreelist = True
									if not silent:
										dbg.log("Address is part of chunk on FreeLists[%d] at 0x%08x, heap 0x%08x:" % (flindex,freelist_addy,mHeap.heapbase))
									break
							if foundinfreelist:
								flindicator = 0
								for flentry in thisfreelist[flindex]:
									freelist_chunk = thisfreelist[flindex][flentry]
									chunksize = freelist_chunk.size * 8	
									extra = "     "
									if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):						
										extra = " --> "
										foundchunk = freelist_chunk
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, Blink: 0x%08x, ChunkSize: 0x%x (%d), Usersize: 0x%x (%d)" % (extra,freelist_chunk.chunkptr,freelist_chunk.userptr,freelist_chunk.flink,freelist_chunk.blink,chunksize,chunksize,freelist_chunk.usersize,freelist_chunk.usersize))
									if flindex != 0 and chunksize != (8*flindex):
										dbg.log("     ** Header may be corrupted! **", highlight = True)
									flindicator = 1
								if flindex > 1 and int(thisfreelistinusebitmap[flindex]) != flindicator:
									if not silent:
										dbg.log("     ** FreeListsInUseBitmap mismatch for index %d! **" % flindex, highlight = True)
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break		

		if dodump and dumpsize > 0 and dumpsize < 1025 and not silent:
			self.dumpObjectAtLocation(dumpsize)	

		return foundinheap, foundinsegment, foundinva, foundinchunk

	def showHeapStackTrace(self,thischunk):
		# show stacktrace if any
		if __DEBUGGERAPP__ == "WinDBG": 
			stacktrace_address = thischunk.dph_block_information_stacktrace
			stacktrace_index = thischunk.dph_block_information_traceindex
			stacktrace_startstamp = 0xabcdaaaa
			if thischunk.hasust and stacktrace_address > 0:
				if stacktrace_startstamp == thischunk.dph_block_information_startstamp:
					cmd2run = "dds 0x%08x L 24" % (stacktrace_address)
					output = dbg.nativeCommand(cmd2run)
					outputlines = output.split("\n")
					if "!" in output:
						dbg.log("Stack trace, index 0x%x:" % stacktrace_index)
						dbg.log("--------------------------")
						for outputline in outputlines:
							if "!" in outputline:
								lineparts = outputline.split(" ")
								if len(lineparts) > 2:
									firstpart = len(lineparts[0])+1
									dbg.log(outputline[firstpart:])
		return
	
	def memLocation(self):
		"""
		Gets the memory location associated with a given pointer (modulename, stack, heap or empty)
		
		Arguments:
		None
		
		Return:
		String
		"""

		memloc = self.belongsTo()
		
		if memloc == "":
			if self.isOnStack():
				return "Stack"
			if self.isInHeap():
				return "Heap"
			return "??"
		return memloc

	def getPtrFunction(self):
		funcinfo = ""
		global silent
		silent = True
		if __DEBUGGERAPP__ == "WinDBG":
			lncmd = "ln 0x%08x" % self.address
			lnoutput = dbg.nativeCommand(lncmd)
			for line in lnoutput.split("\n"):
				if line.replace(" ","") != "" and line.find("%08x" % self.address) > -1:
					lineparts = line.split("|")
					funcrefparts = lineparts[0].split(")")
					if len(funcrefparts) > 1:
						funcinfo = funcrefparts[1].replace(" ","")
						break

		if funcinfo == "":
			memloc = self.belongsTo()
			if not memloc == "":
				mod = MnModule(memloc)
				if not mod is None:
					start = mod.moduleBase
					offset = self.address - start
					offsettxt = ""
					if offset > 0:
						offsettxt = "+0x%08x" % offset
					else:
						offsettxt = "__base__"
					funcinfo = memloc+offsettxt
		silent = False
		return funcinfo

	def dumpObjectAtLocation(self,size,levels=0,nestedsize=0,customthislog="",customlogfile=""):
		dumpdata = {}
		origdumpdata = {} 
		if __DEBUGGERAPP__ == "WinDBG":
			addy = self.address
			if not silent:
				dbg.log("")
				dbg.log("----------------------------------------------------")
				if (size < 0x500):
					dbg.log("[+] Dumping object at 0x%08x, 0x%02x bytes" % (addy,size))
				else:
					dbg.log("[+] Dumping object at 0x%08x, 0x%02x bytes (output below will be limited to the first 0x500 bytes !)" % (addy,size))
					size = 0x500
				if levels > 0:
					dbg.log("[+] Also dumping up to %d levels deep, max size of nested objects: 0x%02x bytes" % (levels, nestedsize))
				dbg.log("")

			parentlist = []
			levelcnt = 0
			if customthislog == "" and customlogfile == "":
				logfile = MnLog("dumpobj.txt")
				thislog = logfile.reset()
			else:
				logfile = customlogfile
				thislog = customthislog
			addys = [addy]
			parent = ""
			parentdata = {}
			while levelcnt <= levels:
				thisleveladdys = []
				for addy in addys:
					cmdtorun = "dps 0x%08x L 0x%02x/%x" % (addy,size,archValue(4,8))
					startaddy = addy
					endaddy = addy + size
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					offset = 0
					for outputline in outputlines:
						if not outputline.replace(" ","") == "":
							loc = outputline[0:archValue(8,17)].replace("`","")
							content = outputline[archValue(10,19):archValue(18,36)].replace("`","")
							symbol = outputline[archValue(19,37):]
							if not "??" in content and symbol.replace(" ","") == "":
								contentaddy = hexStrToInt(content)
								info = self.getLocInfo(hexStrToInt(loc),contentaddy,startaddy,endaddy)
								info.append(content)
								dumpdata[hexStrToInt(loc)] = info
							else:
								info = ["",symbol,"",content]
								dumpdata[hexStrToInt(loc)] = info
					if addy in parentdata:
						pdata = parentdata[addy]
						parent = "Referenced at 0x%08x (object 0x%08x, offset +0x%02x)" % (pdata[0],pdata[1],pdata[0]-pdata[1])
					else:
						parent = ""
					
					cmd2torun = "!heap -p -a 0x%08x" % (addy)
					output2 = dbg.nativeCommand(cmd2torun)
					heapdata = output2.split("\n")
					
					self.