#!/usr/bin/python
#
#   Copyright 2012 David Ellefsen 
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# An LG DZ file has the following format:
# Header:
#  Offset	Length		Description
#   0x00	 0x8		MAGIC ("MSTXMETX")
#   0x08	 0x4	 	DZ Version [0x00000003]
#   0x0C	 0x4            Number of SSTX sections
#   0x10	 0x8		Creation time in FILEDATE format
#   0x18	 0x8		String - Phone Model [LG-C900]
#   0x20	 0x4		Seperator (?) [0x00000000] (Reserved)
#   0x24	 0x50		ROM Model
#   0x74	 0x1C		Concatinated NULL-terminated strings "chipmodel"\0"osname"\0
#   0x90	 0x80		String DZ filename
#   0x110	 0x20		Seperator (0xFF)
#   0x130	 0x10		Header MD5 Hash
#   0x140	 var		Subfiles[0..n]
#   -----	 0x78		Offset Table
#
# Subfile format:
#   0x00	 0x04		MAGIC ("SSTX")
#   0x04	 0x04		Unknown Value [0x0001] - SSTX Version?
#   0x08	 0x04		File Type
#   0x0C	 0x04		Seperator (?) 0x00000000 (Reserved)
#   0x10	 0x04		Data Length
#   0x14	 0x80		Filename (null terminated)
#   0x94	 0x04		Uncompressed Data Size (Split total)
#   0x98	 0x04		Split Number
#   0x9C	 0x08		Seperator (0xFF)		
#   0xA4	 0x10		Uncompressed data MD5
#   0xB4	 0x10		Subheader MD5
#   0xC4	 DataLen	Gzip compressed Data
#
# Partial Source: http://www.frenchcoder.com/content/dzextract-lg-dz-file-format-and-extract-tool-lg-ks20
#
# Offset table format:
#   0x00	 0x04		MAGIC ("OSTX")
#   0x04	 0x10		MD5 hash
#   0x14	 0x04		Number of sections
#   0x18	 0x04		Data Type 1
#   0x1C	 0x04		Offset in DZ file
#   0x20	 0x04		Data Type 2
#   0x24	 0x04		Offset in DZ file
#   ...
#   ----	 0x04		Size of sections (number of section * 8 + 8)
#   ----         0x04		MAGIX ("ESTX")
# Source: http://forum.xda-developers.com/archive/index.php/t-399249.html

import argparse
import struct
import hashlib
import gzip
import zlib
import tempfile
import os
import json
import time
import math

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def getFileDateTimestamp():
	"""
	Get a timestamp that is in FILEDATE format
	"""
	timestamp = time.time() * 10000000 + 116444736000000000;
	return timestamp

def FileDateToTimestamp(FDTimestamp):
	"""
	Turn a FILEDATE into a UNIX timestamp
	"""
	timestamp = (FDTimestamp - 116444736000000000) / 10000000;
	return int(timestamp)

def createGZStream(buffer):
	"""
	Manually create a GZ stream using the zlib library - the built in python
	one seems to create incompatable GZ streams thankfully, the file format
	is quite simple. See: http://www.gzip.org/zlib/rfc-gzip.html
	"""
	compressedBuffer = zlib.compress(buffer, 6);
	header = struct.pack('BBBBIBB',
		0x1f,	#ID1
		0x8b,	#ID2
		0x08,	#Compression Method = 8 (Deflate)
		0x00, 	#Flags - set nothing
		0x00000000,	#MTime - No Modification Time
		0x00,	#eXtra Flags
		0x0B)	#OS - specify NTFS (just because)

	#simplest format no CRCs are included, and no extra data is added
	#concatinate and return - also, python zlib inserts a two-byte header and a 4 byte footer
	# that must be striped out, we want everything from byte 3 up to (and not including)
	# the last 4 bytes. We will then append the correct gzip footer

	footer = struct.pack('<iI', zlib.crc32(buffer), len(buffer));

	return header + compressedBuffer[2:-4] + footer

class DZCreator:
	""" A class to manage the creation of a DZ file"""
	def __init__(self, indir, cfgfile, outfile):
		self.indir = indir
		self.cfgfile = cfgfile
		self.outfile = outfile
		
		self.ofile = open(outfile, "wb");
		return

	def __readConfigFile(self):
		""" Read the config file and return populate the config variable """
		jsonConfig = self.cfgfile.read()
		self.config = json.loads(jsonConfig)
		return

	def writeOSTXTable(self):
		""" Write out the OSTX table to the DZ file """

		print "\nWriting out the Offset Table..."

		#write the number of sections
		buffer = struct.pack('<I', len(self.config['Offset']))
		
		#write each section into the buffer
		for section in self.config['Offset']:
			buffer = buffer + struct.pack('<II',
				section[0],	#section type
				section[1])	#offset in file
			print " -> Type (" + ("%0x" % section[0]) + ") is at " + ("0x%0x" % section[1]) 
		
		#write out the table size
		buffer = buffer + struct.pack('<I', len(self.config['Offset'])*8+8)

		#generate an MD5 hash
		h = hashlib.md5()
		h.update(buffer)
	
		print " Hash: " + h.hexdigest()
	
		#write it all out to the file
		self.ofile.write(struct.pack('<4s', "OSTX"))
		self.ofile.write(h.digest())
		self.ofile.write(buffer)
		self.ofile.write(struct.pack('<4s', "ESTX"))

		return;

	def writeSSTXEntries(self):
		""" Write the DZ entries to outfile with the correct header and content """
		
		self.config['Offset'] = list()

		#hack - json stores the keys of a dictionary as a string
		# and string don't sort in the correct numerical order
		keys = list()
		for x in self.config['SSTX'].keys():
			keys.append(int(x));
	
		for sstxType in sorted(keys):
			sstxFile = self.config['SSTX'][str(sstxType)]	
			print "Write " + sstxFile + "..."
 		
			sFile = open(self.indir + "/" + sstxFile, "rb");
			sstxFileContent = sFile.read()

			#get the file size
			sFile.seek(0, os.SEEK_END)
			sstxFileSize = sFile.tell()
			sFile.seek(0, os.SEEK_SET)

			hasSplit = (sstxFileSize > self.config['split'])
			splitNum = 0;

			buf = sFile.read(self.config['split'])
			while (len(buf) != 0):
				#get hash for current split
				h = hashlib.md5()
				h.update(buf)

				fileName = sstxFile.replace("\x00", "").strip()
				if (hasSplit):
					fileName = fileName + "_temp" + str(splitNum)

				#compress the buffer - it must be compressed to a gz file
				# so we have to write out a temp gz file and read the contents back
				#tempGZFile = tempfile.mkstemp()
				#os.close(tempGZFile[0])
				#gzFile = gzip.open(tempGZFile[1], 'wb', 6)
				#gzFile.write(buf)
				#gzFile.close()
		
				#gzFile = open(tempGZFile[1], 'rb')
				#compressed = gzFile.read()
				#gzFile.close()

				#os.unlink(tempGZFile[1])	

				compressed = createGZStream(buf);

				#write out the SSTX header and content to the file
				print str(fileName)
				hdrbuffer = struct.pack('<4sIIII128sII2I',
					"SSTX",		#magic
					0x00000001,	#version
					sstxType,	#type
					0x00000000,	#reserved
					len(compressed),#compressed datalength
					str(fileName),	#filename
					sstxFileSize,	#total uncompressed size
					splitNum,	#split number
					0xFFFFFFFF,	#padding
					0xFFFFFFFF);	#padding

				splitNum += 1

				#add the MD5 hash of the uncompressed data
				hdrbuffer = hdrbuffer + h.digest();

				#calculate a hash of the header
				h1 = hashlib.md5()
				h1.update(hdrbuffer)
				hdrMD5buffer = h1.digest()

				#print some info
				print " Filename:\t" + fileName
				print " Filetype:\t" + ("%02x" % sstxType)
				print " Data Size:\t" + str(len(buf)) + " bytes (Unpacked) " + str(len(compressed)) + " bytes (Packed)"
				print " Data Hash:\t" + h.hexdigest()
				print " Header Hash:\t" + h1.hexdigest()

				#write it all out to the outfile
			 	self.config['Offset'].append( (sstxType, self.ofile.tell()) ) #keep track of where we are for the offset table
				self.ofile.write(hdrbuffer)
				self.ofile.write(hdrMD5buffer)
				self.ofile.write(compressed)

				#get more data
				buf = sFile.read(self.config['split'])

		return

	def __calculateNumberSSTX(self):
		""" Calculate the number of SSTX entries in this file, including all the splits """
		items = 0
		for fileType,fileName in self.config['SSTX'].iteritems():
			filesize = os.stat(self.indir + "/" + fileName).st_size
			ceiling = math.ceil(float(filesize) / self.config['split'])
			items += ceiling
		return int(items)
	
	def createDZFileFromConfig(self):
		""" Create a DZ file from the passed config file """
		
		#read the config file
		self.__readConfigFile()

		print "Writing out the header..."

		creation = getFileDateTimestamp()
		numberSSTX = self.__calculateNumberSSTX()

		#write out the header as specified by the config file
		hdrbuffer = struct.pack('<8s2IQ8sI80s28s128s8I',
			"MSTXMETX",
			0x3,
			numberSSTX,
			creation,	
			str(self.config['Header']['PhoneModel']), 
			0x0000,
			str(self.config['Header']['ROMModel']),
			str(self.config['Header']['ChipModel'] + "\0" + self.config['Header']['OSName'] + "\0"),
			self.outfile,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);

		#generate an MD5 hash of the hdr
		h = hashlib.md5()
		h.update(hdrbuffer)

		#print some data
		print "Model:\t\t" + self.config['Header']['PhoneModel']
		print "ROM Model:\t" + self.config['Header']['ROMModel']
		print "SSTX Records:\t" + ("0x%0x" % numberSSTX)
		print "Creation:\t" +  time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(FileDateToTimestamp(creation)))	
	
		print "Chip Model:\t" + self.config['Header']['ChipModel']
		print "OS Name:\t" + self.config['Header']['OSName']
	
		print "Filename:\t" + self.outfile
		print "Header hash:\t" + h.hexdigest()
		
		#write out the header and the hash
		self.ofile.write(hdrbuffer)
		self.ofile.write(h.digest())

		#write out each of the SSTX entries
		self.writeSSTXEntries();

		#write out the offset table
		self.writeOSTXTable();

		#close the file
		self.ofile.close()

		return
	

class DZDecoder:
	"""A class to manage the decoding of a DZ file"""
	def __init__(self, infile, outdir, cfgfile):
		self.infile = infile
		self.outdir = outdir
		self.cfgfile = cfgfile
		return

	def extractSSTXEntries(self, sstxTable, printInfo=True):
		#extract the SSTX entries from the sstxTable that has been passed
	
		splitfiles = []

		for file, data in sstxTable.iteritems():
			print "Extracting " + file + "(" + str(data['datasize']) + ") ..."
			
			#is this a split?
			if ("_temp" in file):
				splitfile = file.split("_temp")[0];
				if (splitfile not in splitfiles):
					splitfiles.append(splitfile)

			#open the new file in the directory
			outfile = open(self.outdir + "/" + file, 'wb')

			# go to file and skip SSTX header
			filepos = data['offset']
			self.infile.seek(filepos + 0xC4)

			dbuffer = self.infile.read(data['datasize'])

			#write the gziped data to a temp file
			# decompress, read back, and delete the temp file
			tempGZFile = self.outdir + "/" + file + "-temp"
			gzFile = open(tempGZFile, 'wb')
			gzFile.write(dbuffer)
			gzFile.close()
	
			gzFile = gzip.open(tempGZFile, 'rb')
			dbuffer = gzFile.read()
			gzFile.close()
			os.unlink(tempGZFile)	

			#calculate an md5 hash of the decompressed data		
			h = hashlib.md5()
			h.update(dbuffer)

			#display the hash of the component of the DZ file
			if (str(data['datahash']) == h.digest()):
				print "Hash: " + h.hexdigest() + " - OK"
			else:
				print "Hash: " + h.hexdigest() + " - FAIL"
			
			outfile.write(dbuffer)
			outfile.close()

		print "\n"

		#combine any split files
		for sfile in splitfiles:
			print "Combining " + sfile;

			moreParts = True
			partNum = 0
			
			combFile = open(self.outdir + "/" + sfile, "wb") 

			while (moreParts):
				splitfilename = sfile + "_temp" + str(partNum)

				try:
					combFilePart = open(self.outdir + "/" + splitfilename, "rb")
					partBuffer = combFilePart.read()
					combFile.write(partBuffer)
					combFilePart.close()
					#os.unlink(self.outdir + "/" + splitfilename)
				except IOError as e:
					moreParts = False

				if (moreParts):
					partNum = partNum + 1
					print " ... " + splitfilename + " - " + str(sstxTable[splitfilename]['datasize'])

			combFile.close();
		return;	
		

	def locateSSTXEntries(self, printInfo=True):
		#locate all of the SSTX entries in this DZ file, do not extract them,
		# just store the offsets
	
		done = False;		

		#seek to the first SSTX entry (at 0x140)
		self.infile.seek(0x140)

		sstxTable = dict();
		self.sstxinfo = {};

		while (done == False):
			filepos = self.infile.tell()
			SSTXheader = self.infile.read(0xB4)	#read SSTX subheader
			SSTXheaderMD5 = self.infile.read(0x10)		

			hdr = struct.unpack_from('4sHHH6sI128s16s16s', SSTXheader, 0)
	
			if (hdr[0] == 'SSTX'): 
				print "\nFound SSTX header @ " + str(filepos)
				
				h = hashlib.md5()
				h.update(SSTXheader)
				if (SSTXheaderMD5 != h.digest()):
					print "Hash does not match!"
		
				print "Filename:\t" + hdr[6].rstrip()
				print "Data size:\t" + str(hdr[5])
				print "File type:\t" + str(hdr[3])
				print "Header Hash:\t" + h.hexdigest()

				sstxTable[hdr[6].replace("\x00", "")] = {
					'offset' : filepos,
					'datasize' : hdr[5],
					'filetype' : hdr[3],
					'datahash' : hdr[8]
				}

				#record the file information for the cfg file
				filename = hdr[6].replace("\x00", "").strip();
				
				#if there is a split, just store the information for the base file
				if ("_temp" in filename):
					filename = filename.split("_temp")[0];
				self.sstxinfo[hdr[3]] = filename;

				#seek past the dataportion to the next SSTX header
				self.infile.seek(hdr[5], 1)
			else:

				print "\nFound: " + hdr[0] + " - Done"
				done = True;

		return sstxTable;


	def parseDZfromFile(self, printInfo=True):
		#read all 140 bytes of the verion 3 header, and only proceed if the version matches
		print "Parsing header..."

		header = self.infile.read(0x130);
		headerMD5 = self.infile.read(0x10);
		hdr = struct.unpack_from('8sH', header, 0);

		#check the version number, if ok reread the rest of the header
		if (hdr[1] != 3):
			raise ValueError("DZ file is not version 3")
	
		hdr = struct.unpack_from('8s2IQ8sI80s28s128s32s', header, 0)
		hdrMD5 = struct.unpack_from('10s', headerMD5, 0)		
		
		#check the the MD5 hash matches
		h = hashlib.md5()
		h.update(header)
		if (headerMD5 != h.digest()):
			raise ValueError("Header hash does not match")

		osinfo = hdr[7].split('\0', 2)
	
		#print some information for the user
		if (printInfo):
			print "Magic Number:\t" + hdr[0]
			print "DZ Verion:\t" + str(hdr[1])
			print "Number of SSTX:\t" + ("%0x" % hdr[2])
			print "Phone Model:\t" + hdr[4].rstrip()
			print "ROM Model:\t" + hdr[6].rstrip()
			
			print "Chip Model:\t" + osinfo[0]
			print "OS Name:\t" + osinfo[1]
	
			print "Creation:\t" + time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(FileDateToTimestamp(long(hdr[3]))));	
			print "Filename:\t" + hdr[8]
			print "Header hash:\t" + h.hexdigest()
	
		#record some header information to be written out later
		self.hdrinfo = {
			'PhoneModel' : hdr[4].replace("\x00", "").strip(),
			'ROMModel' : hdr[6].replace("\x00", "").strip(),
			'ChipModel' : osinfo[0],
			'OSName' : osinfo[1],
		}

		return

	def writeOutConfig(self):
		# write out the config file for the decoded dz file
		print "\nWriting out the config file"
		cfg = {
			'Header' : self.hdrinfo,
			'SSTX' : self.sstxinfo,
			'split' : 0x1000000
		}

		self.cfgfile.write(json.dumps(cfg, sort_keys=True, indent=4))

		return

def main():
	#Parse the command line arguments
	parser = argparse.ArgumentParser(prog="dztool")
	parser.add_argument("-m", '--mode', choices=['create','decode'], required=True, 
		help='specify the mode of operation decode or create. Default: %(default)s')
	parser.add_argument("-i", "--infile", type=argparse.FileType('rb'),
		help="specify the input DZ file")
	parser.add_argument("-o", "--outdir", default=".", type=str,
		help="specify the output directory: Default: %(default)s")
	parser.add_argument("-c", "--cfgfile", default="dz.cfg", type=str,
		help="specify the output config file. Default: %(default)s")
	
	parser.add_argument("-d", "--indir", default=".", type=str,
		help="specify the input directory, used in create mode. Default: %(default)s")
	parser.add_argument("-f", "--outfile", default="outfile.dz", type=str,
		help="specify the output file")
			

	args = parser.parse_args()

	if (args.mode == 'decode'):
		#open the config file
		cfgfile = open(args.outdir + "/" + args.cfgfile, "w")

		decoder = DZDecoder(args.infile, args.outdir, cfgfile)
		decoder.parseDZfromFile()
		sstxTable = decoder.locateSSTXEntries()
		decoder.extractSSTXEntries(sstxTable)
		decoder.writeOutConfig()
		
		args.infile.close()
		cfgfile.close()

	if (args.mode == 'create'):
		#create a DZ file containing all the items specified in the passed config file
		cfgfile = open(args.indir + "/" + args.cfgfile, "r")
		
		creator = DZCreator(args.indir, cfgfile, args.outfile)
		creator.createDZFileFromConfig()

		cfgfile.close()

	getFileDateTimestamp()

if (__name__ == '__main__'):
	#execute the main function
	main()
