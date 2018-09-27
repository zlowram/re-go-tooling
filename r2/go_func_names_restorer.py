#!/usr/bin/env python

import base64
import re
import sys
import r2pipe


class GoPclntabParser():
	"""
	This radare2 script reads the Gopclntab section on Go binaries in order to retrieve information about
	the function names and the corresponding PC value where it starts.

	This information is used when a Go binary panics, to show the stack traces, but it can also be retrieved
	to perform an "smart" analysis of the binary with r2 and rename the functions to their original name.

	Note that the command "strip" does not affect the information residing on the Gopclntab section of the binary
	so this will highly ease the reversing process of any Go binary.

	All platforms and architectures should work with this script except for Mips due to its Big Endianess (needs to be fixed).
	"""

	def __init__(self):
		self.r2 = r2pipe.open()
		self.ptr_size = 0
		self.instr_size = 0
		self.table_size = 0
		self.source_file_table_addr = 0
		gopclntab_addr = self.r2.cmdj('/xj fbffffff0000')[0]['offset']
		self.r2.cmd('s {}'.format(gopclntab_addr))
		self.pclntab_baseaddr = int(self.r2.cmd('s'), 16)
		self._read_header()

	def read_table(self):
		parsed_table = []
		for _ in range(0, self.table_size):
			self._skip_bytes(self.ptr_size)  # skip the PC address (it also appears within the Func struct)
			func_ptr = self._read_bytes(self.ptr_size) + self.pclntab_baseaddr
			parsed_table.append(self._read_func(func_ptr))
		self._skip_bytes(self.ptr_size)
		self.source_file_table_addr = self._read_bytes(4) + self.pclntab_baseaddr
		return parsed_table

	def _read_header(self):
		self._skip_bytes(4)  # read magic value 0xfffffffb
		self._skip_bytes(2)
		self.instr_size = self._read_bytes(1)
		self.ptr_size = self._read_bytes(1)
		self.table_size = self._read_bytes(2)
		self._skip_bytes(self.ptr_size - 2)

	def _read_func(self, func_ptr):
		current_seek = self._get_current_seek()
		self.r2.cmd('s {}'.format(func_ptr))
		func_str = {
				"entry": self._read_bytes(self.ptr_size),
				"name": self._read_string_at(self.pclntab_baseaddr + self._read_bytes(4)),
				"args": self._read_bytes(4),
				"frame": self._read_bytes(4)
		}
		self._skip_bytes(5 * 4)  # skip the rest of the Func struct (not interesting for us)
		self._seek(current_seek)
		return func_str

	def _read_source_table(self):
		source_files = []
		self._seek(self.source_file_table_addr)
		count = self._read_bytes(4)-1
		for _ in range(0, count):
			source_files.append(self._read_string_at(self.pclntab_baseaddr + self._read_bytes(4)))

	def _read_bytes(self, n):
		value = self.r2.cmdj('pfj n{}'.format(n))[0]['value']
		self.r2.cmd('s +{}'.format(n))
		return value

	def _read_string_at(self, addr):
		return self.r2.cmd('ps @ {}'.format(addr))

	def _skip_bytes(self, n):
		self.r2.cmd('s +{}'.format(n))

	def _get_current_seek(self):
		return int(self.r2.cmd('s'), 16)

	def _seek(self, addr):
		self.r2.cmd('s {}'.format(addr))


if __name__ == '__main__':
	pclntab_parser = GoPclntabParser()
	print "- Instruction size: {}".format(pclntab_parser.instr_size)
	print "- Pointer size: {}".format(pclntab_parser.ptr_size)
	print "- Pclntab size: {}".format(pclntab_parser.table_size)
	pclntab = pclntab_parser.read_table()
	r2 = r2pipe.open()
	for func in pclntab:
		# Uncomment only if you want to analyze all the functions (not recommended, really slow)
		# r2.cmd('af @ {}'.format(func['entry']))
		clean_name = re.sub("[^a-zA-Z0-9\n\.]", "_", func['name'])
		r2.cmd('afn {} @ {}'.format(clean_name, func['entry']))
		r2.cmd('CCu {} @ {}'.format(base64.b64encode(func['name']), func['entry']))
