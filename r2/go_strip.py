#!/usr/bin/env python

import sys
import re
import r2pipe


class GoBinaryStripper():
	"""
	This script leverages radare2 scripting capabilities to overwrite with null
	bytes all the relevant information located within the Gopclntab section that
	might allow restoration of the original function names, difficulting this way
	the reverse engineering of any Go binary.

	All platforms and architectures should work with this script except for Mips
	due to its Big Endianess (needs to be fixed).
	"""

	def __init__(self, binary_path):
		self.r2 = r2pipe.open(binary_path, ['-w', '-2'])
		self.ptr_size = 0
		self.table_size = 0
		self.source_file_table_addr = 0
		gopclntab_addr = self.r2.cmdj('/xj fbffffff0000')[0]['offset']
		self.r2.cmd('s {}'.format(gopclntab_addr))
		self.pclntab_baseaddr = int(self.r2.cmd('s'), 16)
		self._read_header()

	def strip(self):
		parsed_table = []
		for _ in range(0, self.table_size):
			self._skip_bytes(self.ptr_size)
			self._overwrite_func_name(self._read_bytes(self.ptr_size) + self.pclntab_baseaddr)
		self._skip_bytes(self.ptr_size)
		self.source_file_table_addr = self._read_bytes(4) + self.pclntab_baseaddr
		self._overwrite_source_files_table()
		return parsed_table

	def _read_header(self):
		self._skip_bytes(4)  # read magic value 0xfffffffb
		self._skip_bytes(3)
		self.ptr_size = self._read_bytes(1)
		self.table_size = self._read_bytes(2)
		self._skip_bytes(self.ptr_size - 2)

	def _overwrite_func_name(self, func_ptr):
		current_seek = self._get_current_seek()
		self.r2.cmd('s {}'.format(func_ptr))
		self._skip_bytes(self.ptr_size)
		name_addr = self.pclntab_baseaddr + self._read_bytes(4)
		name = self._read_string_at(name_addr)
		self._write_string_at('00'*len(name), name_addr)
		self._skip_bytes(28)
		self._seek(current_seek)

	def _overwrite_source_files_table(self):
		self._seek(self.source_file_table_addr)
		count = self._read_bytes(4)-1
		for _ in range(0, count):
			source_file_addr = self.pclntab_baseaddr + self._read_bytes(4)
			source_file = self._read_string_at(source_file_addr)
			self._write_string_at('00'*len(source_file), source_file_addr)

	def _read_bytes(self, n):
		value = self.r2.cmdj('pfj n{}'.format(n))[0]['value']
		self.r2.cmd('s +{}'.format(n))
		return value

	def _read_string_at(self, addr):
		return self.r2.cmd('ps @ {}'.format(addr))

	def _write_string_at(self, string, addr):
		return self.r2.cmd('wx {} @ {}'.format(string, addr))

	def _skip_bytes(self, n):
		self.r2.cmd('s +{}'.format(n))

	def _get_current_seek(self):
		return int(self.r2.cmd('s'), 16)

	def _seek(self, addr):
		self.r2.cmd('s {}'.format(addr))


if __name__ == '__main__':
	go_stripper = GoBinaryStripper(sys.argv[1])
	go_stripper.strip()
