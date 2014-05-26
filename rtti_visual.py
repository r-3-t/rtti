"""
Copyright (c) 2012, jp luyten
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


 please report bugs or ask features to [jp] [@] [r-3-t] [.] [org]

"""

from idautils import *
from idaapi import *

import logging
import os
import sys

rtti_logger = 0
fileHandler = 0
RttiLogFile = os.path.realpath(__file__) + ".log"
g_Is64bit = False
g_pointer_size = 4

g_deep_scan = False

Map_BaseClassDescriptor			= {}
Map_TypeDescriptor				= {}
Map_ClassHierarchyDescriptor	= {}
Map_CompleteObjectLocator		= {}
Map_Vtable						= {}
Map_Class						= {}
Map_VbTable						= {}
#_______________________________________________________________________________
def ReadPointer(addr) :
	if g_Is64bit :
		return Qword(addr)
	else :
		return Dword(addr)

def ReadUint32(addr):
	return Dword(addr)


def ReadRva(addr):
	return Dword(addr) + get_imagebase()
	
#_______________________________________________________________________________
def IsValidAddress(addr) :
	""" return True if addr is a valid address (in the database) """
	try:
		if GetSegmentAttr(addr, SEGATTR_TYPE) == SEG_DATA :
			return True
			
		if GetSegmentAttr(addr, SEGATTR_TYPE) == SEG_CODE and g_deep_scan :
			return True
			
		return False
		
	except:
		return False

#_______________________________________________________________________________
class RttiError(Exception):
	def __init__(self, error):
		self.error = error
		
	def __str__(self):
		return self.error

#_______________________________________________________________________________					
class BaseClassDescritorObject:
	def __init__(self, addr) :
		rtti_logger.debug("try to build BaseClassDescritor Object at '%x'" % (addr))
		if not IsValidAddress(addr) :
			raise	RttiError("Not a BaseClassDescritor")
		
		if g_Is64bit :
			self.addr								= addr
			self.Address_TypeDescriptor				= ReadRva(addr +  0)
			self.numContainedBases					= ReadUint32(addr +  4)
			self.PMD								= [ReadUint32(addr + 8), ReadUint32(addr +  12), ReadUint32(addr +  16)]
			self.Attributes							= ReadUint32(addr +  20)
			self.Address_ClassHierarchyDescriptor	= ReadRva(addr +  24)
		else :
			self.addr								= addr
			self.Address_TypeDescriptor				= ReadPointer(addr +  0)
			self.numContainedBases					= ReadUint32(addr +  4)
			self.PMD								= [ReadUint32(addr + 8), ReadUint32(addr +  12), ReadUint32(addr +  16)]
			self.Attributes							= ReadUint32(addr +  20)
			self.Address_ClassHierarchyDescriptor	= ReadPointer(addr +  24)
	
		if not IsValidAddress(self.Address_TypeDescriptor) or not IsValidAddress(self.Address_ClassHierarchyDescriptor):
			raise RttiError ("Not a BaseClassDescritor")
			
		test_TypeDescriptor = TypeDescriptorObject(self.Address_TypeDescriptor)
		test_ClassHierarchyDescriptor = ClassHierarchyDescriptorObject(self.Address_ClassHierarchyDescriptor)
	
	def __str__(self):
		str = "BaseClassDescritorObject(%x - %s)\n" % (self.addr, self.GetClassName());
		str += "\tTypeDescriptor          : %8x\n" % self.Address_TypeDescriptor;
		str += "\tnumContainedBases       : %8d\n" % self.numContainedBases;
		str += "\tPMD                     : %8x | %8x | %8x\n" % (self.PMD[0], self.PMD[1], self.PMD[2]);
		str += "\tAttributes              : %8x\n" % self.Attributes;
		str += "\tClassHierarchyDescriptor: %8x" % self.Address_ClassHierarchyDescriptor;
		return str
	
	def GetTypeDescriptor(self):
		if not (self.Address_TypeDescriptor in Map_TypeDescriptor) :
			Map_TypeDescriptor[self.Address_TypeDescriptor] = TypeDescriptorObject(self.Address_TypeDescriptor)
			rtti_logger.debug("add  addr '%08X' to Map_TypeDescriptor" % (self.Address_TypeDescriptor))	
			
		return Map_TypeDescriptor[self.Address_TypeDescriptor]	
		
	def GetClassHierarchyDescriptor(self) :
		if not (self.Address_ClassHierarchyDescriptor in Map_ClassHierarchyDescriptor) :
			Map_ClassHierarchyDescriptor[self.Address_ClassHierarchyDescriptor] = ClassHierarchyDescriptorObject(self.Address_ClassHierarchyDescriptor)
			
		return Map_ClassHierarchyDescriptor[self.Address_ClassHierarchyDescriptor]
		
	def GetClassName(self) :
		TypeDescriptor = self.GetTypeDescriptor()
		return TypeDescriptor.GetClassName()
		
	def RegisterAllRttiObjects(self):
		if self.addr not in Map_BaseClassDescriptor :
			Map_BaseClassDescriptor[self.addr] = self
			
			TypeDescriptor = self.GetTypeDescriptor()
			TypeDescriptor.RegisterAllRttiObjects()
			
			ClassHierarchyDescriptor = self.GetClassHierarchyDescriptor()
			ClassHierarchyDescriptor.RegisterAllRttiObjects()
			
	def ExportToDot(self):
		label	 = 	"<start>BaseClassDescriptorObject for Class %s" % Map_TypeDescriptor[self.Address_TypeDescriptor].GetClassName()
		label	+= 	"|<o00>TypeDescriptor			: %8x" % (self.Address_TypeDescriptor)
		label	+= 	"|<o04>NumContainedBases		: %8x" % (self.numContainedBases)
		label	+=	"|{<o08>PMD	                    :|{mdisp : %8x |pdisp : %8x |vdisp : %8x }} " % (self.PMD[0], self.PMD[1], self.PMD[2])
		label	+=	"|<o20>Attributes	            : %8x" % (self.Attributes)
		label	+= 	"|<o24>ClassHierarchyDescriptor	: %8x" % (self.Address_ClassHierarchyDescriptor)
		
		node	 = 	"BaseClassDescriptorObject_%x [shape=record, label=\"%s\"];\n" % (self.addr, label)		
		
		link	 =	"BaseClassDescriptorObject_%x:<o00> -> TypeDescriptorObject_%x:start;\n" % (self.addr, self.Address_TypeDescriptor)
		link	+=	"BaseClassDescriptorObject_%x:<o24> -> ClassHierarchyDescriptorObject_%x:start;\n" % (self.addr, self.Address_ClassHierarchyDescriptor)
		
		
		
		return (node, link, "BaseClassDescriptorObject_%x" % self.addr)
		
#_______________________________________________________________________________					
class ClassHierarchyDescriptorObject:
	def __init__(self, addr, name = "") :
		rtti_logger.debug("try to build ClassHierarchyDescriptor Object at '%x'" % (addr))
		if not IsValidAddress(addr) :
			raise	RttiError("Not a ClassHierarchyDescriptor Object")
			
		self.addr								=	addr
		
		self.Signature							=	ReadUint32 (addr +  0)
		self.Attributes							=	ReadUint32 (addr +  4)
		self.numBaseClasses						=	ReadUint32 (addr +  8)
		if g_Is64bit :
			self.Address_BaseClassDescriptorArray	=	ReadRva (addr + 12)
		else :
			self.Address_BaseClassDescriptorArray	=	ReadPointer (addr + 12)
		self.Name								=	name
		
		if (self.Signature != 0):
			raise	RttiError("Not a ClassHierarchyDescriptor Object" )
		
		
		if not IsValidAddress(self.Address_BaseClassDescriptorArray):
			raise	RttiError("Not a ClassHierarchyDescriptor" )
		
		# test if each entry is valid
		self.GetBaseClassDescriptorArray()
		
	def GetBaseClassDescriptorArray(self) :
		Array = []
		for i in range(self.numBaseClasses) :
			if g_Is64bit :
				BaseClassDescriptorAddress = ReadRva(self.Address_BaseClassDescriptorArray + 4*i)
			else:
				BaseClassDescriptorAddress = ReadPointer(self.Address_BaseClassDescriptorArray + 4*i)
			# strange, but some times there are duplicate values
			if not IsValidAddress(BaseClassDescriptorAddress):
				raise RttiError("BaseClassDescriptorAddress : invalid address")
			
			if BaseClassDescriptorAddress not in Array :
				Array += [BaseClassDescriptorAddress]
			
		return Array
			
	def RegisterAllRttiObjects(self):
		if self.addr not in Map_ClassHierarchyDescriptor :
			Map_ClassHierarchyDescriptor[self.addr] = self
			
		BaseClassDescriptorArray	= self.GetBaseClassDescriptorArray()
		for i in BaseClassDescriptorArray :
			if i not in Map_BaseClassDescriptor :
				BaseClassDescritor = BaseClassDescritorObject(i)
				BaseClassDescritor.RegisterAllRttiObjects()
					
	def ExportToDot(self):
		label	 = 	"<start>ClassHierarchyDescriptorObject of Class %s" % self.Name
		label	+= 	"|<o00>Signature			: %x" % (self.Signature)
		label	+= 	"|<o04>Attributes			: %x" % (self.Attributes)
		label	+= 	"|<o08>numBaseClasses		: %s" % (self.numBaseClasses)
		label	+=	"|<o12>BaseClassDescriptor	: %x" % (self.Address_BaseClassDescriptorArray)
		node	 = 	"ClassHierarchyDescriptorObject_%x [shape=record, label=\"%s\"];\n" % (self.addr, label)		
		
		link	 =	"ClassHierarchyDescriptorObject_%x:<o12> -> BaseClassDescriptorArray_%x:start;\n" % (self.addr, self.Address_BaseClassDescriptorArray)
		
		node	+=	"BaseClassDescriptorArray_%x [shape=record, label=\"<start>BaseClassDescriptorArray of Class %s" % (self.Address_BaseClassDescriptorArray, self.Name)
		for i in self.GetBaseClassDescriptorArray() :
			node +=	"|<o%x>%x (for class %s)" % (i, i, Map_BaseClassDescriptor[i].GetClassName())
			link +=	"BaseClassDescriptorArray_%x:o%x -> BaseClassDescriptorObject_%x:start;\n" % (self.Address_BaseClassDescriptorArray, i, i)
		node	+=	"\"];\n"
		
		return (node, link, "ClassHierarchyDescriptorObject_%x" % self.addr, "BaseClassDescriptorArray_%x" % (self.Address_BaseClassDescriptorArray))

def MyGetString(addr):
	ret = ""
	while Byte(addr) != 0:
		ret += chr(Byte(addr))
		addr += 1
		
	return ret
#_______________________________________________________________________________			
class TypeDescriptorObject:
	def __init__(self, addr) :
		rtti_logger.debug("try to build TypeDescriptor Object at '%x'" % (addr))
		if not IsValidAddress(addr) :
			raise	RttiError("Not a TypeDescriptor at address : %x" % (addr) )
		self.addr			= addr
		self.pVFTable		= ReadPointer (addr + 0)
		
		if not IsValidAddress(self.pVFTable):
			raise	RttiError("Not a TypeDescriptor" )
		
		if g_Is64bit :
			self.Name			= MyGetString(addr + 16)
		else :
			self.Name			= MyGetString(addr + 8)
		self.Name			= self.Name.replace(".?AU", "")
		self.Name			= self.Name.replace(".?AV", "")		
		self.Name			= self.Name.replace("@@", "")
		self.Name			= self.Name.replace("@", "_")
		if self.Name == "" :
			raise	RttiError("Not a TypeDescriptor" )
			
		rtti_logger.debug("Type Descriptor at '%x', name : '%s'" % (addr, self.Name))
			
	def GetClassName(self):
		return self.Name
		
	def RegisterAllRttiObjects(self):
		if self.addr not in Map_TypeDescriptor :
			Map_TypeDescriptor[self.addr] = self
			rtti_logger.debug("add  addr '%08X' to Map_TypeDescriptor" % (self.addr))
			
	def ExportToDot(self):
		label	 = 	"<start>TypeDescriptorObject"
		label	+= 	"|<o00>pVFTable : %x" % (self.pVFTable)
		label	+= 	"|<o04>spare    : --"
		label	+= 	"|<o08>Name     : %s" % (self.Name)		
		node	 = 	"TypeDescriptorObject_%x [shape=record, label=\"%s\"];\n" % (self.addr, label)
		return (node, "", "TypeDescriptorObject_%x" % self.addr)
		
#_______________________________________________________________________________	
class CompleteObjectLocatorObject :	
	def __init__(self, addr) :
		rtti_logger.debug("try to build CompleteObjectLocator Object at '%x'" % (addr))
		if not IsValidAddress(addr) :
			raise	RttiError("Not a CompleteObjectLocator Object" ) 
		
		self.addr								= addr
		self.signature							= ReadUint32(addr +  0) # offset  0
		self.Offset								= ReadUint32(addr +  4) # offset  4
		self.cdOffset							= ReadUint32(addr +  8) # offset  8
		if g_Is64bit :
			self.Address_TypeDescriptor				= ReadRva(addr + 12) # offset 12
			self.Address_ClassHierarchyDescriptor	= ReadRva(addr + 16) # offset 16
		else :
			self.Address_TypeDescriptor				= ReadPointer(addr + 12) # offset 12
			self.Address_ClassHierarchyDescriptor	= ReadPointer(addr + 16) # offset 16
		self.Name								= 0
		
		if g_Is64bit :
			if (self.signature != 1):
				raise	RttiError("Not a CompleteObjectLocator Object" ) 
		else :
			if (self.signature != 0):
				raise	RttiError("Not a CompleteObjectLocator Object" ) 
		
		if not IsValidAddress(self.Address_TypeDescriptor) or not IsValidAddress(self.Address_ClassHierarchyDescriptor):
			raise	RttiError("Not a CompleteObjectLocator Object" )
		
		
		test_TypeDescriptor = TypeDescriptorObject(self.Address_TypeDescriptor)
		test_ClassHierarchyDescriptorObject = ClassHierarchyDescriptorObject(self.Address_ClassHierarchyDescriptor)
		
		
	def GetTypeDescriptor(self) :
		if self.Address_TypeDescriptor not in Map_TypeDescriptor :
			Map_TypeDescriptor[self.Address_TypeDescriptor] = TypeDescriptorObject(self.Address_TypeDescriptor)
			rtti_logger.debug("add  addr '%08X' to Map_TypeDescriptor" % (self.Address_TypeDescriptor))
			
		return Map_TypeDescriptor[self.Address_TypeDescriptor]
	
	def GetClassHierarchyDescriptor(self) :
		if self.Address_ClassHierarchyDescriptor not in Map_ClassHierarchyDescriptor :
			Map_ClassHierarchyDescriptor[self.Address_ClassHierarchyDescriptor] = ClassHierarchyDescriptorObject(self.Address_ClassHierarchyDescriptor, self.GetClassName())
			
		return Map_ClassHierarchyDescriptor[self.Address_ClassHierarchyDescriptor]
	
	def GetOffset(self) :
		return self.Offset
	
	def GetClassName(self) :
		TypeDescriptor = TypeDescriptorObject(self.Address_TypeDescriptor)
		return TypeDescriptor.GetClassName()
			
	def RegisterAllRttiObjects(self):
		if self.addr not in Map_CompleteObjectLocator :
			rtti_logger.debug("add complete object locator at addr %08X" % (self.addr))
			Map_CompleteObjectLocator[self.addr] = self
			
		TypeDescriptor				= self.GetTypeDescriptor()
		TypeDescriptor.RegisterAllRttiObjects()
		ClassHierarchyDescriptor	= self.GetClassHierarchyDescriptor()
		ClassHierarchyDescriptor.RegisterAllRttiObjects()
			
	def ExportToDot(self):
		label	 = 	"<start>CompleteObjectLocatorObject of class %s at offset %x" % (self.GetClassName(), self.addr)
		label	+= 	"|<o00>signature: %x" % (self.signature)
		label	+= 	"|<o04>Offset   : %x" % (self.Offset)
		label	+= 	"|<o08>cdOffset : %x" % (self.cdOffset)		
		label	+= 	"|<o12>TypeDesc : %x" % (self.Address_TypeDescriptor)
		label	+= 	"|<o16>ClasDesc : %x" % (self.Address_ClassHierarchyDescriptor)
		node	 = 	"CompleteObjectLocatorObject_%x [shape=record, label=\"%s\"];\n" % (self.addr, label)
		link	 =	"CompleteObjectLocatorObject_%x:o12 -> TypeDescriptorObject_%x:start;\n" % (self.addr, self.Address_TypeDescriptor)
		link	+=	"CompleteObjectLocatorObject_%x:o16 -> ClassHierarchyDescriptorObject_%x:start;\n" % (self.addr, self.Address_ClassHierarchyDescriptor)
		return (node, link, "CompleteObjectLocatorObject_%x" % self.addr)
	
#_______________________________________________________________________________	
class VtableObject :
	def __init__(self, vtable_addr):
		rtti_logger.debug("try to build Vtable object at '%x'" % (vtable_addr))
		if not IsValidAddress(vtable_addr) :
			raise	RttiError("Not a Vtable Object" )
			
		self.addr								= vtable_addr
		if g_Is64bit :
			self.Address_CompleteObjectLocator		= ReadPointer(self.addr - 8)
		else :
			self.Address_CompleteObjectLocator		= ReadPointer(self.addr - 4)
		
		if not self.IsValid() :
			raise	RttiError("Not a Vtable Object" )
		
		if not IsValidAddress(self.Address_CompleteObjectLocator):
			raise	RttiError("Not a Vtable Object" )
		
		test_CompleteObjectLocator = CompleteObjectLocatorObject(self.Address_CompleteObjectLocator)
		
		rtti_logger.debug("Found vtable of class %s at offset %x\n" % (test_CompleteObjectLocator.GetClassName(), self.GetCompleteObjectLocator().Offset))
							
	def GetCompleteObjectLocator(self) :
		if self.Address_CompleteObjectLocator not in Map_CompleteObjectLocator :
			Map_CompleteObjectLocator[self.Address_CompleteObjectLocator] = CompleteObjectLocatorObject(self.Address_CompleteObjectLocator)
			
		return Map_CompleteObjectLocator[self.Address_CompleteObjectLocator]
	
	def GetClassName(self) :
		CompleteObjectLocator = self.GetCompleteObjectLocator()
		return CompleteObjectLocator.GetClassName();
	
	def GetOffset(self) :
		return self.GetCompleteObjectLocator().GetOffset()
	
	def IsValid(self) :
		try :
			ClassName = self.GetClassName()
			return True
		except RttiError :
			return False
	
	def ExportToDot(self):
		label	 = 	"<comp_>CompleteObjectLocatorObject : %x" % (self.Address_CompleteObjectLocator)
		label	+=	"|<vtable> vtable addr : %x" % (self.addr)
		node	 = 	"VtableObject_%x [shape=record, label=\"%s\"];\n" % (self.addr, label)
		link	 =	"VtableObject_%x:comp_ -> CompleteObjectLocatorObject_%x:start;\n" % (self.addr, self.Address_CompleteObjectLocator)
		return (node, link, "VtableObject_%x" % self.addr)
	
	def RegisterAllRttiObjects(self):
		if self.addr not in Map_Vtable :
			
			rtti_logger.debug("add vtable at addr %08X with complete_obj_loc at %08X" % (self.addr, self.Address_CompleteObjectLocator))				
			Map_Vtable[self.addr] = self
						
			CompleteObjectLocator = self.GetCompleteObjectLocator()
			CompleteObjectLocator.RegisterAllRttiObjects()
		
#_______________________________________________________________________________

class ClassObject:
	def __init__(self, Name):
		self.Name			= Name
		self.VtableAddress	= []
		self.DirectParents	= {}
	
	def GetClassName(self) :
		return Map_Vtable[self.VtableAddress[0]].GetClassName()
	
	# return the BaseClassDescriptorArray
	# (there is one BaseClassDescriptorArray per vtable but it must be the same)
	def GetBaseClassDescriptorArray(self):
		BaseClassDescriptorArray = 0
		for vtable_addr in self.VtableAddress :
			vtable = Map_Vtable[vtable_addr]
			CompleteObjectLocator = vtable.GetCompleteObjectLocator()
			ClassHierarchyDescriptor = CompleteObjectLocator.GetClassHierarchyDescriptor ()
			if BaseClassDescriptorArray == 0 :
				BaseClassDescriptorArray = ClassHierarchyDescriptor.GetBaseClassDescriptorArray()
			else :
				# check that it is the same array
				if BaseClassDescriptorArray != ClassHierarchyDescriptor.GetBaseClassDescriptorArray() :
					rtti_logger.debug("Class '%s' has more than one BaseClassDescriptorArray" % (self.Name))
					raise RttiError ("Class has more than one BaseClassDescriptorArray")
					
		return BaseClassDescriptorArray
	
	# return the list of parents class
	# @return list of tupple. Each elem is (offset, name)
	def GetParents(self) :
		ListParents = []
		BaseClassDescriptorArray = self.GetBaseClassDescriptorArray()
		for i in BaseClassDescriptorArray:
			ParentName = Map_BaseClassDescriptor[i].GetClassName()
			BaseClassDescriptor = Map_BaseClassDescriptor[i]
			if ParentName != self.GetClassName() :
				ListParents += [(ParentName, BaseClassDescriptor.PMD[0])]
				
		return ListParents
					
	def GetBaseClassAtOffset(self, offset) :
		Parents = self.GetParents()
		ParentClassName = ""
		
		for (Name, OffsetVtable) in Parents :
			if OffsetVtable == offset :
				ParentClassName = Name
				break
				
		return ParentClassName
				
	

	def GetLayout(self):
		Layout = {}
		BaseClassDescriptorArray = self.GetBaseClassDescriptorArray()
		for i in BaseClassDescriptorArray:
			BaseClassDescriptor = Map_BaseClassDescriptor[i]
			if BaseClassDescriptor.GetClassName() != self.GetClassName() :
				if BaseClassDescriptor.PMD[1] == 0xFFFFFFFF :
					Layout[BaseClassDescriptor.PMD[0]] =  BaseClassDescriptor.GetClassName()
				else :
					vbtable = Map_VbTable[self.GetClassName()]
					for (name, offset) in vbtable :
						if name == BaseClassDescriptor.GetClassName() : 
							Layout[offset] =  BaseClassDescriptor.GetClassName()
							break
		
		return Layout
				
	def ExportToDot(self):
		label	 = 	"Class : %s" % (self.Name)
		link 	 =	""
		for addr in self.VtableAddress :
			label	+=	"|<vtable_%x> Offset %x : vtable addr : %x" % (addr, Map_Vtable[addr].GetCompleteObjectLocator().Offset ,addr)
			link	+=	"ClassObject_%s:vtable_%x -> VtableObject_%x:vtable;\n" % (self.Name, addr, addr)
			
		node	 = 	"ClassObject_%s [shape=record, label=\"%s\"];\n" % (self.Name, label)
		
		return (node, link, "ClassObject_%s" % self.Name)

#_______________________________________________________________________________
# @return the list of each code segment
def GetCodeSegment() :
	CodeSegment = []
	for seg_ea in Segments() :
		if GetSegmentAttr(seg_ea, SEGATTR_TYPE) == SEG_CODE  :
			CodeSegment += [seg_ea]
			rtti_logger.debug("code segment from : %x to %x" % (SegStart(seg_ea), SegEnd(seg_ea)))
	
	return CodeSegment
	
#_______________________________________________________________________________
# @return the list of all functions' address in each code segement 
def GetFunctions() :
	# get current ea
	functions = []
	#for seg in GetCodeSegment() :
	for funcea in Functions() :
		functions += [funcea]
	return functions
		
#_______________________________________________________________________________
# @param function_adress address of the function to process
# @return the list of each instructions of the function at function_address
def GetFunctionInstructions(function_address) :
	return list(FuncItems(function_address))
	
#_______________________________________________________________________________
# @param instructions a list of instructions address to parse
# @return the list of instructions address of the form : mov [reg], immediate_value
def GetMovInstructions(instructions) :
	movInstructions = []
	for curentInstructionAddress in instructions:
	
		# get current instructions
		currentInstruction = DecodeInstruction(curentInstructionAddress)
		# if it is a 2 operands instructions
		if (currentInstruction != None) and ((currentInstruction.size >= 6) and (currentInstruction.size <= 10)) :
			mnemonic = currentInstruction.get_canon_mnem()
			if (mnemonic == "mov") and ((GetOpType(curentInstructionAddress, 0) == idaapi.o_phrase) or (GetOpType(curentInstructionAddress, 0) == idaapi.o_displ)) and (GetOpType(curentInstructionAddress, 1) == idaapi.o_imm) :
				movInstructions += [curentInstructionAddress]
				
	return movInstructions


#_______________________________________________________________________________
def RegisterAllVtables() :
	rtti_logger.debug("--- RegisterAllVtables [STARTED]")
	# foreach functions in the database
	# functions = GetFunctions()
	listClass = []
	sys.stdout.write('----------------- rtti scanner -----------------\n')
	#for funcea in functions:
	current_segment = FirstSeg()
	while current_segment != BADADDR :
		percent = 0
		old_percent = -1
		segment_start = SegStart(current_segment)
		segment_end   = SegEnd(current_segment)
		segment_name  = SegName(current_segment)
		
		# skip current segment if we dot not want do scan code segment
		if not g_deep_scan :	
			seg = idaapi.getseg(segment_start)
			if seg.type == SEG_CODE :
				rtti_logger.debug("--- skip segment %s (attr: %x)" % (segment_name, seg.type))
				current_segment = NextSeg(current_segment)
				continue
				
		sys.stdout.write("[+] Scan segment : %s (%08X to %08X) : " % (segment_name, segment_start, segment_end - g_pointer_size))
		vtable_address = current_segment
		while vtable_address < (segment_end - g_pointer_size) :
			#sys.stdout.write('.')
		# for each instructions in function
		# for curentInstructionAddress in GetMovInstructions(GetFunctionInstructions(funcea)):
		# vtable_address = GetOperandValue(curentInstructionAddress, 1)
			rtti_logger.debug("try data at : 0x%08X" % (vtable_address))
			try:
				Vtable = VtableObject(vtable_address)	
				Vtable.RegisterAllRttiObjects()
				rtti_logger.debug("data : %08X match" % (vtable_address))
			except RttiError:
				pass
				#rtti_logger.debug("data : %08X not match" % (vtable_address))

			vtable_address += 4
			percent = int(((vtable_address - segment_start) * 100) / (segment_end - segment_start))
			if percent != old_percent :
				old_percent = percent
				sys.stdout.write(".")

		current_segment = NextSeg(current_segment)
		sys.stdout.write ('\n')
		
	sys.stdout.write('[OK]\n')
	rtti_logger.debug("--- RegisterAllVtables [FINISHED]")
	RttiHelp()

#_______________________________________________________________________________

# from the list of parents, keep only one parent per offset
def GetClassLayout(Class):
	Layout = {}
	for (ParentName, OffsetVtable) in Class.GetParents() :
		if OffsetVtable not in Layout :
			Layout[OffsetVtable] = []
		Layout[OffsetVtable] += [ParentName]
			
	for Offset, Parents in Layout.items() :
		ParentToKeep = Parents[0]
		for Parent in Parents[1:] :
			try :
				if len(Map_Class[Parent].GetParents()) > len(Map_Class[ParentToKeep].GetParents()) :
					ParentToKeep = Parent
			except:
				pass				
		Layout[Offset] = ParentToKeep
		
	return Layout
#_______________________________________________________________________________
def BuildClassFromVtables():
	rtti_logger.debug("--- BuildClassFromVtables [STARTED]")			
	
	# from vtable map, build class Object
	
	# add each vtable to its object
	for vtable_addr, vtable in Map_Vtable.items():
		ClassName = vtable.GetClassName()
		rtti_logger.debug("[Object %s] : add vtable %08X" % (ClassName, vtable_addr))
		if ClassName not in Map_Class :
			Map_Class[ClassName] = ClassObject(ClassName)
			
		Map_Class[ClassName].VtableAddress += [vtable_addr]
		
		
	# computes direct parents
	for ClassName, Class in Map_Class.items() :	
		# order VtableAddress
		Map_Class[ClassName].VtableAddress.sort()
	
		# get direct parents
		DirectCost = {}
		rtti_logger.debug("[Object %s] : GetClassLayout" % (ClassName))
		Layout = GetClassLayout(Class)
		
		for (OffsetVtable, ParentName) in Layout.items() :
			DirectCost[ParentName] = OffsetVtable
			
		for (OffsetVtable, ParentName) in Layout.items() :
			if ParentName in Map_Class :
				for (ParentOffsetVtable, ParentParentName) in GetClassLayout(Map_Class[ParentName]).items() :
					if (ParentParentName in DirectCost) and DirectCost[ParentParentName] == (OffsetVtable + ParentOffsetVtable) :
						del DirectCost[ParentParentName]
					
		
		# get virtual class position
		VtablesAddr = Map_Class[ClassName].VtableAddress
		ListCompleteObjectLocator = {}
		for i in VtablesAddr :
			CompleteObjectLocator = Map_Vtable[i].GetCompleteObjectLocator()
			ListCompleteObjectLocator[CompleteObjectLocator.Offset] = CompleteObjectLocator
		
		
		# should have two cross-ref
		ref = get_first_dref_to(VtablesAddr[0])
		ListCref = []
		#while ref != BADADDR and ref != None :
		#	if get_func(ref) != None :
		#		ListCref += [get_func(ref).startEA]
		#		ref = get_next_dref_to(VtablesAddr[0], ref)
		
		OffsetUsed = {}
		if  len(ListCref) != 2 :
			error = "%x has %d dref : " % (VtablesAddr[0], len(ListCref))
			for dref in ListCref :
				error += "'%x'" % dref
			rtti_logger.debug(error)
		else :
			mov_instr = GetMovInstructions(GetFunctionInstructions(get_func(ListCref[0]).startEA))
			mov_instr += GetMovInstructions(GetFunctionInstructions(get_func(ListCref[1]).startEA))
			
			for instr in mov_instr :
				if GetOperandValue(instr, 1) not in Map_Vtable and IsValidAddress(GetOperandValue(instr, 1)) and GetOperandValue(instr, 0) != 0:
					OffsetUsed[GetOperandValue(instr, 0)] = instr

		ListClassDescriptor = Class.GetBaseClassDescriptorArray()
		for addr in ListClassDescriptor :
			ClassDescriptor = Map_BaseClassDescriptor[addr]
			if ClassDescriptor.PMD[1] == 0xFFFFFFFF :
				for (ParentName, Offset) in DirectCost.items() :
					if Offset == ClassDescriptor.PMD[0] :
						CompleteObjectLocator.Name = ParentName
			else :
				if ClassDescriptor.PMD[1] in OffsetUsed :
					VbTable = GetOperandValue(OffsetUsed[ClassDescriptor.PMD[1]], 1)
					ParentName = ClassDescriptor.GetClassName()
					ParentOffset = Dword(VbTable+ClassDescriptor.PMD[2]) + ClassDescriptor.PMD[1]
					CompleteObjectLocator.Name = ParentName
					if ClassName not in Map_VbTable :
						Map_VbTable[ClassName] = []
					Map_VbTable[ClassName] += [(ParentName, ParentOffset)]
				#print "class %s : Found a vbtable (%x)  for class %s which is at offset %x" % (ClassName, VbTable, ParentName, ParentOffset)
			

		
		Map_Class[ClassName].DirectParents = DirectCost
	
	rtti_logger.debug("--- RegisterAllVtables [FINISHED]")
			
#_______________________________________________________________________________

def CreateStruct(name):
	structId = GetStrucIdByName(name)
	if structId != BADADDR:
		DelStruc(structId)
	
	return AddStrucEx(-1, name, 0)

	
#_______________________________________________________________________________		
def RttiCreateIdaStruct():
	sid = CreateStruct("RTTI_TypeInformation")
	if g_Is64bit :
		AddStrucMember(sid, "pVFTable", 0, FF_QWRD|FF_DATA, BADADDR, 4)
		SetType(sid, "PVOID;")
		AddStrucMember(sid, "spare", 8, FF_QWRD|FF_DATA, BADADDR, 4)
		SetType(sid+4, "PVOID;")
		AddStrucMember(sid, "Name", 16, FF_ASCI|FF_DATA, ASCSTR_C, 1)
	else :
		AddStrucMember(sid, "pVFTable", 0, FF_DWRD|FF_DATA, BADADDR, 4)
		SetType(sid, "PVOID;")
		AddStrucMember(sid, "spare", 4, FF_ALIGN|FF_DATA, BADADDR, 4)
		SetType(sid+4, "PVOID;")
		AddStrucMember(sid, "Name", 8, FF_ASCI|FF_DATA, ASCSTR_C, 1)

	sid = CreateStruct("RTTI_ClassHierarchyDescriptor")
	AddStrucMember(sid, "signature", 0, FF_DWRD|FF_DATA, BADADDR, 4)
	SetType(sid, "DWORD;")
	AddStrucMember(sid, "Attributes", 4, FF_DWRD|FF_DATA, BADADDR, 4)
	SetType(sid+4, "DWORD;")
	AddStrucMember(sid, "numBaseClasses", 8, FF_DWRD|FF_DATA, BADADDR, 4)
	SetType(sid+8, "DWORD;")
	if g_Is64bit :
		AddStrucMember(sid, "BaseClassArray", 12, offflag()|FF_DWRD|FF_DATA, BADADDR, 4, BADADDR, 0, REFINFO_RVA|REF_OFF64)
	else :
		AddStrucMember(sid, "BaseClassArray", 12, offflag()|FF_DWRD|FF_DATA, BADADDR, 4, BADADDR)
	
	
	sid = CreateStruct("RTTI_CompleteObjectLocator")
	AddStrucMember(sid, "signature", 0, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid, "DWORD;")
	AddStrucMember(sid, "offset", 4, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+4, "DWORD;")
	AddStrucMember(sid, "cdOffset", 8, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+8, "DWORD;")
	if g_Is64bit :
		AddStrucMember(sid, "TypeDescriptor", 12, offflag()|FF_DWRD|FF_DATA, BADADDR, 4, BADADDR, 0, REFINFO_RVA|REF_OFF64)
		AddStrucMember(sid, "ClassHierarchyDescriptor", 16, offflag()|FF_DWRD|FF_DATA, BADADDR, 4, BADADDR, 0, REFINFO_RVA|REF_OFF64)
	else :
		AddStrucMember(sid, "TypeDescriptor", 12, offflag()|FF_DWRD|FF_DATA, -1, 4)
		AddStrucMember(sid, "ClassHierarchyDescriptor", 16, offflag()|FF_DWRD|FF_DATA, -1, 4)

	SetType(sid+12, "RTTI_TypeInformation*;")
	SetType(sid+16, "RTTI_ClassHierarchyDescriptor*;")
		
	sid = CreateStruct("RTTI_PMD")
	AddStrucMember(sid, "mdisp", 0, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+0, "DWORD;")
	AddStrucMember(sid, "pdisp", 4, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+4, "DWORD;")
	AddStrucMember(sid, "vdisp", 8, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+8, "DWORD;")
	
	sid = CreateStruct("RTTI_BaseClassDescriptor")
	if g_Is64bit :
		AddStrucMember(sid, "TypeDescriptor", 0, offflag()|FF_DWRD|FF_DATA, -1, 4, BADADDR, 0, REFINFO_RVA|REF_OFF64)
	else:
		AddStrucMember(sid, "TypeDescriptor", 0, offflag()|FF_DWRD|FF_DATA, -1, 4)
	SetType(sid, "RTTI_TypeInformation* TypeDescriptor;")
	AddStrucMember(sid, "numContainedBases", 4, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+4, "DWORD;")
	AddStrucMember(sid, "PMD", 8, FF_STRU|FF_DATA, GetStrucIdByName("RTTI_PMD"), 12)
	SetType(sid+8, "RTTI_PMD;")
	AddStrucMember(sid, "Attributes", 20, FF_DWRD|FF_DATA, -1, 4)
	SetType(sid+20, "DWORD;")
	if g_Is64bit :
		AddStrucMember(sid, "ClassHierarchyDescriptor", 24, offflag()|FF_DWRD|FF_DATA, -1, 4, BADADDR, 0, REFINFO_RVA|REF_OFF64)
	else:
		AddStrucMember(sid, "ClassHierarchyDescriptor", 24, offflag()|FF_DWRD|FF_DATA, -1, 4)
	
	SetType(sid+24, "RTTI_ClassHierarchyDescriptor*;")
	
	SetType(GetStrucIdByName("RTTI_ClassHierarchyDescriptor")+12, "RTTI_BaseClassDescriptor**;")

#_______________________________________________________________________________
def RttiRenameIdaField() :
	RttiCreateIdaStruct()
	
	for addr, class_ in Map_Class.items() :
		# first vtable
		address = class_.VtableAddress[0]
		
		# should have two cross-ref
		ref = get_first_dref_to(address)
		ListCref = []
		while ref != BADADDR :
			ListCref += [ref]
			ref = get_next_dref_to(address, ref)
			
		if  len(ListCref) >= 1 :
			rtti_logger.debug("Create Constructor for class : %s" % (class_.GetClassName()))
			
			ctor_ = get_func(ListCref[0])
			
			if ctor_ :
				MakeNameEx(get_func(ListCref[0]).startEA, "class_%s_ctor_dtor" % (class_.GetClassName()), SN_NOWARN)
			else :
				print "[+] You must create a function 'class_%s_ctor_dtor' at offset : %08X" % (class_.GetClassName(), ListCref[0])
				
		if  len(ListCref) >= 2 :
			dtor_ = get_func(ListCref[1])
			if dtor_ : 
				MakeNameEx(get_func(ListCref[1]).startEA, "class_%s_ctor_dtor_" % (class_.GetClassName()), SN_NOWARN)
			else:
				print "[+] You must create a function 'class_%s_ctor_dtor_' at offset : %08X" % (class_.GetClassName(), ListCref[1])
				
	
	for addr, vtable in Map_Vtable.items() :
		if g_Is64bit :
			MakeQword(addr)
			MakeQword(addr-8)
		else :
			MakeDword(addr)
			MakeDword(addr-4)
			
		ClassName = vtable.GetClassName()
		ParentClassName = Map_Class[ClassName].GetBaseClassAtOffset(vtable.GetOffset())
			
		if ParentClassName != "" :
			if MakeNameEx(addr, "rtti_vtable_%s_for_class_%s" % (vtable.GetClassName(), ParentClassName), SN_NOWARN) == 0 :
				counter = 1
				while MakeNameEx(addr, "rtti_vtable_%s_for_class_%s_%d" % (vtable.GetClassName(), ParentClassName, counter), SN_NOWARN) == 0 :
					counter += 1
		else :
			if MakeNameEx(addr, "rtti_vtable_%s" % (vtable.GetClassName()), SN_NOWARN) == 0 :
				counter = 1
				while MakeNameEx(addr, "rtti_vtable_%s_%d" % (vtable.GetClassName(), counter), SN_NOWARN) == 0 :
					counter += 1

				
	for addr, CompleteObjectLocator in Map_CompleteObjectLocator.items() :
		MakeStructEx(addr, -1, "RTTI_CompleteObjectLocator");
		try :
			ClassName = CompleteObjectLocator.GetClassName()
			ParentClassName = Map_Class[ClassName].GetBaseClassAtOffset(CompleteObjectLocator.GetOffset())
			if ParentClassName != "" :
				if MakeNameEx(addr, "rtti_CompleteObjectLocator_%s_for_class_%s" % (ClassName, ParentClassName), SN_NOWARN) == 0 :
					counter = 1
					while MakeNameEx(addr, "rtti_CompleteObjectLocator_%s_for_class_%s_%d" % (ClassName, ParentClassName, counter), SN_NOWARN) == 0 :
						counter += 1
			else :
				if MakeNameEx(addr, "rtti_CompleteObjectLocator_%s" % (ClassName), SN_NOWARN) == 0 :
					counter = 1
					while MakeNameEx(addr, "rtti_CompleteObjectLocator_%s_%d" % (ClassName, counter), SN_NOWARN) == 0 :
						counter += 1
		except :
			print "MakeNameEx CompleteObjectLocator failed at address : %x" % (addr)
	
	for addr, ClassHierarchyDescriptor in Map_ClassHierarchyDescriptor.items() :
		ClassName = ClassHierarchyDescriptor.Name
		MakeStructEx(addr, -1, "RTTI_ClassHierarchyDescriptor");
		if MakeNameEx(addr, "rtti_ClassHierarchyDescriptor_Class_%s" % (ClassName), SN_NOWARN) == 0 :
			counter = 1
			while MakeNameEx(addr, "rtti_ClassHierarchyDescriptor_Class_%s_%d" % (ClassName, counter), SN_NOWARN) == 0 :
				counter += 1
		
		if MakeNameEx(ClassHierarchyDescriptor.Address_BaseClassDescriptorArray, "rtti_BaseClassDescriptorArray_Class_%s" % (ClassName), SN_NOWARN) == 0 :
			counter = 1
			while MakeNameEx(ClassHierarchyDescriptor.Address_BaseClassDescriptorArray, "rtti_BaseClassDescriptorArray_Class_%s_%d" % (ClassName, counter), SN_NOWARN) == 0 :
				counter += 1
				
		for i in range(ClassHierarchyDescriptor.numBaseClasses) :
			MakeDword(ClassHierarchyDescriptor.Address_BaseClassDescriptorArray + i * 4)
	
	for addr, TypeDescriptor in Map_TypeDescriptor.items() :
		MakeStructEx(addr, -1, "RTTI_TypeInformation");
		MakeStr(addr + 8, BADADDR)
		if MakeNameEx(addr, "rtti_TypeInformation_%s" % (TypeDescriptor.GetClassName()), SN_NOWARN) == 0 :
			counter = 1
			while MakeNameEx(addr, "rtti_TypeInformation_%s_%d" % (CompleteObjectLocator.GetClassName(), counter), SN_NOWARN) == 0 :
				counter += 1
	
	for addr, BaseClassDescriptor in Map_BaseClassDescriptor.items() :
		MakeStructEx(addr, -1, "RTTI_BaseClassDescriptor");
		ClassName = BaseClassDescriptor.GetClassName()
		if ClassName in Map_Class :
			ParentClassName = Map_Class[ClassName].GetBaseClassAtOffset(BaseClassDescriptor.PMD[0])
			if MakeNameEx(addr, "rtti_BaseClassDescriptor_%s_for_class_%s" % (ClassName, ParentClassName), SN_NOWARN) == 0 :
				counter = 1
				while MakeNameEx(addr, "rtti_BaseClassDescriptor_%s_for_class_%s_%d" % (ClassName, ParentClassName, counter), SN_NOWARN) == 0 :
					counter += 1

#_______________________________________________________________________________
def RttiGetInfo() :
	print "Class found : "
	for ClassName, Class in Map_Class.items() :
		print "\t'%s'" % (ClassName)
#_______________________________________________________________________________
def RttiGetClassInfo(ClassName) :
	try :
		Class = Map_Class[ClassName]
	
		for (OffsetVtable, ParentName) in Class.GetLayout().items() :
			print "offset : %x - vtable for class %s" % (OffsetVtable, ParentName)

	except :
		print "Unknown Class %s" % (ClassName)

#_______________________________________________________________________________
def RttiSaveClass():
	RttiFile = AskFile(1, "*.gml", "Do you want to save the Rtti Informations ?")
	if RttiFile == "":
		return
		
	def AddNode (NodeId, NodeName, NodeColor = None) :
		str	=	"\tnode [\n"
		str	+=	"\t\tid %d\n" % (NodeId)
		str	+=	"\t\tlabel \"%s\"\n" % (NodeName)
		str	+=	"\t\tgraphics [\n"
		str	+=	"\t\t\ttype  \"roundrectangle\"\n"
		if NodeColor :
			str	+=	"\t\t\tfill \"%s\" \n" % (NodeColor)
		str	+=	"\t\t\tw  150\n"
		str	+=	"\t\t]\n"
		str	+=	"\t]\n"
		return str
	
	
	file = open(RttiFile, 'w')
		
	file.write("graph [\n")
	file.write("\tdirected	1\n")
	file.write("\tIsPlanar	1\n\n")
	CurrentId = 1
	MapId = {}
	for ClassName, Class in Map_Class.items() :
		file.write(AddNode(CurrentId, ClassName))
		MapId[ClassName] = CurrentId
		CurrentId += 1
		
	for ClassName, Class in Map_Class.items() :	
		for base_class, offset in  Class.DirectParents.items():
			if base_class not in MapId:
				file.write(AddNode(CurrentId, base_class, "#FF0000"))
				MapId[base_class] = CurrentId
				CurrentId += 1
			str	=	"\tedge [\n"
			str	+=	"\t\tsource %d\n" % (MapId[ClassName])
			str	+=	"\t\ttarget %d\n" % (MapId[base_class])
			str	+=	"\t\tlabel \"%d\"\n" % (offset)
			str	+=	"\t]\n"
			
			file.write(str)

	file.write("]\n")
	file.close()

#_______________________________________________________________________________
def RttiSaveInformations(ClassName = ""):
	RttiFile = AskFile(1, "*.gv", "Do you want to save the Rtti Informations ?")
	if RttiFile == "":
		return
		
	nodes = ""
	links = ""
	node_class = ""
	node_vtable = ""
	node_compobj = ""
	node_hierdesc = ""
	node_typedesc = ""
	node_classdesc = ""
	node_baseclass = ""
	
	if ClassName != "" :
		SaveClass = {}
		SaveClass[ClassName] = Map_Class[ClassName]
	else :
		SaveClass = Map_Class
	
	Set_AddedObject = set([])
	
	for name, class_ in SaveClass.items() :
		(node, link, name) = class_.ExportToDot()
		nodes += node
		links += link
		node_class += name + " "
	
		for vtable_addr in class_.VtableAddress :
			Vtable = Map_Vtable[vtable_addr]
			(node, link, name) = Vtable.ExportToDot()
			nodes += node
			links += link
			node_vtable += name + " "
			
			CompleteObjectLocator =  Map_CompleteObjectLocator[Vtable.Address_CompleteObjectLocator]
			if CompleteObjectLocator.addr not in Set_AddedObject :
				(node, link, name) = CompleteObjectLocator.ExportToDot()
				nodes += node
				links += link
				node_compobj += name + " "
				Set_AddedObject.add(CompleteObjectLocator.addr)
	
				TypeDescriptor = Map_TypeDescriptor[CompleteObjectLocator.Address_TypeDescriptor]
				if TypeDescriptor.addr not in Set_AddedObject :
					(node, link, name) = TypeDescriptor.ExportToDot()
					nodes += node
					links += link
					node_typedesc += name + " "
					Set_AddedObject.add(TypeDescriptor.addr)
					
				ClassHierarchyDescriptor = Map_ClassHierarchyDescriptor[CompleteObjectLocator.Address_ClassHierarchyDescriptor]
				if ClassHierarchyDescriptor.addr not in Set_AddedObject :
					(node, link, name, BaseClassArrayName) = ClassHierarchyDescriptor.ExportToDot()
					nodes += node
					links += link
					node_hierdesc += name + " "
					node_baseclass += BaseClassArrayName + " "
					Set_AddedObject.add(ClassHierarchyDescriptor.addr)
	
					BaseClassDescriptorArray = ClassHierarchyDescriptor.GetBaseClassDescriptorArray()
					for BaseClassDescriptorAddr in BaseClassDescriptorArray :
						BaseClassDescriptor = Map_BaseClassDescriptor[BaseClassDescriptorAddr]
						if BaseClassDescriptor.addr not in Set_AddedObject :
							(node, link, name) = BaseClassDescriptor.ExportToDot()
							nodes += node
							links += link
							node_classdesc += name + " "
							Set_AddedObject.add(BaseClassDescriptor.addr)
	
	
	
	file = open(RttiFile, 'w')
	file.write("digraph RTTI {\n")
	file.write("\trankdir = LR\n")
	file.write(nodes)
	file.write(links)
	file.write("{rank=same; %s}" % node_class)
	file.write("{rank=same; %s}" % node_vtable)
	file.write("{rank=same; %s}" % (node_compobj))
	file.write("{rank=same; %s %s}" % (node_hierdesc, node_typedesc))
	file.write("{rank=same; %s}" % (node_baseclass))
	file.write("{rank=same; %s}" % node_classdesc)
	file.write("}")
	file.close

def RttiHelp() :
	print "RttiSaveInformations() : Save the Rtti structures in a .dot file"
	print "RttiSaveClass()        : Save the class hierarchy in a .gml file"
	print "RttiGetInfo()          : Print all the classes"
	print "RttiGetClassInfo(name) : print the class hierarchy"
	print "RttiRenameIdaField()   : Rename the rtti structures in the ida database"
	
	
def main() :
	global rtti_logger
	global fileHandler
	global Map_BaseClassDescriptor
	global Map_TypeDescriptor
	global Map_ClassHierarchyDescriptor
	global Map_CompleteObjectLocator
	global Map_Vtable
	global Map_Class
	global Map_VbTable
	global g_Is64bit
	global g_pointer_size

	if rtti_logger == 0 :
		if os.path.isfile(RttiLogFile) :
			f = open(RttiLogFile, 'w')
			f.close()
		rtti_logger = logging.getLogger("rtti")
		fileHandler = logging.FileHandler(RttiLogFile)
		rtti_logger.addHandler(fileHandler)
		rtti_logger.setLevel(level=logging.DEBUG)
	
	Map_BaseClassDescriptor			=	{}
	Map_TypeDescriptor				=	{}
	Map_ClassHierarchyDescriptor	=	{}
	Map_CompleteObjectLocator		=	{}
	Map_Vtable						=	{}
	Map_Class						=	{}
	Map_VbTable						=	{}
	
	# find all vtables
	RegisterAllVtables()
	BuildClassFromVtables()
	RttiGetInfo()
	
	
if __name__ == "__main__" :
	
	if AskYN(0, "Include code section in the scan ?\n(in very few cases, rtti data are in the code section)") == 1:
		g_deep_scan = True
	
	# if the binary is a 64 bit one : 
	if GetLongPrm(INF_LFLAGS) & LFLG_64BIT : 
		g_Is64bit		= True
		g_pointer_size	= 8
	main()
