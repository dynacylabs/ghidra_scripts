# @runtime PyGhidra

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import ReferenceManager

program = getCurrentProgram()
listing = program.getListing()
reference_manager = program.getReferenceManager()

current_address = currentAddress

memory_block = program.getMemory().getBlock(current_address)
block_start = memory_block.getStart()
block_end = memory_block.getEnd()

address_set = AddressSet(block_start, block_end)

function_names = set()

addresses = address_set.getAddresses(True)
while addresses.hasNext():
    address = addresses.next()
    references = reference_manager.getReferencesTo(address)
    for reference in references:
        from_address = reference.getFromAddress()
        function = listing.getFunctionContaining(from_address)
        if function is not None:
            function_names.add(function.getName())

for function_name in sorted(function_names):
    print(function_name)