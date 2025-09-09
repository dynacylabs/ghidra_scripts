# @runtime PyGhidra

# Export memory regions from a Ghidra program
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Export Memory Layout

import pickle
import time

def export_memory_layout():
    """
    Export memory region information from the current program.
    This includes memory blocks with their properties, permissions, and layout.
    """
    
    file_path = askFile('Save memory layout file as', 'OK').path
    if not file_path.endswith('.mem'):
        file_path += '.mem'
    
    print('Exporting memory layout...')
    
    # Get memory manager
    memory = currentProgram.getMemory()
    
    # Create data structure to store memory information
    memory_data = {
        'program_name': currentProgram.getName(),
        'timestamp': time.time(),
        'memory_blocks': [],
        'address_factory_info': {
            'default_space': str(currentProgram.getAddressFactory().getDefaultAddressSpace()),
            'address_spaces': []
        }
    }
    
    # Get address factory information
    address_factory = currentProgram.getAddressFactory()
    for space in address_factory.getAddressSpaces():
        space_info = {
            'name': space.getName(),
            'size': space.getSize(),
            'address_size': space.getAddressableUnitSize(),
            'type': space.getType(),
            'unique': space.isUniqueSpace(),
            'loaded_space': space.isLoadedMemorySpace(),
            'memory_space': space.isMemorySpace(),
            'non_loaded_space': space.isNonLoadedMemorySpace(),
            'overlay_space': space.isOverlaySpace(),
            'register_space': space.isRegisterSpace(),
            'stack_space': space.isStackSpace(),
            'variable_space': space.isVariableSpace()
        }
        memory_data['address_factory_info']['address_spaces'].append(space_info)
    
    # Export each memory block
    total_blocks = 0
    for block in memory.getBlocks():
        total_blocks += 1
    
    print(f'Found {total_blocks} memory blocks to export')
    
    current_block = 0
    for block in memory.getBlocks():
        current_block += 1
        print(f'Processing block {current_block}/{total_blocks}: {block.getName()}')
        
        # Get block properties
        block_info = {
            'name': block.getName(),
            'comment': block.getComment(),
            'start_address': str(block.getStart()),
            'end_address': str(block.getEnd()),
            'size': block.getSize(),
            'permissions': {
                'read': block.isRead(),
                'write': block.isWrite(),
                'execute': block.isExecute()
            },
            'properties': {
                'initialized': block.isInitialized(),
                'loaded': block.isLoaded(),
                'overlay': block.isOverlay(),
                'artificial': block.isArtificial(),
                'volatile': block.isVolatile()
            },
            'source_info': {
                'source_name': block.getSourceName() if block.getSourceName() else None,
            }
        }
        
        # Handle overlay blocks
        if block.isOverlay():
            overlay_space = block.getStart().getAddressSpace()
            block_info['overlay_info'] = {
                'overlay_space_name': overlay_space.getName(),
                'base_space_name': overlay_space.getOverlayedSpace().getName() if overlay_space.getOverlayedSpace() else None
            }
        
        # Get memory block type information
        if hasattr(block, 'getType'):
            block_info['block_type'] = str(block.getType())
        
        # Export initialized data if the block is small enough and initialized
        if block.isInitialized() and block.getSize() <= 0x10000:  # Only for blocks <= 64KB
            try:
                data = bytearray()
                block_start = block.getStart()
                for i in range(int(block.getSize())):
                    try:
                        byte_val = memory.getByte(block_start.add(i))
                        data.append(byte_val & 0xFF)
                    except:
                        data.append(0)  # Fill with zeros if can't read
                block_info['data'] = data
                print(f'  Exported {len(data)} bytes of data')
            except Exception as e:
                print(f'  Could not export data for block {block.getName()}: {str(e)}')
                block_info['data'] = None
        else:
            block_info['data'] = None
            if block.isInitialized():
                print(f'  Block too large ({block.getSize()} bytes), skipping data export')
        
        memory_data['memory_blocks'].append(block_info)
    
    # Save the memory layout data
    try:
        with open(file_path, 'wb') as f:
            pickle.dump(memory_data, f)
        
        print(f'Successfully exported memory layout to: {file_path}')
        print(f'Exported {len(memory_data["memory_blocks"])} memory blocks')
        
        # Print summary
        initialized_blocks = sum(1 for b in memory_data['memory_blocks'] if b['properties']['initialized'])
        executable_blocks = sum(1 for b in memory_data['memory_blocks'] if b['permissions']['execute'])
        writable_blocks = sum(1 for b in memory_data['memory_blocks'] if b['permissions']['write'])
        blocks_with_data = sum(1 for b in memory_data['memory_blocks'] if b['data'] is not None)
        
        print(f'Summary:')
        print(f'  - {initialized_blocks} initialized blocks')
        print(f'  - {executable_blocks} executable blocks') 
        print(f'  - {writable_blocks} writable blocks')
        print(f'  - {blocks_with_data} blocks with exported data')
        
    except Exception as e:
        print(f'Error saving memory layout: {str(e)}')
        return

# Run the export function
export_memory_layout()
