# @runtime PyGhidra

# Import memory regions into a Ghidra program
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Import Memory Layout

import pickle
import time

def import_memory_layout():
    """
    Import memory region information into the current program.
    This recreates memory blocks with their properties, permissions, and data.
    """
    
    # Load the memory layout file
    mem_file = askFile('Select memory layout file (.mem)', 'OK')
    if not mem_file or not mem_file.path.endswith('.mem'):
        print("Please select a valid memory layout file (.mem)")
        return
    
    print('Loading memory layout...')
    
    try:
        with open(mem_file.path, 'rb') as f:
            memory_data = pickle.load(f)
    except Exception as e:
        print(f'Error loading memory layout file: {str(e)}')
        return
    
    # Show information about what we loaded
    total_blocks = len(memory_data.get('memory_blocks', []))
    source_program = memory_data.get('program_name', 'Unknown')
    timestamp = memory_data.get('timestamp', 0)
    
    print(f'Loaded memory layout from: {source_program}')
    if timestamp:
        print(f'Export timestamp: {time.ctime(timestamp)}')
    print(f'Found {total_blocks} memory blocks to import')
    
    # Get current program's memory manager
    memory = currentProgram.getMemory()
    address_factory = currentProgram.getAddressFactory()
    
    # Track import statistics
    imported_blocks = 0
    skipped_blocks = 0
    errors = []
    
    # Import each memory block
    for i, block_info in enumerate(memory_data.get('memory_blocks', [])):
        block_num = i + 1
        block_name = block_info.get('name', f'imported_block_{block_num}')
        
        print(f'Processing block {block_num}/{total_blocks}: {block_name}')
        
        try:
            # Parse addresses
            start_addr_str = block_info.get('start_address')
            end_addr_str = block_info.get('end_address')
            size = block_info.get('size', 0)
            
            if not start_addr_str:
                print(f'  Skipping block {block_name}: missing start address')
                skipped_blocks += 1
                continue
            
            # Get address space (try to match by parsing the address string)
            try:
                start_addr = address_factory.getAddress(start_addr_str)
                if start_addr is None:
                    print(f'  Skipping block {block_name}: invalid start address {start_addr_str}')
                    skipped_blocks += 1
                    continue
            except Exception as e:
                print(f'  Skipping block {block_name}: could not parse address {start_addr_str}: {str(e)}')
                skipped_blocks += 1
                continue
            
            # Check if block already exists at this address
            existing_block = memory.getBlock(start_addr)
            if existing_block is not None:
                print(f'  Skipping block {block_name}: memory block already exists at {start_addr_str}')
                skipped_blocks += 1
                continue
            
            # Get block properties
            permissions = block_info.get('permissions', {})
            properties = block_info.get('properties', {})
            is_read = permissions.get('read', True)
            is_write = permissions.get('write', False)
            is_execute = permissions.get('execute', False)
            is_initialized = properties.get('initialized', False)
            is_overlay = properties.get('overlay', False)
            comment = block_info.get('comment', '')
            
            # Create the memory block
            try:
                if is_overlay:
                    # Handle overlay blocks
                    overlay_info = block_info.get('overlay_info', {})
                    base_space_name = overlay_info.get('base_space_name')
                    
                    if base_space_name:
                        base_space = address_factory.getAddressSpace(base_space_name)
                        if base_space:
                            # Create overlay space first
                            overlay_space_name = overlay_info.get('overlay_space_name', f'{block_name}_overlay')
                            try:
                                overlay_space = address_factory.getAddressSpace(overlay_space_name)
                                if overlay_space is None:
                                    # Note: Creating new overlay spaces might require special handling
                                    print(f'  Warning: Could not find or create overlay space {overlay_space_name}')
                                    # Fall back to creating regular block
                                    is_overlay = False
                            except:
                                is_overlay = False
                
                if is_initialized and block_info.get('data') is not None:
                    # Create initialized block with data
                    data = block_info['data']
                    byte_array = []
                    for byte_val in data:
                        byte_array.append(byte_val)
                    
                    # Convert to java byte array
                    java_bytes = []
                    for b in byte_array:
                        if b > 127:
                            java_bytes.append(b - 256)  # Convert to signed byte
                        else:
                            java_bytes.append(b)
                    
                    block = memory.createInitializedBlock(
                        block_name,
                        start_addr,
                        java_bytes,
                        comment,
                        None,  # source
                        is_overlay
                    )
                    print(f'  Created initialized block with {len(data)} bytes of data')
                    
                elif is_initialized:
                    # Create initialized block without data (filled with zeros)
                    block = memory.createInitializedBlock(
                        block_name,
                        start_addr,
                        size,
                        0,  # fill value
                        None,  # TaskMonitor
                        is_overlay
                    )
                    print(f'  Created initialized block (filled with zeros)')
                    
                else:
                    # Create uninitialized block
                    block = memory.createUninitializedBlock(
                        block_name,
                        start_addr,
                        size,
                        is_overlay
                    )
                    print(f'  Created uninitialized block')
                
                # Set block permissions
                block.setRead(is_read)
                block.setWrite(is_write)
                block.setExecute(is_execute)
                
                # Set additional properties if available
                if hasattr(block, 'setVolatile') and properties.get('volatile'):
                    try:
                        block.setVolatile(True)
                    except:
                        pass  # Not all block types support this
                
                # Set comment if provided
                if comment:
                    block.setComment(comment)
                
                imported_blocks += 1
                print(f'  Successfully imported block: {block_name}')
                
            except Exception as e:
                error_msg = f'Error creating block {block_name}: {str(e)}'
                errors.append(error_msg)
                print(f'  {error_msg}')
                skipped_blocks += 1
                
        except Exception as e:
            error_msg = f'Error processing block {block_name}: {str(e)}'
            errors.append(error_msg)
            print(f'  {error_msg}')
            skipped_blocks += 1
    
    # Print final summary
    print(f'\nMemory import completed:')
    print(f'  - {imported_blocks} blocks imported successfully')
    print(f'  - {skipped_blocks} blocks skipped or failed')
    
    if errors:
        print(f'  - {len(errors)} errors encountered:')
        for error in errors[:10]:  # Show first 10 errors
            print(f'    * {error}')
        if len(errors) > 10:
            print(f'    * ... and {len(errors) - 10} more errors')
    
    if imported_blocks > 0:
        print(f'\nRecommendation: Re-run Ghidra\'s analyzer to process the imported memory regions.')

# Run the import function
import_memory_layout()
