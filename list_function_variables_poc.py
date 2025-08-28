# @runtime PyGhidra
"""
Proof of Concept: List All Variables in Selected Function

Simple script to verify that all variables visible in the decompiler window
can be extracted and displayed.

USAGE: 
1. Place cursor inside a function or select text in a function
2. Run this script

The script will try to auto-detect the function at your current location.
"""

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType

def get_current_function():
    """Try to get the function at the current cursor location."""
    current_program = getCurrentProgram()
    if not current_program:
        return None
    
    function_manager = current_program.getFunctionManager()
    
    # Try multiple methods to get current address
    current_addr = None
    
    # Method 1: Try currentAddress (most common in Ghidra scripts)
    try:
        current_addr = currentAddress
        if current_addr:
            return function_manager.getFunctionContaining(current_addr)
    except NameError:
        pass
    
    # Method 2: Try currentLocation
    try:
        if currentLocation and hasattr(currentLocation, 'getAddress'):
            current_addr = currentLocation.getAddress()
            if current_addr:
                return function_manager.getFunctionContaining(current_addr)
    except NameError:
        pass
    
    # Method 3: Try currentSelection
    try:
        if currentSelection and not currentSelection.isEmpty():
            current_addr = currentSelection.getMinAddress()
            if current_addr:
                return function_manager.getFunctionContaining(current_addr)
    except NameError:
        pass
    
    return None

# Main execution
current_program = getCurrentProgram()
if not current_program:
    print("Error: No program loaded")
else:
    # Try to get function at current location
    target_function = get_current_function()
    
    if not target_function:
        # Fallback: show available functions and use first one
        function_manager = current_program.getFunctionManager()
        all_functions = list(function_manager.getFunctions(True))
        if all_functions:
            print("Could not detect current function. Available functions:")
            for i, func in enumerate(all_functions[:5]):
                print(f"  {func.getName()} at {func.getEntryPoint()}")
            target_function = all_functions[0]
            print(f"\nUsing first function: {target_function.getName()}")
        else:
            print("Error: No functions found in program")
            target_function = None
    
    if target_function:
        
        print("FUNCTION: " + target_function.getName())
        print("ADDRESS: " + str(target_function.getEntryPoint()))
        print("=" * 60)
        
        # Initialize and run decompiler
        decompiler = DecompInterface()
        decompiler.openProgram(current_program)
        result = decompiler.decompileFunction(target_function, 30, None)  # Use None instead of monitor
        
        if result and result.decompileCompleted():
            high_function = result.getHighFunction()
            
            if high_function:
                # Count variables
                param_count = 0
                local_count = 0
                global_count = 0
                
                print("PARAMETERS:")
                prototype = high_function.getFunctionPrototype()
                if prototype:
                    param_count = prototype.getNumParams()
                    for i in range(param_count):
                        param = prototype.getParam(i)
                        current_name = param.getName()
                        data_type = param.getDataType().getDisplayName()
                        print(f"  {current_name} ({data_type})")
                        
                        # Ask user for new name
                        new_name = askString("Rename Parameter", f"Enter new name for parameter '{current_name}' (or press Cancel/Enter to skip):")
                        if new_name and new_name.strip() and new_name != current_name:
                            try:
                                # Start a transaction for the change
                                transaction_id = current_program.startTransaction("Rename Parameter")
                                try:
                                    # Rename the parameter in the function signature
                                    if i < target_function.getParameterCount():
                                        function_param = target_function.getParameter(i)
                                        function_param.setName(new_name.strip(), SourceType.USER_DEFINED)
                                        print(f"    ✓ Renamed '{current_name}' to '{new_name}'")
                                    else:
                                        print(f"    ✗ Parameter index out of range for '{current_name}'")
                                finally:
                                    current_program.endTransaction(transaction_id, True)
                            except Exception as e:
                                print(f"    ✗ Error renaming '{current_name}': {e}")
                
                print("\nLOCAL VARIABLES:")
                local_map = high_function.getLocalSymbolMap()
                for symbol in local_map.getSymbols():
                    if not (hasattr(symbol, 'isParameter') and symbol.isParameter()):
                        local_count += 1
                        current_name = symbol.getName()
                        data_type = symbol.getDataType().getDisplayName()
                        print(f"  {current_name} ({data_type})")
                        
                        # Ask user for new name
                        new_name = askString("Rename Local Variable", f"Enter new name for variable '{current_name}' (or press Cancel/Enter to skip):")
                        if new_name and new_name.strip() and new_name != current_name:
                            try:
                                # Start a transaction for the change
                                transaction_id = current_program.startTransaction("Rename Local Variable")
                                try:
                                    # Try different methods to rename local variables
                                    renamed = False
                                    
                                    # Method 1: Try through the symbol directly
                                    if hasattr(symbol, 'getSymbol'):
                                        actual_symbol = symbol.getSymbol()
                                        if actual_symbol and hasattr(actual_symbol, 'setName'):
                                            actual_symbol.setName(new_name.strip(), SourceType.USER_DEFINED)
                                            renamed = True
                                    
                                    # Method 2: Try through HighLocal if it has a symbol
                                    if not renamed and hasattr(symbol, 'setName'):
                                        symbol.setName(new_name.strip())
                                        renamed = True
                                    
                                    # Method 3: Try through symbol table
                                    if not renamed:
                                        symbol_table = current_program.getSymbolTable()
                                        symbols = symbol_table.getSymbols(current_name, target_function)
                                        for sym in symbols:
                                            if sym.getParentNamespace() == target_function:
                                                sym.setName(new_name.strip(), SourceType.USER_DEFINED)
                                                renamed = True
                                                break
                                    
                                    if renamed:
                                        print(f"    ✓ Renamed '{current_name}' to '{new_name}'")
                                    else:
                                        print(f"    ✗ Could not rename local variable '{current_name}' - no available method")
                                        
                                finally:
                                    current_program.endTransaction(transaction_id, True)
                            except Exception as e:
                                print(f"    ✗ Error renaming '{current_name}': {e}")
                
                print("\nGLOBAL REFERENCES:")
                global_map = high_function.getGlobalSymbolMap()
                for symbol in global_map.getSymbols():
                    global_count += 1
                    current_name = symbol.getName()
                    try:
                        data_type = symbol.getDataType().getDisplayName()
                    except:
                        data_type = "unknown"
                    print(f"  {current_name} ({data_type})")
                    
                    # Note: Global variables typically can't be renamed from function context
                    print(f"    (Global variable - renaming not supported)")
                
                print("\n" + "=" * 60)
                print("SUMMARY:")
                print("  Parameters: " + str(param_count))
                print("  Local variables: " + str(local_count)) 
                print("  Global references: " + str(global_count))
                print("  TOTAL: " + str(param_count + local_count + global_count))
                
                # Ask if user wants to see the decompiled code
                show_code = askYesNo("Show Decompiled Code", "Would you like to see the decompiled code after renaming?")
                if show_code:
                    print("\nDECOMPILED CODE (after renaming):")
                    print("-" * 60)
                    # Re-decompile to show updated names
                    fresh_result = decompiler.decompileFunction(target_function, 30, None)
                    if fresh_result and fresh_result.decompileCompleted():
                        print(fresh_result.getDecompiledFunction().getC())
                    else:
                        print("Could not re-decompile function to show updated code")
                
                print("\nVariable renaming complete!")
                
            else:
                print("Error: Could not get high-level function representation")
        else:
            print("Error: Failed to decompile function")
