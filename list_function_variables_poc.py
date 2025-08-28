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
                        print("  " + param.getName() + " (" + param.getDataType().getDisplayName() + ")")
                
                print("\nLOCAL VARIABLES:")
                local_map = high_function.getLocalSymbolMap()
                for symbol in local_map.getSymbols():
                    if not (hasattr(symbol, 'isParameter') and symbol.isParameter()):
                        local_count += 1
                        print("  " + symbol.getName() + " (" + symbol.getDataType().getDisplayName() + ")")
                
                print("\nGLOBAL REFERENCES:")
                global_map = high_function.getGlobalSymbolMap()
                for symbol in global_map.getSymbols():
                    global_count += 1
                    try:
                        data_type = symbol.getDataType().getDisplayName()
                    except:
                        data_type = "unknown"
                    print("  " + symbol.getName() + " (" + data_type + ")")
                
                print("\n" + "=" * 60)
                print("SUMMARY:")
                print("  Parameters: " + str(param_count))
                print("  Local variables: " + str(local_count)) 
                print("  Global references: " + str(global_count))
                print("  TOTAL: " + str(param_count + local_count + global_count))
                
                print("\nDECOMPILED CODE:")
                print("-" * 60)
                print(result.getDecompiledFunction().getC())
                
            else:
                print("Error: Could not get high-level function representation")
        else:
            print("Error: Failed to decompile function")
