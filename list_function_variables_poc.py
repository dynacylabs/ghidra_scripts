# @runtime PyGhidra
"""
Proof of Concept: List All Variables in Selected Function

Simple script to verify that all variables visible in the decompiler window
can be extracted and displayed.

USAGE: 
1. Select a function in the listing or decompiler window
2. Run this script
"""

from ghidra.app.decompiler import DecompInterface

# Get current program
current_program = getCurrentProgram()
if not current_program:
    print("Error: No program loaded")
else:
    # Ask user to manually select a function
    function_manager = current_program.getFunctionManager()
    all_functions = list(function_manager.getFunctions(True))
    
    if not all_functions:
        print("Error: No functions found in program")
    else:
        # For this POC, just use the first function or let user choose
        # In practice, you'd select the function at cursor
        print("Available functions:")
        for i, func in enumerate(all_functions[:10]):  # Show first 10
            print(f"{i}: {func.getName()} at {func.getEntryPoint()}")
        
        # For demo, just use the first function
        target_function = all_functions[0]
        print(f"\nAnalyzing first function: {target_function.getName()}")
        
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
