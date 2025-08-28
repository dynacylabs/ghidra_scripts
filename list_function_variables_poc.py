# @runtime PyGhidra
"""
Proof of Concept: List All Variables in Selected Function

Simple script to verify that all variables visible in the decompiler window
can be extracted and displayed.

USAGE: Place your cursor inside a function and run this script.
"""

from ghidra.app.decompiler import DecompInterface

# Get current program and selected function
current_program = getCurrentProgram()
if not current_program:
    print("Error: No program loaded")
else:
    # Get function at cursor location
    current_location = getCurrentLocation()
    if not current_location:
        print("Error: No location selected")
    else:
        function_manager = current_program.getFunctionManager()
        target_function = function_manager.getFunctionContaining(current_location.getAddress())
        
        if not target_function:
            print("Error: No function at cursor location. Place cursor inside a function.")
        else:
            print("FUNCTION: " + target_function.getName())
            print("ADDRESS: " + str(target_function.getEntryPoint()))
            print("=" * 60)
            
            # Initialize and run decompiler
            decompiler = DecompInterface()
            decompiler.openProgram(current_program)
            result = decompiler.decompileFunction(target_function, 30, monitor)
            
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
