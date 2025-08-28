# @runtime PyGhidra
"""
Ghidra Script for Function Variable Analysis and Management.

This script provides comprehensive variable analysis capabilities for a selected
function in Ghidra, including:
- Extraction of all variables visible in the decompiler window
- Display of variable information (name, type, scope, location)
- Interactive variable renaming functionality
- Support for local variables, parameters, and stack variables

The script uses Ghidra's decompiler interface to access the complete variable
information that is displayed in the decompiler window, ensuring all variables
are captured and can be renamed.
"""

# Standard library imports
from typing import Dict, List, Optional, Set, Tuple

# Ghidra imports
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Function, Parameter, Variable
from ghidra.program.model.pcode import HighFunction, HighLocal, HighParam, HighSymbol
from ghidra.program.model.symbol import SourceType


class FunctionVariableManager:
    """
    Manager for analyzing and manipulating variables within a Ghidra function.
    
    This class provides comprehensive access to all variables that appear in
    the decompiler window, including local variables, parameters, and other
    symbols. It handles variable extraction, display, and renaming operations.
    """
    
    def __init__(self, current_program=None):
        """
        Initialize the function variable manager.
        
        Args:
            current_program: The current Ghidra program instance.
        """
        self.current_program = current_program
        self.function_manager = current_program.getFunctionManager()
        
        # Initialize decompiler interface with proper options
        self.decompiler_interface = DecompInterface()
        self.decompiler_options = DecompileOptions()
        self.decompiler_interface.setOptions(self.decompiler_options)
        self.decompiler_interface.openProgram(current_program)
        
        # Storage for current function analysis
        self.current_function: Optional[Function] = None
        self.high_function: Optional[HighFunction] = None
        self.variables_info: Dict[str, Dict] = {}
        
    def set_target_function(self, target_function: Function) -> bool:
        """
        Set the target function for variable analysis.
        
        Args:
            target_function: The Ghidra function to analyze.
            
        Returns:
            True if the function was successfully set and decompiled, False otherwise.
        """
        self.current_function = target_function
        
        # Decompile the function to get high-level representation
        decompile_result = self.decompiler_interface.decompileFunction(
            target_function, 30, monitor
        )
        
        if decompile_result and decompile_result.decompileCompleted():
            self.high_function = decompile_result.getHighFunction()
            self._extract_all_variables()
            return True
        else:
            print(f"Failed to decompile function: {target_function.getName()}")
            return False
    
    def _extract_all_variables(self) -> None:
        """
        Extract all variables from the decompiled function.
        
        This method gathers information about all variables that would be
        visible in the decompiler window, including their types, names,
        storage locations, and other metadata.
        """
        if not self.high_function:
            return
            
        self.variables_info.clear()
        
        # Extract function parameters
        self._extract_parameters()
        
        # Extract local variables (including stack variables)
        self._extract_local_variables()
        
        # Extract global variables referenced in the function
        self._extract_referenced_globals()
    
    def _extract_parameters(self) -> None:
        """Extract function parameters from the high-level representation."""
        if not self.high_function:
            return
            
        # Get function signature parameters
        function_prototype = self.high_function.getFunctionPrototype()
        if function_prototype:
            param_count = function_prototype.getNumParams()
            
            for i in range(param_count):
                param = function_prototype.getParam(i)
                if isinstance(param, HighParam):
                    param_info = {
                        'category': 'parameter',
                        'index': i,
                        'name': param.getName(),
                        'data_type': param.getDataType().getDisplayName(),
                        'size': param.getSize(),
                        'storage': self._get_storage_info(param),
                        'high_symbol': param,
                        'can_rename': True
                    }
                    self.variables_info[param.getName()] = param_info
    
    def _extract_local_variables(self) -> None:
        """Extract local variables from the high-level representation."""
        if not self.high_function:
            return
            
        # Get all local symbols from the high function
        local_symbol_map = self.high_function.getLocalSymbolMap()
        symbols = local_symbol_map.getSymbols()
        
        for symbol in symbols:
            if isinstance(symbol, HighLocal):
                # Skip parameters (they're handled separately)
                if isinstance(symbol, HighParam):
                    continue
                    
                var_info = {
                    'category': 'local',
                    'name': symbol.getName(),
                    'data_type': symbol.getDataType().getDisplayName(),
                    'size': symbol.getSize(),
                    'storage': self._get_storage_info(symbol),
                    'high_symbol': symbol,
                    'can_rename': True
                }
                self.variables_info[symbol.getName()] = var_info
    
    def _extract_referenced_globals(self) -> None:
        """Extract global variables referenced by the function."""
        if not self.high_function:
            return
            
        # Get global symbols referenced in the function
        global_symbol_map = self.high_function.getGlobalSymbolMap()
        symbols = global_symbol_map.getSymbols()
        
        for symbol in symbols:
            if hasattr(symbol, 'getName') and hasattr(symbol, 'getDataType'):
                var_info = {
                    'category': 'global',
                    'name': symbol.getName(),
                    'data_type': symbol.getDataType().getDisplayName(),
                    'size': symbol.getSize() if hasattr(symbol, 'getSize') else 0,
                    'storage': self._get_storage_info(symbol),
                    'high_symbol': symbol,
                    'can_rename': False  # Global variables have different rename rules
                }
                self.variables_info[symbol.getName()] = var_info
    
    def _get_storage_info(self, symbol) -> str:
        """
        Get human-readable storage information for a variable.
        
        Args:
            symbol: The high-level symbol to get storage info for.
            
        Returns:
            A string describing where the variable is stored.
        """
        try:
            if hasattr(symbol, 'getStorage'):
                storage = symbol.getStorage()
                if storage:
                    return storage.toString()
            
            if hasattr(symbol, 'getPCAddress'):
                pc_address = symbol.getPCAddress()
                if pc_address:
                    return f"PC: {pc_address}"
                    
            return "Unknown storage"
        except:
            return "Storage info unavailable"
    
    def display_all_variables(self) -> None:
        """
        Display all variables found in the current function.
        
        This method prints a comprehensive list of all variables with their
        details, organized by category (parameters, locals, globals).
        """
        if not self.current_function:
            print("No function selected. Please select a function first.")
            return
            
        function_name = self.current_function.getName()
        print(f"\n{'='*60}")
        print(f"VARIABLES IN FUNCTION: {function_name}")
        print(f"{'='*60}")
        
        if not self.variables_info:
            print("No variables found in this function.")
            return
        
        # Group variables by category
        categories = {
            'parameter': 'FUNCTION PARAMETERS',
            'local': 'LOCAL VARIABLES', 
            'global': 'GLOBAL REFERENCES'
        }
        
        for category, title in categories.items():
            category_vars = [
                (name, info) for name, info in self.variables_info.items()
                if info['category'] == category
            ]
            
            if category_vars:
                print(f"\n{title}:")
                print("-" * len(title))
                
                for i, (var_name, var_info) in enumerate(category_vars, 1):
                    rename_status = "✓" if var_info['can_rename'] else "✗"
                    print(f"{i:2d}. [{rename_status}] {var_name}")
                    print(f"     Type: {var_info['data_type']}")
                    print(f"     Size: {var_info['size']} bytes")
                    print(f"     Storage: {var_info['storage']}")
                    if category == 'parameter':
                        print(f"     Parameter Index: {var_info.get('index', 'N/A')}")
                    print()
        
        print(f"\nTotal variables found: {len(self.variables_info)}")
        rename_count = sum(1 for info in self.variables_info.values() if info['can_rename'])
        print(f"Variables that can be renamed: {rename_count}")
    
    def get_renameable_variables(self) -> List[Tuple[str, Dict]]:
        """
        Get a list of variables that can be renamed.
        
        Returns:
            A list of tuples containing (variable_name, variable_info) for
            variables that can be renamed.
        """
        return [
            (name, info) for name, info in self.variables_info.items()
            if info['can_rename']
        ]
    
    def rename_variable(self, old_name: str, new_name: str) -> bool:
        """
        Rename a variable in the function.
        
        Args:
            old_name: The current name of the variable.
            new_name: The new name to assign to the variable.
            
        Returns:
            True if the variable was successfully renamed, False otherwise.
        """
        if old_name not in self.variables_info:
            print(f"Variable '{old_name}' not found in current function.")
            return False
            
        var_info = self.variables_info[old_name]
        
        if not var_info['can_rename']:
            print(f"Variable '{old_name}' cannot be renamed (likely global variable).")
            return False
        
        try:
            high_symbol = var_info['high_symbol']
            
            # Validate new name
            if not self._is_valid_variable_name(new_name):
                print(f"Invalid variable name: '{new_name}'. Must be valid C identifier.")
                return False
            
            # Check if new name already exists
            if new_name in self.variables_info and new_name != old_name:
                print(f"Variable name '{new_name}' already exists in this function.")
                return False
            
            # Perform the rename based on variable type
            if var_info['category'] == 'parameter':
                success = self._rename_parameter(high_symbol, new_name, var_info['index'])
            else:
                success = self._rename_local_variable(high_symbol, new_name)
            
            if success:
                # Update our internal tracking
                var_info['name'] = new_name
                self.variables_info[new_name] = self.variables_info.pop(old_name)
                print(f"Successfully renamed '{old_name}' to '{new_name}'")
                return True
            else:
                print(f"Failed to rename variable '{old_name}' to '{new_name}'")
                return False
                
        except Exception as e:
            print(f"Error renaming variable '{old_name}': {e}")
            return False
    
    def _rename_parameter(self, high_param, new_name: str, param_index: int) -> bool:
        """
        Rename a function parameter.
        
        Args:
            high_param: The HighParam object to rename.
            new_name: The new parameter name.
            param_index: The parameter index.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            # Get the actual Parameter object from the function
            if param_index < self.current_function.getParameterCount():
                param = self.current_function.getParameter(param_index)
                param.setName(new_name, SourceType.USER_DEFINED)
                return True
            else:
                print(f"Parameter index {param_index} out of range")
                return False
        except Exception as e:
            print(f"Error renaming parameter: {e}")
            return False
    
    def _rename_local_variable(self, high_local, new_name: str) -> bool:
        """
        Rename a local variable.
        
        Args:
            high_local: The HighLocal object to rename.
            new_name: The new variable name.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            # For local variables, we need to work with the symbol
            if hasattr(high_local, 'getSymbol'):
                symbol = high_local.getSymbol()
                if symbol:
                    symbol.setName(new_name, SourceType.USER_DEFINED)
                    return True
            
            # Alternative approach for local variables
            local_symbol_map = self.high_function.getLocalSymbolMap()
            if hasattr(local_symbol_map, 'renameSymbol'):
                local_symbol_map.renameSymbol(high_local, new_name)
                return True
                
            print("Unable to rename local variable - method not available")
            return False
            
        except Exception as e:
            print(f"Error renaming local variable: {e}")
            return False
    
    def _is_valid_variable_name(self, name: str) -> bool:
        """
        Check if a variable name is valid according to C naming rules.
        
        Args:
            name: The variable name to validate.
            
        Returns:
            True if the name is valid, False otherwise.
        """
        if not name or not isinstance(name, str):
            return False
            
        # Check if name starts with letter or underscore
        if not (name[0].isalpha() or name[0] == '_'):
            return False
        
        # Check if rest of name contains only alphanumeric characters and underscores
        return all(c.isalnum() or c == '_' for c in name[1:])
    
    def interactive_rename_session(self) -> None:
        """
        Start an interactive session for renaming variables.
        
        This method provides a user-friendly interface for browsing and
        renaming variables in the current function.
        """
        if not self.current_function:
            print("No function selected. Please select a function first.")
            return
        
        renameable_vars = self.get_renameable_variables()
        
        if not renameable_vars:
            print("No variables can be renamed in this function.")
            return
        
        print(f"\nInteractive Variable Renaming Session")
        print(f"Function: {self.current_function.getName()}")
        print(f"Variables available for renaming: {len(renameable_vars)}")
        print("\nCommands:")
        print("  list - Show all renameable variables")
        print("  rename <old_name> <new_name> - Rename a variable")
        print("  info <variable_name> - Show detailed info about a variable")
        print("  refresh - Re-analyze the function")
        print("  quit - Exit renaming session")
        
        while True:
            try:
                command = askString(
                    "Variable Rename Command",
                    "Enter command (or 'quit' to exit):"
                )
                
                if not command:
                    continue
                    
                command = command.strip().lower()
                parts = command.split()
                
                if command == "quit":
                    break
                elif command == "list":
                    self._show_renameable_variables_list()
                elif command == "refresh":
                    self._refresh_analysis()
                elif parts[0] == "info" and len(parts) == 2:
                    self._show_variable_info(parts[1])
                elif parts[0] == "rename" and len(parts) == 3:
                    old_name, new_name = parts[1], parts[2]
                    self.rename_variable(old_name, new_name)
                else:
                    print("Invalid command. Type 'list', 'rename <old> <new>', 'info <name>', 'refresh', or 'quit'")
                    
            except Exception as e:
                print(f"Error: {e}")
                break
        
        print("Variable renaming session ended.")
    
    def _show_renameable_variables_list(self) -> None:
        """Show a numbered list of renameable variables."""
        renameable_vars = self.get_renameable_variables()
        
        if not renameable_vars:
            print("No variables available for renaming.")
            return
        
        print(f"\nRenameable Variables in {self.current_function.getName()}:")
        print("-" * 50)
        
        for i, (var_name, var_info) in enumerate(renameable_vars, 1):
            category_label = var_info['category'].upper()
            print(f"{i:2d}. {var_name} ({category_label}) - {var_info['data_type']}")
    
    def _show_variable_info(self, var_name: str) -> None:
        """Show detailed information about a specific variable."""
        if var_name not in self.variables_info:
            print(f"Variable '{var_name}' not found.")
            return
        
        var_info = self.variables_info[var_name]
        print(f"\nDetailed Information for Variable: {var_name}")
        print("-" * 40)
        print(f"Category: {var_info['category'].title()}")
        print(f"Data Type: {var_info['data_type']}")
        print(f"Size: {var_info['size']} bytes")
        print(f"Storage: {var_info['storage']}")
        print(f"Can Rename: {'Yes' if var_info['can_rename'] else 'No'}")
        
        if var_info['category'] == 'parameter':
            print(f"Parameter Index: {var_info.get('index', 'N/A')}")
    
    def _refresh_analysis(self) -> None:
        """Re-analyze the current function to pick up any changes."""
        if self.current_function:
            print("Refreshing function analysis...")
            self.set_target_function(self.current_function)
            print("Analysis refreshed.")
        else:
            print("No function to refresh.")


def select_current_function():
    """
    Get the currently selected function in Ghidra.
    
    Returns:
        The selected function, or None if no function is selected.
    """
    current_program = getCurrentProgram()
    if not current_program:
        return None
    
    # Get the current selection or cursor location
    current_selection = getCurrentSelection()
    current_location = getCurrentLocation()
    
    function_manager = current_program.getFunctionManager()
    
    # Try to get function from selection first
    if current_selection and not current_selection.isEmpty():
        min_address = current_selection.getMinAddress()
        function = function_manager.getFunctionContaining(min_address)
        if function:
            return function
    
    # Try to get function from current cursor location
    if current_location:
        function = function_manager.getFunctionContaining(current_location.getAddress())
        if function:
            return function
    
    return None


def main():
    """
    Main execution function for the variable analysis script.
    """
    current_program = getCurrentProgram()
    
    if not current_program:
        print("Error: This script must be run within Ghidra.")
        return
    
    # Try to get the currently selected function
    target_function = select_current_function()
    
    if not target_function:
        print("No function selected. Please:")
        print("1. Place your cursor inside a function, or")
        print("2. Select a portion of a function")
        return
    
    print(f"Analyzing function: {target_function.getName()}")
    
    # Create variable manager and analyze the function
    var_manager = FunctionVariableManager(current_program)
    
    if not var_manager.set_target_function(target_function):
        print("Failed to analyze the selected function.")
        return
    
    # Display all variables found
    var_manager.display_all_variables()
    
    # Ask user if they want to start interactive renaming
    start_renaming = askYesNo(
        "Interactive Renaming",
        "Would you like to start an interactive variable renaming session?"
    )
    
    if start_renaming:
        var_manager.interactive_rename_session()
    
    print("\nVariable analysis complete.")


if __name__ == "__main__":
    main()
