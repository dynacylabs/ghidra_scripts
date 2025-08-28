# @runtime PyGhidra
"""
Ghidra Script for AI-powered Function Analysis and Enhancement.

This script provides automated function analysis capabilities for Ghidra,
including:
- Function renaming based on decompiled code analysis
- Function commenting with detailed documentation
- Function signature generation with proper parameter typing

The script uses Azure OpenAI for natural language processing to analyze
decompiled C code and generate meaningful function names, comments, and
signatures.
"""

# Standard library imports
import json
import os
from collections import defaultdict, deque
from typing import (
    Any,
    Deque,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# Third-party imports
import httpx
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI

# Ghidra imports
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    ArrayDataType,
    BooleanDataType,
    CharDataType,
    DoubleDataType,
    FloatDataType,
    IntegerDataType,
    LongDataType,
    LongLongDataType,
    PointerDataType,
    ShortDataType,
    UnsignedCharDataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
    UnsignedLongLongDataType,
    UnsignedShortDataType,
    VoidDataType,
)
from ghidra.program.model.listing import CodeUnit, ParameterImpl
from ghidra.program.model.symbol import SourceType

# Ghidra script global functions and variables
# These are automatically available in Ghidra script environment
import sys

# Check if we're running in Ghidra by looking for Ghidra modules
IN_GHIDRA = any('ghidra' in module for module in sys.modules.keys())

if not IN_GHIDRA:
    # We're not in Ghidra environment, provide fallbacks for development
    def askString(title: str, message: str) -> str:
        return "3"
    
    def askYesNo(title: str, message: str) -> bool:
        return True
    
    def getCurrentProgram():
        return None
    
    # Create a dummy monitor class for development
    class DummyMonitor:
        def checkCancelled(self):
            pass
    
    monitor = DummyMonitor()
else:
    # In Ghidra, these will be available as globals
    # We can't import them, they're injected by Ghidra
    pass

os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://aiml-aoai-api.gc1.myngc.com"


class AzureOpenAIClient:
    """
    Azure OpenAI client for natural language processing.
    
    This class provides a simplified interface to Azure OpenAI for querying
    large language models with custom system prompts and user queries.
    """
    
    def __init__(self, system_prompt: str = "") -> None:
        """
        Initialize the Azure OpenAI client.
        
        Args:
            system_prompt: The system prompt to use for all queries. Provides
                context and instructions for the AI model.
        """
        self.system_prompt: str = system_prompt
        self.chain = self._get_langchain_pipeline()

    def query(self, user_query: str = "") -> Optional[str]:
        """
        Send a query to the AI model and return the response.
        
        Args:
            user_query: The user's input query to send to the model.
            
        Returns:
            The AI model's response as a string, or None if an error occurred.
        """
        try:
            return self.chain.invoke({"input": user_query})
        except Exception as error:
            print(f"AI query failed: query='{user_query}', error={error}")
            return None

    def _get_langchain_pipeline(self):
        """
        Create and configure the LangChain processing pipeline.
        
        Returns:
            A configured LangChain processing chain for AI queries.
        """
        # Create HTTP client with HTTP/2 support and disabled SSL verification
        http_client = httpx.Client(http2=True, verify=False)

        # Initialize Azure OpenAI language model
        language_model = AzureChatOpenAI(
            azure_deployment="gpt-4o",
            http_client=http_client,
            api_version="2024-02-01",
        )

        # Configure string output parser
        string_parser = StrOutputParser()

        # Create chat prompt template with system and user messages
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", self.system_prompt), 
            ("user", "{input}")
        ])

        # Build the processing chain: prompt -> model -> parser
        processing_chain = prompt_template | language_model | string_parser

        return processing_chain


class FunctionRenamer:
    """
    AI-powered function renaming system for Ghidra.
    
    This class analyzes decompiled function code using AI to generate
    meaningful function names based on the function's behavior and purpose.
    It handles function renaming workflows, including dependency tracking
    and iterative updates.
    """
    
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        max_rename_iterations: int = 3,
    ) -> None:
        """
        Initialize the function renamer.
        
        Args:
            current_program: The current Ghidra program instance.
            program_listing: The program's listing for code access.
            function_manager: Manager for function operations.
            decompiler_interface: Interface for decompiling functions.
            reference_manager: Manager for tracking function references.
            max_rename_iterations: Maximum times to rename a function to
                prevent infinite loops.
        """
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager
        
        # Initialize AI client with function naming prompt
        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_function_naming_prompt()
        )
        
        # Get max rename iterations from user if not provided
        if current_program is not None:
            self.max_rename_iterations = int(
                askString(
                    "Max Number Of Times To Rename A Function (int)",
                    "As functions are renamed, other functions may change. "
                    "This is the maximum number of times to update a "
                    "function's name before skipping. This avoids an "
                    "infinite loop where functions keep getting updated "
                    "based on other functions.",
                )
            )
        else:
            self.max_rename_iterations = max_rename_iterations

    def decompile_function(self, target_function) -> Optional[str]:
        """
        Decompile a function and return its C code representation.
        
        Args:
            target_function: The Ghidra function to decompile.
            
        Returns:
            The decompiled C code as a string, or None if decompilation
            failed.
        """
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 30, monitor
        )
        
        if (decompilation_result and 
            decompilation_result.decompileCompleted()):
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def initialize_function_queue(self) -> Deque:
        """
        Create a queue of all functions in the program for processing.
        
        Returns:
            A deque containing all functions in the program.
        """
        return deque(self.function_manager.getFunctions(True))

    def rename_single_function(
        self, 
        target_function, 
        decompiled_code: str
    ) -> None:
        """
        Rename a single function using AI analysis.
        
        Args:
            target_function: The Ghidra function to rename.
            decompiled_code: The decompiled C code of the function.
        """
        new_function_name = self.ai_client.query(query=decompiled_code)
        
        if new_function_name:
            try:
                target_function.setName(
                    new_function_name, 
                    SourceType.USER_DEFINED
                )
            except Exception as error:
                print(f"Failed to rename function to '{new_function_name}': "
                      f"{error}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for renaming.
        
        This method implements an iterative renaming process that handles
        function dependencies and prevents infinite loops through rename
        count tracking.
        """
        function_queue = self.initialize_function_queue()
        changed_functions: Set = set()
        rename_iteration_count: Dict = defaultdict(int)

        while function_queue:
            current_function = function_queue.popleft()

            # Skip if maximum rename iterations reached
            if (rename_iteration_count[current_function] >= 
                self.max_rename_iterations):
                continue

            # Decompile and analyze function
            decompiled_code = self.decompile_function(
                target_function=current_function
            )
            
            if decompiled_code:
                original_name = current_function.getName()
                
                self.rename_single_function(
                    target_function=current_function, 
                    decompiled_code=decompiled_code
                )
                
                updated_name = current_function.getName()

                # Track changes and update dependent functions
                if original_name != updated_name:
                    print(f"Renamed: {original_name} -> {updated_name}")
                    changed_functions.add(current_function)
                    rename_iteration_count[current_function] += 1
                    
                    # Queue functions that call this renamed function
                    calling_functions = self._get_calling_functions(
                        target_function=current_function, 
                        changed_functions=changed_functions
                    )
                    function_queue.extend(calling_functions)
            
    def _get_calling_functions(
        self, 
        target_function, 
        changed_functions: Set
    ) -> Set:
        """
        Find functions that call the target function.
        
        Args:
            target_function: The function to find callers for.
            changed_functions: Set of already changed functions to exclude.
            
        Returns:
            Set of functions that call the target function.
        """
        calling_functions: Set = set()
        function_references = self.reference_manager.getReferencesTo(
            target_function.getEntryPoint()
        )
        
        for reference in function_references:
            calling_function = self.function_manager.getFunctionContaining(
                reference.getFromAddress()
            )
            
            if (calling_function and 
                calling_function not in changed_functions):
                calling_functions.add(calling_function)

        return calling_functions

    def _get_function_naming_prompt(self) -> str:
        """
        Get the system prompt for AI-powered function naming.
        
        Returns:
            A detailed prompt for generating meaningful function names.
        """
        return """
        You are a reverse engineer using Ghidra.
        You will receive the decompiler output from Ghidra for a function.
        You are to provide a meaningful function name based on the 
        decompiler's output.
        
        Requirements:
        - Provide only the function name with no extra information, 
          commentary, or punctuation
        - Use only valid C function name characters (letters, numbers, 
          underscores)
        - Make the name descriptive of the function's purpose
        - Follow snake_case or camelCase naming conventions
        - Avoid generic names like 'function1' or 'temp'
        """


class FunctionCommenter:
    """
    AI-powered function commenting system for Ghidra.
    
    This class generates detailed, structured comments for functions based
    on their decompiled code. Comments include descriptions, functionality
    explanations, and return value documentation.
    """
    
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
    ) -> None:
        """
        Initialize the function commenter.
        
        Args:
            current_program: The current Ghidra program instance.
            program_listing: The program's listing for code access.
            function_manager: Manager for function operations.
            decompiler_interface: Interface for decompiling functions.
            reference_manager: Manager for tracking function references.
        """
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager

        # Initialize AI client with function commenting prompt
        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_function_commenting_prompt()
        )

    def add_comment_to_function(
        self, 
        target_function, 
        decompiler_interface=None
    ) -> None:
        """
        Add an AI-generated comment to a single function.
        
        Args:
            target_function: The Ghidra function to comment.
            decompiler_interface: Optional decompiler interface (unused).
        """
        function_name = target_function.getName()
        print(f"Generating comment for function: {function_name}")
        
        # Decompile the function
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 30, monitor
        )
        
        if (decompilation_result and 
            decompilation_result.decompileCompleted()):
            # Get decompiled C code
            decompiled_code = (decompilation_result
                             .getDecompiledFunction()
                             .getC())
            
            # Get code unit for the function entry point
            function_code_unit = self.program_listing.getCodeUnitAt(
                target_function.getEntryPoint()
            )
            
            if function_code_unit:
                # Generate AI comment
                ai_generated_comment = self.ai_client.query(
                    user_query=decompiled_code
                )
                
                if ai_generated_comment:
                    # Add plate comment to function
                    function_code_unit.setComment(
                        CodeUnit.PLATE_COMMENT, 
                        ai_generated_comment
                    )
                else:
                    print(f"Failed to generate comment for {function_name}")
        else:
            print(f"Decompilation of {function_name} failed or timed out, "
                  f"skipping comment generation")

    def process_all_functions(self) -> None:
        """
        Add comments to all functions in the program.
        
        Functions are processed in order of size (smallest first) to
        optimize processing time and resource usage.
        """
        # Get all functions and sort by size (number of addresses)
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())
        
        # Process each function
        for function in all_functions:
            self.add_comment_to_function(target_function=function)

    def _get_function_commenting_prompt(self) -> str:
        """
        Get the system prompt for AI-powered function commenting.
        
        Returns:
            A detailed prompt for generating structured function comments.
        """
        return """
        You are a reverse engineer using Ghidra.
        You will receive the decompiler output from Ghidra for a function.
        You are to provide a comment to be placed at the top of the function.
        
        Your comment shall:
        - Be in C docstring format
        - Be word-wrapped at 80 characters
        - Be tab indented
        - Follow this format:
          - DESCRIPTION: A description of the function as a whole
          - FUNCTIONALITY: A detailed explanation of what the function does
          - RETURN: A sorted list of return values and their meaning
        
        Example format:
        ```
        DESCRIPTION
          This function handles peripheral-related logic, checking the state
          of specific memory addresses and performing operations accordingly.
          It reacts to conditions involving data at memory-mapped peripheral
          registers or other hardware-related data locations.

        FUNCTIONALITY
          - The function first checks if the value at PTR_PERIPH1_0x20 equals
            0x01. If true:
              - It then checks if *(PTR_PERIPH1_0x2C + 0x58) equals
                DAT_00000600. If this condition is met, it returns 3.
              - Otherwise, it updates *(PTR_PERIPH1_0x2C + 0x58) to
                DAT_00000600, clears a specific bit at PTR_PERIPH89_0x0 + 8,
                sets *(PTR_PERIPH89_0x0 + 0x24) to 2, and returns 5.
          - If the initial value at PTR_PERIPH1_0x20 is not 0x01, the
            function directly returns 4.

        RETURN
          - 3: When *(PTR_PERIPH1_0x2C + 0x58) matches DAT_00000600.
          - 4: When the initial condition (*PTR_PERIPH1_0x20 == 0x01) is
               false.
          - 5: When the initial condition is true, but *(PTR_PERIPH1_0x2C +
               0x58) does not match DAT_00000600 and is updated.
        ```
        
        Provide only the comment with no extra information or commentary.
        """

class FunctionSignatureGenerator:
    """
    AI-powered function signature generation system for Ghidra.
    
    This class analyzes decompiled function code to generate proper function
    signatures with appropriate return types and parameter definitions. It
    uses AI to determine meaningful parameter names and correct C data types.
    """
    
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
    ) -> None:
        """
        Initialize the function signature generator.
        
        Args:
            current_program: The current Ghidra program instance.
            program_listing: The program's listing for code access.
            function_manager: Manager for function operations.
            decompiler_interface: Interface for decompiling functions.
            reference_manager: Manager for tracking function references.
        """
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager

        # Initialize AI client with signature generation prompt
        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_signature_generation_prompt()
        )

    def decompile_function(self, target_function) -> Optional[str]:
        """
        Decompile a function and return its C code representation.
        
        Args:
            target_function: The Ghidra function to decompile.
            
        Returns:
            The decompiled C code as a string, or None if decompilation
            failed.
        """
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 30, monitor
        )
        
        if (decompilation_result and 
            decompilation_result.decompileCompleted()):
            return decompilation_result.getDecompiledFunction().getC()

        return None
    
    def parse_ai_signature_response(
        self, 
        ai_response: str = ""
    ) -> Tuple[Optional[str], List[Tuple[str, str]]]:
        """
        Parse AI response for function signature information.
        
        Args:
            ai_response: JSON response from AI containing signature data.
            
        Returns:
            A tuple containing (return_type, parameters_list) where
            parameters_list is a list of (type, name) tuples.
        """
        try:
            # Clean up response format
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()

            # Parse JSON response
            parsed_data = json.loads(clean_response)

            # Extract return type
            return_type = parsed_data.get("return_type")
            
            # Extract parameters
            parameter_list = []
            for param_data in parsed_data.get("parameters", []):
                param_type = param_data.get("type")
                param_name = param_data.get("name")
                if param_type and param_name:
                    parameter_list.append((param_type, param_name))

        except (json.JSONDecodeError, KeyError, AttributeError):
            return_type = None
            parameter_list = []
        
        return return_type, parameter_list

    def apply_function_signature(self, target_function) -> None:
        """
        Generate and apply a function signature to a Ghidra function.
        
        Args:
            target_function: The Ghidra function to update with a new
                signature.
        """
        function_name = target_function.getName()
        
        # Decompile the function
        decompiled_code = self.decompile_function(
            target_function=target_function
        )
        
        if not decompiled_code:
            print(f"Unable to sign {function_name}")
            return
            
        # Get AI-generated signature
        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            print(f"Unable to sign {function_name}")
            return
            
        # Parse AI response
        return_type_string, parameter_definitions = (
            self.parse_ai_signature_response(ai_response=ai_response)
        )

        try:
            # Validate parsed data
            if not return_type_string or not parameter_definitions:
                raise ValueError("Invalid signature data from AI")

            # Convert return type string to Ghidra data type
            ghidra_return_type = self._map_c_type_to_ghidra_type(
                type_string=return_type_string
            )
            if ghidra_return_type is None:
                raise ValueError(f"Unknown return type: {return_type_string}")

            # Set function return type
            target_function.setReturnType(
                ghidra_return_type, 
                SourceType.USER_DEFINED
            )

            # Prepare parameter data
            ghidra_data_types = []
            parameter_names = []

            for param_type_string, param_name in parameter_definitions:
                ghidra_param_type = self._map_c_type_to_ghidra_type(
                    type_string=param_type_string
                )

                if ghidra_param_type is None:
                    raise ValueError(f"Unknown parameter type: "
                                   f"{param_type_string}")
                
                ghidra_data_types.append(ghidra_param_type)
                parameter_names.append(param_name)
            
            # Clear existing parameters
            while target_function.getParameterCount() > 0:
                target_function.removeParameter(0)

            # Add new parameters
            for data_type, param_name in zip(ghidra_data_types, 
                                           parameter_names):
                parameter = ParameterImpl(
                    param_name, 
                    data_type, 
                    self.current_program
                )
                target_function.addParameter(
                    parameter, 
                    SourceType.USER_DEFINED
                )

            print(f"Signed {function_name} with return type "
                  f"{return_type_string} and {len(parameter_definitions)} "
                  f"parameter(s)")

        except (ValueError, Exception):
            print(f"Unable to sign {function_name}")
    
    def process_all_functions(self) -> None:
        """
        Generate signatures for all functions in the program.
        
        Functions are processed in order of size (smallest first) to
        optimize processing time and resource usage.
        """
        # Get all functions and sort by size
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())
        
        # Process each function
        for function in all_functions:
            self.apply_function_signature(target_function=function)

    def _map_c_type_to_ghidra_type(self, type_string: str):
        """
        Map C type strings to corresponding Ghidra data types.
        
        Args:
            type_string: A C type string (e.g., "int", "char*", "uint32_t").
            
        Returns:
            The corresponding Ghidra DataType object, or None if not found.
        """
        # Normalize type string
        normalized_type = type_string.lower().strip()

        # Basic integer types
        if normalized_type in ["int", "signed int"]:
            return IntegerDataType()
        elif normalized_type in ["unsigned int", "uint"]:
            return UnsignedIntegerDataType()
        elif normalized_type in ["short", "signed short"]:
            return ShortDataType()
        elif normalized_type in ["unsigned short", "ushort"]:
            return UnsignedShortDataType()
        elif normalized_type in ["long", "signed long"]:
            return LongDataType()
        elif normalized_type in ["unsigned long", "ulong"]:
            return UnsignedLongDataType()
        elif normalized_type in ["char", "signed char"]:
            return CharDataType()
        elif normalized_type in ["unsigned char", "uchar", "byte"]:
            return UnsignedCharDataType()
        elif normalized_type in ["bool", "boolean"]:
            return BooleanDataType()
        elif normalized_type in ["float"]:
            return FloatDataType()
        elif normalized_type in ["double"]:
            return DoubleDataType()
        elif normalized_type == "void":
            return VoidDataType()
        
        # Pointer types
        elif normalized_type.endswith("*"):
            base_type = self._map_c_type_to_ghidra_type(
                normalized_type[:-1].strip()
            )
            if base_type is not None:
                return PointerDataType(base_type)
            else:
                return PointerDataType(VoidDataType())
        
        # Fixed-width integer types
        elif normalized_type in ["int8", "int8_t", "signed char"]:
            return CharDataType()
        elif normalized_type in ["uint8", "uint8_t"]:
            return UnsignedCharDataType()
        elif normalized_type in ["int16", "int16_t", "short", "signed short"]:
            return ShortDataType()
        elif normalized_type in ["uint16", "uint16_t"]:
            return UnsignedShortDataType()
        elif normalized_type in ["int32", "int32_t", "int"]:
            return IntegerDataType()
        elif normalized_type in ["uint32", "uint32_t", "unsigned int"]:
            return UnsignedIntegerDataType()
        elif normalized_type in ["int64", "int64_t", "long long"]:
            return LongLongDataType()
        elif normalized_type in ["uint64", "uint64_t", "unsigned long long"]:
            return UnsignedLongLongDataType()
        
        # String types
        elif normalized_type in ["char *", "string"]:
            return PointerDataType(CharDataType())
        
        # Array types
        elif "[" in normalized_type and "]" in normalized_type:
            base_type_part, _, array_size_part = normalized_type.partition("[")
            base_type = self._map_c_type_to_ghidra_type(
                base_type_part.strip()
            )
            if (base_type is not None and 
                array_size_part[:-1].isdigit()):
                array_size = int(array_size_part[:-1])
                return ArrayDataType(
                    base_type, 
                    array_size, 
                    base_type.getLength()
                )

        # Default fallback
        return IntegerDataType()

    def _get_signature_generation_prompt(self) -> str:
        """
        Get the system prompt for AI-powered signature generation.
        
        Returns:
            A detailed prompt for generating function signatures.
        """
        return """
        You are a reverse engineer using Ghidra.
        You will receive the decompiler output from Ghidra for a function.
        You are to provide a function signature/definition based on the
        decompiler's output.
        
        Requirements:
        - Do not change the function name
        - Respond with JSON data only, no extra information or commentary
        - Determine the data type for each parameter using standard C types
          (int, float, char*, uint32_t, etc.)
        - Determine the return type using standard C types
        - Provide meaningful variable names based on function behavior
        - Use only valid C identifier characters (letters, numbers, 
          underscores)
        - Avoid generic names like 'param1', 'arg', 'temp'
        
        Response format:
        {
          "return_type": "int",
          "parameters": [
            {"type": "int", "name": "device_id"},
            {"type": "char*", "name": "buffer_ptr"},
            {"type": "uint32_t", "name": "buffer_size"}
          ]
        }
        
        Provide meaningful parameter names that reflect their purpose in
        the function.
        """

def main() -> None:
    """
    Main execution function for the Ghidra function analysis script.
    
    This function orchestrates the AI-powered analysis workflow by:
    1. Initializing Ghidra program interfaces
    2. Getting user preferences for analysis types
    3. Creating appropriate analyzer instances
    4. Executing the selected analysis operations
    """
    # Initialize Ghidra program interfaces
    current_program = getCurrentProgram()
    
    # Check if we're running in Ghidra environment
    if current_program is None:
        print("Error: This script must be run within Ghidra environment")
        return
    
    program_listing = current_program.getListing()
    function_manager = current_program.getFunctionManager()

    # Initialize decompiler interface
    decompiler_interface = DecompInterface()
    decompiler_interface.openProgram(current_program)

    # Initialize reference manager
    reference_manager = current_program.getReferenceManager()

    # Get user preferences for analysis operations
    should_rename_functions: bool = askYesNo(
        "Rename Functions?",
        "Should functions be renamed based on the function's decompiled "
        "output using AI analysis?",
    )

    should_comment_functions: bool = askYesNo(
        "Comment Functions?",
        "Should functions be commented based on the function's decompiled "
        "output using AI analysis?",
    )

    should_generate_signatures: bool = askYesNo(
        "Generate Function Signatures?",
        "Should function signatures be generated based on the function's "
        "decompiled output using AI analysis?",
    )

    # Initialize analysis classes based on user preferences
    function_renamer: Optional[FunctionRenamer] = None
    function_commenter: Optional[FunctionCommenter] = None
    signature_generator: Optional[FunctionSignatureGenerator] = None

    if should_rename_functions:
        function_renamer = FunctionRenamer(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
        )

    if should_comment_functions:
        function_commenter = FunctionCommenter(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
        )

    if should_generate_signatures:
        signature_generator = FunctionSignatureGenerator(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
        )

    # Execute analysis operations in order
    if should_rename_functions and function_renamer:
        function_renamer.process_all_functions()

    if should_comment_functions and function_commenter:
        function_commenter.process_all_functions()

    if should_generate_signatures and signature_generator:
        signature_generator.process_all_functions()


# Entry point for script execution
if __name__ == "__main__":
    main()