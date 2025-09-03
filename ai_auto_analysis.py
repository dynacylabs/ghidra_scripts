# @runtime PyGhidra
"""
AI-Powered Ghidra Auto-Analysis Script

This script provides comprehensive AI-powered analysis capabilities for Ghidra,
including function renaming, signature generation, variable renaming/retyping,
function commenting, and struct generation. It uses Azure OpenAI to analyze
decompiled code and provide meaningful names and types.

"""

import json
import logging
import os
from abc import ABC, abstractmethod
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

import httpx
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    ArrayDataType,
    BooleanDataType,
    CategoryPath,
    CharDataType,
    DataType,
    DataTypeManager,
    DoubleDataType,
    FloatDataType,
    IntegerDataType,
    LongDataType,
    LongLongDataType,
    PointerDataType,
    ShortDataType,
    Structure,
    StructureDataType,
    UnsignedCharDataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
    UnsignedLongLongDataType,
    UnsignedShortDataType,
    VoidDataType,
)

from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl, Program
from ghidra.program.model.pcode import HighFunction, HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Azure OpenAI Configuration
os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://aiml-aoai-api.gc1.myngc.com"



# Type mapping for C types to Ghidra data types
C_TYPE_MAPPING = {
    "int": IntegerDataType,
    "signed int": IntegerDataType,
    "unsigned int": UnsignedIntegerDataType,
    "uint": UnsignedIntegerDataType,
    "short": ShortDataType,
    "signed short": ShortDataType,
    "unsigned short": UnsignedShortDataType,
    "ushort": UnsignedShortDataType,
    "long": LongDataType,
    "signed long": LongDataType,
    "unsigned long": UnsignedLongDataType,
    "ulong": UnsignedLongDataType,
    "char": CharDataType,
    "signed char": CharDataType,
    "unsigned char": UnsignedCharDataType,
    "uchar": UnsignedCharDataType,
    "byte": UnsignedCharDataType,
    "bool": BooleanDataType,
    "boolean": BooleanDataType,
    "float": FloatDataType,
    "double": DoubleDataType,
    "void": VoidDataType,
    "int8": CharDataType,
    "int8_t": CharDataType,
    "uint8": UnsignedCharDataType,
    "uint8_t": UnsignedCharDataType,
    "int16": ShortDataType,
    "int16_t": ShortDataType,
    "uint16": UnsignedShortDataType,
    "uint16_t": UnsignedShortDataType,
    "int32": IntegerDataType,
    "int32_t": IntegerDataType,
    "uint32": UnsignedIntegerDataType,
    "uint32_t": UnsignedIntegerDataType,
    "int64": LongLongDataType,
    "int64_t": LongLongDataType,
    "uint64": UnsignedLongLongDataType,
    "uint64_t": UnsignedLongLongDataType,
    "long long": LongLongDataType,
    "unsigned long long": UnsignedLongLongDataType,
}


def map_c_type_to_ghidra_type(type_string: str) -> DataType:
    """
    Map a C type string to the corresponding Ghidra DataType.
    
    This function handles various C data types including pointers, arrays,
    and standard primitive types, converting them to appropriate Ghidra
    DataType objects.
    
    Args:
        type_string: C type string to convert (e.g., "int", "char*", "uint32_t")
        
    Returns:
        DataType: Corresponding Ghidra DataType object
        
    Examples:
        >>> map_c_type_to_ghidra_type("int")
        IntegerDataType()
        >>> map_c_type_to_ghidra_type("char*")
        PointerDataType(CharDataType())
    """
    if not type_string:
        logger.warning("Empty type string provided, defaulting to int")
        return IntegerDataType()
        
    normalized_type = type_string.lower().strip()
    
    # Handle basic types
    if normalized_type in C_TYPE_MAPPING:
        return C_TYPE_MAPPING[normalized_type]()
    
    # Handle pointer types
    if normalized_type.endswith("*"):
        base_type_string = normalized_type[:-1].strip()
        base_type = map_c_type_to_ghidra_type(type_string=base_type_string)
        return PointerDataType(dataType=base_type)
    
    # Handle common string types
    if normalized_type in ["char *", "string"]:
        return PointerDataType(dataType=CharDataType())
    
    # Handle array types
    if "[" in normalized_type and "]" in normalized_type:
        try:
            base_type_part, _, array_size_part = normalized_type.partition("[")
            base_type = map_c_type_to_ghidra_type(type_string=base_type_part.strip())
            array_size_str = array_size_part.rstrip("]")
            
            if array_size_str.isdigit():
                array_size = int(array_size_str)
                element_length = base_type.getLength()
                return ArrayDataType(
                    dataType=base_type,
                    numElements=array_size,
                    elementLength=element_length
                )
        except (ValueError, AttributeError) as error:
            logger.warning(f"Failed to parse array type '{type_string}': {error}")
    
    logger.warning(f"Unknown type '{type_string}', defaulting to int")
    return IntegerDataType()


def _map_c_type_to_ghidra_type(type_string: str) -> DataType:
    """
    Legacy wrapper for backward compatibility.
    
    Args:
        type_string: C type string to convert
        
    Returns:
        DataType: Corresponding Ghidra DataType object
    """
    return map_c_type_to_ghidra_type(type_string=type_string)


class AzureOpenAIClient:
    """
    Client for interacting with Azure OpenAI services.
    
    This class provides a simplified interface for querying Azure OpenAI
    models using LangChain. It handles the setup of the language model,
    prompt templates, and response parsing.
    
    Attributes:
        system_prompt: The system prompt to use for all queries
        chain: The LangChain processing pipeline
    """
    
    def __init__(self, system_prompt: str = "") -> None:
        """
        Initialize the Azure OpenAI client.
        
        Args:
            system_prompt: System prompt to set context for AI responses
        """
        self.system_prompt: str = system_prompt
        self.chain = self._get_langchain_pipeline()

    def query(self, user_query: str = "") -> Optional[str]:
        """
        Send a query to the AI model and return the response.
        
        Args:
            user_query: The user's query to send to the AI model
            
        Returns:
            Optional[str]: AI response or None if query failed
        """
        if not user_query.strip():
            logger.warning("Empty query provided to AI client")
            return None
            
        try:
            response = self.chain.invoke(input={"input": user_query})
            logger.debug(f"AI query successful, response length: {len(response) if response else 0}")
            return response
        except Exception as error:
            logger.error(f"AI query failed: query='{user_query[:100]}...', error={error}")
            return None

    def _get_langchain_pipeline(self):
        """
        Create and configure the LangChain processing pipeline.
        
        Returns:
            Processing chain configured with Azure OpenAI model and prompt template
        """
        try:
            http_client = httpx.Client(http2=True, verify=False)

            language_model = AzureChatOpenAI(
                azure_deployment="gpt-4o",
                http_client=http_client,
                api_version="2024-02-01",
            )

            string_parser = StrOutputParser()

            prompt_template = ChatPromptTemplate.from_messages(
                messages=[
                    ("system", self.system_prompt), 
                    ("user", "{input}")
                ]
            )

            processing_chain = prompt_template | language_model | string_parser
            logger.info("LangChain pipeline initialized successfully")
            return processing_chain
            
        except Exception as error:
            logger.error(f"Failed to initialize LangChain pipeline: {error}")
            raise


class BaseGhidraAnalyzer(ABC):
    """
    Abstract base class for Ghidra analysis tools.
    
    This class provides common functionality for all analyzers, including
    decompilation, AI client setup, and shared utility methods. It reduces
    code duplication across different analyzer implementations.
    
    Attributes:
        current_program: The current Ghidra program being analyzed
        program_listing: Program listing interface
        function_manager: Function manager for the program
        decompiler_interface: Decompiler interface for generating code
        reference_manager: Reference manager for cross-references
        high_func_db_util: High function database utility
        ai_client: AI client for making queries
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
    ) -> None:
        """
        Initialize the base analyzer with common Ghidra components.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            high_func_db_util: High function database utility instance
        """
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager
        self.high_func_db_util = high_func_db_util
        
        # Initialize AI client with subclass-specific prompt
        self.ai_client = AzureOpenAIClient(system_prompt=self._get_system_prompt())
        
        logger.info(f"{self.__class__.__name__} initialized")

    def decompile_function(self, target_function: Function) -> Optional[str]:
        """
        Decompile a function and return the C code representation.
        
        This method handles the decompilation process, including error handling
        and timeout management. It's used by all analyzer subclasses.
        
        Args:
            target_function: The Ghidra function to decompile
            
        Returns:
            Optional[str]: Decompiled C code or None if decompilation failed
        """
        if not target_function:
            logger.warning("No target function provided for decompilation")
            return None
            
        function_name = target_function.getName()
        logger.debug(f"Decompiling function: {function_name}")
        
        try:
            decompilation_result = self.decompiler_interface.decompileFunction(
                func=target_function, 
                timeoutSecs=120, 
                monitor=monitor
            )

            if decompilation_result and decompilation_result.decompileCompleted():
                decompiled_code = decompilation_result.getDecompiledFunction().getC()
                logger.debug(f"Successfully decompiled {function_name}")
                return decompiled_code
            else:
                logger.warning(f"Decompilation failed or timed out for {function_name}")
                return None
                
        except Exception as error:
            logger.error(f"Error decompiling function {function_name}: {error}")
            return None

    def get_high_function(self, target_function: Function) -> Optional[HighFunction]:
        """
        Get the high-level function representation for analysis.
        
        Args:
            target_function: The Ghidra function to analyze
            
        Returns:
            Optional[HighFunction]: High-level function representation or None if failed
        """
        if not target_function:
            return None
            
        try:
            decompiled_result = self.decompiler_interface.decompileFunction(
                func=target_function, 
                timeoutSecs=120, 
                monitor=monitor
            )
            
            if decompiled_result and decompiled_result.decompileCompleted():
                return decompiled_result.getHighFunction()
                
        except Exception as error:
            logger.error(f"Error getting high function for {target_function.getName()}: {error}")
            
        return None

    @abstractmethod
    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for the AI client.
        
        This method must be implemented by each subclass to provide
        the appropriate system prompt for their specific analysis task.
        
        Returns:
            str: System prompt for AI interactions
        """
        pass

    @abstractmethod
    def process_all_functions(self) -> None:
        """
        Process all functions in the program.
        
        This method must be implemented by each subclass to define
        how they want to process the functions in the program.
        """
        pass


class FunctionRenamer(BaseGhidraAnalyzer):
    """
    AI-powered function renamer for Ghidra analysis.
    
    This class analyzes decompiled functions and suggests meaningful names
    based on the function's behavior and purpose. It handles iterative
    renaming to account for dependencies between functions.
    
    Attributes:
        max_rename_iterations: Maximum number of times to rename a function
                              to avoid infinite loops
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        max_rename_iterations: int = 3,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
    ) -> None:
        """
        Initialize the function renamer.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface  
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            max_rename_iterations: Maximum times to rename a function
            high_func_db_util: High function database utility instance
        """
        super().__init__(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

        # Get max iterations from user if in interactive mode
        if current_program is not None:
            self.max_rename_iterations = int(
                askString(
                    title="Max Number Of Times To Rename A Function (int)",
                    message="As functions are renamed, other functions may change. "
                    "This is the maximum number of times to update a "
                    "function's name before skipping. This avoids an "
                    "infinite loop where functions keep getting updated "
                    "based on other functions.",
                )
            )
        else:
            self.max_rename_iterations = max_rename_iterations

    def initialize_function_queue(self) -> Deque[Function]:
        """
        Initialize a queue with all functions in the program.
        
        Returns:
            Deque[Function]: Queue containing all functions to process
        """
        function_queue = deque(self.function_manager.getFunctions(True))
        logger.info(f"Initialized function queue with {len(function_queue)} functions")
        return function_queue

    def rename_single_function(self, target_function: Function, decompiled_code: str) -> None:
        """
        Rename a single function based on its decompiled code.
        
        Args:
            target_function: Function to rename
            decompiled_code: Decompiled C code for analysis
        """
        if not decompiled_code.strip():
            logger.warning(f"Empty decompiled code for function {target_function.getName()}")
            return
            
        new_function_name = self.ai_client.query(user_query=decompiled_code)

        if new_function_name and new_function_name.strip():
            try:
                # Clean the function name (remove any unwanted characters)
                cleaned_name = new_function_name.strip()
                target_function.setName(name=cleaned_name, source=SourceType.USER_DEFINED)
                logger.info(f"Function renamed to: {cleaned_name}")
            except Exception as error:
                logger.error(
                    f"Failed to rename function to '{new_function_name}': {error}"
                )
        else:
            logger.warning(f"AI did not provide a valid name for function {target_function.getName()}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for renaming.
        
        This method implements an iterative approach where functions are
        renamed based on their decompiled code, and calling functions are
        re-analyzed when a function name changes.
        """
        function_queue = self.initialize_function_queue()
        changed_functions: Set[Function] = set()
        rename_iteration_count: Dict[Function, int] = defaultdict(int)

        total_processed = 0
        while function_queue:
            current_function = function_queue.popleft()
            total_processed += 1

            if rename_iteration_count[current_function] >= self.max_rename_iterations:
                logger.debug(f"Skipping {current_function.getName()} - max iterations reached")
                continue

            decompiled_code = self.decompile_function(target_function=current_function)

            if decompiled_code:
                original_name = current_function.getName()

                self.rename_single_function(
                    target_function=current_function, 
                    decompiled_code=decompiled_code
                )

                updated_name = current_function.getName()

                if original_name != updated_name:
                    logger.info(f"Renamed: {original_name} -> {updated_name}")
                    changed_functions.add(current_function)
                    rename_iteration_count[current_function] += 1

                    calling_functions = self._get_calling_functions(
                        target_function=current_function,
                        changed_functions=changed_functions,
                    )
                    function_queue.extend(calling_functions)
            else:
                logger.warning(f"Could not decompile function {current_function.getName()}")
                
        logger.info(f"Function renaming completed. Processed {total_processed} functions, "
                   f"changed {len(changed_functions)} functions")

    def _get_calling_functions(self, target_function: Function, changed_functions: Set[Function]) -> Set[Function]:
        """
        Get functions that call the target function.
        
        Args:
            target_function: Function to find callers for
            changed_functions: Set of functions already processed to avoid duplicates
            
        Returns:
            Set[Function]: Set of calling functions not yet processed
        """
        calling_functions: Set[Function] = set()
        
        try:
            function_references = self.reference_manager.getReferencesTo(
                addr=target_function.getEntryPoint()
            )

            for reference in function_references:
                calling_function = self.function_manager.getFunctionContaining(
                    addr=reference.getFromAddress()
                )

                if calling_function and calling_function not in changed_functions:
                    calling_functions.add(calling_function)
                    
        except Exception as error:
            logger.error(f"Error getting calling functions for {target_function.getName()}: {error}")

        logger.debug(f"Found {len(calling_functions)} calling functions for {target_function.getName()}")
        return calling_functions

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for function naming AI queries.
        
        Returns:
            str: Detailed prompt for AI-powered function naming
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
        - Consider what the function does, not just what it contains
        - Be concise but descriptive (prefer 2-4 words)
        
        Examples of good names:
        - calculate_checksum
        - validate_input_buffer  
        - initialize_device_state
        - parse_config_file
        - send_network_packet
        """

class FunctionCommenter(BaseGhidraAnalyzer):
    """
    AI-powered function commenter for Ghidra analysis.
    
    This class generates comprehensive comments for functions based on their
    decompiled code. Comments include descriptions, functionality breakdowns,
    and return value documentation.
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
    ) -> None:
        """
        Initialize the function commenter.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            high_func_db_util: High function database utility instance
        """
        super().__init__(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    def add_comment_to_function(self, target_function: Function) -> None:
        """
        Add an AI-generated comment to a function.
        
        Args:
            target_function: Function to comment
        """
        function_name = target_function.getName()
        logger.info(f"Generating comment for function: {function_name}")

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            logger.warning(f"Could not decompile {function_name}, skipping comment generation")
            return

        function_code_unit = self.program_listing.getCodeUnitAt(
            addr=target_function.getEntryPoint()
        )

        if function_code_unit:
            ai_generated_comment = self.ai_client.query(user_query=decompiled_code)

            if ai_generated_comment and ai_generated_comment.strip():
                try:
                    function_code_unit.setComment(
                        commentType=CodeUnit.PLATE_COMMENT, 
                        comment=ai_generated_comment
                    )
                    logger.info(f"Successfully added comment to {function_name}")
                except Exception as error:
                    logger.error(f"Failed to set comment for {function_name}: {error}")
            else:
                logger.warning(f"AI did not generate a valid comment for {function_name}")
        else:
            logger.error(f"Could not get code unit for {function_name}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for commenting.
        
        Functions are sorted by size (smallest first) to process
        simpler functions before more complex ones.
        """
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        logger.info(f"Processing {len(all_functions)} functions for commenting")

        for index, function in enumerate(all_functions, 1):
            logger.debug(f"Processing function {index}/{len(all_functions)}: {function.getName()}")
            self.add_comment_to_function(target_function=function)
            
        logger.info("Function commenting completed")

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for function commenting AI queries.
        
        Returns:
            str: Detailed prompt for AI-powered function commenting
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
        Focus on clarity and technical accuracy.
        """


class VariableRenamer(BaseGhidraAnalyzer):
    """
    AI-powered variable renamer for Ghidra analysis.
    
    This class analyzes decompiled functions and suggests meaningful variable
    names and types based on the function's behavior and variable usage patterns.
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
    ) -> None:
        """
        Initialize the variable renamer.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            high_func_db_util: High function database utility instance
        """
        super().__init__(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    def parse_ai_variable_response(self, ai_response: str = "") -> Optional[Dict[str, Dict[str, str]]]:
        """
        Parse AI response for variable rename mappings.
        
        Args:
            ai_response: Raw AI response containing variable mappings
            
        Returns:
            Optional[Dict]: Parsed variable mapping or None if parsing failed
        """
        if not ai_response.strip():
            logger.warning("Empty AI response for variable parsing")
            return None
            
        try:
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()

            mapping = json.loads(clean_response)
            logger.debug(f"Successfully parsed variable mapping with {len(mapping)} entries")
            return mapping

        except (json.JSONDecodeError, KeyError, AttributeError) as error:
            logger.error(f"Failed to parse AI variable response: {error}")
            return None

    def rename_variables(self, target_function: Function) -> None:
        """
        Rename variables in a function based on AI analysis.
        
        Args:
            target_function: Function whose variables should be renamed
        """
        function_name = target_function.getName()
        logger.info(f"Processing variables for function: {function_name}")

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            logger.warning(f"Unable to rename/retype variables for {function_name} - no decompiled code")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            logger.warning(f"Unable to rename/retype variables for {function_name} - no AI response")
            return

        high_function = self.get_high_function(target_function=target_function)
        if not high_function:
            logger.error(f"Could not get high function for {function_name}")
            return
            
        local_symbols = high_function.getLocalSymbolMap().getSymbols()
        mapping = self.parse_ai_variable_response(ai_response=ai_response)

        if not mapping:
            logger.warning(f"No valid variable mapping received for {function_name}")
            return

        variables_processed = 0
        variables_renamed = 0
        
        for symbol in local_symbols:
            variables_processed += 1
            
            try:
                old_name = symbol.getName()
                variable_info = mapping.get(old_name, {})
                
                new_name = variable_info.get("name", old_name)
                data_type_string = variable_info.get("type", "int")

                # Skip if no changes needed
                if new_name == old_name and data_type_string == "int":
                    continue

                data_type = map_c_type_to_ghidra_type(type_string=data_type_string)
                
                self.high_func_db_util.updateDBVariable(
                    symbol=symbol, 
                    name=new_name, 
                    dataType=data_type, 
                    source=SourceType.USER_DEFINED
                )
                
                self.high_func_db_util.commitParamsToDatabase(
                    highFunction=high_function,
                    useDataTypes=True,
                    commit=HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                    source=SourceType.USER_DEFINED,
                )

                if old_name != new_name:
                    variables_renamed += 1
                    logger.info(f"{function_name}.{old_name} -> {function_name}.{new_name} ({data_type_string})")
                    
            except Exception as error:
                logger.error(f"Unable to rename/retype {function_name}.{old_name}: {error}")
                
        logger.info(f"Processed {variables_processed} variables, renamed {variables_renamed} in {function_name}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for variable renaming.
        
        Functions are sorted by size (smallest first) to process
        simpler functions before more complex ones.
        """
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        logger.info(f"Processing {len(all_functions)} functions for variable renaming")

        for index, function in enumerate(all_functions, 1):
            logger.debug(f"Processing function {index}/{len(all_functions)}: {function.getName()}")
            self.rename_variables(target_function=function)
            
        logger.info("Variable renaming completed")

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for variable renaming AI queries.
        
        Returns:
            str: Detailed prompt for AI-powered variable renaming
        """
        return """
        You are a reverse engineer using Ghidra.
        You will receive the decompiler output from Ghidra for a function.
        You are to determine meaningful variable names for the variables in the function based on the decompiler's output.
        You are to provide a map that links the old name to the new name.
        
        Requirements:
        - Respond with JSON data only, no extra information or commentary
        - Determine the data type for each variable using standard C types
          (int, float, char*, uint32_t, etc.)
        - Provide meaningful variable names based on function behavior
        - Use only valid C identifier characters (letters, numbers, 
          underscores)
        - Avoid generic names like 'param1', 'arg', 'temp'
        - Consider variable usage patterns (loop counters, buffers, etc.)
        - Use descriptive names that indicate purpose
        
        Response format:
        {{
            "<old_name>": {{"type": "int", "name": "<new_name>"}},
            "param_1": {{"type": "char*", "name": "input_buffer"}},
            "local_10": {{"type": "uint32_t", "name": "buffer_size"}},
            "iVar1": {{"type": "int", "name": "loop_counter"}}
        }}
        
        Provide meaningful variable names that reflect their purpose in
        the function. Focus on how variables are used, not just their type.
        """


class FunctionSignatureGenerator(BaseGhidraAnalyzer):
    """
    AI-powered function signature generator for Ghidra analysis.
    
    This class analyzes decompiled functions and generates appropriate
    function signatures including return types and parameter definitions
    based on the function's behavior and usage patterns.
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
    ) -> None:
        """
        Initialize the function signature generator.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            high_func_db_util: High function database utility instance
        """
        super().__init__(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    def parse_ai_signature_response(self, ai_response: str = "") -> Tuple[Optional[str], List[Tuple[str, str]]]:
        """
        Parse AI response for function signature information.
        
        Args:
            ai_response: Raw AI response containing signature data
            
        Returns:
            Tuple containing return type and list of parameter definitions
        """
        if not ai_response.strip():
            logger.warning("Empty AI response for signature parsing")
            return None, []
            
        try:
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()

            parsed_data = json.loads(clean_response)

            return_type = parsed_data.get("return_type")

            parameter_list = []
            for param_data in parsed_data.get("parameters", []):
                param_type = param_data.get("type")
                param_name = param_data.get("name")
                if param_type and param_name:
                    parameter_list.append((param_type, param_name))

            logger.debug(f"Parsed signature: return={return_type}, params={len(parameter_list)}")
            return return_type, parameter_list

        except (json.JSONDecodeError, KeyError, AttributeError) as error:
            logger.error(f"Failed to parse AI signature response: {error}")
            return None, []

    def apply_function_signature(self, target_function: Function) -> None:
        """
        Apply AI-generated function signature to a function.
        
        Args:
            target_function: Function to update with new signature
        """
        function_name = target_function.getName()
        logger.info(f"Generating signature for function: {function_name}")

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            logger.warning(f"Unable to sign {function_name} - no decompiled code")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            logger.warning(f"Unable to sign {function_name} - no AI response")
            return

        return_type_string, parameter_definitions = self.parse_ai_signature_response(
            ai_response=ai_response
        )

        try:
            if not return_type_string or not parameter_definitions:
                logger.warning(f"Incomplete signature data from AI for {function_name}")
                return

            # Set return type
            ghidra_return_type = map_c_type_to_ghidra_type(type_string=return_type_string)
            target_function.setReturnType(
                returnType=ghidra_return_type, 
                source=SourceType.USER_DEFINED
            )

            # Prepare parameter data
            ghidra_data_types = []
            parameter_names = []

            for param_type_string, param_name in parameter_definitions:
                ghidra_param_type = map_c_type_to_ghidra_type(type_string=param_type_string)
                ghidra_data_types.append(ghidra_param_type)
                parameter_names.append(param_name)

            # Clear existing parameters
            while target_function.getParameterCount() > 0:
                target_function.removeParameter(0)

            # Add new parameters
            for data_type, param_name in zip(ghidra_data_types, parameter_names):
                parameter = ParameterImpl(
                    name=param_name, 
                    dataType=data_type, 
                    program=self.current_program
                )
                target_function.addParameter(
                    parameter=parameter, 
                    source=SourceType.USER_DEFINED
                )

            logger.info(
                f"Applied signature to {function_name}: {return_type_string} "
                f"({len(parameter_definitions)} parameters)"
            )

        except (ValueError, Exception) as error:
            logger.error(f"Unable to apply signature to {function_name}: {error}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for signature generation.
        
        Functions are sorted by size (smallest first) to process
        simpler functions before more complex ones.
        """
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        logger.info(f"Processing {len(all_functions)} functions for signature generation")

        for index, function in enumerate(all_functions, 1):
            logger.debug(f"Processing function {index}/{len(all_functions)}: {function.getName()}")
            self.apply_function_signature(target_function=function)
            
        logger.info("Function signature generation completed")

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for signature generation AI queries.
        
        Returns:
            str: Detailed prompt for AI-powered signature generation
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
        - Provide meaningful parameter names based on function behavior
        - Use only valid C identifier characters (letters, numbers, 
          underscores)
        - Avoid generic names like 'param1', 'arg', 'temp'
        - Consider parameter usage patterns and purpose
        - Analyze return value patterns to determine correct return type
        
        Response format:
        {{
          "return_type": "int",
          "parameters": [
            {{"type": "int", "name": "device_id"}},
            {{"type": "char*", "name": "buffer_ptr"}},
            {{"type": "uint32_t", "name": "buffer_size"}}
          ]
        }}
        
        Provide meaningful parameter names that reflect their purpose in
        the function. Consider how parameters are used, validated, and
        transformed within the function logic.
        """
class StructGenerator(BaseGhidraAnalyzer):
    """
    AI-powered struct generator for Ghidra analysis.
    
    This class analyzes decompiled functions to identify potential struct
    definitions and applies them to variables. It maintains a registry of
    generated structs to avoid duplication and handles struct compatibility.
    
    Attributes:
        data_type_manager: Ghidra data type manager for struct creation
        global_struct_registry: Registry of all created structs
    """
    
    def __init__(
        self,
        current_program: Optional[Program] = None,
        program_listing=None,
        function_manager=None,
        decompiler_interface: Optional[DecompInterface] = None,
        reference_manager=None,
        high_func_db_util: Optional[HighFunctionDBUtil] = None,
        data_type_manager: Optional[DataTypeManager] = None,
    ) -> None:
        """
        Initialize the struct generator.
        
        Args:
            current_program: Current Ghidra program instance
            program_listing: Program listing interface
            function_manager: Function manager instance
            decompiler_interface: Decompiler interface instance
            reference_manager: Reference manager instance
            high_func_db_util: High function database utility instance
            data_type_manager: Data type manager for struct creation
        """
        super().__init__(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )
        
        self.data_type_manager = data_type_manager
        self.global_struct_registry: Dict[str, Structure] = {}
        self._initialize_struct_registry()

    def _initialize_struct_registry(self) -> None:
        """
        Initialize the struct registry with existing AI-generated structs.
        
        This method scans for previously generated structs to avoid
        duplication and maintain consistency across analysis sessions.
        """
        if not self.data_type_manager:
            logger.warning("No data type manager available, struct registry not initialized")
            return
            
        try:
            category_path = CategoryPath("/AI_Generated_Structs")
            category = self.data_type_manager.getCategory(categoryPath=category_path)
            
            if category:
                existing_structs = category.getDataTypes()
                for data_type in existing_structs:
                    if isinstance(data_type, Structure):
                        struct_name = data_type.getName()
                        self.global_struct_registry[struct_name] = data_type
                        logger.debug(f"Loaded existing struct into registry: {struct_name}")
                        
                logger.info(f"Initialized struct registry with {len(self.global_struct_registry)} existing structs")
        except Exception as error:
            logger.warning(f"Could not initialize struct registry: {error}")

    def parse_ai_struct_response(self, ai_response: str = "") -> Optional[Dict[str, Any]]:
        """
        Parse AI response for struct definitions and variable mappings.
        
        Args:
            ai_response: Raw AI response containing struct data
            
        Returns:
            Optional[Dict]: Parsed struct definitions and mappings or None if parsing failed
        """
        if not ai_response.strip():
            logger.warning("Empty AI response for struct parsing")
            return None
            
        try:
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()
            
            mapping = json.loads(clean_response)
            
            structs_count = len(mapping.get("structs", []))
            variables_count = len(mapping.get("variable_mappings", []))
            logger.debug(f"Parsed struct response: {structs_count} structs, {variables_count} variable mappings")
            
            return mapping

        except (json.JSONDecodeError, KeyError, AttributeError) as error:
            logger.error(f"Failed to parse AI struct response: {error}")
            return None
    def find_existing_struct(self, struct_name: str) -> Optional[Structure]:
        """
        Find an existing struct by name in the data type manager.
        
        Args:
            struct_name: Name of the struct to find
            
        Returns:
            Optional[Structure]: Found struct or None if not found
        """
        if not struct_name:
            return None
            
        try:
            category_path = CategoryPath("/AI_Generated_Structs")
            
            # Try exact match first
            existing_dt = self.data_type_manager.getDataType(
                path=category_path, 
                name=struct_name
            )
            if existing_dt and isinstance(existing_dt, Structure):
                logger.debug(f"Found exact match for struct: {struct_name}")
                return existing_dt
            
            # Try to find conflict variants
            category = self.data_type_manager.getCategory(categoryPath=category_path)
            if category:
                for data_type in category.getDataTypes():
                    if isinstance(data_type, Structure):
                        dt_name = data_type.getName()
                        if dt_name.startswith(struct_name) and '.conflict' in dt_name:
                            logger.debug(f"Found conflict variant: {dt_name}")
                            return data_type
            
        except Exception as error:
            logger.error(f"Error finding existing struct '{struct_name}': {error}")
        
        return None

    def are_structs_compatible(self, existing_struct: Structure, new_fields: List[Dict[str, Any]]) -> bool:
        """
        Check if a new struct definition is compatible with an existing one.
        
        Args:
            existing_struct: Existing struct to compare against
            new_fields: List of new field definitions
            
        Returns:
            bool: True if structs are compatible, False otherwise
        """
        if not existing_struct or not new_fields:
            return False
        
        try:
            existing_fields = {}
            for i in range(existing_struct.getNumComponents()):
                component = existing_struct.getComponent(i)
                if component and not component.isUndefined():
                    offset = component.getOffset()
                    existing_fields[offset] = {
                        'name': component.getFieldName(),
                        'type': component.getDataType(),
                        'length': component.getLength()
                    }
        
            conflicts = 0
            compatible_fields = 0
            
            for field in new_fields:
                field_offset = field.get("offset", 0)
                field_name = field.get("name", "unknown_field")
                field_type_str = field.get("type", "int")
                
                if field_offset in existing_fields:
                    existing_field = existing_fields[field_offset]
                    new_field_type = map_c_type_to_ghidra_type(type_string=field_type_str)
                    
                    if self._are_types_compatible(existing_field['type'], new_field_type):
                        compatible_fields += 1
                        logger.debug(f"Compatible field at offset {field_offset}: {field_name}")
                    else:
                        conflicts += 1
                        logger.debug(f"Type conflict at offset {field_offset}: "
                                   f"existing={existing_field['type']}, new={new_field_type}")
                else:
                    compatible_fields += 1
            
            total_overlapping = conflicts + compatible_fields
            if total_overlapping == 0:
                return True
            
            compatibility_ratio = compatible_fields / total_overlapping
            logger.info(f"Struct compatibility: {compatible_fields}/{total_overlapping} "
                       f"fields compatible ({compatibility_ratio:.2%})")
            
            return compatibility_ratio >= 0.5
            
        except Exception as error:
            logger.error(f"Error checking struct compatibility: {error}")
            return False

    def _are_types_compatible(self, type1: DataType, type2: DataType) -> bool:
        """
        Check if two data types are compatible.
        
        Args:
            type1: First data type to compare
            type2: Second data type to compare
            
        Returns:
            bool: True if types are compatible, False otherwise
        """
        if not type1 or not type2:
            return False
            
        try:
            # Exact match
            if type1.equals(type2):
                return True
            
            # Same size compatibility
            if hasattr(type1, 'getLength') and hasattr(type2, 'getLength'):
                if type1.getLength() == type2.getLength():
                    return True
            
            # Pointer type compatibility
            if isinstance(type1, PointerDataType) and isinstance(type2, PointerDataType):
                return True
                
            # Name-based compatibility for similar types
            type1_name = type1.getName().lower() if hasattr(type1, 'getName') else str(type1).lower()
            type2_name = type2.getName().lower() if hasattr(type2, 'getName') else str(type2).lower()
            
            integer_types = {'int', 'integer', 'signed int', 'int32', 'int32_t'}
            unsigned_types = {'unsigned int', 'uint', 'uint32', 'uint32_t', 'unsigned'}
            char_types = {'char', 'int8', 'int8_t', 'byte'}
            uchar_types = {'unsigned char', 'uchar', 'uint8', 'uint8_t'}
            short_types = {'short', 'int16', 'int16_t'}
            ushort_types = {'unsigned short', 'ushort', 'uint16', 'uint16_t'}
            
            type_groups = [integer_types, unsigned_types, char_types, 
                          uchar_types, short_types, ushort_types]
            
            for group in type_groups:
                if type1_name in group and type2_name in group:
                    return True
            
        except Exception as error:
            logger.debug(f"Error comparing types: {error}")
        
        return False

    def merge_struct_fields(self, existing_struct: Structure, new_fields: List[Dict[str, Any]]) -> Structure:
        """
        Merge new fields into an existing struct definition.
        
        Args:
            existing_struct: Existing struct to merge with
            new_fields: List of new field definitions to merge
            
        Returns:
            Structure: Merged struct with combined fields
        """
        if not existing_struct or not new_fields:
            logger.warning("Cannot merge: missing existing struct or new fields")
            return existing_struct
            
        try:
            category_path = CategoryPath("/AI_Generated_Structs")
            merged_struct = StructureDataType(
                categoryPath=category_path, 
                name=existing_struct.getName(), 
                length=existing_struct.getLength()
            )
            
            # Copy existing fields
            fields_copied = 0
            for i in range(existing_struct.getNumComponents()):
                component = existing_struct.getComponent(i)
                if component and not component.isUndefined():
                    try:
                        merged_struct.insertAtOffset(
                            offset=component.getOffset(),
                            dataType=component.getDataType(),
                            length=component.getLength(),
                            name=component.getFieldName(),
                            comment=component.getComment()
                        )
                        fields_copied += 1
                    except Exception as error:
                        logger.warning(f"Could not copy existing field at offset {component.getOffset()}: {error}")
            
            # Add new fields
            fields_added = 0
            for field in new_fields:
                field_name = field.get("name", "unknown_field")
                field_type_str = field.get("type", "int")
                field_offset = field.get("offset", 0)
                
                field_data_type = map_c_type_to_ghidra_type(type_string=field_type_str)
                
                # Check if field already exists at this offset
                existing_component = None
                for i in range(merged_struct.getNumComponents()):
                    comp = merged_struct.getComponent(i)
                    if comp and comp.getOffset() == field_offset:
                        existing_component = comp
                        break
                
                if not existing_component:
                    try:
                        merged_struct.insertAtOffset(
                            offset=field_offset, 
                            dataType=field_data_type,
                            length=field_data_type.getLength(), 
                            name=field_name, 
                            comment=None
                        )
                        fields_added += 1
                    except Exception as error:
                        logger.warning(f"Could not add new field '{field_name}' at offset {field_offset}: {error}")
            
            logger.info(f"Merged struct '{existing_struct.getName()}': "
                       f"copied {fields_copied} existing fields, added {fields_added} new fields")
            
            resolved_struct = self.data_type_manager.resolve(dataType=merged_struct, handler=None)
            return resolved_struct
            
        except Exception as error:
            logger.error(f"Error merging struct fields: {error}")
            return existing_struct

    def create_struct_in_ghidra(self, struct_def: Dict[str, Any]) -> Optional[Structure]:
        """
        Create a new struct in Ghidra based on the definition.
        
        Args:
            struct_def: Dictionary containing struct name and field definitions
            
        Returns:
            Optional[Structure]: Created struct or None if creation failed
        """
        if not self.data_type_manager:
            logger.error("No data type manager available for struct creation")
            return None

        struct_name = struct_def.get("name", "UnknownStruct")
        fields = struct_def.get("fields", [])

        if not struct_name or not fields:
            logger.warning(f"Invalid struct definition: name='{struct_name}', fields={len(fields)}")
            return None

        try:
            existing_struct = self.find_existing_struct(struct_name=struct_name)
            
            if existing_struct:
                logger.info(f"Found existing struct: {existing_struct.getName()}")
                
                if self.are_structs_compatible(existing_struct=existing_struct, new_fields=fields):
                    logger.info("Structs are compatible, merging fields...")
                    return self.merge_struct_fields(existing_struct=existing_struct, new_fields=fields)
                else:
                    logger.info("Structs are incompatible, creating new struct with modified name")
                    counter = 1
                    while True:
                        new_name = f"{struct_name}_variant{counter}"
                        if not self.find_existing_struct(struct_name=new_name):
                            struct_name = new_name
                            break
                        counter += 1
            
            # Create new struct
            category_path = CategoryPath("/AI_Generated_Structs")
            struct_dt = StructureDataType(categoryPath=category_path, name=struct_name, length=0)

            fields_added = 0
            for field in fields:
                field_name = field.get("name", "unknown_field")
                field_type_str = field.get("type", "int")
                field_offset = field.get("offset", 0)

                field_data_type = map_c_type_to_ghidra_type(type_string=field_type_str)

                try:
                    struct_dt.insertAtOffset(
                        offset=field_offset, 
                        dataType=field_data_type,
                        length=field_data_type.getLength(), 
                        name=field_name, 
                        comment=None
                    )
                    fields_added += 1
                except Exception as error:
                    logger.warning(f"Could not add field '{field_name}' at offset {field_offset}: {error}")
                    # Try adding without specific offset
                    try:
                        struct_dt.add(
                            dataType=field_data_type, 
                            length=field_data_type.getLength(),
                            name=field_name, 
                            comment=None
                        )
                        fields_added += 1
                    except Exception as error2:
                        logger.error(f"Could not add field '{field_name}' to struct: {error2}")

            resolved_struct = self.data_type_manager.resolve(dataType=struct_dt, handler=None)
            logger.info(f"Created struct: {struct_name} with {fields_added} fields")
            return resolved_struct

        except Exception as error:
            logger.error(f"Error creating struct '{struct_name}': {error}")
            return None
    def apply_struct_to_variables(
        self, 
        target_function: Function, 
        struct_mappings: List[Dict[str, Any]], 
        created_structs: Dict[str, Structure]
    ) -> None:
        """
        Apply struct types to variables in a function.
        
        Args:
            target_function: Function whose variables should be updated
            struct_mappings: List of variable-to-struct mappings
            created_structs: Dictionary of created structs by name
        """
        if not struct_mappings or not created_structs:
            logger.debug("No struct mappings or created structs to apply")
            return
            
        high_function = self.get_high_function(target_function=target_function)
        if not high_function:
            logger.error("Could not get high function for variable mapping")
            return

        local_symbols = high_function.getLocalSymbolMap().getSymbols()
        variables_updated = 0

        for mapping in struct_mappings:
            var_name = mapping.get("variable_name", "")
            struct_name = mapping.get("struct_name", "")
            is_pointer = mapping.get("is_pointer", False)
            
            if not var_name or not struct_name:
                logger.warning(f"Invalid mapping: var_name='{var_name}', struct_name='{struct_name}'")
                continue

            # Find the struct
            struct_dt = None
            if struct_name in created_structs:
                struct_dt = created_structs[struct_name]
            elif struct_name in self.global_struct_registry:
                struct_dt = self.global_struct_registry[struct_name]
            else:
                # Try to find variant names
                for name, struct in self.global_struct_registry.items():
                    if name.startswith(struct_name):
                        struct_dt = struct
                        logger.debug(f"Using struct variant '{name}' for original name '{struct_name}'")
                        break

            if not struct_dt:
                logger.warning(f"Struct '{struct_name}' not found for variable '{var_name}'")
                continue
            
            # Determine variable data type
            if is_pointer:
                var_data_type = PointerDataType(dataType=struct_dt)
            else:
                var_data_type = struct_dt

            # Apply to matching variables
            for symbol in local_symbols:
                if symbol.getName() == var_name:
                    try:
                        self.high_func_db_util.updateDBVariable(
                            symbol=symbol, 
                            name=var_name, 
                            dataType=var_data_type, 
                            source=SourceType.USER_DEFINED
                        )
                        self.high_func_db_util.commitParamsToDatabase(
                            highFunction=high_function,
                            useDataTypes=True,
                            commit=HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                            source=SourceType.USER_DEFINED,
                        )
                        variables_updated += 1
                        pointer_str = "*" if is_pointer else ""
                        logger.info(f"Applied struct '{struct_dt.getName()}{pointer_str}' to variable '{var_name}'")
                    except Exception as error:
                        logger.error(f"Error applying struct to variable '{var_name}': {error}")
                    break
            else:
                logger.warning(f"Variable '{var_name}' not found in function {target_function.getName()}")
                
        logger.info(f"Updated {variables_updated} variables with struct types in {target_function.getName()}")

    def generate_structs(self, target_function: Function) -> None:
        """
        Generate structs for a function based on AI analysis.
        
        Args:
            target_function: Function to analyze for struct generation
        """
        function_name = target_function.getName()
        logger.info(f"Generating structs for function: {function_name}")

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            logger.warning(f"Unable to generate structs for {function_name} - no decompiled code")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            logger.warning(f"Unable to generate structs for {function_name} - no AI response")
            return
        
        try:
            parsed_response = self.parse_ai_struct_response(ai_response=ai_response)
            if not parsed_response:
                logger.warning(f"Failed to parse AI response for {function_name}")
                return

            created_structs = {}
            structs_data = parsed_response.get("structs", [])
            
            # Create or reuse structs
            for struct_def in structs_data:
                struct_name = struct_def.get("name", "")
                
                if not struct_name:
                    logger.warning("Struct definition missing name, skipping")
                    continue
                
                if struct_name in self.global_struct_registry:
                    logger.debug(f"Reusing existing struct from registry: {struct_name}")
                    created_structs[struct_name] = self.global_struct_registry[struct_name]
                else:
                    created_struct = self.create_struct_in_ghidra(struct_def=struct_def)
                    if created_struct:
                        actual_name = created_struct.getName()
                        created_structs[struct_name] = created_struct
                        self.global_struct_registry[actual_name] = created_struct
                        
                        # Also register under original name if different
                        if actual_name != struct_name:
                            self.global_struct_registry[struct_name] = created_struct

            # Apply struct mappings to variables
            variable_mappings = parsed_response.get("variable_mappings", [])
            if variable_mappings and created_structs:
                self.apply_struct_to_variables(
                    target_function=target_function, 
                    struct_mappings=variable_mappings, 
                    created_structs=created_structs
                )
            
            logger.info(f"Struct generation completed for {function_name}: "
                       f"{len(created_structs)} structs, {len(variable_mappings)} variable mappings")
    
        except Exception as error:
            logger.error(f"Unable to generate structs for {function_name}: {error}")

    def process_all_functions(self) -> None:
        """
        Process all functions in the program for struct generation.
        
        Functions are sorted by size (smallest first) to process
        simpler functions before more complex ones.
        """
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        logger.info(f"Processing {len(all_functions)} functions for struct generation")

        for index, function in enumerate(all_functions, 1):
            logger.debug(f"Processing function {index}/{len(all_functions)}: {function.getName()}")
            self.generate_structs(target_function=function)
            
        logger.info("Struct generation completed")

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for struct generation AI queries.
        
        Returns:
            str: Detailed prompt for AI-powered struct generation
        """
        return """
        You are a reverse engineer using Ghidra.
        You will receive the decompiler output from Ghidra for a function.
        You are to determine what structs are present in the function.
        You are to provide a map that defines the struct fields and their types.
        You are also to provide a map between the struct and which variables need to typed with the new structs.

        Requirements:
        - Respond with JSON data only, no extra information or commentary
        - Determine the data type for each variable using standard C types
          (int, float, char*, uint32_t, etc.)
        - Provide meaningful struct and field names based on function behavior
        - Use only valid C identifier characters (letters, numbers, 
          underscores)
        - Avoid generic names like 'param1', 'arg', 'temp'
        - Look for patterns of field access that suggest struct usage
        - Consider memory layout and field offsets
        - Only create structs when there's clear evidence of structured data
        
        Response format:
        {{
            "structs": [
                {{
                    "name": "DeviceConfig",
                    "fields": [
                        {{"name": "device_id", "type": "uint32_t", "offset": 0}},
                        {{"name": "status_flags", "type": "uint16_t", "offset": 4}},
                        {{"name": "buffer_ptr", "type": "char*", "offset": 8}},
                        {{"name": "buffer_size", "type": "uint32_t", "offset": 12}}
                    ]
                }},
                {{
                    "name": "StatusInfo",
                    "fields": [
                        {{"name": "error_code", "type": "int", "offset": 0}},
                        {{"name": "timestamp", "type": "uint64_t", "offset": 4}}
                    ]
                }}
            ],
            "variable_mappings": [
                {{"variable_name": "param_1", "struct_name": "DeviceConfig", "is_pointer": true}},
                {{"variable_name": "local_status", "struct_name": "StatusInfo", "is_pointer": false}}
            ]
        }}
        
        Provide meaningful names that reflect their purpose in the function.
        Be sure to only generate full, valid JSON that can be parsed by python's json library.
        Only suggest structs when there's clear evidence of structured data access patterns.
        """


def main() -> None:
    """
    Main entry point for the AI-powered Ghidra analysis script.
    
    This function orchestrates the various analysis components based on
    user preferences and manages the overall analysis workflow.
    """
    current_program = getCurrentProgram()

    if current_program is None:
        logger.error("This script must be run within Ghidra environment")
        return

    logger.info("Starting AI-powered Ghidra analysis")

    # Initialize Ghidra components
    program_listing = current_program.getListing()
    function_manager = current_program.getFunctionManager()

    decompiler_interface = DecompInterface()
    decompiler_interface.openProgram(current_program)

    reference_manager = current_program.getReferenceManager()
    high_func_db_util = HighFunctionDBUtil()
    data_type_manager = current_program.getDataTypeManager()

    # Get user preferences for analysis components
    should_rename_functions: bool = askYesNo(
        title="Rename Functions?",
        message="Should functions be renamed based on the function's decompiled "
        "output using AI analysis?"
    )

    should_generate_signatures: bool = askYesNo(
        title="Generate Function Signatures?",
        message="Should function signatures be generated based on the function's "
        "decompiled output using AI analysis?"
    )

    should_rename_variables: bool = askYesNo(
        title="Rename/Retype Variables?",
        message="Should variables be renamed/retyped based on the function's decompiled "
        "output using AI analysis?"
    )

    should_comment_functions: bool = askYesNo(
        title="Comment Functions?",
        message="Should functions be commented based on the function's decompiled "
        "output using AI analysis?"
    )
    
    should_generate_structs: bool = askYesNo(
        title="Generate Structs?",
        message="Should structs be generated based on the function's decompiled "
        "output using AI analysis?"
    )

    # Initialize analysis components based on user preferences
    analyzers = []

    if should_rename_functions:
        function_renamer = FunctionRenamer(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )
        analyzers.append(("Function Renaming", function_renamer))

    if should_generate_signatures:
        signature_generator = FunctionSignatureGenerator(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )
        analyzers.append(("Signature Generation", signature_generator))

    if should_rename_variables:
        variable_renamer = VariableRenamer(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )
        analyzers.append(("Variable Renaming", variable_renamer))

    if should_comment_functions:
        function_commenter = FunctionCommenter(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )
        analyzers.append(("Function Commenting", function_commenter))

    if should_generate_structs:
        struct_generator = StructGenerator(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
            data_type_manager=data_type_manager,
        )
        analyzers.append(("Struct Generation", struct_generator))

    # Execute selected analyses
    if not analyzers:
        logger.info("No analysis components selected. Exiting.")
        return

    total_functions = function_manager.getFunctionCount()
    logger.info(f"Starting analysis of {total_functions} functions with {len(analyzers)} analyzers")

    for analysis_name, analyzer in analyzers:
        logger.info(f"Starting {analysis_name}...")
        try:
            analyzer.process_all_functions()
            logger.info(f"Completed {analysis_name}")
        except Exception as error:
            logger.error(f"Error during {analysis_name}: {error}")

    logger.info("AI-powered Ghidra analysis completed successfully")


if __name__ == "__main__":
    main()
