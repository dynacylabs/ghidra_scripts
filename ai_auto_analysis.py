# @runtime PyGhidra
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

from ghidra.program.model.listing import CodeUnit, ParameterImpl, Variable
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

os.environ["AZURE_OPENAI_API_KEY"] = "682a97c3cb0241499579a8b76dacda94"
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://aiml-aoai-api.gc1.myngc.com"


def _map_c_type_to_ghidra_type(type_string: str):
    normalized_type = type_string.lower().strip()

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

    elif normalized_type.endswith("*"):
        base_type = _map_c_type_to_ghidra_type(normalized_type[:-1].strip())
        if base_type is not None:
            return PointerDataType(base_type)
        else:
            return PointerDataType(VoidDataType())

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

    elif normalized_type in ["char *", "string"]:
        return PointerDataType(CharDataType())

    elif "[" in normalized_type and "]" in normalized_type:
        base_type_part, _, array_size_part = normalized_type.partition("[")
        base_type = _map_c_type_to_ghidra_type(base_type_part.strip())
        if base_type is not None and array_size_part[:-1].isdigit():
            array_size = int(array_size_part[:-1])
            return ArrayDataType(base_type, array_size, base_type.getLength())

    return IntegerDataType()


class AzureOpenAIClient:
    def __init__(self, system_prompt: str = "") -> None:
        self.system_prompt: str = system_prompt
        self.chain = self._get_langchain_pipeline()

    def query(self, user_query: str = "") -> Optional[str]:
        try:
            return self.chain.invoke({"input": user_query})
        except Exception as error:
            print(f"AI query failed: query='{user_query}', error={error}")
            return None

    def _get_langchain_pipeline(self):
        http_client = httpx.Client(http2=True, verify=False)

        language_model = AzureChatOpenAI(
            azure_deployment="gpt-4o",
            http_client=http_client,
            api_version="2024-02-01",
        )

        string_parser = StrOutputParser()

        prompt_template = ChatPromptTemplate.from_messages(
            [("system", self.system_prompt), ("user", "{input}")]
        )

        processing_chain = prompt_template | language_model | string_parser

        return processing_chain


class FunctionRenamer:
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        max_rename_iterations: int = 3,
        high_func_db_util=None,
    ) -> None:
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager

        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_function_naming_prompt()
        )

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
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 120, monitor
        )

        if decompilation_result and decompilation_result.decompileCompleted():
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def initialize_function_queue(self) -> Deque:
        return deque(self.function_manager.getFunctions(True))

    def rename_single_function(self, target_function, decompiled_code: str) -> None:
        new_function_name = self.ai_client.query(user_query=decompiled_code)

        if new_function_name:
            try:
                target_function.setName(new_function_name, SourceType.USER_DEFINED)
            except Exception as error:
                print(
                    f"Failed to rename function to '{new_function_name}': " f"{error}"
                )

    def process_all_functions(self) -> None:
        function_queue = self.initialize_function_queue()
        changed_functions: Set = set()
        rename_iteration_count: Dict = defaultdict(int)

        while function_queue:
            current_function = function_queue.popleft()

            if rename_iteration_count[current_function] >= self.max_rename_iterations:
                continue

            decompiled_code = self.decompile_function(target_function=current_function)

            if decompiled_code:
                original_name = current_function.getName()

                self.rename_single_function(
                    target_function=current_function, decompiled_code=decompiled_code
                )

                updated_name = current_function.getName()

                if original_name != updated_name:
                    print(f"Renamed: {original_name} -> {updated_name}")
                    changed_functions.add(current_function)
                    rename_iteration_count[current_function] += 1

                    calling_functions = self._get_calling_functions(
                        target_function=current_function,
                        changed_functions=changed_functions,
                    )
                    function_queue.extend(calling_functions)

    def _get_calling_functions(self, target_function, changed_functions: Set) -> Set:
        calling_functions: Set = set()
        function_references = self.reference_manager.getReferencesTo(
            target_function.getEntryPoint()
        )

        for reference in function_references:
            calling_function = self.function_manager.getFunctionContaining(
                reference.getFromAddress()
            )

            if calling_function and calling_function not in changed_functions:
                calling_functions.add(calling_function)

        return calling_functions

    def _get_function_naming_prompt(self) -> str:
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
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        high_func_db_util=None,
    ) -> None:
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager

        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_function_commenting_prompt()
        )

    def add_comment_to_function(
        self, target_function, decompiler_interface=None
    ) -> None:
        function_name = target_function.getName()
        print(f"Generating comment for function: {function_name}")

        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 120, monitor
        )

        if decompilation_result and decompilation_result.decompileCompleted():
            decompiled_code = decompilation_result.getDecompiledFunction().getC()

            function_code_unit = self.program_listing.getCodeUnitAt(
                target_function.getEntryPoint()
            )

            if function_code_unit:
                ai_generated_comment = self.ai_client.query(user_query=decompiled_code)

                if ai_generated_comment:
                    function_code_unit.setComment(
                        CodeUnit.PLATE_COMMENT, ai_generated_comment
                    )
                else:
                    print(f"Failed to generate comment for {function_name}")
        else:
            print(
                f"Decompilation of {function_name} failed or timed out, "
                f"skipping comment generation"
            )

    def process_all_functions(self) -> None:
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        for function in all_functions:
            self.add_comment_to_function(target_function=function)

    def _get_function_commenting_prompt(self) -> str:
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


class VariableRenamer:
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        high_func_db_util=None,
    ) -> None:
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager
        self.high_func_db_util = high_func_db_util

        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_variable_rename_prompt()
        )

    def decompile_function(self, target_function) -> Optional[str]:
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 120, monitor
        )

        if decompilation_result and decompilation_result.decompileCompleted():
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def getHighFunc(self, function):
        decompiled_result = self.decompiler_interface.decompileFunction(
            function, 120, monitor
        )
        if decompiled_result and decompiled_result.decompileCompleted():
            return decompiled_result.getHighFunction()
        return None

    def parse_ai_signature_response(
        self, ai_response: str = ""
    ) -> Tuple[Optional[str], List[Tuple[str, str]]]:
        try:
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()

            mapping = json.loads(clean_response)

        except (json.JSONDecodeError, KeyError, AttributeError):
            mapping = None

        return mapping

    def rename_variables(self, target_function) -> None:
        function_name = target_function.getName()

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            print(f"Unable to rename/retype variables for {function_name}")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            print(f"Unable to rename/retype variables for {function_name}")
            return

        high_func = self.getHighFunc(function=target_function)
        local_symbols = high_func.getLocalSymbolMap().getSymbols()

        mapping = self.parse_ai_signature_response(ai_response=ai_response)

        for symbol in local_symbols:
            try:
                old_name = symbol.getName()
            
                new_name = mapping.get(old_name, {}).get("name")
                data_type_string = mapping.get(old_name, {}).get("type")

                data_type = _map_c_type_to_ghidra_type(type_string=data_type_string)
                self.high_func_db_util.updateDBVariable(
                    symbol, new_name, data_type, SourceType.USER_DEFINED
                )
                self.high_func_db_util.commitParamsToDatabase(
                    high_func,
                    True,
                    HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                    SourceType.USER_DEFINED,
                )

                print(f"{target_function.getName()}.{symbol.getName()} -> {target_function.getName()}.{new_name}")
            except Exception as e:
                print(f"Unable to rename/retype {target_function.getName()}.{old_name}: {e}")


    def process_all_functions(self) -> None:
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        for function in all_functions:
            self.rename_variables(target_function=function)

    def _get_variable_rename_prompt(self) -> str:
        """
        Get the system prompt for AI-powered variable renaming.

        Returns:
            A detailed prompt for generating variable renames.
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
        
        Response format:
        {{
            "<old_name>": {{"type": "int", "name": "new_name>"}},
            }} 
        }}
        
        Provide meaningful variable names that reflect their purpose in
        the function.
        """


class FunctionSignatureGenerator:
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        high_func_db_util=None,
    ) -> None:
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager

        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_signature_generation_prompt()
        )

    def decompile_function(self, target_function) -> Optional[str]:
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 120, monitor
        )

        if decompilation_result and decompilation_result.decompileCompleted():
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def parse_ai_signature_response(
        self, ai_response: str = ""
    ) -> Tuple[Optional[str], List[Tuple[str, str]]]:
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

        except (json.JSONDecodeError, KeyError, AttributeError):
            return_type = None
            parameter_list = []

        return return_type, parameter_list

    def apply_function_signature(self, target_function) -> None:
        function_name = target_function.getName()

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            print(f"Unable to sign {function_name}")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            print(f"Unable to sign {function_name}")
            return

        return_type_string, parameter_definitions = self.parse_ai_signature_response(
            ai_response=ai_response
        )

        try:
            if not return_type_string or not parameter_definitions:
                raise ValueError("Invalid signature data from AI")

            ghidra_return_type = _map_c_type_to_ghidra_type(
                type_string=return_type_string
            )
            if ghidra_return_type is None:
                raise ValueError(f"Unknown return type: {return_type_string}")

            target_function.setReturnType(ghidra_return_type, SourceType.USER_DEFINED)

            ghidra_data_types = []
            parameter_names = []

            for param_type_string, param_name in parameter_definitions:
                ghidra_param_type = _map_c_type_to_ghidra_type(
                    type_string=param_type_string
                )

                if ghidra_param_type is None:
                    raise ValueError(f"Unknown parameter type: " f"{param_type_string}")

                ghidra_data_types.append(ghidra_param_type)
                parameter_names.append(param_name)

            while target_function.getParameterCount() > 0:
                target_function.removeParameter(0)

            for data_type, param_name in zip(ghidra_data_types, parameter_names):
                parameter = ParameterImpl(param_name, data_type, self.current_program)
                target_function.addParameter(parameter, SourceType.USER_DEFINED)

            print(
                f"Signed {function_name} with return type "
                f"{return_type_string} and {len(parameter_definitions)} "
                f"parameter(s)"
            )

        except (ValueError, Exception):
            print(f"Unable to sign {function_name}")

    def process_all_functions(self) -> None:
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        for function in all_functions:
            self.apply_function_signature(target_function=function)

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
        {{
          "return_type": "int",
          "parameters": [
            {{"type": "int", "name": "device_id"}},
            {{"type": "char*", "name": "buffer_ptr"}},
            {{"type": "uint32_t", "name": "buffer_size"}}
          ]
        }}
        
        Provide meaningful parameter names that reflect their purpose in
        the function.
        """
    
class StructGenerator:
    def __init__(
        self,
        current_program=None,
        program_listing=None,
        function_manager=None,
        decompiler_interface=None,
        reference_manager=None,
        high_func_db_util=None,
        data_type_manager=None,
    ) -> None:
        self.current_program = current_program
        self.program_listing = program_listing
        self.function_manager = function_manager
        self.decompiler_interface = decompiler_interface
        self.reference_manager = reference_manager
        self.high_func_db_util = high_func_db_util
        self.data_type_manager = data_type_manager

        self.ai_client = AzureOpenAIClient(
            system_prompt=self._get_struct_generator_prompt()
        )
        
        self.global_struct_registry = {}
        self._initialize_struct_registry()

    def _initialize_struct_registry(self):
        try:
            category_path = CategoryPath("/AI_Generated_Structs")
            category = self.data_type_manager.getCategory(category_path)
            
            if category:
                for dt in category.getDataTypes():
                    if isinstance(dt, Structure):
                        self.global_struct_registry[dt.getName()] = dt
                        print(f"Loaded existing struct into registry: {dt.getName()}")
        except Exception as e:
            print(f"Warning: Could not initialize struct registry: {e}")

    def decompile_function(self, target_function) -> Optional[str]:
        decompilation_result = self.decompiler_interface.decompileFunction(
            target_function, 120, monitor
        )

        if decompilation_result and decompilation_result.decompileCompleted():
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def getHighFunc(self, function):
        decompiled_result = self.decompiler_interface.decompileFunction(
            function, 120, monitor
        )
        if decompiled_result and decompiled_result.decompileCompleted():
            return decompiled_result.getHighFunction()
        return None

    def parse_ai_struct_response(
        self, ai_response: str = ""
    ) -> Tuple[Optional[str], List[Tuple[str, str]]]:
        try:
            clean_response = ai_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()
            mapping = json.loads(clean_response)

        except (json.JSONDecodeError, KeyError, AttributeError):
            mapping = None

        return mapping
    

    def map_c_type_to_ghidra_type(self, type_string: str):
        normalized_type = type_string.lower().strip()

        type_mapping = {
            "int": IntegerDataType(),
            "signed int": IntegerDataType(),
            "unsigned int": UnsignedIntegerDataType(),
            "uint": UnsignedIntegerDataType(),
            "short": ShortDataType(),
            "signed short": ShortDataType(),
            "unsigned short": UnsignedShortDataType(),
            "ushort": UnsignedShortDataType(),
            "long": LongDataType(),
            "signed long": LongDataType(),
            "unsigned long": UnsignedLongDataType(),
            "ulong": UnsignedLongDataType(),
            "char": CharDataType(),
            "signed char": CharDataType(),
            "unsigned char": UnsignedCharDataType(),
            "uchar": UnsignedCharDataType(),
            "byte": UnsignedCharDataType(),
            "bool": BooleanDataType(),
            "boolean": BooleanDataType(),
            "float": FloatDataType(),
            "double": DoubleDataType(),
            "void": VoidDataType(),
            "int8": CharDataType(),
            "int8_t": CharDataType(),
            "uint8": UnsignedCharDataType(),
            "uint8_t": UnsignedCharDataType(),
            "int16": ShortDataType(),
            "int16_t": ShortDataType(),
            "uint16": UnsignedShortDataType(),
            "uint16_t": UnsignedShortDataType(),
            "int32": IntegerDataType(),
            "int32_t": IntegerDataType(),
            "uint32": UnsignedIntegerDataType(),
            "uint32_t": UnsignedIntegerDataType(),
            "int64": LongLongDataType(),
            "int64_t": LongLongDataType(),
            "uint64": UnsignedLongLongDataType(),
            "uint64_t": UnsignedLongLongDataType(),
            "long long": LongLongDataType(),
            "unsigned long long": UnsignedLongLongDataType(),
        }

        if normalized_type in type_mapping:
            return type_mapping[normalized_type]

        if normalized_type.endswith("*"):
            base_type_str = normalized_type[:-1].strip()
            base_type = self.map_c_type_to_ghidra_type(base_type_str)
            return PointerDataType(base_type)

        if normalized_type in ["char *", "string"]:
            return PointerDataType(CharDataType())

        if "[" in normalized_type and "]" in normalized_type:
            base_type_part, _, array_size_part = normalized_type.partition("[")
            base_type = self.map_c_type_to_ghidra_type(base_type_part.strip())
            try:
                array_size = int(array_size_part[:-1])
                return ArrayDataType(base_type, array_size, base_type.getLength())
            except (ValueError, AttributeError):
                pass

        print(f"Warning: Unknown type '{type_string}', defaulting to int")
        return IntegerDataType()
    
    def find_existing_struct(self, struct_name: str) -> Optional[Structure]:
        category_path = CategoryPath("/AI_Generated_Structs")
        
        existing_dt = self.data_type_manager.getDataType(category_path, struct_name)
        if existing_dt and isinstance(existing_dt, Structure):
            return existing_dt
        
        category = self.data_type_manager.getCategory(category_path)
        if category:
            for dt in category.getDataTypes():
                if isinstance(dt, Structure):
                    dt_name = dt.getName()
                    if dt_name.startswith(struct_name) and ('.conflict' in dt_name):
                        return dt
        
        return None

    def are_structs_compatible(self, existing_struct: Structure, new_fields: List[Dict]) -> bool:
        if not existing_struct or not new_fields:
            return False
        
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
                new_field_type = self.map_c_type_to_ghidra_type(field_type_str)
                
                if self.are_types_compatible(existing_field['type'], new_field_type):
                    compatible_fields += 1
                    print(f"Compatible field at offset {field_offset}: {field_name}")
                else:
                    conflicts += 1
                    print(f"Type conflict at offset {field_offset}: existing={existing_field['type']}, new={new_field_type}")
            else:
                compatible_fields += 1
        
        total_overlapping = conflicts + compatible_fields
        if total_overlapping == 0:
            return True
        
        compatibility_ratio = compatible_fields / total_overlapping
        print(f"Struct compatibility: {compatible_fields}/{total_overlapping} fields compatible ({compatibility_ratio:.2%})")
        
        return compatibility_ratio >= 0.5

    def are_types_compatible(self, type1, type2) -> bool:
        if type1.equals(type2):
            return True
        
        if hasattr(type1, 'getLength') and hasattr(type2, 'getLength'):
            if type1.getLength() == type2.getLength():
                return True
        
        if (isinstance(type1, PointerDataType) and isinstance(type2, PointerDataType)):
            return True
            
        type1_name = type1.getName().lower() if hasattr(type1, 'getName') else str(type1).lower()
        type2_name = type2.getName().lower() if hasattr(type2, 'getName') else str(type2).lower()
        
        integer_types = {'int', 'integer', 'signed int', 'int32', 'int32_t'}
        unsigned_types = {'unsigned int', 'uint', 'uint32', 'uint32_t', 'unsigned'}
        char_types = {'char', 'int8', 'int8_t', 'byte'}
        uchar_types = {'unsigned char', 'uchar', 'uint8', 'uint8_t'}
        short_types = {'short', 'int16', 'int16_t'}
        ushort_types = {'unsigned short', 'ushort', 'uint16', 'uint16_t'}
        
        type_groups = [integer_types, unsigned_types, char_types, uchar_types, short_types, ushort_types]
        
        for group in type_groups:
            if type1_name in group and type2_name in group:
                return True
        
        return False

    def merge_struct_fields(self, existing_struct: Structure, new_fields: List[Dict]) -> Structure:
        try:
            category_path = CategoryPath("/AI_Generated_Structs")
            merged_struct = StructureDataType(category_path, existing_struct.getName(), existing_struct.getLength())
            
            for i in range(existing_struct.getNumComponents()):
                component = existing_struct.getComponent(i)
                if component and not component.isUndefined():
                    try:
                        merged_struct.insertAtOffset(
                            component.getOffset(),
                            component.getDataType(),
                            component.getLength(),
                            component.getFieldName(),
                            component.getComment()
                        )
                    except Exception as e:
                        print(f"Warning: Could not copy existing field at offset {component.getOffset()}: {e}")
            
            fields_added = 0
            for field in new_fields:
                field_name = field.get("name", "unknown_field")
                field_type_str = field.get("type", "int")
                field_offset = field.get("offset", 0)
                
                field_data_type = self.map_c_type_to_ghidra_type(field_type_str)
                
                existing_component = None
                for i in range(merged_struct.getNumComponents()):
                    comp = merged_struct.getComponent(i)
                    if comp and comp.getOffset() == field_offset:
                        existing_component = comp
                        break
                
                if not existing_component:
                    try:
                        merged_struct.insertAtOffset(field_offset, field_data_type, 
                                                   field_data_type.getLength(), field_name, None)
                        fields_added += 1
                    except Exception as e:
                        print(f"Warning: Could not add new field '{field_name}' at offset {field_offset}: {e}")
            
            if fields_added > 0:
                print(f"Merged {fields_added} new fields into existing struct '{existing_struct.getName()}'")
            else:
                print(f"No new fields added to existing struct '{existing_struct.getName()}'")
            
            resolved_struct = self.data_type_manager.resolve(merged_struct, None)
            return resolved_struct
            
        except Exception as e:
            print(f"Error merging struct fields: {e}")
            return existing_struct

    def create_struct_in_ghidra(self, struct_def: Dict) -> Optional[Structure]:
        if not self.data_type_manager:
            print("Error: No data type manager available")
            return None

        struct_name = struct_def.get("name", "UnknownStruct")
        fields = struct_def.get("fields", [])

        try:
            existing_struct = self.find_existing_struct(struct_name)
            
            if existing_struct:
                print(f"Found existing struct: {existing_struct.getName()}")
                
                if self.are_structs_compatible(existing_struct, fields):
                    print(f"Structs are compatible, merging fields...")
                    return self.merge_struct_fields(existing_struct, fields)
                else:
                    print(f"Structs are incompatible, creating new struct with modified name")
                    counter = 1
                    while True:
                        new_name = f"{struct_name}_variant{counter}"
                        if not self.find_existing_struct(new_name):
                            struct_name = new_name
                            break
                        counter += 1
            
            category_path = CategoryPath("/AI_Generated_Structs")
            struct_dt = StructureDataType(category_path, struct_name, 0)

            for field in fields:
                field_name = field.get("name", "unknown_field")
                field_type_str = field.get("type", "int")
                field_offset = field.get("offset", 0)

                field_data_type = self.map_c_type_to_ghidra_type(field_type_str)

                try:
                    struct_dt.insertAtOffset(field_offset, field_data_type, 
                                           field_data_type.getLength(), field_name, None)
                except Exception as e:
                    print(f"Warning: Could not add field '{field_name}' at offset {field_offset}: {e}")
                    try:
                        struct_dt.add(field_data_type, field_data_type.getLength(), 
                                    field_name, None)
                    except Exception as e2:
                        print(f"Error: Could not add field '{field_name}' to struct: {e2}")

            resolved_struct = self.data_type_manager.resolve(struct_dt, None)
            print(f"Created struct: {struct_name} with {len(fields)} fields")
            return resolved_struct

        except Exception as e:
            print(f"Error creating struct '{struct_name}': {e}")
            return None
    
    def apply_struct_to_variables(self, target_function, struct_mappings: List[Dict], 
                                created_structs: Dict[str, Structure]):
        high_function = self.getHighFunc(target_function)
        if not high_function:
            print("Could not get high function for variable mapping")
            return

        local_symbols = high_function.getLocalSymbolMap().getSymbols()

        for mapping in struct_mappings:
            var_name = mapping.get("variable_name", "")
            struct_name = mapping.get("struct_name", "")
            is_pointer = mapping.get("is_pointer", False)

            struct_dt = None
            if struct_name in created_structs:
                struct_dt = created_structs[struct_name]
            elif struct_name in self.global_struct_registry:
                struct_dt = self.global_struct_registry[struct_name]
            else:
                for name, struct in self.global_struct_registry.items():
                    if name.startswith(struct_name):
                        struct_dt = struct
                        print(f"Using struct variant '{name}' for original name '{struct_name}'")
                        break

            if not struct_dt:
                print(f"Warning: Struct '{struct_name}' not found for variable '{var_name}'")
                continue
            
            if is_pointer:
                var_data_type = PointerDataType(struct_dt)
            else:
                var_data_type = struct_dt

            for symbol in local_symbols:
                if symbol.getName() == var_name:
                    try:
                        self.high_func_db_util.updateDBVariable(
                            symbol, var_name, var_data_type, SourceType.USER_DEFINED
                        )
                        self.high_func_db_util.commitParamsToDatabase(
                            high_function,
                            True,
                            HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                            SourceType.USER_DEFINED,
                        )
                        print(f"Applied struct '{struct_dt.getName()}' to variable '{var_name}'")
                    except Exception as e:
                        print(f"Error applying struct to variable '{var_name}': {e}")
                    break
            else:
                print(f"Warning: Variable '{var_name}' not found in function")


    def generate_structs(self, target_function) -> None:
        function_name = target_function.getName()

        decompiled_code = self.decompile_function(target_function=target_function)

        if not decompiled_code:
            print(f"Unable to generate structs for {function_name}")
            return

        ai_response = self.ai_client.query(user_query=decompiled_code)
        if not ai_response:
            print(f"Unable to generate structs for {function_name}")
            return
        
        try:

            parsed_response = self.parse_ai_struct_response(ai_response=ai_response)

            created_structs = {}
            structs_data = parsed_response.get("structs", [])
            
            for struct_def in structs_data:
                struct_name = struct_def.get("name", "")
                
                if struct_name in self.global_struct_registry:
                    print(f"Reusing existing struct from registry: {struct_name}")
                    created_structs[struct_name] = self.global_struct_registry[struct_name]
                else:
                    created_struct = self.create_struct_in_ghidra(struct_def)
                    if created_struct:
                        actual_name = created_struct.getName()
                        created_structs[struct_name] = created_struct
                        self.global_struct_registry[actual_name] = created_struct
                        
                        if actual_name != struct_name:
                            self.global_struct_registry[struct_name] = created_struct

            variable_mappings = parsed_response.get("variable_mappings", [])
            if variable_mappings and created_structs:
                self.apply_struct_to_variables(target_function, variable_mappings, created_structs)
    
        except Exception as e:
            print(f"Unable to generate structs for {function_name}: {e}")

    def process_all_functions(self) -> None:
        all_functions = list(self.function_manager.getFunctions(True))
        all_functions.sort(key=lambda func: func.getBody().getNumAddresses())

        for function in all_functions:
            self.generate_structs(target_function=function)

    def _get_struct_generator_prompt(self) -> str:
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
        - Provide meaningful variable names based on function behavior
        - Use only valid C identifier characters (letters, numbers, 
          underscores)
        - Avoid generic names like 'param1', 'arg', 'temp'
        
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
        Be sure sure to only generate full, valid json that can be parsed by python's json library.
        """


def main() -> None:
    current_program = getCurrentProgram()

    if current_program is None:
        print("Error: This script must be run within Ghidra environment")
        return

    program_listing = current_program.getListing()
    function_manager = current_program.getFunctionManager()

    decompiler_interface = DecompInterface()
    decompiler_interface.openProgram(current_program)

    reference_manager = current_program.getReferenceManager()

    high_func_db_util = HighFunctionDBUtil()

    data_type_manager = current_program.getDataTypeManager()

    should_rename_functions: bool = askYesNo(
        "Rename Functions?",
        "Should functions be renamed based on the function's decompiled "
        "output using AI analysis?",
    )

    should_generate_signatures: bool = askYesNo(
        "Generate Function Signatures?",
        "Should function signatures be generated based on the function's "
        "decompiled output using AI analysis?",
    )

    should_rename_variables: bool = askYesNo(
        "Rename/retype Variables?",
        "Should variables be renamed/retype based on the function's decompiled "
        "output using AI analysis?",
    )

    should_comment_functions: bool = askYesNo(
        "Comment Functions?",
        "Should functions be commented based on the function's decompiled "
        "output using AI analysis?",
    )
    
    should_generate_structs: bool = askYesNo(
        "Generate Structs?",
        "Should structs be generated based on the function's decompiled "
        "output using AI analysis?",
    )

    function_renamer: Optional[FunctionRenamer] = None
    signature_generator: Optional[FunctionSignatureGenerator] = None
    variable_renamer = None
    function_commenter: Optional[FunctionCommenter] = None

    if should_rename_functions:
        function_renamer = FunctionRenamer(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    if should_generate_signatures:
        signature_generator = FunctionSignatureGenerator(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    if should_rename_variables:
        variable_renamer = VariableRenamer(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

    if should_comment_functions:
        function_commenter = FunctionCommenter(
            current_program=current_program,
            program_listing=program_listing,
            function_manager=function_manager,
            decompiler_interface=decompiler_interface,
            reference_manager=reference_manager,
            high_func_db_util=high_func_db_util,
        )

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

    if should_rename_functions and function_renamer:
        function_renamer.process_all_functions()

    if should_generate_signatures and signature_generator:
        signature_generator.process_all_functions()

    if should_rename_variables and variable_renamer:
        variable_renamer.process_all_functions()

    if should_comment_functions and function_commenter:
        function_commenter.process_all_functions()

    if should_generate_structs and struct_generator:
        struct_generator.process_all_functions()


if __name__ == "__main__":
    main()
