from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI
import httpx
import os

os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://aiml-aoai-api.gc1.myngc.com"

class AIFunctionAnalyzer:
    def __init__(self, system_prompt=""):
        self.system_prompt = system_prompt
        self.chain = self._get_chain()

    def query(self, query=""):
        try:
            return self.chain.invoke({"input": query})
        except Exception as e:
            print(f"query='{query}'\nexception={e}")

    def _get_chain(self):
        httpx_client = httpx.Client(http2=True, verify=False)

        llm = AzureChatOpenAI(
            azure_deployment="gpt-4o",
            http_client=httpx_client,
            api_version="2024-02-01",
        )

        string_parser = StrOutputParser()

        prompt = ChatPromptTemplate.from_messages(
            [("system", self.system_prompt), ("user", "{input}")]
        )

        chain = prompt | llm | string_parser

        return chain

ghidra_program = currentProgram
function_listing = ghidra_program.getListing()
selected_function = getFunctionContaining(currentAddress)

if selected_function is None:
    print("No function selected!")
else:
    decompiler_interface = DecompInterface()
    decompiler_interface.openProgram(currentProgram)
    decompile_result = decompiler_interface.decompileFunction(selected_function, 120, None)
    
    if not decompile_result.decompileCompleted():
        print("Decompilation failed for the selected function.")
    else:
        decompiled_code = decompile_result.getDecompiledFunction().getC()
        
        analysis_prompt = f"""
You are analyzing a function from a binary reverse engineering task. The decompiler output for the function is provided below.

Please:
1. Identify how many parameters the function takes.
2. Name each function parameter meaningfully based on the surrounding context provided in the decompiled output.
3. Determine the data type for each parameter (use standard C types like `int`, `float`, `char*`, etc.).
4. Determine the return type of the function.

Respond with the following format EXACTLY:
-----
Return Type: [return type]
Parameters:
1. [parameter type] [parameter name]
2. [parameter type] [parameter name]
3. ...
-----
Decompiled Function:
{decompiled_code}
"""
        ai_analyzer = AIFunctionAnalyzer(system_prompt=analysis_prompt)

        ai_response = ai_analyzer.query(query=decompile_result)
        print("AI Response Received:")
        print(ai_response)

        response_lines = ai_response.split("\n")
        function_return_type = None
        function_parameters = []

        for line in response_lines:
            if line.startswith("Return Type:"):
                function_return_type = line.split(":")[1].strip()
            elif line.startswith("Parameters:"):
                continue
            elif line.strip() and line[0].isdigit():
                parts = line.split()
                param_type = parts[1]
                param_name = parts[2]
                function_parameters.append((param_type, param_name))

        if function_return_type is None:
            print("Failed to parse return type. Check AI response.")
        elif not function_parameters:
            print("No parameters found. Check AI response.")
        else:
            signature_update_transaction = ghidra_program.startTransaction("Update Function Signature")
            try:
                new_return_type = map_type_string_to_ghidra_type(function_return_type)
                
                if new_return_type is None:
                    print(f"Unrecognized return type '{function_return_type}'. Defaulting to `int`.")
                    new_return_type = IntegerDataType()

                selected_function.setReturnType(new_return_type, SourceType.USER_DEFINED)
                
                selected_function.getParameters()[:] = []

                for param_type, param_name in function_parameters:
                    param_data_type = map_type_string_to_ghidra_type(param_type)
                    if param_data_type is None:
                        print(f"Unrecognized parameter type '{param_type}'. Defaulting to `int`.")
                        param_data_type = IntegerDataType()
                    selected_function.addParameter(param_data_type, param_name, SourceType.USER_DEFINED)

                print(f"Function signature updated successfully with return type '{function_return_type}' and {len(function_parameters)} parameter(s).")
            except Exception as e:
                print(f"Error updating the function signature: {e}")
            finally:
                ghidra_program.endTransaction(signature_update_transaction, True)

def map_type_string_to_ghidra_type(type_string):
    from ghidra.program.model.data import (
        IntegerDataType,
        ShortDataType,
        LongDataType,
        CharDataType,
        FloatDataType,
        DoubleDataType,
        VoidDataType,
        BooleanDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        UnsignedLongDataType,
        UnsignedCharDataType,
        PointerDataType
    )
    
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
        base_type = map_type_string_to_ghidra_type(normalized_type[:-1].strip())
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
        from ghidra.program.model.data import LongLongDataType
        return LongLongDataType()
    elif normalized_type in ["uint64", "uint64_t", "unsigned long long"]:
        from ghidra.program.model.data import UnsignedLongLongDataType
        return UnsignedLongLongDataType()
    elif normalized_type in ["char *", "string"]:
        return PointerDataType(CharDataType())
    elif "[" in normalized_type and "]" in normalized_type:
        base_type_part, _, array_size_part = normalized_type.partition("[")
        base_type = map_type_string_to_ghidra_type(base_type_part.strip())
        if base_type is not None and array_size_part[:-1].isdigit():
            from ghidra.program.model.data import ArrayDataType
            return ArrayDataType(base_type, int(array_size_part[:-1]), base_type.length)

    print(f"WARNING: Unrecognized data type '{type_string}', defaulting to `int`.")
    return IntegerDataType()