# @runtime PyGhidra
from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.symbol import SourceType

import httpx
import os

from ghidra.program.model.symbol import SourceType

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI

from ghidra.app.decompiler import DecompInterface


os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://aiml-aoai-api.gc1.myngc.com"

class AI:
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

        parse_string = StrOutputParser()

        prompt = ChatPromptTemplate.from_messages(
            [("system", self.system_prompt), ("user", "{input}")]
        )

        chain = prompt | llm | parse_string

        return chain

# Get the current program and context
program = currentProgram
listing = program.getListing()
current_function = getFunctionContaining(currentAddress)

if current_function is None:
    print("No function selected!")
else:
    # Extract the decompiled output for the current function
    decompiler_ifc = DecompInterface()  # Get decompiler interface
    decompiler_ifc.openProgram(currentProgram)
    decompilation_result = decompiler_ifc.decompileFunction(current_function, 120, None)
    
    if not decompilation_result.decompileCompleted():
        print("Decompilation failed for the selected function.")
    else:
        # Get the decompiled C-like code
        decompiled_output = decompilation_result.getDecompiledFunction().getC()
        
        # Prepare a clear and structured prompt for the AI
        ai_prompt = f"""
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
{decompiled_output}
"""
        ai = AI(system_prompt=ai_prompt)

        # Connect this script to your AI integration
        # Replace `send_to_ai(prompt)` with your custom implementation
        ai_response = ai.query(query=decompilation_result)  # Function you need to implement
        print("AI Response Received:")
        print(ai_response)  # Debugging: Print AI response for verification

        # Parse AI response (assuming the AI returns output in the specified format)
        lines = ai_response.split("\n")
        return_type = None
        parameters = []

        for line in lines:
            if line.startswith("Return Type:"):
                return_type = line.split(":")[1].strip()
            elif line.startswith("Parameters:"):
                continue  # Skip the 'Parameters:' line
            elif line.strip() and line[0].isdigit():  # Parse parameter lines
                parts = line.split()
                param_type = parts[1]  # Extract type
                param_name = parts[2]  # Extract name
                parameters.append((param_type, param_name))

        # Validate the parsed data
        if return_type is None:
            print("Failed to parse return type. Check AI response.")
        elif not parameters:
            print("No parameters found. Check AI response.")
        else:
            # Update the function signature in Ghidra
            transaction = program.startTransaction("Update Function Signature")
            try:
                # Set the return type
                new_return_type = guessDataType(return_type)  # Convert string to Ghidra data type
                
                if new_return_type is None:
                    print(f"Unrecognized return type '{return_type}'. Defaulting to `int`.")
                    new_return_type = IntegerDataType()

                current_function.setReturnType(new_return_type, SourceType.USER_DEFINED)
                
                # Clear existing parameters first
                current_function.getParameters()[:] = []

                # Add the new AI-generated parameters
                for param_type, param_name in parameters:
                    param_data_type = guessDataType(param_type)  # Convert string to Ghidra data type
                    if param_data_type is None:
                        print(f"Unrecognized parameter type '{param_type}'. Defaulting to `int`.")
                        param_data_type = IntegerDataType()
                    current_function.addParameter(param_data_type, param_name, SourceType.USER_DEFINED)

                print(f"Function signature updated successfully with return type '{return_type}' and {len(parameters)} parameter(s).")
            except Exception as e:
                print(f"Error updating the function signature: {e}")
            finally:
                program.endTransaction(transaction, True)

# Helper function to map AI-generated type strings to Ghidra types
def guessDataType(type_str):
    """
    Map a string type from AI response to a Ghidra data type.
    Handles a wide range of C/C++ data types, including pointers and arrays.
    """
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
    
    dtm = currentProgram.getDataTypeManager()  # Get the program's data type manager
    type_str = type_str.lower().strip()  # Normalize case and trim whitespace
    
    # Integer types
    if type_str in ["int", "signed int"]:
        return IntegerDataType()
    elif type_str in ["unsigned int", "uint"]:
        return UnsignedIntegerDataType()
    elif type_str in ["short", "signed short"]:
        return ShortDataType()
    elif type_str in ["unsigned short", "ushort"]:
        return UnsignedShortDataType()
    elif type_str in ["long", "signed long"]:
        return LongDataType()
    elif type_str in ["unsigned long", "ulong"]:
        return UnsignedLongDataType()

    # Char types
    elif type_str in ["char", "signed char"]:
        return CharDataType()
    elif type_str in ["unsigned char", "uchar", "byte"]:
        return UnsignedCharDataType()

    # Boolean type
    elif type_str in ["bool", "boolean"]:
        return BooleanDataType()
    
    # Floating-point types
    elif type_str in ["float"]:
        return FloatDataType()
    elif type_str in ["double"]:
        return DoubleDataType()

    # Void type
    elif type_str == "void":
        return VoidDataType()

    # Pointer types
    elif type_str.endswith("*"):
        base_type = guessDataType(type_str[:-1].strip())  # Recursively find the base type
        if base_type is not None:
            return PointerDataType(base_type)
        else:
            return PointerDataType(VoidDataType())  # Default for unknown pointer types

    # Fixed-size types or type aliases (e.g., uint8_t)
    elif type_str in ["int8", "int8_t", "signed char"]:
        return CharDataType()
    elif type_str in ["uint8", "uint8_t"]:
        return UnsignedCharDataType()
    elif type_str in ["int16", "int16_t", "short", "signed short"]:
        return ShortDataType()
    elif type_str in ["uint16", "uint16_t"]:
        return UnsignedShortDataType()
    elif type_str in ["int32", "int32_t", "int"]:
        return IntegerDataType()
    elif type_str in ["uint32", "uint32_t", "unsigned int"]:
        return UnsignedIntegerDataType()
    elif type_str in ["int64", "int64_t", "long long"]:
        from ghidra.program.model.data import LongLongDataType
        return LongLongDataType()
    elif type_str in ["uint64", "uint64_t", "unsigned long long"]:
        from ghidra.program.model.data import UnsignedLongLongDataType
        return UnsignedLongLongDataType()

    # String types (common heuristic for pointers to characters)
    elif type_str in ["char *", "string"]:
        return PointerDataType(CharDataType())

    # Array types (e.g., int[10])
    elif "[" in type_str and "]" in type_str:
        base_type_str, _, array_size_str = type_str.partition("[")
        base_type = guessDataType(base_type_str.strip())
        if base_type is not None and array_size_str[:-1].isdigit():  # Example: int[10]
            from ghidra.program.model.data import ArrayDataType
            return ArrayDataType(base_type, int(array_size_str[:-1]), base_type.length)

    # Default fallback for unknown data types
    print(f"WARNING: Unrecognized data type '{type_str}', defaulting to `int`.")
    return IntegerDataType()  # Fallback to `int` for unknown/ambiguous types