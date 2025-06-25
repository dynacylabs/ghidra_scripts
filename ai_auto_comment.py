# @runtime PyGhidra

import httpx
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI

class AI:
    def __init__(self):
        os.environ["AZURE_OPENAI_API_KEY"] = ""
        os.environ["AZURE_OPENAI_ENDPOINT"] = ""

        self.chain = self._get_chain()

    def get_comment_for_code(self, decompiler_output=""):
        return self.chain.invoke({"input": decompiler_output})

    def _get_chain(self):
        httpx_client = httpx.Client(http2=True, verify=False)

        llm = AzureChatOpenAI(
            azure_deployment="gpt-4",
            http_client=httpx_client,
            api_version="2024-02-01",
        )

        parse_string = StrOutputParser()

        prompt = ChatPromptTemplate.from_messages([
            ("system", self.system_prompt),
            ("user", "{input}")
        ])

        chain = prompt | llm | parse_string

        return chain


    @property
    def system_prompt(self):
        system_prompt = """
        You are a reverse engineer using ghidra.
        You will receive the decompiler output from ghidra for a function.
        You are to provide a comment to be placed at the top of the function.
        Your comment shall:
        - Be in c docstring format
        - Word-wrapped at 80 characters
        - Be tab indented
        - Follow the format:
          - FUNCTION_NAME
            - A meaningful name for the function in c format
          - DESCRIPTION
            - A description of the function as a whole
          - FUNCTIONALITY
            - A detailed explanation of what the function is doing
          - RETURN
            - A sorted list of return values and their meaning
        Example of what a comment should look like:
        ```
        FUNCTION_NAME handle_periph_state

        DESCRIPTION
          This function seems to handle some peripheral-related logic, checking
          the state of specific memory addresses and performing operations on them
          accordingly. It reacts to conditions involving data at memory-mapped
          peripheral registers or other hardware-related data locations.

        FUNCTIONALITY
          - The function first checks if the value at PTR_PERIPH1_0x20 is equal to 
            0x01. If true:
              - It then checks if the value at *(PTR_PERIPH1_0x2C + 0x58) equals 
                DAT_00000600. If this condition is met, it returns 3.
              - Otherwise, it updates *(PTR_PERIPH1_0x2C + 0x58) to DAT_00000600, 
                clears a specific bit of a value at PTR_PERIPH89_0x0 + 8, sets
                *(PTR_PERIPH89_0x0 + 0x24) to 2, and then returns 5.
          - If the initial value at PTR_PERIPH1_0x20 is not 0x01, the function
            directly returns 4.

        RETURN
          - 3: When the value at *(PTR_PERIPH1_0x2C + 0x58) matches DAT_00000600.
          - 4: When the initial condition (*PTR_PERIPH1_0x20 == 0x01) is false.
          - 5: When the initial condition is true, but *(PTR_PERIPH1_0x2C + 0x58) 
               does not match DAT_00000600 and is subsequently updated.
        ```
        You should only provide the comment with no extra information or commentary.
        """

        return system_prompt

if __name__ == "__main__":
    current_program = getCurrentProgram()
    listing = current_program.getListing()
    function_manager = current_program.getFunctionManager()

    ai = AI()

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)

    functions = list(function_manager.getFunctions(True))
    functions.sort(key=lambda f: f.getBody().getNumAddresses())

    for function in functions:
        original_function_name = function.getName()
        decompile_results = decompiler.decompileFunction(function, 30, monitor)
        if decompile_results and decompile_results.decompileCompleted():
            decompiled_code = decompile_results.getDecompiledFunction().getC()
            code_unit = listing.getCodeUnitAt(function.getEntryPoint())
            if code_unit:
                comment = ai.get_comment_for_code(decompiler_output=decompiled_code)
                code_unit.setComment(CodeUnit.PLATE_COMMENT, comment)

                comment_lines = comment.splitlines()
                for comment_line in comment_lines:
                    if comment_line.startswith("FUNCTION_NAME"):
                        comment_line_parts = comment_line.split()
                        if len(comment_line_parts) > 1:
                            new_function_name = comment_line_parts[1]
                            print(f"{original_function_name} -> {new_function_name}")
                            function.setName(new_function_name, SourceType.USER_DEFINED)
                            break
        else:
            print(f"Decompile of {original_function_name} took too long, not commenting...")
    decompiler.dispose()
