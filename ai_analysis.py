# @runtime PyGhidra

import httpx
import os

from collections import deque, defaultdict

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import AzureChatOpenAI

os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = ""


class AI:
    def __init__(self, system_prompt=""):
        self.system_prompt = system_prompt
        self.chain = self._get_chain()

    def query(self, query=""):
        return self.chain.invoke({"input": query})

    def _get_chain(self):
        httpx_client = httpx.Client(http2=True, verify=False)

        llm = AzureChatOpenAI(
            azure_deployment="gpt-4",
            http_client=httpx_client,
            api_version="2024-02-01",
        )

        parse_string = StrOutputParser()

        prompt = ChatPromptTemplate.from_messages(
            [("system", self.system_prompt), ("user", "{input}")]
        )

        chain = prompt | llm | parse_string

        return chain


class FunctionRenamer:
    def __init__(
        self,
        current_program=None,
        listing=None,
        function_manager=None,
        decompiler=None,
        reference_manager=None,
    ):
        self.current_program = current_program
        self.listing = listing
        self.function_manager = function_manager
        self.decompiler = decompiler
        self.reference_manager = reference_manager

        self.ai = AI(system_prompt=self.system_prompt)

        self.max_renames = int(
            askString(
                "Max Number Of Times To Rename A Function (int)",
                "As functions are renamed, other functions may change. This is the maximum "
                "number of times to update a function's name before skipping. This avoids an "
                "infinite loop where functions keep getting updated based on other functions.",
            )
        )

    def decompile_function(self, function=None):
        decompilation_result = self.decompiler.decompileFunction(function, 30, monitor)
        if decompilation_result and decompilation_result.decompileCompleted():
            return decompilation_result.getDecompiledFunction().getC()

        return None

    def init_function_queue(self):
        return deque(self.function_manager.getFunctions(True))

    def rename_function(self, function=None, decompiled_output=""):
        new_name = self.ai.query(query=decompiled_output)
        function.setName(new_name, SourceType.USER_DEFINED)

    def rename_functions(self):
        function_queue = self.init_function_queue()
        changed_functions = set()
        rename_count = defaultdict(int)

        while function_queue:
            function = function_queue.popleft()

            if rename_count[function] >= self.max_renames:
                continue

            decompiled_output = self.decompile_function(function=function)
            if decompiled_output:
                old_name = function.getName()
                self.rename_function(
                    function=function, decompiled_output=decompiled_output
                )
                new_name = function.getName()

                if old_name != new_name:
                    print(f"{old_name} -> {new_name}")
                    changed_functions.add(function)
                    rename_count[function] += 1
                    calling_functions = self.update_calling_functions(
                        function, changed_functions
                    )
                    function_queue.extend(calling_functions)

    def update_calling_functions(self, function=None, changed_functions=None):
        calling_functions = set()
        references = self.reference_manager.getReferencesTo(function.getEntryPoint())
        for reference in references:
            calling_function = self.function_manager.getFunctionContaining(
                reference.getFromAddress()
            )
            if calling_function and calling_function not in changed_functions:
                calling_functions.add(calling_function)

        return calling_functions

    @property
    def system_prompt(self):
        system_prompt = """
        You are a reverse engineer using ghidra.
        You will receive the decompiler output from ghidra for a function.
        You are to provide a meaninful function name based on the decompiler's output.
        You should only provide the function name with no extra information, commentary, or punctuation.
        Do not include any invalid characters (all characters should be acceptable as function names in c)
        """

        return system_prompt


class FunctionSignatureGenerator:
    def __init__(
        self,
        current_program=None,
        listing=None,
        function_manager=None,
        decompiler=None,
        reference_manager=None,
    ):
        self.current_program = current_program
        self.listing = listing
        self.function_manager = function_manager
        self.decompiler = decompiler
        self.reference_manager = reference_manager

        self.ai = AI(system_prompt=self.system_prompt)

        self.max_regenerations = int(
            askString(
                "Max Number Of Times To Regenerate Function Signatures (int)",
                "As function signatures are generated, other functions may change. "
                "This is the maximum number of times to update a function's signature "
                "before skipping. This avoids an infinite loop where functions keep getting "
                "updated based on other functions.",
            )
        )

    def generate_function_signature(self):
        pass

    def generate_function_signatures(self):
        pass

    @property
    def system_prompt(self):
        system_prompt = """
        You are a reverse engineer using ghidra.
        You will receive the decompiler output from ghidra for a function.
        You should only provide the function signature with no extra information, commentary, or punctuation.
        """

        return system_prompt


class FunctionCommenter:
    def __init__(
        self,
        current_program=None,
        listing=None,
        function_manager=None,
        decompiler=None,
        reference_manager=None,
    ):
        self.current_program = current_program
        self.listing = listing
        self.function_manager = function_manager
        self.decompiler = decompiler
        self.reference_manager = reference_manager

        self.ai = AI(system_prompt=self.system_prompt)

    def comment_function(self, decompiler=None, function=None):
        print(f"Commenting {function.getName()}...")
        decompile_results = self.decompiler.decompileFunction(function, 30, monitor)
        if decompile_results and decompile_results.decompileCompleted():
            decompiled_code = decompile_results.getDecompiledFunction().getC()
            code_unit = self.listing.getCodeUnitAt(function.getEntryPoint())
            if code_unit:
                comment = self.ai.query(decompiler_output=decompiled_code)
                code_unit.setComment(CodeUnit.PLATE_COMMENT, comment)
        else:
            print(f"Decompile of {function.getName()} took too long, not commenting...")

    def comment_functions(self):
        functions = list(function_manager.getFunctions(True))
        functions.sort(key=lambda f: f.getBody().getNumAddresses())
        for function in functions:
            self.comment_function(function=function)

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
          - DESCRIPTION
            - A description of the function as a whole
          - FUNCTIONALITY
            - A detailed explanation of what the function is doing
          - RETURN
            - A sorted list of return values and their meaning
        Example of what a comment should look like:
        ```
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

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)

    reference_manager = current_program.getReferenceManager()

    rename_functions = askYesNo(
        "Rename Functions?",
        "Should functions be renamed based on the function's decompiled output?",
    )

    generate_signatures = askYesNo(
        "Generate Function Signatures?",
        "Should function signatures be applied based on the function's decompiled output?",
    )

    comment_functions = askYesNo(
        "Comment Functions?",
        "Should functions be commented based on the function's decompiled output?",
    )

    if rename_functions:
        function_renamer = FunctionRenamer(
            current_program=current_program,
            listing=listing,
            function_manager=function_manager,
            decompiler=decompiler,
            reference_manager=reference_manager,
        )

    if generate_signatures:
        function_signature_generator = FunctionSignatureGenerator(
            current_program=current_program,
            listing=listing,
            function_manager=function_manager,
            decompiler=decompiler,
            reference_manager=reference_manager,
        )

    if comment_functions:
        function_commenter = FunctionCommenter(
            current_program=current_program,
            listing=listing,
            function_manager=function_manager,
            decompiler=decompiler,
            reference_manager=reference_manager,
        )

    if rename_functions:
        function_renamer.rename_functions()

    if generate_signatures:
        function_signature_generator.generate_function_signatures()

    if comment_functions:
        function_commenter.comment_functions()
