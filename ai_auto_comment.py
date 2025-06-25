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
    """
    AI is a class designed to generate C-style docstring comments for decompiled functions
    using an Azure OpenAI language model. It sets up the necessary environment variables for
    API access, constructs a processing chain for prompt generation and response parsing, and
    provides a method to generate comments based on decompiler output.

    Attributes:
            chain: The composed processing chain used to interact with the language model.

    Methods:
            __init__():
                    Initializes the AI class, sets environment variables for Azure OpenAI credentials,
                    and creates the processing chain for generating comments.

            get_comment_for_code(decompiler_output=""):
                    Generates a C-style docstring comment for the provided decompiler output using
                    the language model chain.

            _get_chain():
                    Constructs and returns the processing chain, which includes prompt formatting,
                    language model invocation, and output parsing.

            system_prompt (property):
                    Returns the system prompt string containing detailed instructions and an example
                    for generating C docstring comments for decompiled functions.
    """

    def __init__(self):
        """
        Initializes the class by setting environment variables for Azure OpenAI API credentials
        and creating the processing chain used for further operations.
        """
        # Set Azure OpenAI API credentials as environment variables
        os.environ["AZURE_OPENAI_API_KEY"] = ""
        os.environ["AZURE_OPENAI_ENDPOINT"] = ""

        # Initialize the processing chain for generating comments
        self.chain = self._get_chain()

    def get_comment_for_code(self, decompiler_output=""):
        """
        Generates a comment for the provided decompiler output using the language model chain.

        Args:
                decompiler_output (str): The output from the decompiler to be commented. Defaults to an empty string.

        Returns:
                str: The generated comment for the given decompiler output.
        """
        return self.chain.invoke({"input": decompiler_output})

    def _get_chain(self):
        """
        Creates and returns a processing chain for handling chat-based language model interactions.

        This method initializes an HTTP client with HTTP/2 support and disabled SSL verification,
        sets up an AzureChatOpenAI language model with the specified deployment and API version,
        and constructs a prompt template using system and user messages. The chain is composed of
        the prompt template, the language model, and a string output parser, allowing for streamlined
        input processing and response generation.

        Returns:
                Runnable: A composed chain that processes input through the prompt, language model, and output parser.
        """
        # Create an HTTPX client with HTTP/2 enabled and SSL verification disabled.
        httpx_client = httpx.Client(http2=True, verify=False)

        # Initialize the AzureChatOpenAI language model with the specified deployment,
        # using the custom HTTP client and API version.
        llm = AzureChatOpenAI(
            azure_deployment="gpt-4",
            http_client=httpx_client,
            api_version="2024-02-01",
        )

        # Create a parser to extract the string output from the language model's response.
        parse_string = StrOutputParser()

        # Build a chat prompt template using the system prompt and user input.
        prompt = ChatPromptTemplate.from_messages(
            [("system", self.system_prompt), ("user", "{input}")]
        )

        # Compose the processing chain: prompt -> language model -> output parser.
        chain = prompt | llm | parse_string

        # Return the composed chain for use in generating comments.
        return chain

    @property
    def system_prompt(self):
        """
        This function constructs and returns a multi-line string that serves as a
        system prompt for an AI tasked with generating C-style docstring comments
        for decompiled functions in Ghidra. The prompt provides explicit
        instructions and an example format for the AI to follow when commenting
        on reverse-engineered code.

        - Defines a multi-line string containing detailed instructions for the AI,
          specifying the required comment format, indentation, word wrapping, and
          content structure.
        - Includes an example comment illustrating the expected output, covering
          sections such as FUNCTION_NAME, DESCRIPTION, FUNCTIONALITY, and RETURN.
        - Emphasizes that the AI should only output the comment without any
          additional information or commentary.
        - Returns the constructed prompt string for use elsewhere in the application.

        - str: The system prompt string containing instructions and an example for
                   generating C docstring comments for decompiled functions.
        """
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
    # Get the current program loaded in Ghidra
    current_program = getCurrentProgram()
    # Get the listing (code units) for the current program
    listing = current_program.getListing()
    # Get the function manager to access all functions in the program
    function_manager = current_program.getFunctionManager()

    # Instantiate the AI class for generating comments
    ai = AI()

    # Set up the decompiler interface and open the current program
    decompiler = DecompInterface()
    decompiler.openProgram(current_program)

    # Get a list of all functions in the program, sorted by size (number of addresses)
    functions = list(function_manager.getFunctions(True))
    functions.sort(key=lambda f: f.getBody().getNumAddresses())

    # Iterate over each function in the program
    for function in functions:
        original_function_name = function.getName()
        # Attempt to decompile the function (timeout after 30 seconds)
        decompile_results = decompiler.decompileFunction(function, 30, monitor)
        if decompile_results and decompile_results.decompileCompleted():
            # Get the decompiled C code for the function
            decompiled_code = decompile_results.getDecompiledFunction().getC()
            # Get the code unit at the function's entry point
            code_unit = listing.getCodeUnitAt(function.getEntryPoint())
            if code_unit:
                # Generate a comment for the decompiled code using the AI model
                comment = ai.get_comment_for_code(decompiler_output=decompiled_code)
                # Set the generated comment as a plate comment for the code unit
                code_unit.setComment(CodeUnit.PLATE_COMMENT, comment)

                # Optionally, rename the function based on the FUNCTION_NAME in the comment
                comment_lines = comment.splitlines()
                for comment_line in comment_lines:
                    if comment_line.startswith("FUNCTION_NAME"):
                        comment_line_parts = comment_line.split()
                        if len(comment_line_parts) > 1:
                            new_function_name = comment_line_parts[1]
                            print(f"{original_function_name} -> {new_function_name}")
                            # Set the new function name as user-defined
                            function.setName(new_function_name, SourceType.USER_DEFINED)
                            break
        else:
            # If decompilation failed or timed out, print a message and skip commenting
            print(
                f"Decompile of {original_function_name} took too long, not commenting..."
            )
    # Clean up and dispose of the
