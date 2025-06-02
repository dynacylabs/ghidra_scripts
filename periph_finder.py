# @runtime PyGhidra
from enum import Enum
from typing import Optional, Tuple


class AccessType(Enum):
    """
    AccessType is an enumeration representing different types of access permissions using bitwise flags.

    Members:
        R   : Read access.
        W   : Write access.
        X   : Execute access.
        RW  : Read and Write access.
        RX  : Read and Execute access.
        WX  : Write and Execute access.
        RWX : Read, Write, and Execute access.

    Methods:
        __add__(self, other)
            Combine two AccessType values using bitwise OR to produce a new AccessType representing the union of permissions.
            Raises TypeError if 'other' is not an AccessType.
            Returns the corresponding AccessType or None if no match exists.

        __repr__(self)
            Returns the string representation (name) of the AccessType member.
    R = 1
    W = 2
    X = 4
    RW = R | W
    RX = R | X
    WX = W | X
    RWX = R | W | X
    """

    def __add__(self, other) -> Optional["AccessType"]:
        """
        Combine two AccessType values using bitwise OR.

        Args:
            other (AccessType): Another AccessType to combine with self.

        Returns:
            Optional[AccessType]: The AccessType representing the combined permissions,
                                  or None if no matching AccessType exists.

        Raises:
            TypeError: If 'other' is not an AccessType.

        Example:
            AccessType.R + AccessType.W -> AccessType.RW
        """
        if not isinstance(other, AccessType):
            raise TypeError(
                f"Unsupported operand type for +: 'AccessType' and '{type(other).__name__}'"
            )

        # Combine the values using bitwise OR
        val = self.value | other.value

        # Find and return the matching AccessType enum member
        for access_type in AccessType:
            if access_type.value == val:
                return access_type

    def __repr__(self) -> str:
        """
        Return the string representation of the AccessType enum member.

        Returns:
            str: The name of the AccessType (e.g., 'R', 'RW', etc.).
        """
        return self.name


class InvMemRef:
    """
    InvMemRef represents an inverse memory reference extracted from a Ghidra Instruction object.

    This class provides a convenient way to access the source and destination addresses of a memory reference,
    as well as the type of access (read, write, or execute). It offers both integer and hexadecimal representations
    of the addresses and can serialize its data as a dictionary.

        src_int (int): Source address as an integer.
        dst_int (int): Destination address as an integer.
        access (AccessType): Type of access (R for read, W for write, X for execute).

    Properties:
        src_hex (str): Source address as a zero-padded 8-digit hexadecimal string (e.g., '0x1234ABCD').
        dst_hex (str): Destination address as a zero-padded 8-digit hexadecimal string.
        to_dict (dict): Dictionary representation of the object, including both integer and hexadecimal addresses and access type.

        ref (Instruction, optional): Ghidra Instruction reference containing source and destination addresses and access type.

    Example:
        inv_ref = InvMemRef(ref)
        print(inv_ref.src_hex)  # e.g., '0x08001234'
        print(inv_ref.to_dict)
    """

    def __init__(self, ref: Optional["Instruction"] = None) -> None:  # type: ignore
        """
        Initialize an InvMemRef object from a Ghidra Instruction reference.

        Args:
            ref (Instruction, optional): The instruction reference containing source and destination addresses,
                                         and the type of access (READ, WRITE, EXECUTE).

        Attributes:
            src_int (int): Source address as integer.
            dst_int (int): Destination address as integer.
            access (AccessType): Type of access (R, W, or X) based on the reference type.
        """
        # Convert source address to int
        self.src_int = int(str(ref.getFromAddress()), 16)

        # Convert destination address to int
        self.dst_int = int(str(ref.getToAddress()), 16)

        # Get access type as string
        access_str = str(ref.getReferenceType())

        # Default to Read access
        self.access = AccessType.R
        if access_str == "WRITE":
            # Set to Write access if applicable
            self.access = AccessType.W
        if access_str == "EXECUTE":
            # Set to Execute access if applicable
            self.access = AccessType.X

    @property
    def src_hex(self) -> str:
        """
        Returns the source address as a zero-padded 8-digit hexadecimal string.

        Returns:
            str: Source address in the format '0xXXXXXXXX'.
        """
        return f"0x{format(self.src_int, '08X')}"

    @property
    def dst_hex(self) -> str:
        """
        Returns the destination address as a zero-padded 8-digit hexadecimal string.

        Returns:
            str: Destination address in the format '0xXXXXXXXX'.
        """
        return f"0x{format(self.dst_int, '08X')}"

    @property
    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the InvMemRef object, including both integer and hexadecimal
        forms of the source and destination addresses, as well as the access type.

        Returns:
            dict: Dictionary with keys 'src_int', 'src_hex', 'dst_int', 'dst_hex', and 'access'.
        """
        return {
            "src_int": self.src_int,
            "src_hex": self.src_hex,
            "dst_int": self.dst_int,
            "dst_hex": self.dst_hex,
            "access": self.access,
        }


class MemRegion:
    """
    MemRegion represents a region of memory with a start and end address, and associated access permissions.

    Properties:
        start_hex (str): Start address as a zero-padded 8-digit hexadecimal string (e.g., '0x00000000').
        end_hex (str): End address as a zero-padded 8-digit hexadecimal string (e.g., '0x00000000').
        to_dict (dict): Dictionary representation of the region, including both integer and hexadecimal addresses and access type.
        len_int (int): Length of the memory region as an integer (number of addresses).
        len_hex (str): Length of the memory region as a hexadecimal string (not zero-padded).
    """

    def __init__(self, start: int = 0, end: int = 0, access=AccessType.R):
        """
        Initialize a MemRegion object representing a memory region.

        Args:
            start (int, optional): The starting address of the memory region (default is 0).
            end (int, optional): The ending address of the memory region (default is 0).
            access (AccessType, optional): The access permissions for the region (default is AccessType.R).

        Attributes:
            start_int (int): Start address as integer.
            end_int (int): End address as integer.
            access (AccessType): Access permissions for the region.
        """
        self.start_int = start
        self.end_int = end
        self.access = access

    @property
    def start_hex(self) -> str:
        """
        Returns the start address of the memory region as a zero-padded 8-digit hexadecimal string.

        Returns:
            str: Start address in the format '0xXXXXXXXX'.
        """
        return f"0x{format(self.start_int, '08X')}"

    @property
    def end_hex(self) -> str:
        """
        Returns the end address of the memory region as a zero-padded 8-digit hexadecimal string.

        Returns:
            str: End address in the format '0xXXXXXXXX'.
        """
        return f"0x{format(self.end_int, '08X')}"

    @property
    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the MemRegion object, including both integer and hexadecimal
        forms of the start and end addresses, as well as the access type.

        Returns:
            dict: Dictionary with keys 'start_int', 'start_hex', 'end_int', 'end_hex', and 'access'.
        """
        return {
            "start_int": self.start_int,
            "start_hex": self.start_hex,
            "end_int": self.end_int,
            "end_hex": self.end_hex,
            "access": self.access.value,
        }

    @property
    def len_int(self) -> int:
        """
        Returns the length of the memory region as an integer (number of addresses).

        Returns:
            int: The difference between end_int and start_int.
        """
        return int(self.end_int - self.start_int)

    @property
    def len_hex(self) -> str:
        """
        Returns the length of the memory region as a hexadecimal string.

        Returns:
            str: Length of the region in the format '0xX...' (not zero-padded).
        """
        return f"0x{format(self.len_int, 'X')}"


def parse_input(input: Tuple[int, str] = None) -> int:
    """
    Attempts to parse the input as a hexadecimal or decimal integer.

    Args:
        input (Tuple[int, str], optional): The input value to parse, typically a string representing a number.

    Returns:
        int: The parsed integer value.

    Raises:
        ValueError: If the input cannot be converted to either a hexadecimal or decimal integer.
    """
    try:
        # Try to parse as hexadecimal
        input = int(input, 16)

        return input
    except ValueError:
        try:
            # Try to parse as decimal
            input = int(input)

            return input
        except ValueError:
            raise ValueError(f"Unable to convert '{input}' to hex or int")


def get_params() -> Tuple[int, int, int]:
    """
    Prompt the user for memory region parameters and parse them as integers.

    Asks the user for:
        - Reference Proximity: Distance between references to consider part of the same memory region.
        - Region Proximity: Distance between memory regions to consider part of the same memory region.
        - Region Alignment: Alignment value for aligning memory regions.

    Returns:
        Tuple[int, int, int]: A tuple containing (ref_prox, reg_prox, align) as integers.
    """
    ref_prox = parse_input(
        askString(
            "Reference Proximity",
            "Distance between references to consider part of the same memory region.",
        )
    )

    reg_prox = parse_input(
        askString(
            "Region Proximity",
            "Distance between memory regions to consider part of the same memory region.",
        )
    )

    align = parse_input(
        askString("Region Alignment", "Alignment value for aligning memory regions.")
    )

    return ref_prox, reg_prox, align


def get_inv_refs() -> list:
    """
    Collects all inverse memory references from instructions in the current Ghidra program.

    Iterates over all instructions, extracts references that point outside the current memory
    and are not stack addresses, and creates InvMemRef objects for them. If multiple references
    point to the same destination, their access types are combined.

    Returns:
        dict: A dictionary mapping destination hex addresses to InvMemRef objects.
    """
    instr_iter = getCurrentProgram().getListing().getInstructions(True)

    _refs = {}
    while instr_iter.hasNext():
        instr = instr_iter.next()
        refs = instr.getReferencesFrom()

        for ref in refs:
            dst = ref.getToAddress()
            if (
                not getCurrentProgram().getMemory().contains(dst)
                and not dst.isStackAddress()
            ):
                ref = InvMemRef(ref)
                if ref.dst_hex in _refs.keys():
                    _refs[ref.dst_hex].access = _refs[ref.dst_hex].access + ref.access
                else:
                    _refs[ref.dst_hex] = ref

    return _refs


def gen_regs(inv_refs: list = [], ref_prox: int = 0) -> list:
    """
    Generate memory regions from inverse memory references.

    Iterates through all inverse memory references and groups them into memory regions based on proximity.
    If a reference falls within or near an existing region (within ref_prox), it extends the region and
    combines access permissions. Otherwise, it creates a new region.

    Args:
        inv_refs (list, optional): Dictionary of InvMemRef objects keyed by destination hex address.
        ref_prox (int, optional): Maximum distance between references to be considered part of the same region.

    Returns:
        list: List of MemRegion objects representing grouped memory regions.
    """
    regs = []
    for addr_hex, ref in inv_refs.items():
        in_region = False

        # Check if the reference falls within any existing region
        for reg in regs:
            if not in_region:
                if reg.start_int <= ref.dst_int and ref.dst_int <= reg.end_int:
                    reg.access = reg.access + ref.access
                    in_region = True
                    break

        # Check if the reference is close enough to extend an existing region
        if not in_region:
            for reg in regs:
                if ref.dst_int < reg.start_int:
                    if reg.start_int - ref.dst_int <= ref_prox:
                        reg.start_int = ref.dst_int
                        reg.access = reg.access + ref.access
                        in_region = True
                        break
                elif ref.dst_int > reg.end_int:
                    if ref.dst_int - reg.end_int <= ref_prox:
                        reg.end_int = ref.dst_int
                        reg.access = reg.access + ref.access
                        in_region = True
                        break

        # If not in any region, create a new region for this reference
        if not in_region:
            regs.append(
                MemRegion(start=ref.dst_int, end=ref.dst_int + 1, access=ref.access)
            )

    return regs


def sort_regs(regs: list = []) -> list:
    """
    Sorts a list of MemRegion objects by their start address (hexadecimal).

    Args:
        regs (list, optional): List of MemRegion objects to sort.

    Returns:
        list: List of tuples (start_hex, MemRegion), sorted by start_hex.
    """
    _regs = []
    for reg in regs:
        _regs.append((reg.start_hex, reg))
    regs = sorted(_regs, key=lambda x: x[0])

    return regs


def combine_regs(regs: list = [], reg_prox: int = 0) -> list:
    """
    Combines adjacent or nearby memory regions if they are within a specified proximity.

    Iterates through a sorted list of MemRegion objects (as tuples with start_hex) and merges
    consecutive regions if the gap between them is less than or equal to reg_prox. The access
    permissions of merged regions are combined.

    Args:
        regs (list, optional): List of tuples (start_hex, MemRegion) to combine.
        reg_prox (int, optional): Maximum allowed gap between regions to merge them.

    Returns:
        list: List of tuples (start_hex, MemRegion), with combined regions where applicable.
    """
    if len(regs) <= 1:
        return regs

    curr_reg = regs[0][1]
    next_reg = regs[1][1]

    if next_reg.start_int - curr_reg.end_int <= reg_prox:
        # Merge the two regions and combine their access permissions
        combined_reg = MemRegion(
            start=curr_reg.start_int,
            end=next_reg.end_int,
            access=(next_reg.access + curr_reg.access),
        )
        new_regs = [(regs[0][0], combined_reg)] + combine_regs(regs[2:], reg_prox)
        return new_regs
    else:
        # Keep the current region and continue combining the rest
        return [regs[0]] + combine_regs(regs[1:], reg_prox)


def align_regs(regs: list = [], align: int = 0) -> None:
    """
    Aligns the start and end addresses of each memory region in the list to the specified alignment.

    For each region, the start address is rounded down to the nearest alignment boundary,
    and the end address is rounded up to the next alignment boundary.

    Args:
        regs (list, optional): List of tuples (start_hex, MemRegion) to align.
        align (int, optional): Alignment value to use for rounding addresses.
    """
    for reg in regs:
        reg = reg[1]
        reg.start_int = reg.start_int // align * align
        reg.end_int = ((reg.end_int + align) // align) * align


def print_regs(regs: list = []) -> None:
    """
    Prints a summary table of memory regions.

    Iterates through the list of memory regions and prints their start address, end address,
    length, and access permissions in a comma-separated format.

    Args:
        regs (list, optional): List of tuples (start_hex, MemRegion) to print.
    """
    print(f"Start, End, Length, Access")
    for reg in regs:
        reg = reg[1]
        print(f"{reg.start_hex}, {reg.end_hex}, {reg.len_hex}, {reg.access}")


def create_mem_regs(regs: list = []) -> None:
    """
    Optionally creates uninitialized memory blocks in Ghidra for each memory region.

    Prompts the user to confirm creation. For each region, creates an uninitialized memory block
    with the appropriate access permissions (read, write, volatile/execute) based on the region's
    access type.

    Args:
        regs (list, optional): List of tuples (start_hex, MemRegion) to create as memory blocks.
    """
    create = askYesNo(
        "Create memory regions?",
        "Review the console for memory regions to be completed.",
    )

    if create:
        space = getCurrentProgram().getAddressFactory().getDefaultAddressSpace()

        for i, reg in enumerate(regs):
            reg = reg[1]
            mem = getCurrentProgram().memory.createUninitializedBlock(
                f"PERIPH?{i}", space.getAddress(reg.start_int), reg.len_int, False
            )

            # Set read permission if applicable
            if reg.access in [
                AccessType.R,
                AccessType.RW,
                AccessType.RX,
                AccessType.RWX,
            ]:
                mem.setRead(True)

            # Set write permission if applicable
            if reg.access in [
                AccessType.W,
                AccessType.RW,
                AccessType.WX,
                AccessType.RWX,
            ]:
                mem.setWrite(True)

            # Set volatile (execute) permission if applicable
            if reg.access in [
                AccessType.X,
                AccessType.RX,
                AccessType.WX,
                AccessType.RWX,
            ]:
                mem.setVolatile(True)


if __name__ == "__main__":
    if __name__ == "__main__":
        # Collect all inverse memory references from the current Ghidra program
        inv_refs = get_inv_refs()

        # Prompt the user for proximity and alignment parameters
        ref_prox, reg_prox, align = get_params()

        # Generate memory regions from the collected references and user parameters
        regs = gen_regs(inv_refs=inv_refs, ref_prox=ref_prox)

        # Sort the memory regions by their start address
        regs = sort_regs(regs=regs)

        # Combine adjacent or nearby regions based on region proximity
        regs = combine_regs(regs=regs, reg_prox=reg_prox)

        # Align the start and end addresses of each region to the specified alignment
        align_regs(regs=regs, align=align)

        # Print a summary table of the memory regions
        print_regs(regs=regs)

        # Optionally create uninitialized memory blocks in Ghidra for each region
        create_mem_regs(regs=regs)
