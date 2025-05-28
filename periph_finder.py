# @runtime PyGhidra
from enum import Enum
from typing import Optional, Tuple


class AccessType(Enum):
    R = 1
    W = 2
    X = 4
    RW = R | W
    RX = R | X
    WX = W | X
    RWX = R | W | X

    def __add__(self, other) -> Optional["AccessType"]:
        if not isinstance(other, AccessType):
            raise TypeError(
                f"Unsupported operand type for +: 'AccessType' and '{type(other).__name__}'"
            )

        val = self.value | other.value
        for access_type in AccessType:
            if access_type.value == val:
                return access_type

    def __repr__(self) -> str:
        return self.name


class InvMemRef:
    def __init__(self, ref: Optional["Instruction"] = None) -> None:  # type: ignore
        self.src_int = int(str(ref.getFromAddress()), 16)
        self.dst_int = int(str(ref.getToAddress()), 16)
        access_str = str(ref.getReferenceType())

        self.access = AccessType.R
        if access_str == "WRITE":
            self.access = AccessType.W
        if access_str == "EXECUTE":
            self.access = AccessType.X

    @property
    def src_hex(self) -> str:
        return f"0x{format(self.src_int, '08X')}"

    @property
    def dst_hex(self) -> str:
        return f"0x{format(self.dst_int, '08X')}"

    @property
    def to_dict(self) -> dict:
        return {
            "src_int": self.src_int,
            "src_hex": self.src_hex,
            "dst_int": self.dst_int,
            "dst_hex": self.dst_hex,
            "access": self.access,
        }


class MemRegion:
    def __init__(self, start: int = 0, end: int = 0, access=AccessType.R):
        self.start_int = start
        self.end_int = end
        self.access = access

    @property
    def start_hex(self) -> str:
        return f"0x{format(self.start_int, '08X')}"

    @property
    def end_hex(self) -> str:
        return f"0x{format(self.end_int, '08X')}"

    @property
    def to_dict(self) -> dict:
        return {
            "start_int": self.start_int,
            "start_hex": self.start_hex,
            "end_int": self.end_int,
            "end_hex": self.end_hex,
            "access": self.access.value,
        }

    @property
    def len_int(self) -> int:
        return int(self.end_int - self.start_int)

    @property
    def len_hex(self) -> str:
        return f"0x{format(self.len_int, 'X')}"


def parse_input(input: Tuple[int, str] = None) -> int:
    try:
        input = int(input, 16)  # Hex
        return input
    except ValueError:
        try:
            input = int(input)
            return input
        except ValueError:
            raise ValueError(f"Unable to convert '{input}' to hex or int")


def get_params() -> Tuple[int, int, int]:
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
    regs = []
    for addr_hex, ref in inv_refs.items():
        in_region = False

        for reg in regs:
            if not in_region:
                if reg.start_int <= ref.dst_int and ref.dst_int <= reg.end_int:
                    reg.access = reg.access + ref.access
                    in_region = True
                    break

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

        if not in_region:
            regs.append(
                MemRegion(start=ref.dst_int, end=ref.dst_int + 1, access=ref.access)
            )

    return regs


def sort_regs(regs: list = []) -> list:
    _regs = []
    for reg in regs:
        _regs.append((reg.start_hex, reg))
    regs = sorted(_regs, key=lambda x: x[0])

    return regs


# def combine_regs(regs: list=[], reg_prox: int=0) -> list:
#     comb_regs = []
#     curr_reg = regs[0][1]

#     for reg in regs[1:]:
#         reg = reg[1]

#         if reg.start_int - curr_reg.end_int <= reg_prox:
#             comb_regs.append(
#                 MemRegion(
#                     start=curr_reg.start_int,
#                     end=reg.end_int,
#                     access=(reg.access + curr_reg.access),
#                 )
#             )
#         else:
#             comb_regs.append(reg)

#     return comb_regs


def combine_regs(regs: list = [], reg_prox: int = 0) -> list:
    if len(regs) <= 1:
        return regs

    curr_reg = regs[0][1]
    next_reg = regs[1][1]

    if next_reg.start_int - curr_reg.end_int <= reg_prox:
        combined_reg = MemRegion(
            start=curr_reg.start_int,
            end=next_reg.end_int,
            access=(next_reg.access + curr_reg.access),
        )
        new_regs = [(regs[0][0], combined_reg)] + combine_regs(regs[2:], reg_prox)
        return new_regs
    else:
        return [regs[0]] + combine_regs(regs[1:], reg_prox)


def align_regs(regs: list = [], align: int = 0) -> None:
    for reg in regs:
        reg = reg[1]
        reg.start_int = reg.start_int // align * align
        reg.end_int = ((reg.end_int + align) // align) * align


def print_regs(regs: list = []) -> None:
    print(f"Start, End, Length, Access")
    for reg in regs:
        reg = reg[1]
        print(f"{reg.start_hex}, {reg.end_hex}, {reg.len_hex}, {reg.access}")


def create_mem_regs(regs: list = []) -> None:
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

            if reg.access in [
                AccessType.R,
                AccessType.RW,
                AccessType.RX,
                AccessType.RWX,
            ]:
                mem.setRead(True)

            if reg.access in [
                AccessType.W,
                AccessType.RW,
                AccessType.WX,
                AccessType.RWX,
            ]:
                mem.setWrite(True)

            if reg.access in [
                AccessType.X,
                AccessType.RX,
                AccessType.WX,
                AccessType.RWX,
            ]:
                mem.setVolatile(True)


if __name__ == "__main__":
    inv_refs = get_inv_refs()
    ref_prox, reg_prox, align = get_params()
    regs = gen_regs(inv_refs=inv_refs, ref_prox=ref_prox)
    regs = sort_regs(regs=regs)
    regs = combine_regs(regs=regs, reg_prox=reg_prox)
    align_regs(regs=regs, align=align)
    print_regs(regs=regs)
    create_mem_regs(regs=regs)
