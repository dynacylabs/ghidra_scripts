# @runtime PyGhidra

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil

func = getFunctionContaining(currentAddress)
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
result = decompiler.decompileFunction(func, 60, monitor)
highFunc = result.getHighFunction()
local_symbols = highFunc.getLocalSymbolMap().getSymbols()
highFuncDBUtil = HighFunctionDBUtil()
for i, v in enumerate(local_symbols):
    highFuncDBUtil.updateDBVariable(v, f"test{i}", v.getDataType(), SourceType.USER_DEFINED)
    highFuncDBUtil.commitParamsToDatabase(highFunc, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)

local_symbols = highFunc.getLocalSymbolMap().getSymbols()
