import argparse
import re

arguments_parser = argparse.ArgumentParser(description='Assemble a file.')
arguments_parser.add_argument('filename', type=str, help='filename of the assembly file')

args = arguments_parser.parse_args()

filename = args.filename

with open(filename) as f:
    contents = f.readlines()

REGISTER_MAP = {
    "R0" : 0,
    "R1" : 1,
    "R2" : 2,
    "R3" : 3,
    "R4" : 4,
    "R5" : 5,
    "R6" : 6,
    "R7" : 7,
    "R8" : 8,
    "R9" : 9,
    "R10" : 10,
    "R11" : 11,
    "R12" : 12,
    "R13" : 13,
    "R14" : 14,
    "R15" : 15,
    "A0" : 0,
    "A1": 1,
    "A2": 2,
    "A3": 3,
    "RV": 3,
    "T0": 4,
    "T1": 5,
    "S0": 6,
    "S1": 7,
    "S2": 8,
    "GP": 12,
    "FP": 13,
    "SP": 14,
    "RA": 15,
}

OPCODES_R_R_R = {
    "ADD":      0b00000000,
    "SUB":      0b00000001,
    "AND":      0b00000100,
    "OR":       0b00000101,
    "XOR":      0b00000110,
    "NAND":     0b00001100,
    "NOR":      0b00001101,
    "NXOR":     0b00001110,

    "F":        0b00100000,
    "EQ":       0b00100001,
    "LT":       0b00100010,
    "LTE":      0b00100011,
    "T":        0b00101000,
    "NE":       0b00101001,
    "GTE":      0b00101010,
    "GT":       0b00101011,
}

OPCODES_R_R_NUM = {
    "ADDI":     0b10000000,
    "SUBI":     0b10000001,
    "ANDI":     0b10000100,
    "ORI":      0b10000101,
    "XORI":     0b10000110,
    "NANDI":    0b10001100,
    "NORI":     0b10001101,
    "XNORI":    0b10001110,

    "FI":       0b10100000,
    "EQI":      0b10100001,
    "LTI":      0b10100010,
    "LTEI":     0b10100011,
    "TI":       0b10101000,
    "NEI":      0b10101001,
    "GTEI":     0b10101010,
    "GTI":      0b10101011,

}

OPCODES_R_NUM = {
    "MVHI":     0b10001011,
}

OPCODES_R_NUM_R = {
    "LW":       0b10010000,
}

OPCODES_R_RNUM_R = {
    "SW":       0b01010000,
}

OPCODES_R_R_WNUM = {
    "BF":       0b01100000,
    "BEQ":      0b01100001,
    "BLT":      0b01100010,
    "BLTE":     0b01100011,

    "BT":       0b01101000,
    "BNE":      0b01101001,
    "BGT":      0b01101011,
    "BGTE":     0b01101010,
}

OPCODES_R_WNUM = {
    "BEQZ":     0b01100101,
    "BLQZ":     0b01100110,
    "BLQEZ":    0b01100111,

    "BNEZ":     0b01101101,
    "BGTEZ":    0b01101110,
    "BGTZ":     0b01101111,
}

OPCODES_R_WNUM_R = {
    "JAL":      0b10110000,
}

OPCODES_MAP = dict(OPCODES_R_R_R.items() +
    OPCODES_R_R_NUM.items() +
    OPCODES_R_NUM.items() +
    OPCODES_R_NUM_R.items() +
    OPCODES_R_RNUM_R.items() +
    OPCODES_R_WNUM.items() +
    OPCODES_R_WNUM_R.items() +
    OPCODES_R_R_WNUM.items()
)

def normalizeContents(contents):
    output = []
    for raw in contents:
        uncommented = re.sub(";.*", "", raw,flags=re.DOTALL).strip()
        uniform_spaced = re.sub("\s+", " ", uncommented)
        capitalized = uniform_spaced.upper()
        normalized = capitalized
        if len(normalized):
            output.append(normalized)
    return output

def reifyFakeOpcodes(instruction):
    instructions = []
    opcode = instruction[0]
    if opcode == "BR":
        instructions.append(("BEQ", "R6", "R6", instruction[1]))
    elif opcode == "NOT":
        instructions.append(("NAND", instruction[1], instruction[2], instruction[2]))
    elif opcode == "BLE":
        instructions.append(("LTE", "R6", instruction[1], instruction[2]))
        instructions.append(("BNEZ", "R6", instruction[3]))
    elif opcode == "BGE":
        instructions.append(("GTE", "R6", instruction[1], instruction[2]))
        instructions.append(("BNEZ", "R6", instruction[3]))
    elif opcode == "CALL":
        instructions.append(("JAL", "RA", instruction[1]))
    elif opcode == "RET":
        instructions.append(("JAL", "R9", "0(RA)"))
    elif opcode == "JMP":
        instructions.append(("JAL", "R9", instruction[1]))
    else:
        instructions.append(instruction) 
    return instructions

def annotateAddress(contents):
    current_address = 0
    symbol_table = {}
    output = []
    for current_instruction in contents:
        if current_instruction[-1] == ":":
            symbol_table[current_instruction[:-1]] = current_address
        elif current_instruction[:5] == ".ORIG":
            current_address = int(current_instruction[5:], 0)
        elif current_instruction[:5] == ".NAME":
            name, value = map(str.strip, current_instruction[6:].split("="))
            symbol_table[name] = int(value, 0)
        else:
            if current_instruction[:5] == ".WORD":
                output.append((current_address, int(current_instruction[6:], 0)))
            else:
                instruction = map(str.strip, current_instruction.split(","))
                instruction_tuple = tuple(instruction[0].split(" ")) + tuple(instruction[1:]) 
                instruction_tuples = reifyFakeOpcodes(instruction_tuple)
                for i in range(len(instruction_tuples) - 1):
                    output.append((current_address, instruction_tuples[i]))
                    current_address = current_address + 4
                output.append((current_address, instruction_tuples[-1]))
            current_address = current_address + 4
    return sorted(output), symbol_table


def deadRangeInstruction(last_address, next_address, hexes=8):
    hex_format = "{0:0" + str(hexes) + "x}" 
    return "[" + hex_format.format((last_address + 4) >> 2) + ".." + hex_format.format((next_address - 4) >> 2) + "] : DEAD;" 

def opcodeHex(opcode_name):
    return "{0:02x}".format(OPCODES_MAP[opcode_name])

def registerHex(register_name):
    return format(REGISTER_MAP[register_name], "x")

def formatNumber(value):
    if value < 0:
        value = int("0xFFFF", 0) + value + 1
    return "{0:08x}".format(value)

def immediateHex(immediate, symbol_table):
    try:
        return formatNumber(int(immediate, 0))[-4:]
    except ValueError:
        return formatNumber(symbol_table[immediate])[-4:]

def immediateTopHex(immediate, symbol_table):
    try:
        return formatNumber(int(immediate, 0))[:4]
    except ValueError:
        return formatNumber(symbol_table[immediate])[:4]


def shImmediateHex(immediate, symbol_table):
    try:
        return formatNumber(int(immediate, 0))[-4:]
    except ValueError:
        return formatNumber(symbol_table[immediate] >> 2)[-4:]

def pcRelHex(pcRel, symbol_table, address):
    try:
        return formatNumber(int(pcRel, 0))[-4:]
    except ValueError:
        return formatNumber(((symbol_table[pcRel] - address) >> 2) - 1)[-4:]


def instructionHex(instruction, symbol_table, address):
    opcode = instruction[0]
    opcode_hex = opcodeHex(opcode)
    if opcode in OPCODES_R_R_R:
        return opcode_hex + registerHex(instruction[1]) + registerHex(instruction[2]) + registerHex(instruction[3]) + "000"
    elif opcode in OPCODES_R_R_NUM:
        return opcode_hex + registerHex(instruction[1]) + registerHex(instruction[2]) + immediateHex(instruction[3], symbol_table)
    elif opcode in OPCODES_R_NUM:
        return opcode_hex + registerHex(instruction[1]) + "0" + immediateTopHex(instruction[2], symbol_table)
    elif opcode in OPCODES_R_NUM_R:
        immediate, register = instruction[2].split("(")
        register = register[:-1]
        return opcode_hex + registerHex(instruction[1]) + registerHex(register) + immediateHex(immediate, symbol_table)
    elif opcode in OPCODES_R_RNUM_R:
        immediate, register = instruction[2].split("(")
        register = register[:-1]
        return opcode_hex + registerHex(register) + registerHex(instruction[1]) + immediateHex(immediate, symbol_table)
    elif opcode in OPCODES_R_R_WNUM:
        return opcode_hex + registerHex(instruction[1]) + registerHex(instruction[2]) + pcRelHex(instruction[3], symbol_table, address)
    elif opcode in OPCODES_R_WNUM:
        return opcode_hex + registerHex(instruction[1]) + "0" + pcRelHex(instruction[2], symbol_table, address)
    elif opcode in OPCODES_R_WNUM_R:
        immediate, register = instruction[2].split("(")
        register = register[:-1]
        return opcode_hex + registerHex(instruction[1]) + registerHex(register) + shImmediateHex(immediate, symbol_table)
    else:
        return "04000000"

def generateMachineCode(instructions, symbol_table):
    output = []
    last_address = -4
    for address, instruction in instructions:
        if address - last_address > 4:
            output.append(deadRangeInstruction(last_address, address))
            last_address = address
        output.append(" ".join(["--", "@ 0x{0:08x} :\t".format(address, 0), instruction[0] + "\t", ",".join(instruction[1:])]))
        instruction_hex = instructionHex(instruction, symbol_table, address)
        output.append("{0:08x} : ".format(address >> 2) + instruction_hex + ";")
        last_address = address
    if last_address < 2048:
        output.append(deadRangeInstruction(last_address, 2048 << 2, hexes=4))
    return output


contents = normalizeContents(contents)
contents, symbol_table = annotateAddress(contents)
machine_code = generateMachineCode(contents, symbol_table)

machine = []
machine.append("WIDTH=32;")
machine.append("DEPTH=2048;")
machine.append("ADDRESS_RADIX=HEX;")
machine.append("DATA_RADIX=HEX;")
machine.append("CONTENT BEGIN")

for line in machine_code:
    machine.append(line)

machine.append("END;")

print "\n".join(machine).strip()
