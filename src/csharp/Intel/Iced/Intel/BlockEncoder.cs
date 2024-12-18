// SPDX-License-Identifier: MIT
// Copyright (C) 2018-present iced project and contributors

#if ENCODER && BLOCK_ENCODER
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Iced.Intel.BlockEncoderInternal;

namespace Iced.Intel {
	// GENERATOR-BEGIN: RelocKind
	// ⚠️This was generated by GENERATOR!🦹‍♂️
	/// <summary>Relocation kind</summary>
	public enum RelocKind {
		/// <summary>64-bit offset. Only used if it&apos;s 64-bit code.</summary>
		Offset64 = 0,
	}
	// GENERATOR-END: RelocKind

	/// <summary>
	/// Relocation info
	/// </summary>
	public readonly struct RelocInfo {
		/// <summary>
		/// Address
		/// </summary>
		public readonly ulong Address;

		/// <summary>
		/// Relocation kind
		/// </summary>
		public readonly RelocKind Kind;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="kind">Relocation kind</param>
		/// <param name="address">Address</param>
		public RelocInfo(RelocKind kind, ulong address) {
			Kind = kind;
			Address = address;
		}
	}

	/// <summary>
	/// Contains a list of instructions that should be encoded by <see cref="BlockEncoder"/>
	/// </summary>
	public readonly struct InstructionBlock {
		/// <summary>
		/// Code writer
		/// </summary>
		public readonly CodeWriter CodeWriter;

		/// <summary>
		/// All instructions
		/// </summary>
		public readonly IList<Instruction> Instructions;

		/// <summary>
		/// Base IP of all encoded instructions
		/// </summary>
		public readonly ulong RIP;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="codeWriter">Code writer</param>
		/// <param name="instructions">Instructions</param>
		/// <param name="rip">Base IP of all encoded instructions</param>
		public InstructionBlock(CodeWriter codeWriter, IList<Instruction> instructions, ulong rip) {
			CodeWriter = codeWriter ?? throw new ArgumentNullException(nameof(codeWriter));
			Instructions = instructions ?? throw new ArgumentNullException(nameof(instructions));
			RIP = rip;
		}
	}

	/// <summary>
	/// <see cref="BlockEncoder"/> result if it was successful
	/// </summary>
	public readonly struct BlockEncoderResult {
		/// <summary>
		/// Base IP of all encoded instructions
		/// </summary>
		public readonly ulong RIP;

		/// <summary>
		/// If <see cref="BlockEncoderOptions.ReturnRelocInfos"/> option was enabled:
		/// <br/>
		/// All <see cref="RelocInfo"/>s
		/// </summary>
		public readonly List<RelocInfo>? RelocInfos;

		/// <summary>
		/// If <see cref="BlockEncoderOptions.ReturnNewInstructionOffsets"/> option was enabled:
		/// <br/>
		/// Offsets of the instructions relative to the base IP. If the instruction was rewritten to a new instruction
		/// (eg. <c>JE TARGET_TOO_FAR_AWAY</c> -> <c>JNE SHORT SKIP ; JMP QWORD PTR [MEM]</c>), the value <see cref="uint.MaxValue"/> is stored in that array element.
		/// </summary>
		public readonly uint[] NewInstructionOffsets;

		/// <summary>
		/// If <see cref="BlockEncoderOptions.ReturnConstantOffsets"/> option was enabled:
		/// <br/>
		/// Offsets of all constants in the new encoded instructions. If the instruction was rewritten,
		/// the 'default' value is stored in the corresponding array element.
		/// </summary>
		public readonly ConstantOffsets[] ConstantOffsets;

		internal BlockEncoderResult(ulong rip, List<RelocInfo>? relocInfos, uint[]? newInstructionOffsets, ConstantOffsets[]? constantOffsets) {
			RIP = rip;
			RelocInfos = relocInfos;
			NewInstructionOffsets = newInstructionOffsets ?? Array2.Empty<uint>();
			ConstantOffsets = constantOffsets ?? Array2.Empty<ConstantOffsets>();
		}
	}

	// GENERATOR-BEGIN: BlockEncoderOptions
	// ⚠️This was generated by GENERATOR!🦹‍♂️
	/// <summary><see cref="BlockEncoder"/> options</summary>
	[Flags]
	public enum BlockEncoderOptions {
		/// <summary>No option is set</summary>
		None = 0x00000000,
		/// <summary>By default, branches get updated if the target is too far away, eg. <c>Jcc SHORT</c> -&gt; <c>Jcc NEAR</c> or if 64-bit mode, <c>Jcc + JMP [RIP+mem]</c>. If this option is enabled, no branches are fixed.</summary>
		DontFixBranches = 0x00000001,
		/// <summary>The <see cref="BlockEncoder"/> should return <see cref="RelocInfo"/>s</summary>
		ReturnRelocInfos = 0x00000002,
		/// <summary>The <see cref="BlockEncoder"/> should return new instruction offsets</summary>
		ReturnNewInstructionOffsets = 0x00000004,
		/// <summary>The <see cref="BlockEncoder"/> should return <see cref="ConstantOffsets"/></summary>
		ReturnConstantOffsets = 0x00000008,
		/// <summary>The <see cref="BlockEncoder"/> should return new instruction offsets. For instructions that have been rewritten (e.g. to fix branches), the offset to the resulting block of instructions is returned.</summary>
		ReturnAllNewInstructionOffsets = 0x00000014,
	}
	// GENERATOR-END: BlockEncoderOptions

	/// <summary>
	/// Encodes instructions. It can be used to move instructions from one location to another location.
	/// </summary>
	public sealed class BlockEncoder {
		readonly int bitness;
		readonly BlockEncoderOptions options;
		readonly Block[] blocks;
		readonly Encoder nullEncoder;
		readonly Dictionary<ulong, Instr> toInstr;

		internal int Bitness => bitness;
		internal bool FixBranches => (options & BlockEncoderOptions.DontFixBranches) == 0;
		bool ReturnRelocInfos => (options & BlockEncoderOptions.ReturnRelocInfos) != 0;
		bool ReturnNewInstructionOffsets => (options & BlockEncoderOptions.ReturnNewInstructionOffsets) != 0;
		bool ReturnConstantOffsets => (options & BlockEncoderOptions.ReturnConstantOffsets) != 0;
		bool ReturnAllNewInstructionOffsets => (options & BlockEncoderOptions.ReturnAllNewInstructionOffsets) != 0;


		sealed class NullCodeWriter : CodeWriter {
			public static readonly NullCodeWriter Instance = new NullCodeWriter();
			NullCodeWriter() { }
			public override void WriteByte(byte value) { }
		}

		BlockEncoder(int bitness, InstructionBlock[] instrBlocks, BlockEncoderOptions options) {
			if (bitness != 16 && bitness != 32 && bitness != 64)
				throw new ArgumentOutOfRangeException(nameof(bitness));
			if (instrBlocks is null)
				throw new ArgumentNullException(nameof(instrBlocks));
			this.bitness = bitness;
			nullEncoder = Encoder.Create(bitness, NullCodeWriter.Instance);
			this.options = options;

			blocks = new Block[instrBlocks.Length];
			int instrCount = 0;
			for (int i = 0; i < instrBlocks.Length; i++) {
				var instructions = instrBlocks[i].Instructions;
				if (instructions is null)
					throw new ArgumentException();
				var block = new Block(this, instrBlocks[i].CodeWriter, instrBlocks[i].RIP, ReturnRelocInfos ? new List<RelocInfo>() : null);
				blocks[i] = block;
				var instrs = new Instr[instructions.Count];
				ulong ip = instrBlocks[i].RIP;
				for (int j = 0; j < instrs.Length; j++) {
					var instruction = instructions[j];
					var instr = Instr.Create(this, block, instruction);
					instr.IP = ip;
					instrs[j] = instr;
					instrCount++;
					Debug.Assert(instr.Size != 0 || instruction.Code == Code.Zero_bytes);
					ip += instr.Size;
				}
				block.SetInstructions(instrs);
			}
			// Optimize from low to high addresses
			Array.Sort(blocks, (a, b) => a.RIP.CompareTo(b.RIP));

			// There must not be any instructions with the same IP, except if IP = 0 (default value)
			var toInstr = new Dictionary<ulong, Instr>(instrCount);
			this.toInstr = toInstr;
			bool hasMultipleZeroIPInstrs = false;
			foreach (var block in blocks) {
				foreach (var instr in block.Instructions) {
					ulong origIP = instr.OrigIP;
					if (toInstr.TryGetValue(origIP, out _)) {
						if (origIP != 0)
							throw new ArgumentException($"Multiple instructions with the same IP: 0x{origIP:X}");
						hasMultipleZeroIPInstrs = true;
					}
					else
						toInstr[origIP] = instr;
				}
			}
			if (hasMultipleZeroIPInstrs)
				toInstr.Remove(0);

			foreach (var block in blocks) {
				ulong ip = block.RIP;
				foreach (var instr in block.Instructions) {
					instr.IP = ip;
					if (!instr.Done)
						instr.Initialize(this);
					ip += instr.Size;
				}
			}
		}

		/// <summary>
		/// Encodes instructions. Any number of branches can be part of this block.
		/// You can use this function to move instructions from one location to another location.
		/// If the target of a branch is too far away, it'll be rewritten to a longer branch.
		/// You can disable this by passing in <see cref="BlockEncoderOptions.DontFixBranches"/>.
		/// If the block has any <c>RIP</c>-relative memory operands, make sure the data isn't too
		/// far away from the new location of the encoded instructions. Every OS should have
		/// some API to allocate memory close (+/-2GB) to the original code location.
		/// </summary>
		/// <param name="bitness">16, 32 or 64</param>
		/// <param name="block">All instructions</param>
		/// <param name="errorMessage">Updated with an error message if the method failed</param>
		/// <param name="result">Result if this method returns <see langword="true"/></param>
		/// <param name="options">Encoder options</param>
		/// <returns></returns>
		public static bool TryEncode(int bitness, InstructionBlock block, [NotNullWhen(false)] out string? errorMessage, out BlockEncoderResult result, BlockEncoderOptions options = BlockEncoderOptions.None) {
			if (TryEncode(bitness, new[] { block }, out errorMessage, out var resultArray, options)) {
				Debug.Assert(resultArray.Length == 1);
				result = resultArray[0];
				return true;
			}
			else {
				result = default;
				return false;
			}
		}

		/// <summary>
		/// Encodes instructions. Any number of branches can be part of this block.
		/// You can use this function to move instructions from one location to another location.
		/// If the target of a branch is too far away, it'll be rewritten to a longer branch.
		/// You can disable this by passing in <see cref="BlockEncoderOptions.DontFixBranches"/>.
		/// If the block has any <c>RIP</c>-relative memory operands, make sure the data isn't too
		/// far away from the new location of the encoded instructions. Every OS should have
		/// some API to allocate memory close (+/-2GB) to the original code location.
		/// </summary>
		/// <param name="bitness">16, 32 or 64</param>
		/// <param name="blocks">All instructions</param>
		/// <param name="errorMessage">Updated with an error message if the method failed</param>
		/// <param name="result">Result if this method returns <see langword="true"/></param>
		/// <param name="options">Encoder options</param>
		/// <returns></returns>
		public static bool TryEncode(int bitness, InstructionBlock[] blocks, [NotNullWhen(false)] out string? errorMessage, [NotNullWhen(true)] out BlockEncoderResult[]? result, BlockEncoderOptions options = BlockEncoderOptions.None) =>
			new BlockEncoder(bitness, blocks, options).Encode(out errorMessage, out result);

		bool Encode([NotNullWhen(false)] out string? errorMessage, [NotNullWhen(true)] out BlockEncoderResult[]? result) {
			const int MAX_ITERS = 5;
			for (int iter = 0; iter < MAX_ITERS; iter++) {
				bool updated = false;
				foreach (var block in blocks) {
					ulong ip = block.RIP;
					ulong gained = 0;
					foreach (var instr in block.Instructions) {
						instr.IP = ip;
						if (!instr.Done) {
							var oldSize = instr.Size;
							if (instr.Optimize(gained)) {
								if (instr.Size > oldSize) {
									errorMessage = "Internal error: new size > old size";
									result = null;
									return false;
								}
								if (instr.Size < oldSize) {
									gained += oldSize - instr.Size;
									updated = true;
								}
							}
							else if (instr.Size != oldSize) {
								errorMessage = "Internal error: new size != old size";
								result = null;
								return false;
							}
						}
						ip += instr.Size;
					}
				}
				if (!updated)
					break;
			}

			foreach (var block in blocks)
				block.InitializeData();

			var resultArray = new BlockEncoderResult[blocks.Length];
			for (int i = 0; i < blocks.Length; i++) {
				var block = blocks[i];
				var encoder = Encoder.Create(bitness, block.CodeWriter);
				ulong ip = block.RIP;
				var newInstructionOffsets = ReturnNewInstructionOffsets ? new uint[block.Instructions.Length] : null;
				var constantOffsets = ReturnConstantOffsets ? new ConstantOffsets[block.Instructions.Length] : null;
				var instructions = block.Instructions;
				for (int j = 0; j < instructions.Length; j++) {
					var instr = instructions[j];
					uint bytesWritten = block.CodeWriter.BytesWritten;
					bool isOriginalInstruction;
					if (constantOffsets is not null)
						errorMessage = instr.TryEncode(encoder, out constantOffsets[j], out isOriginalInstruction);
					else
						errorMessage = instr.TryEncode(encoder, out _, out isOriginalInstruction);
					if (errorMessage is not null) {
						result = null;
						return false;
					}
					uint size = block.CodeWriter.BytesWritten - bytesWritten;
					if (size != instr.Size) {
						errorMessage = "Internal error: didn't write all bytes";
						result = null;
						return false;
					}
					if (newInstructionOffsets is not null) {
						if (isOriginalInstruction || ReturnAllNewInstructionOffsets)
							newInstructionOffsets[j] = (uint)(ip - block.RIP);
						else
							newInstructionOffsets[j] = uint.MaxValue;
					}
					ip += size;
				}
				resultArray[i] = new BlockEncoderResult(block.RIP, block.relocInfos, newInstructionOffsets, constantOffsets);
				block.WriteData();
			}

			errorMessage = null;
			result = resultArray;
			return true;
		}

		internal TargetInstr GetTarget(ulong address) {
			if (toInstr.TryGetValue(address, out var instr))
				return new TargetInstr(instr);
			return new TargetInstr(address);
		}

		internal uint GetInstructionSize(in Instruction instruction, ulong ip) {
			if (!nullEncoder.TryEncode(instruction, ip, out var size, out _))
				size = IcedConstants.MaxInstructionLength;
			return size;
		}
	}
}
#endif
