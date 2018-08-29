#region license

/*
Copyright (c) 2013, Milosz Krajewski
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions
  and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions
  and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#endregion

using System;

// ReSharper disable InconsistentNaming

namespace MessagePack.LZ4
{
    public static partial class LZ4Codec
    {
        #region configuration

        /// <summary>
        /// Memory usage formula : N->2^N Bytes (examples : 10 -> 1KB; 12 -> 4KB ; 16 -> 64KB; 20 -> 1MB; etc.)
        /// Increasing memory usage improves compression ratio
        /// Reduced memory usage can improve speed, due to cache effect
        /// Default value is 14, for 16KB, which nicely fits into Intel x86 L1 cache
        /// </summary>
        private const int MEMORY_USAGE = 12; // modified use 12.

        /// <summary>
        /// Decreasing this value will make the algorithm skip faster data segments considered "incompressible"
        /// This may decrease compression ratio dramatically, but will be faster on incompressible data
        /// Increasing this value will make the algorithm search more before declaring a segment "incompressible"
        /// This could improve compression a bit, but will be slower on incompressible data
        /// The default value (6) is recommended
        /// </summary>
        private const int NOTCOMPRESSIBLE_DETECTIONLEVEL = 6;

        #endregion

        #region consts

        private const int MINMATCH = 4;

#pragma warning disable 162, 429
        // ReSharper disable once UnreachableCode
        private const int SKIPSTRENGTH =
            NOTCOMPRESSIBLE_DETECTIONLEVEL > 2
            ? NOTCOMPRESSIBLE_DETECTIONLEVEL
            : 2;
#pragma warning restore 162, 429

        private const int COPYLENGTH = 8;
        private const int LASTLITERALS = 5;
        private const int MFLIMIT = COPYLENGTH + MINMATCH;
        private const int MINLENGTH = MFLIMIT + 1;
        private const int MAXD_LOG = 16;
        private const int MAXD = 1 << MAXD_LOG;
        private const int MAXD_MASK = MAXD - 1;
        private const int MAX_DISTANCE = (1 << MAXD_LOG) - 1;
        private const int ML_BITS = 4;
        private const int ML_MASK = (1 << ML_BITS) - 1;
        private const int RUN_BITS = 8 - ML_BITS;
        private const int RUN_MASK = (1 << RUN_BITS) - 1;
        private const int STEPSIZE_64 = 8;
        private const int STEPSIZE_32 = 4;

        private const int LZ4_64KLIMIT = (1 << 16) + (MFLIMIT - 1);

        private const int HASH_LOG = MEMORY_USAGE - 2;
        private const int HASH_TABLESIZE = 1 << HASH_LOG;
        private const int HASH_ADJUST = (MINMATCH * 8) - HASH_LOG;

        private const int HASH64K_LOG = HASH_LOG + 1;
        private const int HASH64K_TABLESIZE = 1 << HASH64K_LOG;
        private const int HASH64K_ADJUST = (MINMATCH * 8) - HASH64K_LOG;

        private const int HASHHC_LOG = MAXD_LOG - 1;
        private const int HASHHC_TABLESIZE = 1 << HASHHC_LOG;
        private const int HASHHC_ADJUST = (MINMATCH * 8) - HASHHC_LOG;
        //private const int HASHHC_MASK = HASHHC_TABLESIZE - 1;

        private static readonly int[] DECODER_TABLE_32 = { 0, 3, 2, 3, 0, 0, 0, 0 };
        private static readonly int[] DECODER_TABLE_64 = { 0, 0, 0, -1, 0, 1, 2, 3 };

        private static readonly int[] DEBRUIJN_TABLE_32 = {
            0, 0, 3, 0, 3, 1, 3, 0, 3, 2, 2, 1, 3, 2, 0, 1,
            3, 3, 1, 2, 2, 2, 2, 0, 3, 1, 2, 0, 1, 0, 1, 1
        };

        private static readonly int[] DEBRUIJN_TABLE_64 = {
            0, 0, 0, 0, 0, 1, 1, 2, 0, 3, 1, 3, 1, 4, 2, 7,
            0, 2, 3, 6, 1, 5, 3, 5, 1, 3, 4, 4, 2, 5, 6, 7,
            7, 0, 1, 2, 3, 3, 4, 6, 2, 6, 5, 5, 3, 4, 5, 6,
            7, 1, 2, 4, 6, 4, 4, 5, 7, 2, 6, 5, 7, 6, 7, 7
        };

        private const int MAX_NB_ATTEMPTS = 256;
        private const int OPTIMAL_ML = (ML_MASK - 1) + MINMATCH;

        private const int BLOCK_COPY_LIMIT = 16;

        private const uint MAGICNUMBER = 0x184D2204U;
        private const uint MAGIC_SKIPPABLE_START = 0x184D2A50U;

        private const byte _1BIT = 0x01;
        private const byte _2BITS = 0x03;
        private const byte _3BITS = 0x07;
        private const byte _4BITS = 0x0F;
        private const byte _8BITS = 0xFF;

        #endregion

        #region public interface (common)

        /// <summary>Gets maximum the length of the output.</summary>
        /// <param name="inputLength">Length of the input.</param>
        /// <returns>Maximum number of bytes needed for compressed buffer.</returns>
        public static int MaximumOutputLength(int inputLength)
        {
            return inputLength + (inputLength / 255) + 16;
        }

        #endregion

        #region internal interface (common)

        internal static void CheckArguments(
            byte[] input, int inputOffset, int inputLength,
            byte[] output, int outputOffset, int outputLength)
        {
            if (inputLength == 0)
            {
                outputLength = 0;
                return;
            }

            if (input == null) throw new ArgumentNullException("input");
            if ((uint)inputOffset > (uint)input.Length) throw new ArgumentOutOfRangeException("inputOffset");
            if ((uint)inputLength > (uint)input.Length - (uint)inputOffset) throw new ArgumentOutOfRangeException("inputLength");

            if (output == null) throw new ArgumentNullException("output");
            if ((uint)outputOffset > (uint)output.Length) throw new ArgumentOutOfRangeException("outputOffset");
            if ((uint)outputLength > (uint)output.Length - (uint)outputOffset) throw new ArgumentOutOfRangeException("outputLength");
        }

        #endregion
    }

    /* The larger the block size, the (slightly) better the compression ratio,
     * though there are diminishing returns.
     * Larger blocks also increase memory usage on both compression and decompression sides. */
    public enum LZ4F_blockSizeID_t
    {
        LZ4F_default = 0,
        LZ4F_max64KB = 4,
        LZ4F_max256KB = 5,
        LZ4F_max1MB = 6,
        LZ4F_max4MB = 7,
        //LZ4F_OBSOLETE_ENUM(max64KB),
        //LZ4F_OBSOLETE_ENUM(max256KB),
        //LZ4F_OBSOLETE_ENUM(max1MB),
        //LZ4F_OBSOLETE_ENUM(max4MB),
    };

    /* Linked blocks sharply reduce inefficiencies when using small blocks,
     * they compress better.
     * However, some LZ4 decoders are only compatible with independent blocks */
    public enum LZ4F_blockMode_t
    {
        LZ4F_blockLinked = 0,
        LZ4F_blockIndependent,
        //LZ4F_OBSOLETE_ENUM(blockLinked),
        //LZ4F_OBSOLETE_ENUM(blockIndependent),
    };

    public enum LZ4F_contentChecksum_t
    {
        LZ4F_noContentChecksum = 0,
        LZ4F_contentChecksumEnabled,
        //LZ4F_OBSOLETE_ENUM(noContentChecksum),
        //LZ4F_OBSOLETE_ENUM(contentChecksumEnabled),
    };

    public enum LZ4F_blockChecksum_t
    {
        LZ4F_noBlockChecksum = 0,
        LZ4F_blockChecksumEnabled
    };

    public enum LZ4F_frameType_t
    {
        LZ4F_frame = 0,
        LZ4F_skippableFrame,
        //LZ4F_OBSOLETE_ENUM(skippableFrame),
    };

    /*! LZ4F_frameInfo_t :
     *  makes it possible to set or read frame parameters.
     *  It's not required to set all fields, as long as the structure was initially memset() to zero.
     *  For all fields, 0 sets it to default value */
    public struct LZ4F_frameInfo_t
    {
        public LZ4F_blockSizeID_t blockSizeID;         /* max64KB, max256KB, max1MB, max4MB; 0 == default */
        public LZ4F_blockMode_t blockMode;           /* LZ4F_blockLinked, LZ4F_blockIndependent; 0 == default */
        public LZ4F_contentChecksum_t contentChecksumFlag; /* 1: frame terminated with 32-bit checksum of decompressed data; 0: disabled (default) */
        public LZ4F_frameType_t frameType;           /* read-only field : LZ4F_frame or LZ4F_skippableFrame */
        public ulong contentSize;         /* Size of uncompressed content ; 0 == unknown */
        public uint dictID;              /* Dictionary ID, sent by compressor to help decoder select correct dictionary; 0 == no dictID provided */
        public LZ4F_blockChecksum_t blockChecksumFlag;   /* 1: each block followed by a checksum of block's compressed data; 0: disabled (default) */
    };

    /*! LZ4F_preferences_t :
     *  makes it possible to supply detailed compression parameters to the stream interface.
     *  Structure is presumed initially memset() to zero, representing default settings.
     *  All reserved fields must be set to zero. */
    public struct LZ4F_preferences_t
    {
        public LZ4F_frameInfo_t frameInfo;
        public int compressionLevel;    /* 0: default (fast mode); values > LZ4HC_CLEVEL_MAX count as LZ4HC_CLEVEL_MAX; values < 0 trigger "fast acceleration" */
        public uint autoFlush;           /* 1: always flush, to reduce usage of internal buffers */
        public uint favorDecSpeed;       /* 1: parser favors decompression speed vs compression ratio. Only works for high compression modes (>= LZ4LZ4HC_CLEVEL_OPT_MIN) */  /* >= v1.8.2 */
        public uint[/*3*/] reserved;         /* must be zero for forward compatibility */
    };
}

// ReSharper restore InconsistentNaming
