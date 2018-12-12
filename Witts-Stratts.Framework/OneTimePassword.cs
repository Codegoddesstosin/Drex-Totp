using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Witts_Stratts.Framework
{
    public class OneTimePassword
    {
        public OneTimePassword()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(SecretBuffer);
            }
            SecretLength = 20;
            ProtectSecret();
        }

        public OneTimePassword(byte[] secret)
        {
            if (secret == null) { throw new ArgumentNullException("secret", "Secret cannot be null."); }
            if (secret.Length > SecretBuffer.Length) { throw new ArgumentOutOfRangeException("secret", "Secret cannot be longer than 8192 bits (1024 bytes)."); }

            Buffer.BlockCopy(secret, 0, SecretBuffer, 0, secret.Length);
            SecretLength = secret.Length;
            ProtectSecret();
        }

        public OneTimePassword(string secret)
        {
            if (secret == null) { throw new ArgumentNullException("secret", "Secret cannot be null."); }

            try
            {
                int length;
                FromBase32(secret, SecretBuffer, out length);
                SecretLength = length;
            }
            catch (IndexOutOfRangeException)
            {
                throw new ArgumentOutOfRangeException("secret", "Secret cannot be longer than 8192 bits (1024 bytes).");
            }
            catch (Exception)
            {
                throw new ArgumentOutOfRangeException("secret", "Secret is not valid Base32 string.");
            }
            ProtectSecret();
        }


        #region Secret buffer

        private readonly byte[] SecretBuffer = new byte[1024]; //ProtectedMemory requires length of the data to be a multiple of 16 bytes.
        private readonly int SecretLength;

        private void ProtectSecret()
        {
            ProtectedMemory.Protect(SecretBuffer, MemoryProtectionScope.SameProcess);
        }

        private void UnprotectSecret()
        {
            ProtectedMemory.Unprotect(SecretBuffer, MemoryProtectionScope.SameProcess);
        }


        public byte[] GetSecret()
        {
            var buffer = new byte[SecretLength];

            UnprotectSecret();
            try
            {
                Buffer.BlockCopy(SecretBuffer, 0, buffer, 0, buffer.Length);
            }
            finally
            {
                ProtectSecret();
            }

            return buffer;
        }

        public string GetBase32Secret()
        {
            return GetBase32Secret(SecretFormatFlags.Spacing);
        }

        public string GetBase32Secret(SecretFormatFlags format)
        {
            UnprotectSecret();
            try
            {
                return ToBase32(SecretBuffer, SecretLength, format);
            }
            finally
            {
                ProtectSecret();
            }
        }

        #endregion


        #region Setup

        private int _digits = 6;
        public int Digits
        {
            get { return _digits; }
            set
            {
                if ((value < 4) || (value > 9)) { throw new ArgumentOutOfRangeException("value", "Number of digits to return must be between 4 and 9."); }
                _digits = value;
            }
        }

        private int _timeStep = 30;
        public int TimeStep
        {
            get { return _timeStep; }
            set
            {
                if (value == 0)
                {
                    _timeStep = 0;
                    Counter = 0;
                }
                else
                {
                    if ((value < 15) || (value > 300)) { throw new ArgumentOutOfRangeException("value", "Time step must be between 15 and 300 seconds."); }
                    _timeStep = value;
                }
            }
        }

        private readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private DateTime TestTime = DateTime.MinValue;

        private long _counter = 0;
        public long Counter
        {
            get
            {
                if (TimeStep == 0)
                {
                    return _counter;
                }
                else
                {
                    var currTime = (TestTime > DateTime.MinValue) ? TestTime : DateTime.UtcNow;
                    var seconds = (currTime.Ticks - Epoch.Ticks) / 10000000;
                    return (seconds / TimeStep);
                }
            }
            set
            {
                if (TimeStep == 0)
                {
                    if (value < 0) { throw new ArgumentOutOfRangeException("value", "Counter value must be a positive number."); }
                    _counter = value;
                }
                else
                {
                    throw new NotSupportedException("Counter value can only be set in HOTP mode (time step is zero).");
                }
            }
        }

        private OneTimePasswordAlgorithm _algorithm = OneTimePasswordAlgorithm.Sha1;
        public OneTimePasswordAlgorithm Algorithm
        {
            get { return _algorithm; }
            set
            {
                switch (value)
                {
                    case OneTimePasswordAlgorithm.Sha1:
                    case OneTimePasswordAlgorithm.Sha256:
                    case OneTimePasswordAlgorithm.Sha512: break;
                    default: throw new ArgumentOutOfRangeException("value", "Unknown algorithm.");
                }
                _algorithm = value;
            }
        }

        #endregion


        #region Code

        public int GetCode()
        {
            return GetCode(Digits);
        }

        private int cachedDigits;
        private long cachedCounter = -1;
        private int cachedCode;

        public int GetCode(int digits)
        {
            if ((digits < 4) || (digits > 9)) { throw new ArgumentOutOfRangeException("digits", "Number of digits to return must be between 4 and 9."); }

            var counter = Counter;

            if ((cachedCounter == counter) && (cachedDigits == digits)) { return cachedCode; } //to avoid recalculation if all is the same

            var code = GetCode(counter, digits);
            if (TimeStep == 0) { Counter = counter + 1; }

            cachedDigits = digits;
            cachedCounter = counter;
            cachedCode = code;

            return code;
        }

        private int GetCode(long counter, int digits)
        {
            byte[] hash;

            var secret = GetSecret();
            try
            {
                var counterBytes = BitConverter.GetBytes(counter);
                if (BitConverter.IsLittleEndian) { Array.Reverse(counterBytes, 0, 8); }
                HMAC hmac = null;
                try
                {
                    switch (Algorithm)
                    {
                        case OneTimePasswordAlgorithm.Sha1: hmac = new HMACSHA1(secret); break;
                        case OneTimePasswordAlgorithm.Sha256: hmac = new HMACSHA256(secret); break;
                        case OneTimePasswordAlgorithm.Sha512: hmac = new HMACSHA512(secret); break;
                    }
                    hash = hmac.ComputeHash(counterBytes);
                }
                finally
                {
                    if (hmac != null) { hmac.Dispose(); }
                }
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
            }

            int offset = hash[hash.Length - 1] & 0x0F;
            var truncatedHash = new byte[] { (byte)(hash[offset + 0] & 0x7F), hash[offset + 1], hash[offset + 2], hash[offset + 3] };
            if (BitConverter.IsLittleEndian) { Array.Reverse(truncatedHash, 0, 4); }
            var number = BitConverter.ToInt32(truncatedHash, 0);

            return number % DigitsDivisor[digits];
        }

        private static readonly int[] DigitsDivisor = new int[] { 0, 0, 0, 0, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

        #endregion


        #region Validate

        public bool IsCodeValid(string code)
        {
            if (code == null) { throw new ArgumentNullException("code", "Code cannot be null."); }
            var number = 0;
            foreach (var ch in code)
            {
                if (char.IsWhiteSpace(ch)) { continue; }
                if (!char.IsDigit(ch)) { throw new ArgumentOutOfRangeException("code", "Code must contain only numbers and whitespace."); }
                if (number >= 100000000) { return false; } //number cannot be more than 9 digits
                number *= 10;
                number += (ch - 0x30);
            }
            return IsCodeValid(number);
        }

        public bool IsCodeValid(int code)
        {
            var currCode = GetCode(Counter, Digits);
            var prevCode = GetCode(Counter - 1, Digits);

            var isCurrValid = (code == currCode);
            var isPrevValid = (code == prevCode) && (Counter > 0); //don't check previous code if counter is zero; but calculate it anyhow (to keep timing)
            var isValid = isCurrValid || isPrevValid;
            if ((TimeStep == 0) && isValid)
            {
                Counter++;
            }
            return isValid;
        }

        #endregion


        #region Base32

        private static readonly IList<char> Base32Alphabet = new List<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").AsReadOnly();
        private static readonly byte[] Base32Bitmask = new byte[] { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F };

        private static void FromBase32(string text, byte[] buffer, out int length)
        {
            var index = 0;

            var bitPosition = 0;
            byte partialByte = 0;
            foreach (var ch in text)
            { 
                if (char.IsWhiteSpace(ch)) { continue; } 
                if (ch == '=')
                { 
                    bitPosition = -1;
                    continue;
                }
                else if (bitPosition == -1) { throw new FormatException("Character '" + ch + "' found after padding ."); }

                var bits = Base32Alphabet.IndexOf(char.ToUpperInvariant(ch));
                if (bits < 0) { throw new FormatException("Unknown character '" + ch + "'."); }

                var bitCount1 = (bitPosition < 3) ? 5 : 8 - bitPosition; //how many bits go in current partial byte
                var bitCount2 = 5 - bitCount1; //how many bits are for next byte

                partialByte <<= bitCount1;
                partialByte |= (byte)(bits >> (5 - bitCount1));
                bitPosition += bitCount1;

                if (bitPosition >= 8)
                {
                    buffer[index] = partialByte;
                    index++;
                    bitPosition = bitCount2;
                    partialByte = (byte)(bits & Base32Bitmask[bitCount2]);
                }
            }

            if ((bitPosition > -1) && (bitPosition >= 5))
            {
                partialByte <<= (8 - bitPosition);
                buffer[index] = partialByte;
                index++;
            }

            length = index;
        }

        private static string ToBase32(byte[] bytes, int length, SecretFormatFlags format)
        {
            if (length == 0) { return string.Empty; }

            var hasSpacing = (format & SecretFormatFlags.Spacing) == SecretFormatFlags.Spacing;
            var hasPadding = (format & SecretFormatFlags.Padding) == SecretFormatFlags.Padding;
            var isUpper = (format & SecretFormatFlags.Uppercase) == SecretFormatFlags.Uppercase;

            var bitLength = (length * 8);
            var textLength = bitLength / 5 + ((bitLength % 5) == 0 ? 0 : 1);
            var totalLength = textLength;

            var padLength = (textLength % 8 == 0) ? 0 : 8 - textLength % 8;
            totalLength += (hasPadding ? padLength : 0);

            var spaceLength = totalLength / 4 + ((totalLength % 4 == 0) ? -1 : 0);
            totalLength += (hasSpacing ? spaceLength : 0);


            var chars = new char[totalLength];
            var index = 0;

            var bits = 0;
            var bitsRemaining = 0;
            for (int i = 0; i < length; i++)
            {
                bits = (bits << 8) | bytes[i];
                bitsRemaining += 8;
                while (bitsRemaining >= 5)
                {
                    var bitsIndex = (bits >> (bitsRemaining - 5)) & 0x1F;
                    bitsRemaining -= 5;
                    chars[index] = isUpper ? Base32Alphabet[bitsIndex] : char.ToLowerInvariant(Base32Alphabet[bitsIndex]);
                    index++;

                    if (hasSpacing && (index < chars.Length) && (bitsRemaining % 4 == 0))
                    {
                        chars[index] = ' ';
                        index++;
                    }
                }
            }
            if (bitsRemaining > 0)
            {
                var bitsIndex = (bits & Base32Bitmask[bitsRemaining]) << (5 - bitsRemaining);
                chars[index] = isUpper ? Base32Alphabet[bitsIndex] : char.ToLowerInvariant(Base32Alphabet[bitsIndex]);
                index++;
            }

            if (hasPadding)
            {
                for (int i = 0; i < padLength; i++)
                {
                    if (hasSpacing && (i % 4 == padLength % 4))
                    {
                        chars[index] = ' ';
                        index++;
                    }
                    chars[index] = '=';
                    index++;
                }
            }

            return new string(chars);
        }

        #endregion

    }



    [Flags()]
    public enum SecretFormatFlags
    {
        None = 0,
        Spacing = 1,
        Padding = 2,
        Uppercase = 4,
    }

    public enum OneTimePasswordAlgorithm
    {
        Sha1 = 0,
        Sha256 = 1,
        Sha512 = 2,
    }

}
