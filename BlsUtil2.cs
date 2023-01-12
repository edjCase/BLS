using System;
using System.Collections.Generic;
using System.Text;

namespace EdjCase.Cryptography.BLS
{
	internal class BlsUtil2
	{
		private const int DomainLength = 8;
		private const int HashLength = 32;
		private const int PrivateKeyLength = 32;
		private const int PublicKeyLength = 96;
		private const int SignatureLength = 48;

		private static object intializeLock = new object();
		private static bool isInitialized = false;

		private static void EnsureInitialized()
		{
			lock (BlsUtil2.intializeLock)
			{
				if (!BlsUtil2.isInitialized)
				{
					Interop2.Init(Interop.MCL_BLS12_381);
					BlsUtil2.isInitialized = true;
				}
			}
		}
		public static bool VerifyHash(
			byte[] publicKey,
			byte[] hash,
			byte[] signature
		)
		{
			if (signature.Length != SignatureLength)
			{
				throw new ArgumentOutOfRangeException(nameof(signature), signature.Length, $"Signature must be {SignatureLength} bytes long.");
			}
			EnsureInitialized();

			var blsPublicKey = default(Interop2.PublicKey);
			ulong publicKeyBytesRead = Interop2.blsPublicKeyDeserialize(ref blsPublicKey, publicKey, (ulong)publicKey!.LongLength);

			if (publicKeyBytesRead != (ulong)publicKey.Length)
			{
				throw new Exception($"Error deserializing BLS public key");
			}

			var blsSignature = default(Interop2.Signature);
			ulong signatureBytesRead = Interop2.blsSignatureDeserialize(ref blsSignature, signature, (ulong)signature.LongLength);
			if (signatureBytesRead != (ulong)signature.LongLength)
			{
				throw new Exception($"Error deserializing BLS signature, length: {signatureBytesRead}");
			}

			int result = Interop2.blsVerify(in blsSignature, in blsPublicKey, hash, (ulong)hash.Length);

			return result == 1;
		}
	}
}
