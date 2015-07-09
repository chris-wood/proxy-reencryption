// Standard Java classes
import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

// jPBC library classes
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBPEDecryptionTask // extends ParallelRegion, possibly Runnable?
{
	private int n;
	private int blockSize;
	private Pairing pairing;
	private Field G1;
	private Field GT;
	private Field Zr;
	private Element g;
	private Element g_s;

	public IBPEDecryptionTask(int n, int blockSize, Pairing pairing, Element g, Element g_s)
	{
		this.n = n;
		this.blockSize = blockSize;
		this.pairing = pairing;
		this.G1 = pairing.getG1();
		this.GT = pairing.getGT();
		this.Zr = pairing.getZr();
		this.g = g;
		this.g_s = g_s;
	}

	// TODO: implement decryption for layer one ciphertexts, if drastically needed...

	public byte[] decryptLayerN(IBPEPublicParameters params, byte[] A_ID, Element sk_A, IBPECiphertextLayerN[] ctBlocks) throws Exception
	{
		byte[] pt = new byte[ctBlocks.length * n];

		// Decrypt each block
		int index = 0;
		for (int b = 0; b < ctBlocks.length; b++)
		{
			byte[] block = decryptLayerNBlock(params, A_ID, sk_A, ctBlocks[b]);
			for (int i = 0; i < block.length; i++)
			{
				pt[index++] = block[i];
			}
		}

		return pt;
	}

	////////////////////////////////
	// Decrypt(params, sk_A, ct(P_ID -> A_ID))
	////////////////////////////////
	private byte[] decryptLayerNBlock(IBPEPublicParameters params, byte[] A_ID, Element sk_A, IBPECiphertextLayerN ct2) throws Exception
	{
		// K = e(H1(P_ID), sk_A)
		Element K_ = pairing.pairing(IBProxyReencryptionModule.H1(ct2.ID), sk_A);

		// sigma_ = B * e(A, H2(K || P_ID || A_ID || N))
		byte[] concatArray = new byte[K_.toBytes().length + ct2.ID.length + A_ID.length + ct2._N.length];
		int ii = 0;
		for (int i = 0; i < K_.toBytes().length; i++)
		{
			concatArray[ii++] = K_.toBytes()[i];
		}
		for (int i = 0; i < ct2.ID.length; i++)
		{
			concatArray[ii++] = ct2.ID[i];
		}
		for (int i = 0; i < A_ID.length; i++)
		{
			concatArray[ii++] = A_ID[i];
		}
		for (int i = 0; i < ct2._N.length; i++)
		{
			concatArray[ii++] = ct2._N[i];
		}
		Element sigma_ = ct2._B.duplicate().mul(pairing.pairing(ct2._A.duplicate(), IBProxyReencryptionModule.H2(concatArray)));

		// m' = C XOR (H5(sigma'))
		byte[] M_ = IBProxyReencryptionModule.XOR(ct2._C, IBProxyReencryptionModule.H5(sigma_));

		// r' = H4(sigma', m')
		Element r_ = IBProxyReencryptionModule.H4(sigma_, M_);

		// Verification... possibly throws an exception if it fails.
		if (!(Arrays.equals(ct2._A.toBytes(), g.duplicate().powZn(r_).toBytes())))
		{
			throw new Exception("Decryption verification did not pass.");
		}

		return M_;
	}

}