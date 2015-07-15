import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBPEReencryptionTask 
{
	private int n;
	private int blockSize;
	private Pairing pairing;
	private Field G1;
	private Field GT;
	private Field Zr;
	private Element g;
	private Element g_s;

	public IBPEReencryptionTask(int n, int blockSize, Pairing pairing, Element g, Element g_s)
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

	////////////////////////////////
	// Reencrypt(params, rk, ct(P_ID))
	////////////////////////////////
	public IBPECiphertextLayerN[] reencrypt(IBPEPublicParameters params, byte[] P_ID, IBPEConversionKey rk, IBPECiphertextLayerOne[] ctBlocks) throws Exception
	{
		int blocks = ctBlocks.length / n;
		IBPECiphertextLayerN[] cts = new IBPECiphertextLayerN[blocks];

		// Reencrypt each block
		for (int b = 0; b < blocks; b++)
		{
			cts[b] = reencryptBlock(params, P_ID, rk, ctBlocks[b]);
		}

		return cts;
	}

	////////////////////////////////
	// Encrypt(params, P_ID, m)
	////////////////////////////////
	private IBPECiphertextLayerN reencryptBlock(IBPEPublicParameters params, byte[] P_ID, IBPEConversionKey rk, IBPECiphertextLayerOne ct) throws Exception
	{
		byte[] concatArray = new byte[P_ID.length + ct._A.toBytes().length + ct._B.toBytes().length + ct._C.length];
		int ii = 0;
		for (int i = 0; i < P_ID.length; i++)
		{
			concatArray[ii++] = P_ID[i];	
		}
		for (int i = 0; i < ct._A.toBytes().length; i++)
		{
			concatArray[ii++] = ct._A.toBytes()[i];
		}
		for (int i = 0; i < ct._B.toBytes().length; i++)
		{
			concatArray[ii++] = ct._B.toBytes()[i];	
		}
		for (int i = 0; i < ct._C.length; i++)
		{
			concatArray[ii++] = ct._C[i];	
		}
		Element h = IBProxyReencryptionModule.H3(concatArray);
		if (!(Arrays.equals(pairing.pairing(g.duplicate(), ct._S.duplicate()).toBytes(), pairing.pairing(h.duplicate(), ct._A.duplicate()).toBytes())))
		{
			throw new Exception("Verification failed during reencryption.");
		}

		// t = Random(Zq)
		Element t = Zr.newRandomElement();

		// B' = B / (e(A, R * h^t) / e(g^t, S))
		Element B_ = ct._B.duplicate().div(
			pairing.pairing(ct._A.duplicate(), rk._R.duplicate().mul(h.powZn(t))).div(
				pairing.pairing(g.duplicate().powZn(t), ct._S.duplicate())
				));

		IBPECiphertextLayerN ct2 = new IBPECiphertextLayerN(ct._A, B_, ct._C, P_ID, rk._N);
		return ct2;
	}
}
