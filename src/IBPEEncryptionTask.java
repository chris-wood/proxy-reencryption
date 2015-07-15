import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class IBPEEncryptionTask 
{
	private int n;
	private int blockSize;
	private Pairing pairing;
	private Field G1;
	private Field GT;
	private Field Zr;
	private Element g;
	private Element g_s;
	private Element s;

	public IBPEEncryptionTask(int n, int blockSize, Pairing pairing, Element g, Element g_s, Element s)
	{
		this.n = n;
		this.blockSize = blockSize;
		this.pairing = pairing;
		this.G1 = pairing.getG1();
		this.GT = pairing.getGT();
		this.Zr = pairing.getZr();
		this.g = g;
		this.g_s = g_s;
		this.s = s;
	}

	public IBPECiphertextLayerOne[] encrypt(IBPEPublicParameters params, byte[] P_ID, byte[] Mblock) throws Exception
	{
		int blocks = Mblock.length / n;
		int rem = Mblock.length % n;
		IBPECiphertextLayerOne[] cts = rem == 0 ? new IBPECiphertextLayerOne[blocks] : new IBPECiphertextLayerOne[blocks + 1];

		// Encrypt each full block
		for (int b = 0; b < blocks; b++)
		{
			cts[b] = encryptBlock(params, P_ID, Arrays.copyOfRange(Mblock, b * n, (b + 1) * n)); // go up to the end and then pad
		}
		
		// Pad the last block and encrypt, if necessary
		if (rem != 0)
		{
			cts[blocks] = encryptBlock(params, P_ID, pad(Arrays.copyOfRange(Mblock, blocks * n, (blocks + 1) * n)));
		}

		return cts;
	}

	private byte[] pad(byte[] m)
	{
		byte[] m_ = new byte[n];
		for (int i = 0; i < m.length; i++)
		{
			m_[i] = m[i];
		}
		for (int i = 0; i < (n - m.length); i++)
		{
			m_[i] = 0; // pad with 0s
		}
		return m_;
	}

	////////////////////////////////
	// Encrypt(params, P_ID, m)
	////////////////////////////////
	private IBPECiphertextLayerOne encryptBlock(IBPEPublicParameters params, byte[] P_ID, byte[] M) throws Exception
	{
		// sigma Random(GT)
		Element sigma = GT.newRandomElement();

		// r = H4(sigma, m)
		Element r = IBProxyReencryptionModule.H4(sigma, M);

		// A = g^r
		Element A = g.duplicate().powZn(r);

		// B = sigma * e(g^s, H1(ID)^r)
		Element B = sigma.duplicate().mul(pairing.pairing(g_s, IBProxyReencryptionModule.H1(P_ID).powZn(r)));

		// C = m XOR H5(sigma)
		byte[] C = IBProxyReencryptionModule.XOR(M, IBProxyReencryptionModule.H5(sigma));

		// C' = Cbytes, where
		// Cbytes is the array of bytes representing: (A, B, C)
		byte[] Cbytes = new byte[P_ID.length + A.toBytes().length + B.toBytes().length + C.length];
		int ii = 0;
		for (int i = 0; i < P_ID.length; i++)
		{
			Cbytes[ii++] = P_ID[i];	
		}
		for (int i = 0; i < A.toBytes().length; i++)
		{
			Cbytes[ii++] = A.toBytes()[i];
		}
		for (int i = 0; i < B.toBytes().length; i++)
		{
			Cbytes[ii++] = B.toBytes()[i];	
		}
		for (int i = 0; i < C.length; i++)
		{
			Cbytes[ii++] = C[i];
		}
		Element S = IBProxyReencryptionModule.H3(Cbytes).powZn(r);
		IBPECiphertextLayerOne ct = new IBPECiphertextLayerOne(S, A, B, C); 
		return ct;
	}
}
