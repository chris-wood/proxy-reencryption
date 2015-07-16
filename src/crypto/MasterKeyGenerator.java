import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class MasterKeyGenerator 
{
    public MasterKeyGenerator(String curveFile) 
    {
        IBProxyReencryptionModule pre = new IBProxyReencryptionModule(curveFile);
        
    }
}
