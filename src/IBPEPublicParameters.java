// jPBC library classes
import it.unisa.dia.gas.jpbc.Element;

public class IBPEPublicParameters
{
	public Element g;   // g
	public Element gps; // g^s
	public IBPEPublicParameters(Element g, Element gps) { this.g = g.duplicate(); this.gps = gps.duplicate(); }
	@Override
	public String toString()
	{
		StringBuilder b = new StringBuilder();
		b.append("g: " + g.toString() + "\n");
		b.append("g^s: " + gps.toString());
		return b.toString();
	}
}