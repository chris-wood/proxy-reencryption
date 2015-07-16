public class Principal 
{
	private Identity identity;
	private Element secretKey;

	public Principal(Identity id) 
	{
		this.identity = id;
		this.secretKey = null; // key generator
	}
}