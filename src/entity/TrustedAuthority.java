package entity;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Vector;

import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;

public class TrustedAuthority {
	
	private ElGamalPublicKey pk_ta;
	private ElGamalPrivateKey sk_ta;
	private ElGamalPublicKey PKEPH;
	private ElGamalPrivateKey SKEPH;
	private Hashtable<Integer, ReputationItem> RL;
	private Hashtable<BigInteger, Integer> PL;
	private int bitLength;
	private BigInteger g;
	private BigInteger p;
	
	public TrustedAuthority(int bitLength)
	{
		this.bitLength = bitLength;
		

		KeyPair TAKP = GenerateElGamalKeyPair(null, null);
		pk_ta = (ElGamalPublicKey)TAKP.getPublic();
		sk_ta = (ElGamalPrivateKey)TAKP.getPrivate();
		RL = new Hashtable<>();
		g = pk_ta.getG();
		p = pk_ta.getP();
	}
	
	public KeyPair Registration(int V_i)
	{
		return Registration(V_i, 0);
	}
	
	public KeyPair Registration(int V_i, int r_i)
	{
		// we take the first generated g as the 'shared among entities'
		var keypair = GenerateElGamalKeyPair(g, p);
		
		var y_i = (ElGamalPublicKey)keypair.getPublic();
		var x_i = (ElGamalPrivateKey)keypair.getPrivate();
//		int r_i = 0;
		RL.put(V_i, new ReputationItem(y_i, x_i, r_i));
		return keypair;
	}
	
	public void ResetRL()
	{
		RL = new Hashtable<>();
	}
	
	public Hashtable<BigInteger, Integer> GeneratePseudonymList()
	{
		// Initialises ephemeral keys
		var keypair = GenerateElGamalKeyPair(g, p);
		PKEPH = (ElGamalPublicKey) keypair.getPublic();
		SKEPH = (ElGamalPrivateKey) keypair.getPrivate();
		
		PL = new Hashtable<BigInteger, Integer>();
		for (int V_i : RL.keySet())
		{
			var RL_i = RL.get(V_i);
			var r_i = RL_i.GetScore();
			var pk_i = RL_i.GetY();
			var p = pk_i.getP();
			var y_i = pk_i.getH(); // h === g^sk
			var sk_eph = SKEPH.getX();// x === sk
			var pid_i = y_i.modPow(sk_eph, p);
			
			// testing pk_eph ^ x_i
//			var pk_eph = PKEPH.getH(); // h === g^sk
//			var x_i = RL_i.GetX().getX(); // first getX gets the sk object, second getX gets the actual x === sk
//			var another_pid_i = pk_eph.modPow(x_i, p);
//			if (pid_i.equals(another_pid_i))
//				System.out.println("hooray we got the same one.");
			PL.put(pid_i, r_i);
			System.out.println("PL: pid size = " + pid_i.bitLength() + ", r size = 4 bytes.");
			
		}
		return PL;
	}
	
	public ElGamalPublicKey getPKEPH()
	{
		return this.PKEPH;
	}
	public ElGamalPrivateKey getSKEPH()
	{
		return this.SKEPH;
	}
	
	public ElGamalPublicKey getPKTA()
	{
		return this.pk_ta;
	}
	public ElGamalPrivateKey getSKTA()
	{
		return this.sk_ta;
	}
	
	private KeyPair GenerateElGamalKeyPair(BigInteger g, BigInteger p)
	{
		ElGamalKeyPairGenerator TA = new ElGamalKeyPairGenerator();
		TA.initialize(this.bitLength, new SecureRandom());
		if (g != null)
			return TA.generateKeyPair(g, p);
		return TA.generateKeyPair();
	}
	
	
	private class ReputationItem {
		private ElGamalPublicKey PK;
		private ElGamalPrivateKey SK;
		private int score;
		
		public ReputationItem(ElGamalPublicKey PK, ElGamalPrivateKey SK, int score)
		{
			this.PK = PK;
			this.SK = SK;
			this.score = score;
		}
		
		public ElGamalPublicKey GetY()
		{
			return this.PK;
		}
		
		public ElGamalPrivateKey GetX()
		{
			return this.SK;
		}
		
		public int GetScore()
		{
			return this.score;
		}
	}

}
