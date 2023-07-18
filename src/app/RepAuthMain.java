package app;

import java.lang.instrument.Instrumentation;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import entity.TrustedAuthority;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;

public class RepAuthMain {
	
	private static ElGamalPublicKey PKEPH;
	private static ElGamalPrivateKey SKEPH;
	
	public static void main(String[] args) throws SignatureException, InvalidKeyException
	{
		// bftest();
		// bftestactual();
		// xortest();
//		 expinv128test();
//		expinv2048test();
//		expinvtest();
		
		// TA generates its master secret key sk_ta and pk_ta
		TrustedAuthority TA = new TrustedAuthority(1024);
		var PKTA = TA.getPKTA();
		var SKTA = TA.getSKTA();
		// a new user registers
		int V_i = 0;
		int cnt = 0;
		
		long start, end = 0;

		start = System.nanoTime();
		var xy_i = TA.Registration(999, 100);
		end = System.nanoTime();
		System.out.println("time spent on reg = " + (end - start) + " with " + cnt + " users.");
		// here we get PL
		start = System.nanoTime();
		var PL = TA.GeneratePseudonymList();
		end = System.nanoTime();
		System.out.println("time spent on release = " + (end - start) + " with " + cnt + " users.");
		// we can get the pk_eph afterwards
		PKEPH = TA.getPKEPH();
		SKEPH = TA.getSKEPH();
		var p = PKEPH.getP();
		var g = PKEPH.getG();
		var q = PKEPH.getQ();
		// try if we can find the reputation score based on xy_i
		start = System.nanoTime();
		getCurrentReputationScore(xy_i, PL);
		end = System.nanoTime();
		System.out.println("time spent on get current rep score = " + (end - start) + " ns. ");
		
		
		// Message Posting 
		BigInteger m_i = BigInteger.valueOf(10);
		String mStr = m_i.toString() + "," + String.valueOf(System.nanoTime());
		ElGamalSignature elgamal_sign = new ElGamalSignature();
		elgamal_sign.initSign((ElGamalPrivateKey)xy_i.getPrivate());
		start = System.nanoTime();
		var mStrArr = mStr.getBytes();
		elgamal_sign.update(mStrArr);
		byte[] S = elgamal_sign.sign();
		
		end = System.nanoTime();
		System.out.println("time spent on message posting: " + (end - start) + " ns.");
		System.out.println("msg post size = " + S.length * 8);
		
		
		// Message Verifying
		start = System.nanoTime();
		elgamal_sign.initVerify((ElGamalPublicKey)xy_i.getPublic());
		var result = elgamal_sign.verify(S);
		if(result == true)
			System.out.println("S is valid...");
		
		end = System.nanoTime();
		System.out.println("time spent on message verifying: " + (end - start) + " ns.");
		
		
		// Feedback Sending
		start = System.nanoTime();
		BigInteger F = BigInteger.valueOf(1);
		BigInteger l = BigInteger.valueOf(new SecureRandom().nextLong());
		var pk_eph = PKEPH.getH();
		var pk_ta = PKTA.getH();
		var x_j = ((ElGamalPrivateKey)xy_i.getPrivate()).getX();
		var C_1 = pk_eph.modPow(l, p);
		var gFx_i = g.modPow(x_j.multiply(F), p);
		var C_2 = (gFx_i.multiply(pk_ta.modPow(l, p))).mod(p);
		end = System.nanoTime();
		System.out.println("time spent on feedback sending: " + (end - start) + " ns.");
		System.out.println("fb send size C1 = " + C_1.bitLength() + ", C2 = " + C_2.bitLength());
		
		// Feedback Verifying
		start = System.nanoTime();
		var sk_ta = SKTA.getX();
		var sk_eph = SKEPH.getX();
		var sk_eph_1 = sk_eph.modInverse(q); // be careful, if you do g^e1 * e1^(-1), you need to mod q for the inverse
//		System.out.println("g = " + g);
//		System.out.println("p = " + p);
		var gskeph = g.modPow(sk_eph, p);
//		System.out.println("g^sk_eph = " + gskeph);
		gskeph = gskeph.modPow(sk_eph_1, p);
//		System.out.println("g^sk_eph^-1 = " + gskeph);
		var gFx_ii = (C_1.modPow(sk_eph_1, p).modPow(sk_ta, p).modInverse(p)).multiply(C_2).mod(p);
		end = System.nanoTime();
		System.out.println("time spent on feedback verifying srv: " + (end - start) + " ms.");
		
		start = System.nanoTime();
		var pid1 = g.modPow(sk_eph, p).modPow(x_j, p).modPow(sk_eph.modInverse(q), p);
		var pid2 = pid1.modPow(BigInteger.valueOf((-1)), p);
		var realF = 0;
		if (gFx_ii.equals(pid1))
		{ System.out.println("realF = 1"); realF = 1; }
		else if (gFx_ii.equals(pid2))
		{ System.out.println("realF = -1"); realF = -1; }
			
		end = System.nanoTime();
		System.out.println("time spent on feedback verifying cli: " + (end - start) + " ms.");
	}
	
	public static Integer getCurrentReputationScore(
			KeyPair keypair, 
			Hashtable<BigInteger, Integer> PL)
	{
		var pk_eph = PKEPH.getH(); // h === g^sk
		var p = PKEPH.getP(); // doesn't matter where to get p as they are the same
		var x_i = ((ElGamalPrivateKey)keypair.getPrivate()).getX(); // first getX gets the sk object, second getX gets the actual x === sk
		var pid_i = pk_eph.modPow(x_i, p);
		
		for (var pid : PL.keySet())
		{
			if (pid_i.equals(pid))
				{ System.out.println("found, score = " + PL.get(pid)); return PL.get(pid); }
		}
		
		return null;
	}
	
	public static void bftest()
	{
		BloomFilter<String> filter = BloomFilter.create(
				  Funnels.stringFunnel(StandardCharsets.UTF_8),
				  500,
				  0.01);
		String test = "";
		for (int i = 0; i < 128; i++)
			test += "0";
		filter.put(test);
		long start = System.nanoTime();
		filter.mightContain(test);
		System.out.println("bf.mightContain = " + (System.nanoTime() - start) + " ns.");
	}
	
	public static void bftestactual()
	{
//		int size [] = {270, 245, 20, 6, 10, 16, 78, 457, 1535, 1837, 2173, 1442, 1091, 869, 785, 796, 812, 860, 845, 457, 582, 364, 166, 338 };
		int size[] = {100000, 1000000, 5000000, 7500000, 10000000};
		double fpp[] = {0.001, 0.0001, 0.00001};
		int base[] = {10000000};
		 for (var b : base){
			 int i = 0;
			for (var f : fpp) {
				System.out.println("fpp = " + f + ", container size = " + b);
				for(var s : size)
					{bftest2(i++, s, b, f);}
				i = 0;
				System.out.println();
			}
			
			}
	}
	public static void bftest2(int ind, int size, int base, double fpp)
	{
		var expectedIns = size ;
		BloomFilter<String> filter = BloomFilter.create(
				Funnels.stringFunnel(StandardCharsets.UTF_8),
				base,
				fpp);
		
		List<String> testData = new ArrayList<>();
		List<String> validateData_1 = new ArrayList<>();
		List<String> validateData_2 = new ArrayList<>();
		SecureRandom rand = new SecureRandom();
		// populate dataset
		for (int i = 0 ; i < size; i++)
			testData.add("" + i);
		
		for (var d : testData)
			filter.put(d);
		
		for (int i = size; i < (size + (size*0.5)); i++)
		{
			// populate validate data
			validateData_1.add("" + i);
		}	
//		for (int i = 0; i < (size*0.5); i++)
//		{
//			while (true) 
//			{
//				// randomly get one from testData
//				var testDataOne = testData.get(rand.nextInt(size));
//				// if it's been added, ignore it
//				if (validateData_2.contains(testDataOne))
//					continue;
//				// otherwise, add the test data into validate data
//				validateData_2.add(testDataOne);
//				break;
//			}
//		}
		double err = 0;
		for (var test : validateData_1)
			err += filter.mightContain(test) == true ? 1 : 0;
//		for (var test : validateData_2)
//			err += filter.mightContain(test) == true ? 0 : 1;
		
//		validateData_2 = null;
//		validateData_1 = null;
//		testData = null;
//		var mem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		var mem = 0;
		// System.out.println(Double.toString(filter.expectedFpp()));
		//System.out.println("BF size = " + base + ", dataset size = " + size + ", fpp = " + fpp + ", errcnt = " + err + ", err = " + (1 - (err / validateData_1.size())));
		System.out.println("(" + size + ", " + (1- (err/validateData_1.size())) + ")");
	}
	
	public static void xortest()
	{
		
		long a = 12345678;
		long b = 23456789;
		long start = System.nanoTime();
		long c = a ^ b;
		long end = System.nanoTime();
		System.out.println("xor time = " + (end - start) + " ns.");
	}
	
	public static void expinvtest()
	{
		BigInteger a = new BigInteger("7698051292189105152011075681074412258971432474727007651117095957652026556890394553191560758005512306331143272955560748101162161036302103693248462706552193495017054593950131975566800723681177087376148848946731304272587779022198358107974362660674733220233684119887660169371413559969278623182375387539475321510764820872953065581851523090206949097864102446013293204059931779255444042651427549293700558930984909749418588727412789162114696600273118338176014488602106473074467808186342495368579745034592186729696455963665379719333734166149895771349305990932102668032425925342723629360770817968641005913001843275249645098288921976704350416155890696455902365157659023515539254859118295013447640319656952287990822054709518348644437996695552116340451930946623694388919141420222926746605040682871669683285108677387893085728217865197252581011274415892787007954048344918983888683585629690729312095802350436548821545330219344435805909415143");
		BigInteger b = new BigInteger("4187063795304945396682665236710587486845868790465231813019723965964118590260561577861387101427634962055340830115201898929733085278523491875806503507157136226687624211733537346201534105547312809619638949052649945462706186581306316872813040010973142744215642486455666735572562819131344065899410640260613631504653976327992996557699167790536237960999494316792415025526720277056532660111553938761979516819223751493645370514500566417835927122144582749623694482545894048775007791939299914577555586328741359540890608276552995608126945547740256593526972966864519424132801586465771228972911542874967195740510524931908398099722400373656129169996512180673974711826946590964674945494182972218584267811220714296722987568540606794281503979216004963208390019400608722826787074544585379735106128126603296923979991560133565957506082339438590348263961463964926485672118896658475966076312127203606878984646818317396611624757573550309405856030163");
		BigInteger p = new BigInteger("3849025646094552576005537840537206129485716237363503825558547978826013278445197276595780379002756153165571636477780374050581080518151051846624231353276096747508527296975065987783400361840588543688074424473365652136293889511099179053987181330337366610116842059943830084685706779984639311591187693769737660755382410436476532790925761545103474548932051223006646602029965889627722021325713774646850279465492454874709294363706394581057348300136559169088007244301053236537233904093171247684289872517296093364848227981832689859666867083074947885674652995466051334016212962671361814680385408984320502956500921637624822549144460988352175208077945348227951182578829511757769627429559147506723820159828476143995411027354759174322218998347776058170225965473311847194459570710111463373302520341435834841642554338693946542864108932598626290505637207946393503977024172459491944341792814845364656047901175218274410772665109672217902954707571");
		System.out.println("sizeof (a) = " + a.bitLength() + ", sizeof(b) = " + b.bitLength() + ", sizeof(p) = " + p.bitLength());
		System.out.println("exp = a^b mod p");
		long start, end = 0;
		start = System.currentTimeMillis();
		a.modPow(b, p);
		end = System.currentTimeMillis();
		System.out.println("exp = " + (end - start) + " ms.");
		
		System.out.println("inv = a^-1 mod p");
		start = System.currentTimeMillis();
		a.modInverse(p);
		end = System.currentTimeMillis();
		System.out.println("inv = " + (end - start) + " ms.");
	
	}
	
	public static void expinv2048test()
	{
		BigInteger a = new BigInteger("61531496354704146606811874991978874589232593453139093167517114444301206066143945300526462317419305600899501008287950670009303791867051741040765244746000075925396225657999147273981270320046932629421127712551971055560523626082366177065881165665838992174002465912879559919346403448416306643199496933861310164498798833210833706413589608210892119906690744424053813711423580336813198537628385346136504419132673641742240886489265910325448482054714037265420756673969036829269349695209768905303614390823526195903438999469206338290759044381780879778236653343842577957146104077891672987366000085331055363925813371640030207438572");
		BigInteger b = new BigInteger("62332909923914846448346856647267949094249596149816421807597916331333695449863998660979284866590834030507717115029576626862084869680346215934329070196076723523602622219838139879475409654091685040776689981568752824391711306555822622975773422879766753040793965909833196931374257061284644002454106078149043955865038530484765787026059788950329079750477313962018809192132946650186538823756659394764407439351715498030919394973958773062081991964857328240175337987323356882451049586541692132618548697650113491879694381034375068847695340619362442867614333527715760971854885509633011767079473545450387153307181084307447491793759");
		BigInteger p = new BigInteger("31166454961957423224173428323633974547124798074908210903798958165666847724931999330489642433295417015253858557514788313431042434840173107967164535098038361761801311109919069939737704827045842520388344990784376412195855653277911311487886711439883376520396982954916598465687128530642322001227053039074521977932519265242382893513029894475164539875238656981009404596066473325093269411878329697382203719675857749015459697486979386531040995982428664120087668993661678441225524793270846066309274348825056745939847190517187534423847670309681221433807166763857880485927442754816505883539736772725193576653590542153723745896879");
		System.out.println("sizeof (a) = " + a.bitLength() + ", sizeof(b) = " + b.bitLength() + ", sizeof(p) = " + p.bitLength());
		System.out.println("exp = a^b mod p");
		long start, end = 0;
		start = System.currentTimeMillis();
		a.modPow(b, p);
		end = System.currentTimeMillis();
		System.out.println("exp = " + (end - start) + " ms.");
		
		System.out.println("inv = a^-1 mod p");
		start = System.currentTimeMillis();
		a.modInverse(p);
		end = System.currentTimeMillis();
		System.out.println("inv = " + (end - start) + " ms.");
	
	}
	
	public static void expinv128test()
	{
		var rand = new SecureRandom();
		BigInteger a = new BigInteger(1024, rand);
		BigInteger b = new BigInteger(1024, rand);
		BigInteger p = new BigInteger(1024, rand);
		System.out.println("sizeof (a) = " + a.bitLength() + ", sizeof(b) = " + b.bitLength() + ", sizeof(p) = " + p.bitLength());
		System.out.println("exp = a^b mod p");
		long start, end = 0;
		start = System.currentTimeMillis();
		a.modPow(b, p);
		end = System.currentTimeMillis();
		System.out.println("exp = " + (end - start) + " ms.");
		
		System.out.println("inv = a^-1 mod p");
		start = System.currentTimeMillis();
		a.modInverse(p);
		end = System.currentTimeMillis();
		System.out.println("inv = " + (end - start) + " ms.");
		
	}
	
	public static void ecctest()
	{
		try {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");

        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        /*
         * Create a Signature object and initialize it with the private key
         */

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");

        ecdsa.initSign(priv);

        String str = "This is string to sign";
        byte[] strByte = str.getBytes("UTF-8");
        ecdsa.update(strByte);

        /*
         * Now that all the data to be signed has been read in, generate a
         * signature for it
         */

        byte[] realSig = ecdsa.sign();
        System.out.println("Signature: " + new BigInteger(1, realSig).toString(16));
		}
		catch (Exception e) {}
	}
	
	public static void test() 
	{
		ElGamalKeyPairGenerator TA = new ElGamalKeyPairGenerator();
		TA.initialize(2048, new SecureRandom());
		KeyPair TAKP = TA.generateKeyPair();
		ElGamalPublicKey PK_sa = (ElGamalPublicKey) TAKP.getPublic();
		ElGamalPrivateKey SK_sa = (ElGamalPrivateKey) TAKP.getPrivate();
		
		
		BigInteger message = BigInteger.valueOf(10);
		long start = System.currentTimeMillis();
		ElGamal_Ciphertext c = ElGamalCipher.encrypt(message, PK_sa);
		System.out.println("Paillier enc = " + (System.currentTimeMillis() - start) + " ms.");
		start = System.currentTimeMillis();
		BigInteger m = ElGamalCipher.decrypt(c, SK_sa);
		System.out.println("Paillier dec = " + (System.currentTimeMillis() - start) + " ms.");
		int cnt = 0;
//		while (cnt < 1000) {
//		ElGamalSignature elgamal_sign = new ElGamalSignature();
//		try {
//			cnt++;
//			elgamal_sign.initSign(SK_sa);
//			elgamal_sign.update(BigInteger.valueOf(cnt).toByteArray());
//			byte[] signed_answer = elgamal_sign.sign();
//			
//			elgamal_sign.initVerify(PK_sa);
//			if(elgamal_sign.verify(signed_answer))
//				System.out.println("test verify passed. " + cnt);
//		} catch (InvalidKeyException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (SignatureException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		}

	}

}
