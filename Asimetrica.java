import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public class Asimetrica {

	private static int BITS_CLAVES = 1024;
	private static int CERTAINTY = 10;//Probabilidad de error de que sean o no primos
	private static int EXPONENTE = 3;
	
	public static void generarClaves(String nombrePrivada, String nombrePublica) throws IOException{
		
		//Generar las claves
		AsymmetricCipherKeyPairGenerator generadorDeClaves = new RSAKeyPairGenerator();
		KeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(EXPONENTE),new SecureRandom(), BITS_CLAVES, CERTAINTY);
		AsymmetricCipherKeyPair par;
		RSAKeyParameters privada, publica;
		
		generadorDeClaves.init(parametros);
		par = generadorDeClaves.generateKeyPair();
		privada = (RSAKeyParameters) par.getPrivate();
		publica = (RSAKeyParameters) par.getPublic();
		
		//Guardar las claves en hexadecimal en ficheros
		OutputStream ficheroPublica = new FileOutputStream(nombrePublica),
					 ficheroPrivada = new FileOutputStream(nombrePrivada);
		byte[] moduloPrivada = privada.getModulus().toByteArray(), 
			   moduloPublica = publica.getModulus().toByteArray(), 
			   intro = "\r\n".getBytes();
		
		Hex.encode(moduloPrivada, ficheroPrivada);
		try {ficheroPrivada.write(intro);
		Hex.encode(privada.getExponent().toByteArray(),ficheroPrivada);}
		finally{ficheroPrivada.close();}
	
		Hex.encode(moduloPublica, ficheroPublica);
		try{ficheroPublica.write(intro);
		Hex.encode(publica.getExponent().toByteArray(),ficheroPublica);}
		finally{ficheroPublica.close();}
		
		//Guardarlas con el formato PEM
		GuardarFormatoPEM pem = new GuardarFormatoPEM();
		pem.guardarClavesPEM(publica, privada);
	}
	
	public static void cifrar(Boolean esPrivada, String n_clave, String n_entrada, String n_salida) throws IOException, InvalidCipherTextException{
		
		//Obtener la clave
		RSAKeyParameters clave;
		BufferedReader ficheroClave = new BufferedReader(new FileReader(n_clave));
		BigInteger modulo = new BigInteger(Hex.decode(ficheroClave.readLine())), 
				   exponente = new BigInteger(Hex.decode(ficheroClave.readLine())); 
		
		ficheroClave.close();
		clave = new RSAKeyParameters(esPrivada, modulo, exponente);
		
		//Leer el fichero de entrada
		BufferedInputStream f_entrada = new BufferedInputStream(new FileInputStream(n_entrada));
		BufferedOutputStream f_salida = new BufferedOutputStream(new FileOutputStream(n_salida));
		
		
		//Crifrar
		PKCS1Encoding cifrador = new PKCS1Encoding(new RSAEngine());
		cifrador.init(true, clave);
		byte[] entrada = new byte[cifrador.getInputBlockSize()];
		byte[] salida = new byte[cifrador.getOutputBlockSize()];
		
		try{
			int leidos = f_entrada.read(entrada, 0, entrada.length);
			while(leidos > 0) {
				salida = cifrador.processBlock(entrada, 0, leidos);
				f_salida.write(salida, 0, salida.length);
				leidos = f_entrada.read(entrada, 0, entrada.length);
			}
		} finally{
			f_entrada.close();
			f_salida.close();
		}
	}
public static void descifrar(Boolean esPrivada, String n_clave, String n_entrada, String n_salida) throws IOException, InvalidCipherTextException{
		
		//Obtener la clave
		RSAKeyParameters clave;
		BufferedReader ficheroClave = new BufferedReader(new FileReader(n_clave));
		BigInteger modulo = new BigInteger(Hex.decode(ficheroClave.readLine())), 
				   exponente = new BigInteger(Hex.decode(ficheroClave.readLine())); 
		
		ficheroClave.close();
		clave = new RSAKeyParameters(esPrivada, modulo, exponente);
		
		//Leer el fichero de entrada
		BufferedInputStream f_entrada = new BufferedInputStream(new FileInputStream(n_entrada));
		BufferedOutputStream f_salida = new BufferedOutputStream(new FileOutputStream(n_salida));
		
		
		//Crifrar
		PKCS1Encoding cifrador = new PKCS1Encoding(new RSAEngine());
		cifrador.init(false, clave);
		byte[] entrada = new byte[cifrador.getInputBlockSize()];
		byte[] salida = new byte[cifrador.getOutputBlockSize()];
		
		try{
			int leidos = f_entrada.read(entrada, 0, entrada.length);
			while(leidos > 0) {
				salida = cifrador.processBlock(entrada, 0, leidos);
				f_salida.write(salida, 0, salida.length);
				leidos = f_entrada.read(entrada, 0, entrada.length);
			}
		} finally{
			f_entrada.close();
			f_salida.close();
		}
	}
	public static void firmar(String n_clave, String n_entrada, String n_salida) throws IOException, InvalidCipherTextException{
		InputStream lector = new FileInputStream(n_entrada);
		OutputStream f_salida = new FileOutputStream(n_salida+"_sincifrar");
		SHA256Digest d = new SHA256Digest();
		byte[] entrada = new byte[d.getDigestSize()], salida = new byte[d.getDigestSize()];
		
		//Leemos y generamos el hash
		try{
			int leidos=lector.read(entrada, 0, entrada.length);
			while(leidos>0) {
				d.update(entrada, 0, entrada.length);
				leidos=lector.read(entrada, 0, entrada.length);
			}
			leidos=d.doFinal(salida, 0);

		}finally {
			lector.close();
		}
		
		//Genero un fichero con el hash
		try {
			f_salida.write(salida, 0, salida.length);
		} finally{
			f_salida.close();
		}
		
		//Cifro el fichero del hash con la clave
		cifrar(true, n_clave, n_salida+"_sincifar", n_salida);
	}
	
	public static int comprobar(String n_clave, String n_hash, String n_fichero) throws IOException, InvalidCipherTextException{
		int resultado = 0;

		try {

			BufferedInputStream streamFicheroPlano = new BufferedInputStream(new FileInputStream(n_fichero));
			BufferedInputStream streamFicheroHash = new BufferedInputStream(new FileInputStream(n_hash));

			SHA256Digest hasher = new SHA256Digest();

			byte[] datos = new byte[hasher.getDigestSize()];
			byte[] hashCalculado = new byte[hasher.getDigestSize()];
			byte[] hashLeido = new byte[hasher.getDigestSize()];

			hasher.reset();

			int leyendo = 0;

			while ((leyendo = streamFicheroPlano.read(datos, 0, hasher.getDigestSize())) > -1) {
				hasher.update(datos, 0, datos.length);
			}
			hasher.doFinal(hashCalculado, 0);

			leyendo = 0;

			while ((leyendo = streamFicheroHash.read(hashLeido, 0, hasher.getDigestSize())) > -1) {
			}

			if (Arrays.equals(hashCalculado, hashLeido)) {
				resultado = 1;
				System.out.println("La firma coincide");
			} else {
				System.out.println("Firma incorrecta. Fichero original manipulado");
			}

			streamFicheroPlano.close();
			streamFicheroHash.close();

		} catch (IOException o) {
			System.out.println(o);

		}
		return resultado;
}

}



