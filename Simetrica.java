import java.io.*;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.params.KeyParameter;

public class Simetrica {

	
	public void generarClave(String ficheroClave) throws IOException {
		CipherKeyGenerator genClave = new CipherKeyGenerator();
		genClave.init(new KeyGenerationParameters(new SecureRandom(), 256));
		byte[] claveBytes = Hex.encode(genClave.generateKey()); 
		BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(ficheroClave));
		try {
			salida.write(claveBytes);
			salida.close();
		} catch (IOException e) {
			System.out.println(e);
		} finally {
			
		}
	}
	public void cifrar(String ficheroClave, String ficheroEntrada, String ficheroSalida) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
		try {
		
		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
		BufferedInputStream entradaFicheroEntrada = new BufferedInputStream(new FileInputStream(ficheroEntrada));
		BufferedOutputStream salidaFicheroSalida = new BufferedOutputStream(new FileOutputStream(ficheroSalida));
		cifrador.init(true, leerClave(ficheroClave));
		byte[] bytes = new byte[cifrador.getBlockSize()];
		byte[] bytesCifrado = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
		int leidos = 0;
		int cifrados = 0;
		while ((leidos = entradaFicheroEntrada.read(bytes, 0, cifrador.getBlockSize())) > 0) {
			System.out.println("Leídos: " + leidos);
			cifrados = cifrador.processBytes(bytes, 0, leidos, bytesCifrado, 0);
			System.out.println("Cifrados: " + cifrados);
			salidaFicheroSalida.write(bytesCifrado, 0, cifrados);
		}

		cifrados = cifrador.doFinal(bytesCifrado, 0);
		System.out.println("doFinal!");
		System.out.println(cifrados);
		salidaFicheroSalida.write(bytesCifrado, 0, cifrados);

		entradaFicheroEntrada.close();
		salidaFicheroSalida.close();
		
		
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void descifrar(String ficheroClave, String ficheroEntrada, String ficheroSalida) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
		try {
		
		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
		BufferedInputStream entradaFicheroEntrada = new BufferedInputStream(new FileInputStream(ficheroEntrada));
		BufferedOutputStream salidaFicheroSalida = new BufferedOutputStream(new FileOutputStream(ficheroSalida));
		cifrador.init(false, leerClave(ficheroClave));
		byte[] bytes = new byte[cifrador.getBlockSize()];
		byte[] bytesCifrado = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
		int leidos = 0;
		int cifrados = 0;
		while ((leidos = entradaFicheroEntrada.read(bytes, 0, cifrador.getBlockSize())) > 0) {
			System.out.println("Leídos: " + leidos);
			cifrados = cifrador.processBytes(bytes, 0, leidos, bytesCifrado, 0);
			System.out.println("Cifrados: " + cifrados);
			salidaFicheroSalida.write(bytesCifrado, 0, cifrados);
		}

		cifrados = cifrador.doFinal(bytesCifrado, 0);
		System.out.println("doFinal!");
		System.out.println(cifrados);
		salidaFicheroSalida.write(bytesCifrado, 0, cifrados);

		entradaFicheroEntrada.close();
		salidaFicheroSalida.close();
		
		
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	public KeyParameter leerClave(String ficheroClave) throws IOException {
		KeyParameter claveParametro = null;
		BufferedReader entradaClave = new BufferedReader(new FileReader(ficheroClave));
		try {
			claveParametro = new KeyParameter(Hex.decode(entradaClave.readLine()));
		} catch (Exception e) {
			System.out.println(e);
		} finally {
			entradaClave.close();
		}
		return claveParametro;
	}
}
