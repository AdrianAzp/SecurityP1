
/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author  Adrian
 * @version 1.0
 */

import java.io.IOException;
import java.util.Scanner;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Principal {

	public static void main (String [ ] args) {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		String nombreClave, nombreFichero, nombreCifrado, publica, privada, respuesta;
		Boolean esPrivada = null;
		Simetrica objSimetrico = new Simetrica();
		Asimetrica objAsimetrico = new Asimetrica();
		do {
			System.out.println("¿Qué tipo de criptografía desea utilizar?");
			System.out.println("1. Simétrico.");
			System.out.println("2. Asimétrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
			sc.nextLine();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
						sc.nextLine();
						
						switch(menu2){
							case 1:
								System.out.println("Introduce el nombre de la clave: ");
								nombreClave = sc.nextLine();
							try {
								objSimetrico.generarClave(nombreClave);
							} catch (IOException e2) {
								e2.printStackTrace();
							}
								System.out.println("La clave ha sido generada con éxito.\n");
							break;
							case 2:
								System.out.println("Introduce el nombre del archivo a cifrar: ");
								nombreFichero = sc.nextLine();
								System.out.println("Introduce el nombre del archivo cifrado resultante: ");
								nombreCifrado = sc.nextLine();
								System.out.println("Introduce el nombre de la clave para cifrar: ");
								nombreClave = sc.nextLine();
							try {
							//	objSimetrico.cifrar(ficheroClave, ficheroEntrada, ficheroSalida);
								objSimetrico.cifrar(nombreClave,nombreFichero, nombreCifrado);
							} catch (DataLengthException | IllegalStateException | InvalidCipherTextException | IOException e1) {
								e1.printStackTrace();
							}
							break;
							case 3:
								System.out.println("Introduce el nombre del archivo cifrado: ");
								nombreFichero = sc.nextLine();
								System.out.println("Introduce el nombre del archivo descifrado: ");
								nombreCifrado = sc.nextLine();
								System.out.println("Introduce el nombre de la clave para descifrar el archivo: ");
								nombreClave = sc.nextLine();
							try {
								//objSimetrico.descifrar(ficheroClave, ficheroEntrada, ficheroSalida);
								objSimetrico.descifrar(nombreClave,nombreFichero,  nombreCifrado);
							} catch (DataLengthException | IllegalStateException | InvalidCipherTextException | IOException e) {
								e.printStackTrace();
							}
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
						sc.nextLine();
				
						switch(menu2){
							case 1:
								System.out.println("Introduce un nombre para la clave privada:");
								privada = sc.nextLine();
								System.out.println("Introduce un nombre para la clave publica:");
								publica = sc.nextLine();
								
							try {
								objAsimetrico.generarClaves(privada, publica);
							} catch (IOException e) {
								e.printStackTrace();
							}
								
							break;
							case 2:
								System.out.println("Indique el nombre de la clave a utilizar por el cifrador:");
								nombreClave = sc.nextLine();
								System.out.println("¿Esta clave es privada? (y/n)");
								respuesta = sc.nextLine();
								
								if(respuesta.equals("y"))
									esPrivada = true;
								else if(respuesta.equals("n"))
									esPrivada = false;
								
								if(respuesta.equals("y") || respuesta.equals("n")){
									System.out.println("Introduce el nombre del archivo a cifrar:");
									nombreFichero = sc.nextLine();
									System.out.println("Introduce un nombre para el archivo cifrado:");
									nombreCifrado = sc.nextLine();
									
									try {
										objAsimetrico.cifrar(esPrivada, nombreClave, nombreFichero, nombreCifrado);
									} catch (IOException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									} catch (InvalidCipherTextException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}
								}else
									System.out.println("No se ha introducido un caracter válido.");
								
							break;
							case 3:
								System.out.println("Indique el nombre de la clave a utilizar por el descifrador:");
								nombreClave = sc.nextLine();
								System.out.println("¿Esta clave es privada? (y/n)");
								respuesta = sc.nextLine();
								
								if(respuesta.equals("y"))
									esPrivada = true;
								else if(respuesta.equals("n"))
									esPrivada = false;
								
								if(respuesta.equals("y") || respuesta.equals("n")){
									System.out.println("Introduce el nombre del archivo cifrado:");
									nombreFichero = sc.nextLine();
									System.out.println("Introduce un nombre para el archivo descifrado:");
									nombreCifrado = sc.nextLine();
									
									try {
										objAsimetrico.descifrar(esPrivada, nombreClave, nombreFichero, nombreCifrado);
									} catch (IOException e) {
										e.printStackTrace();
									} catch (InvalidCipherTextException e) {
										e.printStackTrace();
									}
								}else
									System.out.println("No se ha introducido un caracter válido.");
							break;
							case 4:
								System.out.println("Indique el nombre de la clave a utilizar:(privada)");
								nombreClave = sc.nextLine();
								System.out.println("Introduce el nombre del archivo a firmar:");
								nombreFichero = sc.nextLine();
								System.out.println("Introduce un nombre para el archivo final:");
								nombreCifrado = sc.nextLine();
								
								try {
									objAsimetrico.firmar(nombreClave, nombreFichero, nombreCifrado);
								} catch (InvalidCipherTextException | IOException e) {
									e.printStackTrace();
								}

							break;
							case 5:
								System.out.println("Indique el nombre de la clave a utilizar:(publica)");
								nombreClave = sc.nextLine();
								System.out.println("Introduce el nombre del archivo:");
								nombreFichero = sc.nextLine();
								System.out.println("Introduce el nombre del hash:");
								nombreCifrado = sc.nextLine();
								
							try {
								objAsimetrico.comprobar(nombreClave, nombreCifrado, nombreFichero);
							} catch (InvalidCipherTextException | IOException e) {
								e.printStackTrace();
							}
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}
