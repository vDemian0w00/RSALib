/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsalib;

/**
 *
 * @author alumno
 */

import java.io.*;
import java.security.*;
import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSALib {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)throws Exception {
        //primero tenemos que añadir el nuevo proveedor de algoritmo debido a que security 
        //no tiene soporte para BC
        
        Security.addProvider(new BouncyCastleProvider());
        
        //vamos a la generacion de las clabes
        System.out.println("1.- Crear las claves públicas y privadas");
        
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        
        keygen.initialize(8192);
        
        //vamos a asignar la llave publica y privada
        KeyPair clavesRSA = keygen.genKeyPair();
        
        //definimos a la llave privada
        
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        PublicKey clavePublica = clavesRSA.getPublic();
        
        //System.out.println(clavePrivada);
        //System.out.println(clavePublica);
        
        
        System.out.println("2.- Introducir el texto plano que desea cifrar, maximo 64 caracteres");
        
        //almacenar el texto como arreglos de baits
        
        byte[] bufferPlano = leerLinea(System.in);
        
        //ciframos
        
        Cipher cifrado = Cipher.getInstance("RSA", "BC");
        
        cifrado.init(Cipher.ENCRYPT_MODE, clavePublica);
        
        System.out.println("3.- Ciframos con la clave publica: ");
        
        byte[] bufferCifrado = cifrado.doFinal(bufferPlano);
        
        System.out.println("Texto cifrado: ");
        
        mostrarBytes(bufferCifrado);
        
        System.out.println("\n");
        
        //desciframos con privada
        
        cifrado.init(Cipher.DECRYPT_MODE, clavePrivada);
        
        System.out.println("4.- Desciframos con la clave privada");
        
        byte[] bufferDescifrado = cifrado.doFinal(bufferCifrado);
        
        System.out.println("Texto descifrado:");
        
        mostrarBytes(bufferDescifrado);
        
        System.out.println("");
        
    }

    private static byte[] leerLinea(InputStream in) throws Exception {
        byte[] buffer1 = new byte[1000];
        int i = 0;
        byte c;
        
        c=(byte)in.read();
        
        while((c!='\n') && (i<1000)){
            buffer1[i]=c;
            c=(byte)in.read();
            i++;
        }
        
        byte[] buffer2 = new byte[i];
        for (int j = 0; j < i; j++) {
            buffer2[j] = buffer1[j]; 
        }
        
        return buffer2;
    }

    private static void mostrarBytes(byte[] bufferCifrado) {
        System.out.write(bufferCifrado, 0, bufferCifrado.length);
    }
    
}
