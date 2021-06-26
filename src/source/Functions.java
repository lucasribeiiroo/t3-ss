package source;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Functions {

	public static String passo1(String G, int a, String P) {
		// Passo 1: gerar um valor a menor que p (dado) e calcular A = ga mod p.
		// Enviar o valor de A (em hexadecimal) para o professor.

		// de hexa para decimal
		BigInteger newG = new BigInteger(G, 16);
		BigInteger newP = new BigInteger(P, 16);

		// g elevado ao a
		newG = newG.pow(a);

		// resutlado mod de p
		newG = newG.remainder(newP);

		// retorno do resultado
		return newG.toString(16);
	}

	public static BigInteger passo2(String B, int a, String P) {
		// Passo 2: receber um valor B (em hexadecimal) do professo
		// e calcular V = Ba mod p

		// de hexa para decimal
		BigInteger newB = new BigInteger(B, 16);
		BigInteger newP = new BigInteger(P, 16);

		// b elevado ao a
		newB = newB.pow(a);

		// resutlado mod de p
		newB = newB.remainder(newP);

		// retorno do resultado
		return newB;
	}

	public static byte[] passo3(BigInteger v) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		// Passo 3: calcular S = SHA256(V) e
		// usar os primeiros 128 bits como senha para se comunicar com o professor
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(v.toByteArray());
		return digest.digest();
	}

	public static String invercao(String mensagemParaInverter) {
		String reversed = "";
		for (int i = mensagemParaInverter.length() - 1; i >= 0; i--) {
			reversed = reversed + mensagemParaInverter.charAt(i);
		}
		return reversed;
	}

	// metodo para gravar em um TXT
	public static void gravaResult(String texto, String nomeDoTxt) {
		System.out.println(texto);
		nomeDoTxt = nomeDoTxt + ".txt";
		try {
			FileWriter myWriter = new FileWriter(nomeDoTxt);
			myWriter.write(texto);
			myWriter.close();
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

	// metodo para transformar um array de bytes em uma string, em hexadecimal
	public String byteArrayToHexString(byte[] encrypted) {
		final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char[] hexChars = new char[encrypted.length * 2];
		int v;
		for (int j = 0; j < encrypted.length; j++) {
			v = encrypted[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

}
