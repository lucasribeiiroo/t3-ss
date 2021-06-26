package source;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
	public static byte[] S = new byte[16];
	public static byte[] IV = new byte[16];
	public static byte[] mensagem = null;;

	public static void main(String[] args) throws Exception {
		Functions funcoes = new Functions();		

		// definicao de P 
		String P = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6";
		P = P + "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0";
		P = P + "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70";
		P = P + "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0";
		P = P + "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708";
		P = P + "DF1FB2BC2E4A4371";

		// Definicao de G 
		String G = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F";
		G = G + "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213";
		G = G + "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1";
		G = G + "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A";
		G = G + "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24";
		G = G + "855E6EEB22B3B2E5";

		// definicao de a
		int a = 15;

		// mensagem a ser descriptografada
		String mensagemDoProfessor = "75B505DEA8AE65CA7BF97C170910F233D093D15CDEBDA34DD5B00FA7C9073ECEF6023DD45DEE7B045C6919CE2291CD11E766F9E608E8FA2707BD35AC448EC85D7468604FD8131E298D38C22CE655DCA3DB5B35F8065E284DF32709D2C9495FBD4FC4D47F56F6800B7A69EE1B69A53D91AEF13F168D7FD7FF536D4BDEC5313EE6";

		// DESENVOLVIMENTO DO PROBLEMA
		System.out.println("-------------------ETAPA 1 -----------------------------------");
		System.out.println("ETAPA 1");

		// PASSO 1 - calcula o A
		String A = funcoes.passo1(G, a, P);

		// escreve o resultado (em hexa) em um TXT
		// (numero pode ser grande demais para o terminal/console printar)
		String nomeDoTxt = "resultDeA";
		System.out.println("Resultado de A em string:");
		funcoes.gravaResult(A, nomeDoTxt);
		System.out.println();

		// valor de B recebido pelo professor
		String B = "597D28B7BA101041FB9FB28CFA474EA4701D3557A59FF09FD7815F1BBFAB794562681FBC4A112874F8B9DD304D52AF7C6D356347FF400BE37D452BBA79262E9C02EE1E07A893BA803DB6BADF6F2B5808C9B1F6971453A24448FF2A7E386C4EB26F63CD88267E5467A50517AC42AB3AA5EABADC8BBFDD8637B994106DF688B368";

		// PASSO 2 - calculo o V
		BigInteger V = funcoes.passo2(B, a, P);

		// escreve o resultado (em hexa) em um TXT
		// (numero pode ser grande demais para o terminal/console printar)
		nomeDoTxt = "resultDeV";
		System.out.println("Resultado de V em string:");
		funcoes.gravaResult(V.toString(), nomeDoTxt);
		System.out.println();

		// PASSO 3 - Calcula o S
		byte[] sCompleto = funcoes.passo3(V);

		System.out.println("-------------------ETAPA 2-----------------------------------");

		// Receber uma mensagem do professor (em hexadecimal)
		// cifrada com o AES no modo de operação CBC, e padding
		// Formato da mensagem recebida: [128 bits com IV][mensagem] – em hexadecimal
		System.out.println("mensagemDoProfessor: " + mensagemDoProfessor);
		System.out.println();

		// separacao dos artefatos
		// obtem os valores para o cipher, obtem o S, o IV e MENSAGEM
		System.out.println("dados obtidos da separacao: ");
		separacao(mensagemDoProfessor, sCompleto);

		// Decifrar a mensagem (ja passando a mensagem em byte) e
		byte[] mensagemDescifrada = decifra();
		System.out.println("-------------------TEXTO DESCIFRADO-----------------------------------");
		System.out.println("mensagem em texto: ");
		System.out.println(new String(mensagemDescifrada, StandardCharsets.UTF_8));
		System.out.println();

		// inverte ela
		// String novaMensagem = new String(mensagemDescifrada, StandardCharsets.UTF_8);
		String novaMensagem = new String(mensagemDescifrada, StandardCharsets.UTF_8);
		novaMensagem = funcoes.invercao(novaMensagem);
		System.out.println("mensagem invertida: ");
		System.out.println(novaMensagem);
		System.out.println();

		// gera um novo IV aleatorio
		geraIv();

		// cifra ela para enviar
		byte[] novaMensagembytes = cifra(novaMensagem);
		System.out.println("mensagem criptografada em hex:");
		System.out.println(funcoes.byteArrayToHexString(novaMensagembytes));
		System.out.println();

	}

	private static byte[] cifra(String mensagemParaCriptografar) {
		try {
			// IV
			IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
			// CHAVE
			SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
			// DEFINE O CIPHER
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// EXECUTA O CIPHER
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			// RETORNA DESCRIPTOGRAFADA
			byte[] mensagemCriptografada = cipher.doFinal(mensagemParaCriptografar.getBytes());
			// CONCATENA IV E A MENSAGEM CRIPTOGRAFADA
			byte[] mensagemConcatenada = new byte[IV.length + mensagemCriptografada.length];
			System.arraycopy(IV, 0, mensagemConcatenada, 0, IV.length);
			System.arraycopy(mensagemCriptografada, 0, mensagemConcatenada, IV.length, mensagemCriptografada.length);

			return mensagemConcatenada;
		} catch (Exception ex) {
			ex.printStackTrace();
			// Operation failed
		}
		return null;
	}

	private static void geraIv() {
		Functions funcoes = new Functions();
		try {
			// metodo de geracao de IV recomendado no GIT
			// https://gist.github.com/demisang/716250080d77a7f65e66f4e813e5a636
			SecureRandom secureRandom = new SecureRandom();
			byte[] initVectorBytes = new byte[IV.length / 2];
			secureRandom.nextBytes(initVectorBytes);
			String initVector = funcoes.byteArrayToHexString(initVectorBytes);
			initVectorBytes = initVector.getBytes("UTF-8");
			IV = initVectorBytes;

			System.out.println("novo IV gerado (de forma aleatoria)");
			System.out.println("IV (em hexa): " + funcoes.byteArrayToHexString(initVectorBytes));
			System.out.println();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}


	private static byte[] decifra() {
		try {
			// IV
			IvParameterSpec iv = new IvParameterSpec(IV);
			// CHAVE
			// SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
			SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
			// DEFINE O CIPHER
			// Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// EXECUTA O CIPHER
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
			// RETORNA DESCRIPTOGRAFADA
			return cipher.doFinal(mensagem);
			// return cipher.doFinal(byteTexto);*/
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		// caso ocorrer algum erro
		return null;
	}

	private static void separacao(String mensagemDoProfessor, byte[] Scompleto) throws UnsupportedEncodingException {
		Functions funcoes = new Functions();
		// PRIMEIRO: obtencao do S
		// pega os primeiros 128 bits do SHA para obter o S
		System.arraycopy(Scompleto, 0, S, 0, S.length);
		System.out.println("S em byte[]: ");
		for (int i = 0; i < S.length; i++) {
			System.out.print(S[i] + " ");
		}
		System.out.println();
		System.out.println("S em texto plano: " + new String(S, StandardCharsets.UTF_8));
		System.out.println("S em hexa: " + funcoes.byteArrayToHexString(S));
		System.out.println("S em Base64: " + Base64.getEncoder().encodeToString(S));
		System.out.println();

		// de string (hex) para byte array
		BigInteger aux = new BigInteger(mensagemDoProfessor, 16);
		byte[] mensagemBytes = aux.toByteArray();

		// SEGUNDO: obtencao do IV
		// separa os primeiros 128 bits
		System.arraycopy(mensagemBytes, 0, IV, 0, IV.length);
		System.out.println("IV em texto plano: " + new String(IV, StandardCharsets.UTF_8));

		// TERCEIRO: obtencao da mensagem
		// bits apos os primeiros 128
		int size = mensagemBytes.length - IV.length;
		mensagem = new byte[size];
		System.arraycopy(mensagemBytes, IV.length, mensagem, 0, size);
		System.out.println("Mensagem em texto plano: " + new String(mensagem, StandardCharsets.UTF_8));
		System.out.println();
	}


}
