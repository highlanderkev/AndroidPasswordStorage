package se525.kpw.passwordapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.widget.EditText;
import android.widget.Button;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class MainActivity extends Activity
{
	//setup strings for type of encryption algorithm
	final static String provider = "BC";
	final static String keyAlg = "PBEWithSHA1And128BitAES-CBC-BC";
	final static String cipherAlg = "PBEWithSHA1And128BitAES-CBC-BC/CBC/PKCS5Padding";
			
	//always add some salt
	final static byte[] salt = new byte[]{0x7d,0x60,0x43,0x5f,0x02,(byte)0xe9,(byte)0xe0,(byte)0xae};
	final static int iterationCount = 2048;
	final static String charset = "utf-8";

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        //Text view and Edit Text for Password
		TextView tv1 = new TextView(this);
		tv1.setText("Password:");
		final EditText pWord = new EditText(this);
		pWord.setText(" ");

		//TextView and Edit Text for text encryption/decryption
		TextView tv2 = new TextView(this);
		tv2.setText("Text:");
		final EditText pText = new EditText(this);
		pText.setText(" ");

		//Buttons for encypting and decrypting
		Button bencrypt = new Button(this);
		bencrypt.setText("Encrypt");
		Button bdecrypt = new Button(this);
		bdecrypt.setText("Decrypt");
	
		//Console Log
		final TextView console = new TextView(this);
		console.setText("");

		//set on click listeners for buttons
		bencrypt.setOnClickListener(new View.OnClickListener(){
			public void onClick(View v){
				String temp = encrypt(pWord.getText().toString(), pText.getText().toString());
				console.setText(temp);
				pText.setText("");
				pWord.setText("");
			}
	    });
	
		bdecrypt.setOnClickListener(new View.OnClickListener(){
			public void onClick(View v){
				String temp = decrypt(pWord.getText().toString(), console);
				pText.setText(temp);
				console.setText(console.getText() + "\n Decryption complete.");
			}
		});
	
		//setup the layout for the app
		LinearLayout layout = new LinearLayout(this);
		layout.setOrientation(LinearLayout.VERTICAL);
		layout.addView(tv1);
		layout.addView(pWord);
		layout.addView(tv2);
		layout.addView(pText);
		layout.addView(bencrypt);
		layout.addView(bdecrypt);
		layout.addView(console);
		setContentView(layout);
    }

	//Method to decrypt text
    public String decrypt(String pWord, TextView console){
    	try{
			//turn password in character array
	    	final char[] password = pWord.toCharArray();

	    	//get key from Secret Key factory
	    	SecretKeyFactory skfact = SecretKeyFactory.getInstance(keyAlg, provider);
	    	PBEKeySpec pbespec = new PBEKeySpec(password, salt, iterationCount);
			Key secKey = skfact.generateSecret(pbespec);

	    	//read encrypted text file
    		byte[] fileText = readFile(console);

    		//grab IV from fileText
    		byte[] iv = new byte[16];
    		for(int i = 0; i < 16; i++){
    			iv[i] = fileText[i];
    		}

    		//get the text length by subtracting iv length
    		int cipherLength = fileText.length - 16;

    		//grab cipherText from file
    		byte[] cipherText = new byte[cipherLength];
    		for(int i = 16; i < fileText.length; i++){
    			cipherText[i - 16] = fileText[i];
    		}

    		//get a cipher for decrypting
    		IvParameterSpec ivSpec = new IvParameterSpec(iv);
    		Cipher cipherD = Cipher.getInstance(cipherAlg, provider);
    		cipherD.init(Cipher.DECRYPT_MODE, secKey, ivSpec);
    		byte[] plainTextDec = cipherD.doFinal(cipherText);

    		//create string from decrypted text and return
    		String decryptedText = new String(plainTextDec);
    		
    		return decryptedText;

    	}catch(Exception e){
    		console.setText("(decrypt) Exception: " + e.getMessage().toString());
    		return "";
    	}
    }

    //Method to read from encrypted file
    public byte[] readFile(TextView console){
    	File f = new File(getFilesDir(), "myEncrypted.txt");
    	try{
    		RandomAccessFile raf = new RandomAccessFile(f, "rw");
    		byte[] text = new byte[(int)f.length()];
    		raf.read(text);
    		raf.close();
    		
    		//return byte array of text
    		return text;
    		
    	}catch(Exception e){
    		console.setText("(readFile) Exception: " + e.getMessage().toString());
    		byte[] blank = new byte[16];
    		return blank;
    	}
    }

    //Method to encrypt text 
    public String encrypt(String pWord, String pText){
		try{
	    	//turn password in character array
	    	final char[] password = pWord.toCharArray();
	    
	    	//get key from Secret Key factory
	    	SecretKeyFactory skfact = SecretKeyFactory.getInstance(keyAlg, provider);
	    	PBEKeySpec pbespec = new PBEKeySpec(password, salt, iterationCount);
			Key secKey = skfact.generateSecret(pbespec);

	    	//turn plaintext into byte array
	    	byte[] plainText = pText.getBytes(charset);

	    	//get secure random for IV
	    	byte[] iv = new byte[16];
	    	SecureRandom random = new SecureRandom();
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			//get a cipher
			Cipher cipherE = Cipher.getInstance(cipherAlg, provider);			
			cipherE.init(Cipher.ENCRYPT_MODE, secKey, ivSpec);
			byte[] cipherText = cipherE.doFinal(plainText);
	
			//create byte array for file storage
			byte[] text = new byte[iv.length + cipherText.length];
			for(int i = 0; i < iv.length; i++){
				text[i] = iv[i];
			}

			//include ciphertext after iv
			for(int i = 0; i < cipherText.length; i++){
				text[i+16] = cipherText[i];
			}

			//save the info to file
			return updateFile(text);

		}catch(Exception e){
			return "(encrypt) Exception: " + e.getMessage().toString();
		}
    }

    //Method to update/save to file
    public String updateFile(byte[] text){
    	File f = new File(getFilesDir(), "myEncrypted.txt");
    	String result;
    	try{
    		RandomAccessFile raf = new RandomAccessFile(f, "rw");
    		raf.write(text);
    		raf.close();
    		result = "Success: Text encrypted and stored in myEncrypted.txt.";
    	}catch(Exception e){
    		result = "(updateFile) Exception: " + e.getMessage().toString();
    	}
    	return result;
    }

    //Method to display byte array contents
    public String displayBytes(byte[] buffer){
    	final int displayWidth = 8;
    	StringBuilder sb = new StringBuilder();
    	for(int i = 0; i < buffer.length; i += displayWidth){
    		sb.append(String.format("%04x: ", i));
    		for(int j = 0; j < displayWidth && i+j < buffer.length; j++){
    			sb.append(String.format("%02x ", buffer[i+j]));
    		}
    		sb.append("\n");
    	}
    	return sb.toString();
    }

}
