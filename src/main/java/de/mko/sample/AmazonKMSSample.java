package de.mko.sample;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.AlgorithmSpec;
import com.amazonaws.services.kms.model.CreateKeyRequest;
import com.amazonaws.services.kms.model.CreateKeyResult;
import com.amazonaws.services.kms.model.GetParametersForImportRequest;
import com.amazonaws.services.kms.model.GetParametersForImportResult;
import com.amazonaws.services.kms.model.ImportKeyMaterialRequest;
import com.amazonaws.services.kms.model.ImportKeyMaterialResult;
import com.amazonaws.services.kms.model.KeyMetadata;
import com.amazonaws.services.kms.model.OriginType;
import com.amazonaws.services.kms.model.WrappingKeySpec;

/**
 * This sample demonstrates how to perform a key material import to the Amazon
 * Key Management service.<br>
 * It is rawly
 * 
 * @see the credential_setup.sh script in resources as credentials are taken from environment
 *      variables by default provider chain
 */
public class AmazonKMSSample {

	// the key management service client instance
	static AWSKMS awsKmsCLient;
	
	// simple key material to import - symbols the customer owned key data
	static ByteBuffer keyMaterial = ByteBuffer.wrap(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });

	/**
	 */
	private static void init() throws Exception {

		awsKmsCLient = AWSKMSClientBuilder.standard().withRegion(Regions.US_EAST_1).build();

	}

	public static void main(String[] args) throws Exception {
		init();

		try {

			// create empty key request by setting external origin
			CreateKeyRequest createKeyReq = new CreateKeyRequest().withOrigin(OriginType.EXTERNAL);

			// execute create key
			CreateKeyResult createKeyRes = awsKmsCLient.createKey(createKeyReq);

			// get key id
			KeyMetadata keyMetaData = createKeyRes.getKeyMetadata();
			String keyId = keyMetaData.getKeyId();

			// create request for fetching parameter data
			GetParametersForImportRequest getParametersForImportRequest = new GetParametersForImportRequest()
					.withKeyId(keyId).withWrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
					.withWrappingKeySpec(WrappingKeySpec.RSA_2048);

			// execute request for fetching parameter data
			GetParametersForImportResult getParametersForImportResult = awsKmsCLient
					.getParametersForImport(getParametersForImportRequest);

			// get secrets from result
			ByteBuffer publicImportKey = getParametersForImportResult.getPublicKey();
			ByteBuffer importToken = getParametersForImportResult.getImportToken();

			// basic setup for importing matrial request 
			ImportKeyMaterialRequest impReq = new ImportKeyMaterialRequest().withImportToken(importToken);
			
			// encrypt given key material with received public key from kms
			byte[] rawEncryptedMaterial = encrypt(keyMaterial, publicImportKey);
			
			// add material to request
			impReq.setEncryptedKeyMaterial(ByteBuffer.wrap(rawEncryptedMaterial));

			// execute import request
			ImportKeyMaterialResult impRes = awsKmsCLient.importKeyMaterial(impReq);

			System.out.println("ImportResult:   " + impRes.toString());

		} catch (AmazonServiceException ase) {
			System.out.println("Caught an AmazonServiceException, which means your request made it "
					+ "to AWS, but was rejected with an error response for some reason.");
			System.out.println("Error Message:    " + ase.getMessage());
			System.out.println("HTTP Status Code: " + ase.getStatusCode());
			System.out.println("AWS Error Code:   " + ase.getErrorCode());
			System.out.println("Error Type:       " + ase.getErrorType());
			System.out.println("Request ID:       " + ase.getRequestId());
		} catch (AmazonClientException ace) {
			System.out.println("Caught an AmazonClientException, which means the client encountered "
					+ "a serious internal problem while trying to communicate with AWS, "
					+ "such as not being able to access the network.");
			System.out.println("Error Message: " + ace.getMessage());
		}
	}

	private static byte[] encrypt(ByteBuffer data, ByteBuffer key)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		Key pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(key.array()));

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		byte[] rawEncryptedMaterial = cipher.doFinal(data.array());

		return rawEncryptedMaterial;
	}

}
