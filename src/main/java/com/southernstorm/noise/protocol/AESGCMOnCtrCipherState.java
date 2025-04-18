/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package com.southernstorm.noise.protocol;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.Collections;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.southernstorm.noise.crypto.GHASH;
import java.security.MessageDigest;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;


/**
 * Emulates the "AESGCM" cipher for Noise using the "AES/CTR/NoPadding"
 * transformation from JCA/JCE.
 * 
 * This class is used on platforms that don't have "AES/GCM/NoPadding",
 * but which do have the older "AES/CTR/NoPadding".
 */
class AESGCMOnCtrCipherState implements CipherState {

	private Cipher cipher;
	private SecretKeySpec keySpec;
	private long n;
	private byte[] iv;
	private byte[] hashKey;
	private GHASH ghash;

	private static final Set<String> usedNonces = Collections.synchronizedSet(new HashSet<>());
    private static final int MAX_NONCE_CACHE_SIZE = 10000;
	/**
	 * Constructs a new cipher state for the "AESGCM" algorithm.
	 * 
	 * @throws NoSuchAlgorithmException The system does not have a
	 * provider for this algorithm.
	 */
	public AESGCMOnCtrCipherState() throws NoSuchAlgorithmException
	{
		try {
			cipher = Cipher.getInstance("AES/CTR/NoPadding");
		} catch (NoSuchPaddingException e) {
			// AES/CTR is available, but not the unpadded version?  Huh?
			throw new NoSuchAlgorithmException("AES/CTR/NoPadding not available", e);
		}
		keySpec = null;
		n = 0;
		iv = new byte [16];
		hashKey = new byte [16];
		ghash = new GHASH();
		
		// Try to set a 256-bit key on the cipher.  Some JCE's are
		// configured to disallow 256-bit AES if an extra policy
		// file has not been installed.
		try {
			SecretKeySpec spec = new SecretKeySpec(new byte [32], "AES");
			IvParameterSpec params = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, spec, params);
		} catch (InvalidKeyException e) {
			throw new NoSuchAlgorithmException("AES/CTR/NoPadding does not support 256-bit keys", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new NoSuchAlgorithmException("AES/CTR/NoPadding does not support 256-bit keys", e);
		}
	}

	@Override
	public void destroy() {
		// There doesn't seem to be a standard API to clean out a Cipher.
		// So we instead set the key and IV to all-zeroes to hopefully
		// destroy the sensitive data in the cipher instance.
		ghash.destroy();
		Noise.destroy(hashKey);
		Noise.destroy(iv);
		keySpec = new SecretKeySpec(new byte [32], "AES");
		IvParameterSpec params = new IvParameterSpec(iv);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
		}
	}

	@Override
	public String getCipherName() {
		return "AESGCM";
	}

	@Override
	public int getKeyLength() {
		return 32;
	}

	@Override
	public int getMACLength() {
		return keySpec != null ? 16 : 0;
	}

	@Override
	public void initializeKey(byte[] key, int offset) {
		// Set the encryption key.
		keySpec = new SecretKeySpec(key, offset, 32, "AES");
		
		// Generate the hashing key by encrypting a block of zeroes.
		Arrays.fill(iv, (byte)0);
		Arrays.fill(hashKey, (byte)0);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		try {
			int result = cipher.update(hashKey, 0, 16, hashKey, 0);
			cipher.doFinal(hashKey, result);
		} catch (ShortBufferException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (IllegalBlockSizeException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (BadPaddingException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		ghash.reset(hashKey, 0);
		
		// Reset the nonce.
		n = 0;
	}

	@Override
	public boolean hasKey() {
		return keySpec != null;
	}

	/**
	 * Set up to encrypt or decrypt the next packet.
	 * 
	 * @param ad The associated data for the packet.
	 */
	private void setup(byte[] ad) throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		// Check for nonce wrap-around.
		if (n == -1L)
			throw new IllegalStateException("Nonce has wrapped around");
		
		// Format the counter/IV block for AES/CTR/NoPadding.
		iv[0] = 0;
		iv[1] = 0;
		iv[2] = 0;
		iv[3] = 0;
		iv[4] = (byte)(n >> 56);
		iv[5] = (byte)(n >> 48);
		iv[6] = (byte)(n >> 40);
		iv[7] = (byte)(n >> 32);
		iv[8] = (byte)(n >> 24);
		iv[9] = (byte)(n >> 16);
		iv[10] = (byte)(n >> 8);
		iv[11] = (byte)n;
		iv[12] = 0;
		iv[13] = 0;
		iv[14] = 0;
		iv[15] = 1;
		++n;
		
		// Initialize the CTR mode cipher with the key and IV.
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		
		// Encrypt a block of zeroes to generate the hash key to XOR
		// the GHASH tag with at the end of the encrypt/decrypt operation.
		Arrays.fill(hashKey, (byte)0);
		try {
			cipher.update(hashKey, 0, 16, hashKey, 0);
		} catch (ShortBufferException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		
		// Initialize the GHASH with the associated data value.
		ghash.reset();
		if (ad != null) {
			ghash.update(ad, 0, ad.length);
			ghash.pad();
		}
	}

	@Override
	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset,
			byte[] ciphertext, int ciphertextOffset, int length)
			throws ShortBufferException {
		
	    int space;
	
	    // 구체적인 오류 메시지 추가 및 경계 검사 강화
	    if (ciphertextOffset < 0 || ciphertextOffset > ciphertext.length)
			throw new IllegalArgumentException("Invalid ciphertext offset: " + ciphertextOffset);
	
	    if (length < 0 || plaintextOffset < 0 || plaintextOffset > plaintext.length || 
		length > plaintext.length || (plaintext.length - plaintextOffset) < length)
			throw new IllegalArgumentException("Invalid plaintext parameters: offset=" + 
				plaintextOffset + ", length=" + length + ", array length=" + plaintext.length);
	
	    space = ciphertext.length - ciphertextOffset;
	
	    // 키가 없는 경우 예외 발생 (평문 반환 대신)
	    if (keySpec == null) {
			throw new IllegalStateException("Encryption key is not set");
	    }
	
	    // 출력 버퍼 크기 확인 (MAC 태그 16바이트 포함)
	    if (space < 16 || length > (space - 16))
			throw new ShortBufferException("Output buffer too short: needs " + (length + 16) + 
				" bytes, has " + space + " bytes");
	
	    // nonce(ad) 재사용 방지 - 안전한 해시 사용
	    if (ad != null) {
			try {
		    	// MessageDigest를 사용하여 더 안전한 해시 생성
		    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
		    	byte[] nonceHash = digest.digest(ad);
		    	String nonceId = Base64.getEncoder().encodeToString(nonceHash);
			
		    	// 스레드 안전성을 위해 동기화 블록 사용
		    	synchronized(usedNonces) {
		        	if (usedNonces.contains(nonceId)) {
			    		throw new IllegalStateException("Nonce has already been used");
					}
				
					// nonce 컬렉션 크기 관리
					if (usedNonces.size() > MAX_NONCE_CACHE_SIZE) {
			    	// 간단히 모두 지우는 방식 사용
			    		usedNonces.clear();
					}
				
					usedNonces.add(nonceId);
		    	}
	        } catch (NoSuchAlgorithmException e) {
		    	// SHA-256을 지원하지 않는 경우 (매우 드문 경우)
		   		throw new RuntimeException("Cryptographic algorithm not available", e);
			}
	    }
	
	    try {
			// 암호화 준비
	        setup(ad);
		
			// 실제 암호화 수행
			int result = cipher.update(plaintext, plaintextOffset, length, ciphertext, ciphertextOffset);
			cipher.doFinal(ciphertext, ciphertextOffset + result);
		
			// MAC 계산
			ghash.update(ciphertext, ciphertextOffset, length);
			ghash.pad(ad != null ? ad.length : 0, length);
			ghash.finish(ciphertext, ciphertextOffset + length, 16);
		
			// MAC 태그에 해시 키 적용
			for (int index = 0; index < 16; ++index)
				ciphertext[ciphertextOffset + length + index] ^= hashKey[index];
		
			return length + 16;
	    } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
			IllegalBlockSizeException | BadPaddingException e) {
			// 예외 처리 개선
			throw new IllegalStateException("Encryption error: " + e.getMessage(), e);
	    } finally {
			// 민감한 데이터 제거 - 항상 실행되도록 finally 블록 사용
			if (hashKey != null) {
		    	Arrays.fill(hashKey, (byte) 0);
			}
	    }
    }

	@Override
	public int decryptWithAd(byte[] ad, byte[] ciphertext,
			int ciphertextOffset, byte[] plaintext, int plaintextOffset,
			int length) throws ShortBufferException, BadPaddingException {
		int space;
		if (ciphertextOffset < 0 || ciphertextOffset > ciphertext.length)
			throw new IllegalArgumentException();
		else
			space = ciphertext.length - ciphertextOffset;
		if (length > space)
			throw new ShortBufferException();
		if (length < 0 || plaintextOffset < 0 || plaintextOffset > plaintext.length || length > ciphertext.length || (ciphertext.length - ciphertextOffset) < length)
			throw new IllegalArgumentException();
		space = plaintext.length - plaintextOffset;
		if (keySpec == null) {
			// The key is not set yet - return the ciphertext as-is.
			if (length > space)
				throw new ShortBufferException();
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(ciphertext, ciphertextOffset, plaintext, plaintextOffset, length);
			return length;
		}
		if (length < 16)
			Noise.throwBadTagException();
		int dataLen = length - 16;
		if (dataLen > space)
			throw new ShortBufferException();
		try {
			setup(ad);
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		ghash.update(ciphertext, ciphertextOffset, dataLen);
		ghash.pad(ad != null ? ad.length : 0, dataLen);
		ghash.finish(iv, 0, 16);
		int temp = 0;
		for (int index = 0; index < 16; ++index)
			temp |= (hashKey[index] ^ iv[index] ^ ciphertext[ciphertextOffset + dataLen + index]);
		if ((temp & 0xFF) != 0)
			Noise.throwBadTagException();
		try {
			int result = cipher.update(ciphertext, ciphertextOffset, dataLen, plaintext, plaintextOffset);
			cipher.doFinal(plaintext, plaintextOffset + result);
		} catch (IllegalBlockSizeException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (BadPaddingException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		return dataLen;
	}

	@Override
	public CipherState fork(byte[] key, int offset) {
		CipherState cipher;
		try {
			cipher = new AESGCMOnCtrCipherState();
		} catch (NoSuchAlgorithmException e) {
			// Shouldn't happen.
			return null;
		}
		cipher.initializeKey(key, offset);
		return cipher;
	}

	@Override
	public void setNonce(long nonce) {
		n = nonce;
	}
}
