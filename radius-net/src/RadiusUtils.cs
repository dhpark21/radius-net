//
// System.Net.Radius.RadiusUtils.cs
//
// Author:
//  Cyrille Colin (colin@univ-metz.fr)
//
// Copyright (C) Cyrille COLIN, 2005
//

using System;
using System.Security.Cryptography;
namespace System.Net.Radius {

class Utils {
    static public byte[] makeRFC2865RequestAuthenticator(string sharedSecret) {
		byte[] sharedS = System.Text.Encoding.ASCII.GetBytes(sharedSecret);
        byte[] requestAuthenticator = new byte [16 + sharedS.Length];
        Random r = new Random();
        for (int i = 0; i < 16; i++)
				requestAuthenticator[i] = (byte) r.Next();
        Array.Copy(sharedS,0,requestAuthenticator,16,sharedS.Length);
		MD5 md5 = new MD5CryptoServiceProvider();
		md5.ComputeHash(requestAuthenticator);
        return md5.Hash;
    }
    static public byte[] makeRFC2865ResponseAuthenticator(byte[] data,byte[] requestAuthenticator,string sharedSecret) {
		System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
		byte[] ssArray = System.Text.Encoding.ASCII.GetBytes(sharedSecret);
        byte[] sum = new byte[data.Length + ssArray.Length];
		Array.Copy(data,0,sum,0,data.Length);
		Array.Copy(requestAuthenticator,0,sum,4,16);
		Array.Copy(ssArray,0,sum,data.Length,ssArray.Length);
		md5.ComputeHash(sum);
        return md5.Hash;
    }
    static public byte[] encodePapPassword(byte[] userPass,byte[] requestAuthenticator,string sharedSecret) {
		
		System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

        byte[] userPassBytes = null;
        if (userPass.Length > 128) {
            userPassBytes = new byte[128];
            System.Array.Copy(userPass,0,userPassBytes,0,128);
        } else {
            userPassBytes = userPass;
        }
        byte[] encryptedPass = null;

        if (userPassBytes.Length < 128) {
            if (userPassBytes.Length % 16 == 0) {
                encryptedPass = new byte[userPassBytes.Length];
            } else {
                encryptedPass = new byte[((userPassBytes.Length / 16) * 16) + 16];
            }
        } else {
            encryptedPass = new byte[128];
        }
        System.Array.Copy(userPassBytes, 0, encryptedPass, 0, userPassBytes.Length);
        for(int i = userPassBytes.Length; i < encryptedPass.Length; i++) {
            encryptedPass[i] = 0; 
        }
		byte[] ssArray = System.Text.Encoding.ASCII.GetBytes(sharedSecret);
		byte[] sum = new byte[requestAuthenticator.Length + ssArray.Length];
		Array.Copy(ssArray,0,sum,0,ssArray.Length);
		Array.Copy(requestAuthenticator,0,sum,ssArray.Length,requestAuthenticator.Length);
        md5.ComputeHash(sum);
        byte[] bn = md5.Hash;

        for (int i = 0; i < 16; i++){
            encryptedPass[i] = (byte)(bn[i] ^ encryptedPass[i]);
        }
		//[TODO] encryptedPass.Length > 16
        
		return encryptedPass;
    }
}
}
