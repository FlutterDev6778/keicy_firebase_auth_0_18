library keicy_firebase_auth_0_18;

import 'dart:async';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_sign_in/google_sign_in.dart';
// import 'package:flutter_facebook_login/flutter_facebook_login.dart';

class KeicyAuthentication {
  static KeicyAuthentication _instance = KeicyAuthentication();
  static KeicyAuthentication get instance => _instance;

  final FirebaseAuth _firebaseAuth = FirebaseAuth.instance;
  FirebaseAuth get firebaseAuth => _firebaseAuth;

  final GoogleSignIn _googleSignIn = GoogleSignIn(
    signInOption: SignInOption.standard,
    scopes: <String>[
      'email',
      'https://www.googleapis.com/auth/contacts.readonly',
    ],
  );
  final RegExp regExp = RegExp(r'(PlatformException\()|(FirebaseError)|([(:,.)])');

  Future<Map<String, dynamic>> signIn({@required String email, @required String password}) async {
    try {
      UserCredential userCredential = await _firebaseAuth.signInWithEmailAndPassword(email: email, password: password);
      return {"state": true, "user": userCredential};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<Map<String, dynamic>> signUp({@required String email, @required String password}) async {
    try {
      UserCredential userCredential = await _firebaseAuth.createUserWithEmailAndPassword(email: email, password: password);
      return {"state": true, "user": userCredential};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<Map<String, dynamic>> anonySignIn() async {
    try {
      UserCredential userCredential = await _firebaseAuth.signInAnonymously();
      return {"state": true, "user": userCredential};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<Map<String, dynamic>> googleSignIn() async {
    try {
      GoogleSignInAccount _googleUser = await _googleSignIn.signIn();
      GoogleSignInAuthentication _googleAuth = await _googleUser.authentication;
      OAuthCredential _credential = GoogleAuthProvider.credential(
        accessToken: _googleAuth.accessToken,
        idToken: _googleAuth.idToken,
      );
      UserCredential userCredential = await _firebaseAuth.signInWithCredential(_credential);
      return {"state": true, "user": userCredential};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<void> verifyPhoneNumber({
    @required String phoneNumber,
    Function(PhoneAuthCredential) verificationCompleted,
    Function(FirebaseAuthException) verificationFailed,
    Function(String, int) codeSent,
    Function(String) codeAutoRetrievalTimeout,
    Duration timeout = const Duration(seconds: 30),
    int forceResendingToken,
  }) async {
    await _firebaseAuth.verifyPhoneNumber(
      phoneNumber: phoneNumber,
      verificationCompleted: (PhoneAuthCredential phoneAuthCredential) {
        verificationCompleted(phoneAuthCredential);
      },
      verificationFailed: (FirebaseAuthException firebaseAuthException) {
        verificationFailed(firebaseAuthException);
      },
      codeSent: (String verificationId, int forceResendingToken) {
        codeSent(verificationId, forceResendingToken);
      },
      codeAutoRetrievalTimeout: (String verificationId) {
        codeAutoRetrievalTimeout(verificationId);
      },
      timeout: timeout,
      forceResendingToken: forceResendingToken,
    );
    return;
  }

  Future<Map<String, dynamic>> confirmPhoneVerification({@required String smsCode, @required String verificationId}) async {
    try {
      PhoneAuthCredential _phoneAuthCredential = PhoneAuthProvider.credential(verificationId: verificationId, smsCode: smsCode);
      UserCredential userCredential = await _firebaseAuth.signInWithCredential(_phoneAuthCredential);
      return {"state": true, "user": userCredential};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<void> signOut() async {
    return _firebaseAuth.signOut();
  }

  Future<Map<String, dynamic>> sendPasswordResetEmail({@required String email}) async {
    try {
      await _firebaseAuth.sendPasswordResetEmail(email: email);
      return {"state": true};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);

      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<Map<String, dynamic>> verifyPasswordResetCode({@required String code}) async {
    try {
      String email = await _firebaseAuth.verifyPasswordResetCode(code);
      return {"state": true, "email": email};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }

  Future<Map<String, dynamic>> confirmPasswordReset({@required String code, @required String newPassword}) async {
    try {
      await _firebaseAuth.confirmPasswordReset(code: code, newPassword: newPassword);
      return {"state": true};
    } on FirebaseAuthException catch (e) {
      return {"state": false, "errorCode": e.code, "errorString": e.message};
    } catch (e) {
      List<String> list = e.toString().split(regExp);
      String errorString = list[2];
      String errorCode;
      if (e.toString().contains("FirebaseError")) {
        errorCode = list[4];
      } else {
        errorCode = list[2];
      }

      ///   --- Error Codes ---
      /// ERROR_USER_NOT_FOUND, ERROR_WRONG_PASSWORD,ERROR_NETWORK_REQUEST_FAILED
      ///
      return {"state": false, "errorCode": errorCode, "errorString": errorString};
    }
  }
}
