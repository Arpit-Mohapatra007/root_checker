import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:convert';
import 'package:uuid/uuid.dart';
import 'dart:io';
import 'package:http/io_client.dart';

void main() {
  runApp(const RootCheckerApp());
}

class RootCheckerApp extends StatelessWidget {
  const RootCheckerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Aegis',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF121212),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00E676),
          secondary: Color(0xFFFF5252),
        ),
      ),
      home: const SecurityDashboard(),
    );
  }
}

class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard> {
  static const platform = MethodChannel('com.example.root_checker/security');

  String _statusMessage = "System Ready";
  String _detailedReason = "";
  Color _statusColor = Colors.grey;
  IconData _statusIcon = Icons.shield_outlined;
  bool _isScanning = false;

  void _interpretResult(int code) {
    if (code == 0) {
      _updateUI("Device is Secure", "No threats detected", Colors.greenAccent, Icons.verified_user_rounded);
      return;
    }

    if (code >= 400 && code <= 499) {
      String reason = "Unknown Dev Setting (Code: $code)";
      switch (code) {
        case 401: reason = "Emulator Detected"; break;
        case 402: reason = "Emulator Detected"; break;
        case 403: reason = "Emulator Detected"; break;
        case 404: reason = "Bootloader is Unlocked"; break;
        case 405: reason = "USB Debugging is Enabled"; break;
        case 406: reason = "Active Debugger Attached"; break;
        case 407: reason = "ADB Interface Active"; break;
        case 408: reason = "Suspicious Accessibility Service Active"; break;
        case 409: reason = "Developer Options Enabled"; break;
      }
      _updateUI("Developer Mode", reason, Colors.orangeAccent, Icons.developer_mode);
      return;
    }

    String reason = "Unknown Security Threat (Code: $code)";
    switch (code) {
      case 101: reason = "Root Binary Detected"; break;
      case 102: reason = "Root Binary Detected"; break;
      case 103: reason = "Dangerous File Opened"; break;
      case 104: reason = "Suspicious PATH Environment Variable"; break;
      case 201: reason = "Malicious Process Running"; break;
      case 202: reason = "Malicious Thread Injected into App"; break;
      case 203: reason = "Dangerous Environment Variable Hook"; break;
      case 204: reason = "Suspicious Local Port Open"; break;
      case 205: reason = "Suspicious File Descriptor Linked"; break;
      case 301: reason = "Mount Namespace Tampering"; break;
      case 302: reason = "Custom ROM / Test-Keys Build Detected"; break;
      case 303: reason = "Dynamic Instrumentation"; break;
      case 304: reason = "SELinux is Permissive or Disabled"; break;
      case 305: reason = "KernelSU Detected"; break;
      case 306: reason = "KernelSU Detected"; break;
      case 307: reason = "System Partition Remounted as R/W"; break;
      case 308: reason = "GOT Table Hooking Detected"; break;
      case 310: reason = "Syscall Hooking Detected"; break;
      case 311: reason = "Side-Channel Hooking Detected"; break;
      case 312: reason = "Root Shell Execution Successful"; break;
      case 313: reason = "Memory Tampering"; break;
      case 314: reason = "App Repackaged / Modified"; break;
      case 315: reason = "Hardware Attestation Failed / OS Tampered"; break;
      case 316: reason = "APK Signature Mismatch"; break;
      case 999: reason = "Hooking / Payload Tampering Detected"; break;
    }

    _updateUI("Root Detected", reason, Colors.redAccent, Icons.warning_amber_rounded);
  }

  void _updateUI(String msg, String detail, Color color, IconData icon) {
    setState(() {
      _isScanning = false;
      _statusMessage = msg;
      _detailedReason = detail;
      _statusColor = color;
      _statusIcon = icon;
    });
  }

  Future<void> _runSecurityScan() async {
    setState(() {
      _isScanning = true;
      _statusMessage = "Authenticating...";
      _detailedReason = "Contacting Aegis Security Server";
      _statusColor = Colors.blueAccent;
    });

    const String serverUrl = "https://root-checker-backend.onrender.com";
    final String deviceID = const Uuid().v4();

    String? blockedIssuer;
    try {
      SecurityContext context = SecurityContext(withTrustedRoots: false);
      
      HttpClient httpClient = HttpClient(context: context);
      
      httpClient.badCertificateCallback = (X509Certificate certificate, String host, int port){
        final issuer = certificate.issuer.toLowerCase();
        final subject = certificate.subject.toLowerCase();

        bool isRenderDomain = subject.contains("onrender.com") || subject.contains("cloudflare") || subject.contains("gts");

        bool isTrustedCloud = issuer.contains("let's encrypt") || issuer.contains("cloudflare") || issuer.contains("google trust services") || issuer.contains("digicert") || issuer.contains("sectigo") || issuer.contains("comodoca") || issuer.contains("globalsign") || issuer.contains("amazon") || issuer.contains("entrust") || issuer.contains("buypass") || issuer.contains("ssl.com") || issuer.contains("geotrust") || issuer.contains("certum") || issuer.contains("quovadis") || issuer.contains("trustwave") || issuer.contains("tencent") || issuer.contains("cisco") || issuer.contains("symantec") || issuer.contains("zerossl");

        if (isRenderDomain && isTrustedCloud){
          return true;
        }

        blockedIssuer = "Subject: $subject\nIssuer: $issuer";
        return false;
      };
      
      final IOClient secureClient = IOClient(httpClient);

      final challengeResponse = await secureClient.get(Uri.parse("$serverUrl/api/get-challenge?deviceID=$deviceID"));
      
      if (challengeResponse.statusCode != 200) throw Exception("Network Error");

      final String serverNonce = jsonDecode(challengeResponse.body)['challenge'];

      setState(() {
        _detailedReason = "Challenge Received. Verifying Device...";
      });

      final Map<dynamic,dynamic> nativeResult = await platform.invokeMethod('checkRoot',{
        "nonce": serverNonce
      });

      setState(() {
        _detailedReason = "Verifying Cryptographic Signature...";
      });

      final verifyResponse = await secureClient.post(
        Uri.parse("$serverUrl/api/verify-scan"),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "deviceID": deviceID,
          "scanResult": nativeResult['result'],
          "signature": nativeResult['signature']
        }),
      );

      if (verifyResponse.statusCode == 200 || verifyResponse.statusCode == 403){
          final finalVerdict = jsonDecode(verifyResponse.body);
          final dynamic rawCode = finalVerdict['code'];
          final int serverCode = (rawCode is int)? rawCode : 999;
          _interpretResult(serverCode);
      } else {
        throw Exception("Network Error"); 
      }
    } catch (e) {
      String errorMsg = "Secure connection to the Aegis verification network timed out. Please check your internet connection or try again.";
      if (blockedIssuer != null){
        errorMsg = "MITM BLOCKED ! Untrusted Certificate Intercepted:\n $blockedIssuer";
      }
      _updateUI("Connection Error", errorMsg, Colors.grey, Icons.cloud_off);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("System Integrity"), centerTitle: true, backgroundColor: Colors.transparent, elevation: 0),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 500),
              height: 200, width: 200,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: _statusColor.withOpacity(0.1),
                border: Border.all(color: _statusColor, width: 3),
                boxShadow: [BoxShadow(color: _statusColor.withOpacity(0.4), blurRadius: 20, spreadRadius: 5)],
              ),
              child: _isScanning
                  ? const CircularProgressIndicator(color: Colors.blue)
                  : Icon(_statusIcon, size: 100, color: _statusColor),
            ),
            const SizedBox(height: 40),
            Text(_statusMessage, style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold, color: _statusColor, letterSpacing: 1.2)),
            const SizedBox(height: 10),
            Text(_detailedReason, style: TextStyle(fontSize: 16, color: Colors.grey[400]), textAlign: TextAlign.center,),
          ],
        ),
      ),
      floatingActionButtonLocation: FloatingActionButtonLocation.centerFloat,
      floatingActionButton: SizedBox(
        width: 160, height: 55,
        child: FloatingActionButton.extended(
          onPressed: _isScanning ? null : _runSecurityScan,
          backgroundColor: _isScanning ? Colors.grey : Colors.white,
          label: Text(_isScanning ? "SCANNING" : "SCAN NOW", style: const TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 16)),
          icon: _isScanning ? const SizedBox() : const Icon(Icons.radar, color: Colors.black),
        ),
      ),
    );
  }
}