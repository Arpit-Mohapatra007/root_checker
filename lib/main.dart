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
      if (code == 401) reason = "Emulator Environment Detected";
      if (code == 402) reason = "Abnormal Battery Levels (Emulator)";
      if (code == 403) reason = "Abnormal CPU Temps (Emulator)";
      if (code == 404) reason = "Bootloader is Unlocked";
      if (code == 405) reason = "App is Debuggable";
      if (code == 406) reason = "Active Debugger Attached";
      if (code == 407) reason = "USB Debugging is Enabled";
      if (code == 408) reason = "Accessibility Services Enabled";
      if (code == 409) reason = "Developer Options Enabled";
      _updateUI("Developer Mode", reason, Colors.orangeAccent, Icons.developer_mode);
      return;
    }

    String reason = "Security Violation ($code)";

    if (code == 101) reason = "SU Binary Found";
    if (code == 102) reason = "SU Binary Permissions Abnormal";
    if (code == 103) reason = "SU File Detected (Syscall)";
    if (code == 104) reason = "Suspicious System PATH";

    if (code == 201) reason = "Root Management Process Found";
    if (code == 202) reason = "Suspicious Thread Injection";
    if (code == 203) reason = "Magisk Environment Variable";
    if (code == 204) reason = "Frida Server Port Open";
    if (code == 205) reason = "Suspicious File Descriptor";

    if (code == 301) reason = "Mount Namespace Tampering";
    if (code == 302) reason = "System Seal Broken";
    if (code == 303) reason = "Dynamic Instrumentation (Frida)";
    if (code == 304) reason = "SELinux is Disabled";
    if (code == 305) reason = "KernelSU Active Detected";
    if (code == 306) reason = "KernelSU Passive Detected";
    if (code == 307) reason = "Root Mount Point Found";
    if (code == 308) reason = "Global Offset Table Hooked";
    if (code == 310) reason = "Execution Timing Anomaly";
    if (code == 311) reason = "Timing Side-Channel Attack";
    if (code == 312) reason = "Root Smoke Test Failed";
    if (code == 313) reason = "App Integrity Check Failed";
    if (code == 314) reason = "System Integrity Check Failed"; 
    if (code == 315) reason = "Key Attestation Failed"; 
    if (code == 316) reason = "App Signature Mismatch";

    if (code == 999) reason = "Hooking Detected";

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

        if (issuer.contains("let's encrypt") || issuer.contains("google trust services") || issuer.contains("cloudflare") || issuer.contains("zerossl") || issuer.contains("digicert") || issuer.contains("sectigo") || issuer.contains("comodoca") || issuer.contains("globalsign") || issuer.contains("amazon") || issuer.contains("entrust") || issuer.contains("geotrust") || issuer.contains("thawte") || issuer.contains("buypass") || issuer.contains("ssl.com") || issuer.contains("certum") || issuer.contains("quovadis") || issuer.contains("trustwave") || issuer.contains("network solutions") || issuer.contains("godaddy") || issuer.contains("digi-cert") || issuer.contains("r3") || issuer.contains("isrg root x1") || issuer.contains("gts root r1")){
          return true;
        }

        blockedIssuer = certificate.issuer;
        return false;
      };
      
      final IOClient secureClient = IOClient(httpClient);

      final challengeResponse = await secureClient.get(Uri.parse("$serverUrl/api/get-challenge?deviceID=$deviceID"));
      if (challengeResponse.statusCode != 200) throw Exception("Server rejected connection");

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
        throw Exception("Server Error: ${verifyResponse.statusCode}");
      }
    } catch (e) {

      String errorMsg = e.toString();
      if (blockedIssuer != null){
        errorMsg = "MITM BLOCKED ! Untrusted Certificate Intercepted:\n $blockedIssuer";
      }
      _updateUI("Error", errorMsg, Colors.grey, Icons.cloud_off);
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
            Text(_detailedReason, style: TextStyle(fontSize: 16, color: Colors.grey[400])),
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