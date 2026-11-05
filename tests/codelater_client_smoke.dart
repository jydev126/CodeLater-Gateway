// Optional compatibility check using the adjacent CodeLater's actual transport.
// Run via client_smoke.py; no additional Dart packages or SSH implementation here.
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:remote_code_browser/remote/websocket_ssh_socket.dart';

const password = 'test-only:随机-password-123456';

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Future<void> main(List<String> args) async {
  final url = Uri.parse(args[0]);
  final port = int.parse(args[1]);
  Future<WebSocketSshSocket> connect({
    String secret = password,
    String host = '127.0.0.1',
  }) => WebSocketSshSocket.connect(
    gateway: GatewayProfile(url: url, password: secret),
    targetHost: host,
    targetPort: port,
    allowInsecureLocalhost: true,
  );

  final socket = await connect();
  final payload = Uint8List.fromList(List.generate(2 * 1024 * 1024 + 7, (i) => i % 251));
  final received = BytesBuilder(copy: false);
  final complete = Completer<void>();
  final subscription = socket.stream.listen((chunk) {
    received.add(chunk);
    if (received.length == payload.length) complete.complete();
  }, onError: (Object error, StackTrace stack) {
    if (!complete.isCompleted) complete.completeError(error, stack);
  });
  try {
    await socket.addStream(Stream.fromIterable([
      for (var start = 0; start < payload.length; start += 65536)
        Uint8List.sublistView(payload, start, (start + 65536).clamp(0, payload.length)),
    ]));
    await socket.flush();
    await complete.future.timeout(const Duration(seconds: 10));
    final actual = received.takeBytes();
    check(actual.length == payload.length, 'byte count mismatch');
    for (var i = 0; i < actual.length; i++) {
      check(actual[i] == payload[i], 'byte order/content mismatch');
    }
  } finally {
    socket.destroy();
    await socket.done.timeout(const Duration(seconds: 10));
    await subscription.cancel();
  }

  Future<void> rejects(Future<WebSocketSshSocket> pending, GatewayErrorCode expected) async {
    try {
      final unexpected = await pending;
      unexpected.destroy();
      throw StateError('expected rejection');
    } on GatewayException catch (error) {
      check(error.code == expected, 'incorrect CodeLater error mapping');
    }
  }
  await rejects(connect(secret: 'incorrect-test-only'), GatewayErrorCode.gatewayUnauthorized);
  await rejects(connect(host: '192.0.2.1'), GatewayErrorCode.targetDenied);
  stdout.writeln('CodeLater real transport: 2 MiB+ binary echo, close, 401 and target_denied passed');
}
