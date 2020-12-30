/*
 * Copyright 2015 The gRPC Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.grpc.examples.helloworldtls;

import io.grpc.Server;
import io.grpc.examples.helloworld.GreeterGrpc;
import io.grpc.examples.helloworld.HelloReply;
import io.grpc.examples.helloworld.HelloRequest;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

/** Server that manages startup/shutdown of a {@code Greeter} server with TLS enabled. */
public class HelloWorldServerTls {
  private static final Logger logger = Logger.getLogger(HelloWorldServerTls.class.getName());

  private Server server;

  private final int port;
  private final File certChainFile;
  private final File privateKeyFile;
  private final File trustCertCollectionFile;

  public HelloWorldServerTls(
      int port,
      String certChainFilePath,
      String privateKeyFilePath,
      String trustCertCollectionFilePath) {
    this.port = port;
    this.certChainFile = new File(certChainFilePath);
    this.privateKeyFile = new File(privateKeyFilePath);
    this.trustCertCollectionFile =
        trustCertCollectionFilePath == null ? null : new File(trustCertCollectionFilePath);
  }

  private SslContextBuilder getSslContextBuilder()
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, CertificateException {
    SslContextBuilder sslClientContextBuilder =
        SslContextBuilder.forServer(
            BouncyCastle.readPrivateKey(privateKeyFile),
            BouncyCastle.readCertificate(certChainFile));
    if (trustCertCollectionFile != null) {
      sslClientContextBuilder.trustManager(
          BouncyCastle.readCertificateCollection(trustCertCollectionFile));
      sslClientContextBuilder.clientAuth(ClientAuth.REQUIRE);
    }
    return GrpcSslContexts.configure(sslClientContextBuilder);
  }

  private void start()
      throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
    server =
        NettyServerBuilder.forPort(port)
            .addService(new GreeterImpl())
            .sslContext(getSslContextBuilder().build())
            .build()
            .start();
    logger.info("Server started, listening on " + port);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread() {
              @Override
              public void run() {
                // Use stderr here since the logger may have been reset by its JVM shutdown hook.
                System.err.println("*** shutting down gRPC server since JVM is shutting down");
                HelloWorldServerTls.this.stop();
                System.err.println("*** server shut down");
              }
            });
  }

  private void stop() {
    if (server != null) {
      server.shutdown();
    }
  }

  /** Await termination on the main thread since the grpc library uses daemon threads. */
  private void blockUntilShutdown() throws InterruptedException {
    if (server != null) {
      server.awaitTermination();
    }
  }

  /** Main launches the server from the command line. */
  public static void main(String[] args)
      throws IOException, InterruptedException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException {

    if (args.length < 3 || args.length > 4) {
      System.out.println(
          "USAGE: HelloWorldServerTls port certChainFilePath privateKeyFilePath"
              + " [trustCertCollectionFilePath]\n"
              + "  Note: You only need to supply trustCertCollectionFilePath if you want to enable"
              + " Mutual TLS.");
      System.exit(0);
    }

    final HelloWorldServerTls server =
        new HelloWorldServerTls(
            Integer.parseInt(args[0]), args[1], args[2], args.length == 4 ? args[3] : null);
    server.start();
    server.blockUntilShutdown();
  }

  static class GreeterImpl extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest req, StreamObserver<HelloReply> responseObserver) {
      HelloReply reply = HelloReply.newBuilder().setMessage("Hello " + req.getName()).build();
      responseObserver.onNext(reply);
      responseObserver.onCompleted();
    }
  }
}
