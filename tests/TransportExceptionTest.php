<?php

use Nticaric\Fiskalizacija\Fiskalizacija;
use Nticaric\Fiskalizacija\TransportException;

/**
 * Which transport failures may have left a receipt at CIS.
 *
 * curl reports every timeout as CURLE_OPERATION_TIMEDOUT (28), whatever phase it fired in.
 * Treating 28 as "may have been delivered" held back every receipt whose DNS lookup, TCP
 * connect or TLS handshake timed out — 32 of them across two incidents, none of which had
 * sent a byte. Treating 28 as "never delivered" would re-send the receipt whose reply was cut off
 * mid-flight, which is how one receipt gets two JIRs. The request size separates the two.
 *
 * The sendSoap() tests run real curl against a local socket that listens but never accepts:
 * the kernel completes the TCP handshake into the backlog, so curl gets exactly as far as the
 * phase under test and no further. They assert what curl actually emits rather than an
 * exception built by hand, because a hand-built one only encodes the assumption under test.
 */
class TransportExceptionTest extends \PHPUnit\Framework\TestCase
{
    private string $certificatePath = '';

    /** @var resource|null */
    private $server = null;

    protected function tearDown(): void
    {
        if ($this->certificatePath !== '' && file_exists($this->certificatePath)) {
            unlink($this->certificatePath);
        }

        if (is_resource($this->server)) {
            fclose($this->server);
        }
    }

    public function testAnUnknownRequestSizeStaysIndeterminate()
    {
        $this->assertTrue((new TransportException('Operation timed out', CURLE_OPERATION_TIMEDOUT))->isIndeterminate());
        $this->assertTrue((new TransportException('Operation timed out', CURLE_OPERATION_TIMEDOUT, null))->isIndeterminate());
    }

    public function testATimeoutBeforeAnyRequestByteWasWrittenIsNotIndeterminate()
    {
        $e = new TransportException('Resolving timed out after 10000 milliseconds', CURLE_OPERATION_TIMEDOUT, 0);

        $this->assertFalse($e->isIndeterminate());
        $this->assertSame(0, $e->getRequestSize());
    }

    public function testATimeoutAfterTheRequestWasWrittenIsIndeterminate()
    {
        $e = new TransportException('Operation timed out after 5000 milliseconds with 4312 bytes received', CURLE_OPERATION_TIMEDOUT, 512);

        $this->assertTrue($e->isIndeterminate());
        $this->assertSame(512, $e->getRequestSize());
    }

    public function testANeverDeliveredErrnoIsNotIndeterminateWhateverTheRequestSize()
    {
        $this->assertFalse((new TransportException('Could not connect', CURLE_COULDNT_CONNECT))->isIndeterminate());
        $this->assertFalse((new TransportException('Could not connect', CURLE_COULDNT_CONNECT, 512))->isIndeterminate());
    }

    /**
     * The production case: the connect timeout fires while resolving, connecting or
     * handshaking. Here it is the TLS handshake — the socket accepts the TCP connection and
     * never answers the ClientHello, so not one byte of the HTTP request is written.
     */
    public function testAConnectPhaseTimeoutFromRealCurlIsNotIndeterminate()
    {
        $e = $this->sendTo('https://127.0.0.1:' . $this->listeningPort() . '/', 2, 1);

        $this->assertSame(CURLE_OPERATION_TIMEDOUT, $e->getCurlErrno(), $e->getMessage());
        $this->assertMatchesRegularExpression('/^(Resolving timed out|Connection timed out|SSL connection timeout)/', $e->getMessage());
        $this->assertSame(0, $e->getRequestSize());
        $this->assertFalse($e->isIndeterminate(), 'Nothing was sent, so CIS cannot hold this receipt; it must stay retryable.');
    }

    /**
     * The TCP connect itself never completes: a TEST-NET-1 address (RFC 5737), which most
     * networks drop silently. Where one rejects it instead, there is no timeout to observe.
     */
    public function testATcpConnectTimeoutFromRealCurlIsNotIndeterminate()
    {
        $e = $this->sendTo('https://192.0.2.1/', 2, 1);

        if ($e->getCurlErrno() !== CURLE_OPERATION_TIMEDOUT) {
            $this->markTestSkipped('This network rejects 192.0.2.1 rather than dropping it: ' . $e->getMessage());
        }

        $this->assertStringStartsWith('Connection timed out', $e->getMessage());
        $this->assertSame(0, $e->getRequestSize());
        $this->assertFalse($e->isIndeterminate());
    }

    /**
     * The duplicate-JIR case: the request is written and the reply never completes. Same
     * errno as the connect-phase timeout above — only the request size tells them apart.
     */
    public function testAReplyPhaseTimeoutFromRealCurlIsIndeterminate()
    {
        $e = $this->sendTo('http://127.0.0.1:' . $this->listeningPort() . '/', 1, 1);

        $this->assertSame(CURLE_OPERATION_TIMEDOUT, $e->getCurlErrno(), $e->getMessage());
        $this->assertStringStartsWith('Operation timed out', $e->getMessage());
        $this->assertGreaterThan(0, $e->getRequestSize());
        $this->assertTrue($e->isIndeterminate(), 'The request was written, so CIS may have issued a JIR; it must be held.');
    }

    public function testARefusedConnectionFromRealCurlIsNotIndeterminate()
    {
        $e = $this->sendTo('http://127.0.0.1:' . $this->closedPort() . '/', 1, 1);

        $this->assertSame(CURLE_COULDNT_CONNECT, $e->getCurlErrno(), $e->getMessage());
        $this->assertSame(0, $e->getRequestSize());
        $this->assertFalse($e->isIndeterminate());
    }

    private function sendTo(string $url, int $timeout, int $connectTimeout): TransportException
    {
        $fis = $this->fiskalizacija();
        $fis->setTimeouts($timeout, $connectTimeout);

        // The CIS address is fixed at construction; the tests point it at a local socket.
        $property = new ReflectionProperty(Fiskalizacija::class, 'url');
        $property->setAccessible(true);
        $property->setValue($fis, $url);

        try {
            $fis->sendSoap('<payload/>');
        } catch (TransportException $e) {
            return $e;
        }

        $this->fail('sendSoap() should have thrown a TransportException.');
    }

    /** A port that accepts TCP connections into the backlog and never reads or answers. */
    private function listeningPort(): int
    {
        $this->server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        $this->assertNotFalse($this->server, $error);

        return (int) parse_url('tcp://' . stream_socket_get_name($this->server, false), PHP_URL_PORT);
    }

    /** A port nothing listens on, so the connection is refused. */
    private function closedPort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        $this->assertNotFalse($socket, $error);
        $port = (int) parse_url('tcp://' . stream_socket_get_name($socket, false), PHP_URL_PORT);
        fclose($socket);

        return $port;
    }

    private function fiskalizacija(): Fiskalizacija
    {
        $this->certificatePath = $this->writeCertificate('secret');

        return new Fiskalizacija($this->certificatePath, 'secret', 'TLS', false);
    }

    /** A throwaway self-signed PKCS#12, so no real certificate is needed to construct. */
    private function writeCertificate(string $password): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $csr = openssl_csr_new(
            ['countryName' => 'HR', 'organizationName' => 'Test', 'commonName' => 'test.example'],
            $key
        );
        $cert = openssl_csr_sign($csr, null, $key, 365);

        openssl_pkcs12_export($cert, $pkcs12, $key, $password);

        $base = tempnam(sys_get_temp_dir(), 'fiskal');
        unlink($base);
        $path = $base . '.p12';
        file_put_contents($path, $pkcs12);

        return $path;
    }
}
