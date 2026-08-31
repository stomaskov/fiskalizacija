<?php

use Nticaric\Fiskalizacija\Fiskalizacija;

/**
 * The CIS request timeouts.
 *
 * These were both 5 seconds, which is below what the tax authority's service actually takes
 * under load. Worse than being slow, it is unsafe: when the timeout fires on a response
 * already in flight, CIS has assigned a JIR that the client never sees, the receipt stays
 * unfiscalized locally, and the next run submits the same receipt number again — a second
 * JIR for one receipt. A production log line from that failure mode reads
 * "Operation timed out after 5000 milliseconds with 4312 bytes received": the reply was
 * two thirds delivered when the client hung up.
 */
class CurlTimeoutTest extends \PHPUnit\Framework\TestCase
{
    private string $certificatePath = '';

    protected function tearDown(): void
    {
        if ($this->certificatePath !== '' && file_exists($this->certificatePath)) {
            unlink($this->certificatePath);
        }
    }

    public function testTheRequestTimeoutLeavesCisTimeToAnswer()
    {
        $options = $this->fiskalizacija()->curlOptions('<payload/>');

        $this->assertGreaterThanOrEqual(
            30,
            $options[CURLOPT_TIMEOUT],
            'A short total timeout aborts responses CIS has already committed, producing duplicate JIRs.'
        );
    }

    public function testTheConnectTimeoutIsSeparateFromTheRequestTimeout()
    {
        $options = $this->fiskalizacija()->curlOptions('<payload/>');

        $this->assertGreaterThanOrEqual(10, $options[CURLOPT_CONNECTTIMEOUT]);
        $this->assertLessThan(
            $options[CURLOPT_TIMEOUT],
            $options[CURLOPT_CONNECTTIMEOUT],
            'Connecting must be allowed to fail faster than a whole request.'
        );
    }

    /**
     * Callers run under their own schedules and lock windows, so the timeouts have to be
     * tunable without a package release.
     */
    public function testTheTimeoutsCanBeOverriddenByTheCaller()
    {
        $fis = $this->fiskalizacija();
        $fis->setTimeouts(45, 7);

        $options = $fis->curlOptions('<payload/>');

        $this->assertSame(45, $options[CURLOPT_TIMEOUT]);
        $this->assertSame(7, $options[CURLOPT_CONNECTTIMEOUT]);
    }

    public function testTheOptionsStillCarryTheRequestItself()
    {
        $options = $this->fiskalizacija()->curlOptions('<payload/>');

        $this->assertSame('<payload/>', $options[CURLOPT_POSTFIELDS]);
        $this->assertTrue($options[CURLOPT_POST]);
        $this->assertTrue($options[CURLOPT_RETURNTRANSFER]);
        $this->assertSame(2, $options[CURLOPT_SSL_VERIFYHOST]);
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

        $path = tempnam(sys_get_temp_dir(), 'fiskal') . '.p12';
        file_put_contents($path, $pkcs12);

        return $path;
    }
}
