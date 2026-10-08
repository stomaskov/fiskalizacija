<?php

namespace Nticaric\Fiskalizacija;

use Exception;

/**
 * The request to CIS failed at the transport layer — it never got an HTTP response.
 *
 * Distinct from the Exception parseResponse() throws for a CIS *fault*, and the difference
 * matters for what the caller may safely do next. A fault is CIS answering: it has seen the
 * receipt, rejected it, and is not storing it, so the caller can fix the payload and send
 * the same receipt number again. A transport failure may mean anything, including that CIS
 * accepted the receipt and issued a JIR that never made it back.
 *
 * isIndeterminate() separates the two cases the caller actually needs:
 * failures where the request provably never reached CIS (nothing resolved, nothing
 * connected, TLS never came up) are safe to retry; everything else — above all a timeout
 * partway through a reply — is not.
 */
class TransportException extends Exception
{
    /**
     * curl error codes where the request cannot have been delivered, so no receipt can have
     * been recorded on the far side.
     *
     * CURLE_OPERATION_TIMEDOUT (28) is deliberately absent: curl raises it for every timeout,
     * whatever phase the transfer was in. "Resolving timed out", "Connection timed out" and
     * "SSL connection timeout" are all errno 28 and all fire before a single request byte is
     * written; "Operation timed out after 5000 milliseconds with 4312 bytes received" is
     * also errno 28, and that one may well have been recorded by CIS. The errno cannot tell
     * them apart — the request size can, see isIndeterminate().
     */
    private const NEVER_DELIVERED = [
        CURLE_UNSUPPORTED_PROTOCOL,
        CURLE_URL_MALFORMAT,
        CURLE_COULDNT_RESOLVE_PROXY,
        CURLE_COULDNT_RESOLVE_HOST,
        CURLE_COULDNT_CONNECT,
        CURLE_SSL_CONNECT_ERROR,
        CURLE_SSL_CERTPROBLEM,
        CURLE_SSL_CIPHER,
        CURLE_SSL_CACERT,
    ];

    private int $curlErrno;

    private ?int $requestSize;

    /**
     * @param int|null $requestSize Bytes of the HTTP request curl actually wrote to the
     *                              connection (CURLINFO_REQUEST_SIZE), or null when unknown.
     */
    public function __construct(string $message, int $curlErrno = 0, ?int $requestSize = null)
    {
        parent::__construct($message);

        $this->curlErrno = $curlErrno;
        $this->requestSize = $requestSize;
    }

    public function getCurlErrno(): int
    {
        return $this->curlErrno;
    }

    /** Bytes of the HTTP request written before the failure, or null when unknown. */
    public function getRequestSize(): ?int
    {
        return $this->requestSize;
    }

    /**
     * True when the request may have reached CIS despite failing, so re-sending the same
     * receipt number risks a second JIR for one receipt.
     *
     * Not indeterminate when the errno is one that cannot follow a delivery, or when curl
     * wrote zero bytes of the request: curl only writes the request once the connection
     * (and TLS) is up, so a failure with nothing written happened while resolving,
     * connecting or handshaking, and CIS never saw the receipt. That is what separates a
     * connect-phase errno 28 from a reply-phase one.
     *
     * Everything else is indeterminate: any failure after request bytes were written
     * (whatever the errno, including an unknown 0), and any failure whose request size is
     * unknown (null). Defaulting to "may have been delivered" is the safe direction: the cost
     * of being wrong is a receipt held for reconciliation, versus a duplicate record at the
     * tax authority that cannot be withdrawn.
     */
    public function isIndeterminate(): bool
    {
        if (in_array($this->curlErrno, self::NEVER_DELIVERED, true)) {
            return false;
        }

        return $this->requestSize !== 0;
    }
}
