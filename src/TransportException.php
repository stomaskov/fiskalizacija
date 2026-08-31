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

    public function __construct(string $message, int $curlErrno = 0)
    {
        parent::__construct($message);

        $this->curlErrno = $curlErrno;
    }

    public function getCurlErrno(): int
    {
        return $this->curlErrno;
    }

    /**
     * True when the request may have reached CIS despite failing, so re-sending the same
     * receipt number risks a second JIR for one receipt.
     *
     * Errors not in the never-delivered list — a timeout above all — are treated as
     * indeterminate, and so is an unknown code (0). Defaulting to "may have been delivered"
     * is the safe direction: the cost of being wrong is a receipt held for reconciliation,
     * versus a duplicate record at the tax authority that cannot be withdrawn.
     */
    public function isIndeterminate(): bool
    {
        return !in_array($this->curlErrno, self::NEVER_DELIVERED, true);
    }
}
