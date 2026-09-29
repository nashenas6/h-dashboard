<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // CSP in report-only mode first — validate for 1-2 weeks before enforcing.
        // No report-uri/report-to: no reporting endpoint is registered (issue #742).
        // report-uri is deprecated; reporting needs a separate-domain endpoint
        // (report-to + Reporting-Endpoints) — an architecture decision, not a route.
        $response->headers->set('Content-Security-Policy-Report-Only', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        return $response;
    }
}
