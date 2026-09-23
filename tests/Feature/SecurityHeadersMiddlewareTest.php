<?php

use App\Http\Middleware\SecurityHeaders;
use Tests\TestCase;

covers(SecurityHeaders::class);

uses(TestCase::class);

test('SecurityHeaders middleware sets X-Content-Type-Options on web responses', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('X-Content-Type-Options', 'nosniff');
});

test('SecurityHeaders middleware sets X-Frame-Options DENY', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('X-Frame-Options', 'DENY');
});

test('SecurityHeaders middleware sets Referrer-Policy', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
});

test('SecurityHeaders middleware sets Content-Security-Policy-Report-Only', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('Content-Security-Policy-Report-Only');
    $csp = $response->headers->get('Content-Security-Policy-Report-Only');
    expect($csp)->toContain("default-src 'self'");
    expect($csp)->toContain("frame-ancestors 'none'");
    expect($csp)->toContain('report-uri /csp-report');
});

test('SecurityHeaders middleware sets HSTS header', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

test('SecurityHeaders middleware sets all five headers in a single request', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('X-Content-Type-Options', 'nosniff');
    $response->assertHeader('X-Frame-Options', 'DENY');
    $response->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    $response->assertHeader('Content-Security-Policy-Report-Only');
    $response->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

test('SecurityHeaders middleware adds headers to redirect responses', function () {
    // '/' for guests redirects before the web-group middleware runs, so test
    // the middleware directly with a redirect response instead.
    $middleware = new SecurityHeaders;
    $request = Illuminate\Http\Request::create('/dashboard', 'GET');

    $response = $middleware->handle($request, fn ($req) => redirect('/login'));

    expect($response->getStatusCode())->toBe(302);
    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
    expect($response->headers->get('X-Frame-Options'))->toBe('DENY');
    expect($response->headers->get('Referrer-Policy'))->toBe('strict-origin-when-cross-origin');
    expect($response->headers->has('Content-Security-Policy-Report-Only'))->toBeTrue();
    expect($response->headers->get('Strict-Transport-Security'))->toBe('max-age=31536000; includeSubDomains');
});
