# MiraiCards Laravel Login

Private Laravel 12–13 integration for “Sign in with MiraiCards”. The package implements Authorization Code + PKCE S256, confidential client authentication, nonce/state validation, RS256/JWKS verification, UserInfo subject matching, and safe post-login redirects.

Install from the private GitHub repository through an authenticated Composer VCS repository, publish `miraicards-config` and `miraicards-assets`, bind `MiraiCardsUserResolver`, and set the `MIRAICARDS_*` environment values. Identity linking must use the unique `(issuer, subject)` pair; never link by email.

The package always requests MiraiCards Basic identity. Applications do not configure scopes. The identity response contains the pairwise subject, name, and email address.

```shell
php artisan vendor:publish --tag=miraicards-assets
```

Run `php artisan miraicards:doctor` after configuring the application. Provider callback registration remains a manual administrator check.
