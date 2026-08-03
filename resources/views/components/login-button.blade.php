@once
    <link rel="stylesheet" href="{{ route('miraicards.assets.stylesheet') }}">
@endonce

<a {{ $attributes->merge([
    'href' => route('miraicards.redirect'),
    'class' => 'miraicards-login-button',
]) }}>
    <img
        src="{{ route('miraicards.assets.icon') }}"
        alt=""
        width="28"
        height="28"
        class="miraicards-login-button__icon"
        aria-hidden="true"
    >
    <span class="miraicards-login-button__label">{{ $slot->isEmpty() ? __('Sign in with MiraiCards') : $slot }}</span>
</a>
