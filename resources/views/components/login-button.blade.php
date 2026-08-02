<a {{ $attributes->merge([
    'href' => route('miraicards.redirect'),
    'class' => 'inline-flex items-center justify-center align-middle focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2',
    'style' => 'display: inline-flex; align-items: center; justify-content: center; vertical-align: middle;',
]) }}>
    <img
        src="{{ route('miraicards.assets.login-button') }}"
        alt="{{ $slot->isEmpty() ? __('Sign in with MiraiCards') : $slot }}"
        width="328"
        height="63"
        class="block h-auto w-full max-w-[20.5rem]"
        style="display: block; max-width: 100%; height: auto;"
    >
</a>
