<a {{ $attributes->merge([
    'href' => route('miraicards.redirect'),
    'class' => 'inline-flex min-h-11 items-center justify-center gap-3 rounded-lg border border-slate-300 bg-white px-5 py-3 font-semibold text-slate-900 shadow-sm transition hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2',
]) }}>
    <span aria-hidden="true" class="grid size-6 place-items-center rounded-md bg-indigo-600 text-sm font-bold text-white">M</span>
    <span>{{ $slot->isEmpty() ? __('Sign in with MiraiCards') : $slot }}</span>
</a>
