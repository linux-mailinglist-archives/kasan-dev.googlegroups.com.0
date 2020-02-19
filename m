Return-Path: <kasan-dev+bncBCMIZB7QWENRB6FZWXZAKGQE7QAYJBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9872E164973
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 17:06:18 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id t17sf427360pgb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 08:06:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582128377; cv=pass;
        d=google.com; s=arc-20160816;
        b=spNyq60TmTNrBfezIAzEg1gyIybf9JbweAcqdg5coz2ZgA001uinCVhn/wU7ZosgRO
         HpcjCHLrH4nJT6c10aim/RWZbKrWRyx6fSdUIYtmpyq8gFln84FJ6GuN4OvhhCeCRvey
         VA/9ZJDo+Uk6N4u4pFSVzSP2Rgy1VwBNsUl6y2ppsRKnuVuIKDyH5O3dEMH8TJoqqU/w
         yQTvnYZzPAOwRgp0YXuN1p+SKnZAnqlL3CylTUppgdPSVXiyi6yz20Ufay69dkFA2MZ9
         dEpmzs/hrwBq8MxmlUVUXUn26qiopAJerO7GPQvmGNAPy9vdh+ZwO1v6OXUj8bhWRrhL
         1OBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XgQN7BfKZWsNgy+1iHCjeLFnLTx553wQufmmKm4cvT0=;
        b=sgPg47mxP8W+rgyJY8TN1fsaoA38vahZz6ogSZBQf4M+gafbXpk/8G7X9zrmWci3rM
         L10pUrcdxLbnOCnlXS+eVypQhXxXXfxe01juFXNQPLVD7ja+fJ0nnNMa7D+L6aI3DXDi
         pauckyxEp4eogk1SFCMEzJ2GXdZHT0sUIJ+lVX2EVmZaw8JnlqPae8Dz2GGnax+E8vg9
         IRdDPnL5pWwNcrLyFj6J4xHs49l5Vt2DIRLhKJE4cOY9XKjey74+0CrPNiueVmXRYbNz
         vF/If2BR5/hDxTy3QfPqH0PMaVs0WrzRUBY8r13l6JikgIpJS+zGtnvm2rWAg04BwGef
         P5Sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GzyOGDrL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XgQN7BfKZWsNgy+1iHCjeLFnLTx553wQufmmKm4cvT0=;
        b=PH6yfWW07XMep3Xy17GoSme3H3pxkDxlBz6tMkA8Y66JPXWuefz6jBSc9Z6XHJiL4U
         IdKEeXAbzMrNqOBts8qwgY9RY7NHunnYpA1WQ3ZAZqEkfh1Ieg80OWVQ454VGkGC23om
         n1BViH6jnoMI3majcIypFdefFfOa1PkE/HKISvlJDADwIMJ5+lmmb4silv+RhuFmdX5F
         pNPYSRrPoG5V+TJKMocJvb59xkQHQCnen/Q7d5w/VS8iT0e77M8XHTOxE+Dk2Ooff58f
         7r07v7wKkReNBMrqp58TI3dWP4ZFXkShNTPDmKlGXBQv9EShptcJxkNM//QrtWIuBCiw
         AHrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XgQN7BfKZWsNgy+1iHCjeLFnLTx553wQufmmKm4cvT0=;
        b=BsWsSfl747463ZA5wfowD4N4iOCNNwqkH6uradbqOx8DdeNw+a115oaqA7MkutY1Ev
         YKNHCTeF1TO5+9qsajvdJjs/W6iGkWsvLRo87LDeVXCRApCIeSqxi9AY/WrlVDMGNYzh
         CDmCxap7rDEE6JdPqsPm2KmMBVCLIPC7zgv9h7zQy+MHp9v2WnVZsKhWYfecVM4u95jM
         61UdDaAYeS7Eu2X8nDX42I8WZyq+b5WWyTpBIqsNINEJu3QAecQd1s/WNRepeKeGoOxo
         PM9hxR+yW6jTVDwWIHIkmGpJKu26XkF/fNvfO9IkyibXI72wMOsymL1mf82QtPFwPxnf
         whOg==
X-Gm-Message-State: APjAAAVfyGjlaK76U/2mSJpT8lDKxWaNBoVpO9p6SqxBmQLx7J6Drq2k
	E8XxtRuzEZ+sv3dCRFKad2k=
X-Google-Smtp-Source: APXvYqxpmuESCzx4RK3iCXc2Vwf9f7JoOe4RXWjBUQwvXFFTa+p2prfw0ZcE8mYFqj+Uo0ESx8awjg==
X-Received: by 2002:a17:902:ab81:: with SMTP id f1mr27352217plr.5.1582128376714;
        Wed, 19 Feb 2020 08:06:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:46ce:: with SMTP id jx14ls3053897pjb.3.gmail; Wed,
 19 Feb 2020 08:06:16 -0800 (PST)
X-Received: by 2002:a17:90a:98d:: with SMTP id 13mr9796820pjo.102.1582128376273;
        Wed, 19 Feb 2020 08:06:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582128376; cv=none;
        d=google.com; s=arc-20160816;
        b=k/VOcc47DhdF+4AnHbhwHsrgUG3BvBW1I5pRQUhEeWKV8nIa0vzUBvi/OjrVNrQZi1
         r10r0i+ipP+1tsrepZtpHrUPWdb5LfRHydbEbhK3I/6VfQ0wZBrRmVAR4It0OFUvVeR8
         uZ4o18IencZvTen6h/Y/7aqlY6t9Sq05foB9GLHZTm2YwbTuZGA+EMqyZ440ncuhZE0s
         fgWsGn4UL4bmB7NbvYJwCqXHQwT370/yL/eWtJQWoa1TctHq77YTP6rgbi7zUKovo5aS
         pUT+zejSf4rohzsu741LjtOzjVybJgJsIt9xuHJ56yKuRz307fyIzWfQthA2uzYt6cFx
         89Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uhi4M2kPWQtaIRnOkT6OXlV4BqN3p0xNbs1d1Zj15X4=;
        b=COM9UX+EGck8FMCeQQKoXnEg1aFy58Sc70B4u4C+XYKNaPv+gtQr7qrBgUDbvWyEwC
         Lwh0BQ1hnJ1+eVSScq5Puq/wts5xGznZO0gelc9NKcHdO20ZNIMlHslWN2IcQ6xuVFip
         0tfhXzy4J46cmTU7f++tkbouwAM3pKFecRwdGwAxgduPfVlpj4W9tWQbNoxt/T4J6IZX
         lFNNIx7ndhSHBZj3CgwX4Z+qJ6vBH5naruuV4QHpn6URw6c24bo9gMbOlf90tm0yqsOQ
         8lngYGdzCkAvhTSO44wiPV00Vsuxf5frxvZOB0n5u2kIQPohOGNiuKFmZN7fDf6fBEM+
         Likw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GzyOGDrL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id 59si27100ple.2.2020.02.19.08.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2020 08:06:16 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id b7so577742qkl.7
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2020 08:06:16 -0800 (PST)
X-Received: by 2002:a05:620a:150a:: with SMTP id i10mr2031290qkk.407.1582128375013;
 Wed, 19 Feb 2020 08:06:15 -0800 (PST)
MIME-Version: 1.0
References: <20200219144724.800607165@infradead.org> <20200219150745.651901321@infradead.org>
In-Reply-To: <20200219150745.651901321@infradead.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Feb 2020 17:06:03 +0100
Message-ID: <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is not sanitized
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com, 
	Frederic Weisbecker <frederic@kernel.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GzyOGDrL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Feb 19, 2020 at 4:14 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> In order to ensure poke_int3_handler() is completely self contained --
> we call this while we're modifying other text, imagine the fun of
> hitting another INT3 -- ensure that everything is without sanitize
> crud.

+kasan-dev

Hi Peter,

How do we hit another INT3 here? Does the code do
out-of-bounds/use-after-free writes?
Debugging later silent memory corruption may be no less fun :)

Not sanitizing bsearch entirely is a bit unfortunate. We won't find
any bugs in it when called from other sites too.
It may deserve a comment at least. Tomorrow I may want to remove
__no_sanitize, just because sanitizing more is better, and no int3
test will fail to stop me from doing that...

It's quite fragile. Tomorrow poke_int3_handler handler calls more of
fewer functions, and both ways it's not detected by anything. And if
we ignore all by one function, it is still not helpful, right?
Depending on failure cause/mode, using kasan_disable/enable_current
may be a better option.


> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Reported-by: Thomas Gleixner <tglx@linutronix.de>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  arch/x86/kernel/alternative.c       |    4 ++--
>  arch/x86/kernel/traps.c             |    2 +-
>  include/linux/compiler-clang.h      |    7 +++++++
>  include/linux/compiler-gcc.h        |    6 ++++++
>  include/linux/compiler.h            |    5 +++++
>  include/linux/compiler_attributes.h |    1 +
>  lib/bsearch.c                       |    2 +-
>  7 files changed, 23 insertions(+), 4 deletions(-)
>
> --- a/arch/x86/kernel/alternative.c
> +++ b/arch/x86/kernel/alternative.c
> @@ -979,7 +979,7 @@ static __always_inline void *text_poke_a
>         return _stext + tp->rel_addr;
>  }
>
> -static int notrace patch_cmp(const void *key, const void *elt)
> +static int notrace __no_sanitize patch_cmp(const void *key, const void *elt)
>  {
>         struct text_poke_loc *tp = (struct text_poke_loc *) elt;
>
> @@ -991,7 +991,7 @@ static int notrace patch_cmp(const void
>  }
>  NOKPROBE_SYMBOL(patch_cmp);
>
> -int notrace poke_int3_handler(struct pt_regs *regs)
> +int notrace __no_sanitize poke_int3_handler(struct pt_regs *regs)
>  {
>         struct bp_patching_desc *desc;
>         struct text_poke_loc *tp;
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -496,7 +496,7 @@ dotraplinkage void do_general_protection
>  }
>  NOKPROBE_SYMBOL(do_general_protection);
>
> -dotraplinkage void notrace do_int3(struct pt_regs *regs, long error_code)
> +dotraplinkage void notrace __no_sanitize do_int3(struct pt_regs *regs, long error_code)
>  {
>         if (poke_int3_handler(regs))
>                 return;
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -24,6 +24,13 @@
>  #define __no_sanitize_address
>  #endif
>
> +#if __has_feature(undefined_sanitizer)
> +#define __no_sanitize_undefined \
> +               __atribute__((no_sanitize("undefined")))
> +#else
> +#define __no_sanitize_undefined
> +#endif
> +
>  /*
>   * Not all versions of clang implement the the type-generic versions
>   * of the builtin overflow checkers. Fortunately, clang implements
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -145,6 +145,12 @@
>  #define __no_sanitize_address
>  #endif
>
> +#if __has_attribute(__no_sanitize_undefined__)
> +#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
> +#else
> +#define __no_sanitize_undefined
> +#endif
> +
>  #if GCC_VERSION >= 50100
>  #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
>  #endif
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -199,6 +199,7 @@ void __read_once_size(const volatile voi
>         __READ_ONCE_SIZE;
>  }
>
> +#define __no_kasan __no_sanitize_address
>  #ifdef CONFIG_KASAN
>  /*
>   * We can't declare function 'inline' because __no_sanitize_address confilcts
> @@ -274,6 +275,10 @@ static __always_inline void __write_once
>   */
>  #define READ_ONCE_NOCHECK(x) __READ_ONCE(x, 0)
>
> +#define __no_ubsan __no_sanitize_undefined
> +
> +#define __no_sanitize __no_kasan __no_ubsan
> +
>  static __no_kasan_or_inline
>  unsigned long read_word_at_a_time(const void *addr)
>  {
> --- a/include/linux/compiler_attributes.h
> +++ b/include/linux/compiler_attributes.h
> @@ -41,6 +41,7 @@
>  # define __GCC4_has_attribute___nonstring__           0
>  # define __GCC4_has_attribute___no_sanitize_address__ (__GNUC_MINOR__ >= 8)
>  # define __GCC4_has_attribute___fallthrough__         0
> +# define __GCC4_has_attribute___no_sanitize_undefined__ (__GNUC_MINOR__ >= 9)
>  #endif
>
>  /*
> --- a/lib/bsearch.c
> +++ b/lib/bsearch.c
> @@ -28,7 +28,7 @@
>   * the key and elements in the array are of the same type, you can use
>   * the same comparison function for both sort() and bsearch().
>   */
> -void *bsearch(const void *key, const void *base, size_t num, size_t size,
> +void __no_sanitize *bsearch(const void *key, const void *base, size_t num, size_t size,
>               cmp_func_t cmp)
>  {
>         const char *pivot;
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY%2BnPcnbb8nXGQA1%3D9p8BQYrnzab_4SvuPwbAJkTGgKOQ%40mail.gmail.com.
