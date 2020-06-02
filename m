Return-Path: <kasan-dev+bncBDYJPJO25UGBBF6C3L3AKGQEJH23DAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E3DA1EC23C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:57:29 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id y11sf9063192pfn.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:57:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591124247; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKLcOnwgvHi7bkh/h11rNypB1qkhw8sA4Ryu+k5QFdGYolC/eVrr4Z2UVDyIRBwUUg
         /K0KrrGFKXZVdGLCm6b++AGDf+5TEC7440RHrkqxpJeUA5XWFttHs5RkeG1bGjip7hMx
         zmeR1TJsPlzuQmikwTWuHbZPXq7GQZcOZVP/RaUoHGRI6sRwu6aS6UZ1Zruo49mj0aeL
         KrzcG/xm9PYJVQR7WV+8tluzb1OnyT2U7+L7RTZzvaE9Av5XZIb55WfwURcFKLPWv7J/
         6n8Rj+az6Ugu/1GJyT+X8ynfpnhzdjVjSSnSyVY07qLP9Q0opt1tBR3sqeJCnC37FXi0
         BXkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ds1fFN+LzuPDecNFxL9Q3xIMVzpNXRiZFk04m0zsMeo=;
        b=O29oaMfYu16E59sPyFdb7nqPabw+WY1HbSov0YlFJMrjhMHrjeodvZueMo/q0RGpqc
         iWKxjVItenb9pTpY/e0vN25Ps0yxvpf541vpYhq5u84x0vfQ6HdK0KfPwz2a1fdDI4sy
         bE6uoGF/lNQVl4J2A8giMwpYYfFcWQZv3bsnwHaUALUAAMWhhTZW8oJ4TvLvqX3O8c+I
         uce/n76jONMfQyD/bsNWVAygE5pJRBQ+UeeSJRTWkdBcQtD8F1f+i5wxaVWBw/Vp6NLc
         eLfaNfjpge1zoNV2g5MGz5eTbSgLW6EWvJXVE3CPYs8MRYUHXA+9HTY/HuE8XKwgcceo
         8WhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IZTwU0Bw;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ds1fFN+LzuPDecNFxL9Q3xIMVzpNXRiZFk04m0zsMeo=;
        b=O4v2rqVdxyeq3ZESMkbtE03JnYciwBPD53RB+fUn+pJkyBHUQCas17VnrbaEHJbGS3
         Qf+1sGKpp98B4N3Q5ml24g9ACxpH7vEQ0onJR8Q/kE3qwBE3in2lH0ypJhgckod1CFYq
         lP0jhekF2sUitx05o88hZCuqZClRT/eGzETgTMbuo1TRNW4ukJg3js3fz0KfURCjnop7
         qI+q6X+Rxv4fkrM2yDMdwBBc6+FujoFN3PuftbB98nNmYNoUeh0VvVsp8HKjE9KoUTfj
         8a0AgCZijq6+yydNES5A9ExRVL+IYnZpfMdJ2jJr1IHPpu98uoX8BBeRqbpbn5BP+vvK
         sZ5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ds1fFN+LzuPDecNFxL9Q3xIMVzpNXRiZFk04m0zsMeo=;
        b=kFWcBeTcwcvwd4s4zG0V5r2Up/1rWL74pSs2ibsvqEhzrOILbQIR7CV4sNDf5022UN
         juUHDRVLbUXb7cHam1ldkZHWfYB7NUiZmR6Zeb5yb+uy6CxyzNeqDawL0cQCZL74H0qK
         wWUeMDFBKd9yyGSi813rGV4QCAPQW8ixUQyAonfeMbv1gTa6+nsibiOiGBJ4NaXjdp2p
         UZtUr0BuuKDkuOids+fjyRwGadxglxbGd1EplyVICyDk5ykwNuYK584dHC/K8X7eJbJb
         YL7C59tBylkJYb3LyRq5qCk6nulM2i8ShJyAF6AL4Z5BJRrQnxW/AmNnksKWkCv+Wu4d
         xpHQ==
X-Gm-Message-State: AOAM533j8xygiQTrYAM0JB4b89FGM7NAymmq9gZJsnen/l+sh7Qs25RH
	7bu19Owv4FLYSTc2wY1YSeA=
X-Google-Smtp-Source: ABdhPJx65dLjGs1Rx8RrMmUVPbn6nLosMfoQDe+RglYvuZDpAzoqV/U9O/HwFdWUGBRPaJvGQp2Gjw==
X-Received: by 2002:a62:5f84:: with SMTP id t126mr28345983pfb.124.1591124247664;
        Tue, 02 Jun 2020 11:57:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7604:: with SMTP id s4ls2023258pjk.1.gmail; Tue, 02
 Jun 2020 11:57:27 -0700 (PDT)
X-Received: by 2002:a17:90b:806:: with SMTP id bk6mr687733pjb.122.1591124247177;
        Tue, 02 Jun 2020 11:57:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591124247; cv=none;
        d=google.com; s=arc-20160816;
        b=opzye9zpw0acUh8+RuGmT5xoN9FHY591aEHlGaX93P1srcfK8tth+WgD45pe7G/1T4
         csPoosMvqRwGlEct3ZzMrxJLTag/m6kHOYgk/cwrl+h/ScVk01fh7hLdVRwKQMJcumrl
         DAsZHth982R6TwJvjAjBXhADZRFGCzuWWEw7JOJw7p9KKanDuYkitS0NThZp8vEZRcqP
         UqjOV+ixfJrs6l/blFkKlUZwu6UPG+BS+9qsF1I3ygxs2nOLTGiY7LBd1r5+sUffnRSO
         to7TIWNzwPxwspmllNmirOAN+RwzA6WXoC33nV/KduU+8ICfCnb3GHL3frCURW45Jwu1
         ZSww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NBeXDiXpaNYSmdLg+CEOi/2SkM043Ho1hEbW/kRa2lU=;
        b=PIKes1nJgoAn+nw4LeIM6Dd77fdotGdZdl6g7AtEpb8Vi0MLINqXtCWu3bYMlWEDbV
         WgHSgVtUG20wWNNq1lihyL/J4QdFlK8QsJx4fDZsDh04XnPDZ/K5MweLrsysaBd8lYwq
         Qe5fQ5mA64ScXLnUiL8J8u9RYmAvod479p4K7cAXQ5PJSdhndA9bIhuOX2sWdVrlofE2
         KIiGecxR1mWd5zG/f3Fj9uFHr3kAcTSJ8QS5PqAiYLjvnR2M1wDaqbkceFuDfKRwW2SY
         2C5kQlyTPYNWF+110wJwzzOhMFrR9iUs544c5neueTn0Crt5SxbbuPWmtaxUbQHy4833
         N5kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IZTwU0Bw;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id g10si200444plg.3.2020.06.02.11.57.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:57:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id d10so5522731pgn.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:57:27 -0700 (PDT)
X-Received: by 2002:a63:5644:: with SMTP id g4mr24385954pgm.381.1591124246486;
 Tue, 02 Jun 2020 11:57:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com>
In-Reply-To: <20200602184409.22142-1-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 11:57:15 -0700
Message-ID: <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IZTwU0Bw;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Jun 2, 2020 at 11:44 AM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
>
> Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> have a compiler that does not fail builds due to no_sanitize functions.
> This does not yet mean they work as intended, but for automated
> build-tests, this is the minimum requirement.
>
> For example, we require that __always_inline functions used from
> no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> fails to build entirely, therefore we make the minimum version GCC 8.
>
> For KCSAN this is a non-functional change, however, we should add it in
> case this variable changes in future.
>
> Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>

Is this a problem only for x86?  If so, that's quite a jump in minimal
compiler versions for a feature that I don't think is currently
problematic for other architectures?  (Based on
https://lore.kernel.org/lkml/20200529171104.GD706518@hirez.programming.kicks-ass.net/
)

> ---
> Apply after:
> https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
> ---
>  init/Kconfig      | 3 +++
>  lib/Kconfig.kasan | 1 +
>  lib/Kconfig.kcsan | 1 +
>  lib/Kconfig.ubsan | 1 +
>  4 files changed, 6 insertions(+)
>
> diff --git a/init/Kconfig b/init/Kconfig
> index 0f72eb4ffc87..3e8565bc8376 100644
> --- a/init/Kconfig
> +++ b/init/Kconfig
> @@ -39,6 +39,9 @@ config TOOLS_SUPPORT_RELR
>  config CC_HAS_ASM_INLINE
>         def_bool $(success,echo 'void foo(void) { asm inline (""); }' | $(CC) -x c - -c -o /dev/null)
>
> +config CC_HAS_WORKING_NOSANITIZE
> +       def_bool !CC_IS_GCC || GCC_VERSION >= 80000
> +
>  config CONSTRUCTORS
>         bool
>         depends on !UML
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..15e6c4b26a40 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -20,6 +20,7 @@ config KASAN
>         depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
>                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>           designed to find out-of-bounds accesses and use-after-free bugs.
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 5ee88e5119c2..2ab4a7f511c9 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -5,6 +5,7 @@ config HAVE_ARCH_KCSAN
>
>  config HAVE_KCSAN_COMPILER
>         def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           For the list of compilers that support KCSAN, please see
>           <file:Documentation/dev-tools/kcsan.rst>.
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index a5ba2fd51823..f725d126af7d 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
>
>  menuconfig UBSAN
>         bool "Undefined behaviour sanity checker"
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           This option enables the Undefined Behaviour sanity checker.
>           Compile-time instrumentation is used to detect various undefined
> --

-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3D5_pgx2%2ByQt%3DV_6h7YKiCnVp_L4nsRhz%3DEzawU1Kf1zg%40mail.gmail.com.
