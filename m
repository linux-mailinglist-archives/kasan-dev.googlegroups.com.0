Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYOI46BAMGQEVCZKNFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id A3031345E7E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 13:51:46 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id ga11sf2002681pjb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 05:51:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616503905; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zx61VXYgq+YMbmBjAoVY4urfoVNb+buPpHFnhugpOpTkuZwmqdacQXBkf1UrX68s7Q
         VY/ujChRD1QdkDKMmKiHiaF/oMPB1PHHbHGHTup6hGB3Ag1wMcZkH9vJdNlVlb13VMxA
         6bzQ8g3de7keURzzT3BpL4+jwzCwWDU6FyQrr/fRsoapbGNgIItnXywQ0rICQPMFq29+
         qEyzML8FrvlBThvk9RBsJ3URcXy9UkklpzDI+mVD/t9L/l7zPFiQp5M0i2hVNfNLW17l
         JiUPwRWEIlqScef9cuORfekYTyN5myfjsqUkom3Xpz54PvJDSR2cayPjdT5kZnoPAwaP
         UyFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iAI6DBaCqrbBSwZb9bVsG+3JmwGJkQPOB9OCI0kuuDM=;
        b=DzKoNdlNDwiyrPG5qYkZyuvluDFhyKx5Tx3klZc0sGOpO2FEkJeIQUy+rNPYWYQzBC
         ljtU/ypyI84yNttCEAaJum0ccJ10quInA+BdjEXfLS4fIihVq9srk9PFAwsea33wd+Q5
         B6KPS53Tz6aIlQagQR6oVJsMm+phtfZvLbZqP3oyMXYYtGn9h3TsJkooSMrXiBzKlnRL
         gEPKP1bW7+s0uPf/xY0jp1SEQsgVzdU3nyQ24lxEB7Lto1PzcpdHhLmZ/pekv0W+z9GF
         CkFOjX+ZMoNeCTSdO3PwrqL791sM+KXvPFB3sj8Rc85ECRyq19K6rnlTSW9GurEuC33k
         l67A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fd41GIP8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iAI6DBaCqrbBSwZb9bVsG+3JmwGJkQPOB9OCI0kuuDM=;
        b=jMvOSXuJCrflNPOITgimfbVL6s6CWGLNaE1Qtsd8HqMRXIgi+zPLBvZ2+FcK5WkEf4
         vVGD6+njd+IZPoo8nVuijCyCk4K2+L68c5FXmjmG5Vi6slpy9KtH+0nVZYrSeY7F9Bxc
         2R3X0NZvjpPHLpxN2xnCPJR/55Z2JxRO8MYGnygF98m+CQFxv1iGzkxmD1BfXfOz3d89
         MdSGrxxtY7Kb4vX0zc4rumCdKtX07Eqqa+S3XSWaYOPOQ3G33LszZQxDGPcGyrB5FXur
         P6DKJ0NCPeNh9ydE7WZ/oRF8iOFlOIj3sfhrJoxMyk1IDisMVvFnJW81r+aZ/3eyTvdH
         yeiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iAI6DBaCqrbBSwZb9bVsG+3JmwGJkQPOB9OCI0kuuDM=;
        b=J+KsJxoQovT/wR2hGAcLB18lAiPilWwEKNfaPg7/osqWaD2Sc0Mlf7vEO1n80haKvq
         mvZ0G05upqqCnrp5TlBsg8wcMtfkrVpfsyRVQexOS2OI/Wt19gMAO0L6Ou/xa0IB1op8
         L1q1A6Pqr6OAxHiXvLuNQgm8t3UJlh9YnLxLXPET5O0a7TyoK397PyTngtkHVo91iAgM
         0wgikHvNwIfsTSUJPEuXqIkLrm2tn1jOR2OCVslvBppSC8GrXGU0SAA32+fm84Z1SdTB
         MvadKsFQdbTSu3XPkxFR0fwBPstChkLkwdF2Ra4YWbGpgrNC9gFKnJPrJNsab6R5mxwP
         inJg==
X-Gm-Message-State: AOAM532iheOAAtxMG4oP5UJ8xgLvVdGqoijMiYPQ/j6U7oHQwo3OOeax
	+uLUNunrB9xzWlrSiOpzS70=
X-Google-Smtp-Source: ABdhPJwme7XJj+0RURDisVmzXgSrf1tNTStu1vEWDXLfKL+XSuvL+qBll3HR8cwIbJvlPmySWC6+1g==
X-Received: by 2002:a63:d003:: with SMTP id z3mr3846843pgf.348.1616503905267;
        Tue, 23 Mar 2021 05:51:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls8562572ple.9.gmail; Tue, 23
 Mar 2021 05:51:44 -0700 (PDT)
X-Received: by 2002:a17:90a:8c86:: with SMTP id b6mr4532261pjo.8.1616503904782;
        Tue, 23 Mar 2021 05:51:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616503904; cv=none;
        d=google.com; s=arc-20160816;
        b=HHfNvSqZQVIiv2meScvY1gq2J0l1VahHUwMvnsvT1ERCReT3AuNiq0goJ0c4B/bTfl
         H18Us/ummdartgJYPEwxU0SZoN/W8d70bFs9Z0euxzgn6k0aJryPuf92KgHNZncMr6Rd
         zfdNN2M8CKU165LH2nl8zscvxX7qpATFEvWBhND8lXqsPgqBwPrV/y4xjQodwV/ixUx8
         /mpM8fq96nbjZOrtIVy0uV/zVUj1iWjxSVQvIFG8M2jKiDnASsG1yeI0UpFsOYVNcTe+
         cerUoL/vaHwaUxK21N2E7XxAl2RaUPHpvmOhvV4ErCqAzsJ39QveHwLj3pdy45fjxGqa
         ZSrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IAmVG/HBeCtgkbLWnwaUrodtWDBlDiqTMm626xAgpp8=;
        b=aDmP7ZXoPT4oMthNVldB05zOulPD9/EAQPVzsOVWLn2IoSzbbVrFh07Si16u4atvHU
         bpu/MrYY1+4MHAq02y3Iie0zxJM0k0z4YcxhGDj4DdnUI8liR1lhtkk+/tr5UEWLFRca
         +YGjHGdXd6VaHXyWkLUKiRdL+FRpDDuNcypwD3wFma9n8qMnyAjMXntjxYn0z8n0ZETH
         QG2fIfNQG8i1pzw+AMe89tdn+HFqy4XkoHvLLMya17eKGXBogTxuSw2NYsxNUDMM3NaK
         vrkUw9Q7VQY0Wflje+cfSlAIgWR5wG6DXaDh0goTUk6aO7EBWPWTM/73px7DocBOquPc
         yLfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fd41GIP8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id m9si1030532pgr.3.2021.03.23.05.51.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 05:51:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id n8so16859248oie.10
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 05:51:44 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr3166533oia.172.1616503903973;
 Tue, 23 Mar 2021 05:51:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210323124112.1229772-1-arnd@kernel.org>
In-Reply-To: <20210323124112.1229772-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 13:51:32 +0100
Message-ID: <CANpmjNM8D+yp==DmKP0aa+g6=P38o0v6gd7y5iV52yyDUv91qw@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix hwasan build for gcc
To: Arnd Bergmann <arnd@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fd41GIP8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 23 Mar 2021 at 13:41, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> gcc-11 adds support for -fsanitize=kernel-hwaddress, so it becomes
> possible to enable CONFIG_KASAN_SW_TAGS.
>
> Unfortunately this fails to build at the moment, because the
> corresponding command line arguments use llvm specific syntax.
>
> Change it to use the cc-param macro instead, which works on both
> clang and gcc.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

Although I think you need to rebase against either -mm or -next,
because there have been changes to the CONFIG_KASAN_STACK variable.

> ---
>  scripts/Makefile.kasan | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 1e000cc2e7b4..0a2789783d1b 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -36,14 +36,14 @@ endif # CONFIG_KASAN_GENERIC
>  ifdef CONFIG_KASAN_SW_TAGS
>
>  ifdef CONFIG_KASAN_INLINE
> -    instrumentation_flags := -mllvm -hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
> +    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
>  else
> -    instrumentation_flags := -mllvm -hwasan-instrument-with-calls=1
> +    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
>  endif
>
>  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> -               -mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> -               -mllvm -hwasan-use-short-granules=0 \
> +               $(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
> +               $(call cc-param,hwasan-use-short-granules=0) \
>                 $(instrumentation_flags)
>
>  endif # CONFIG_KASAN_SW_TAGS
> --
> 2.29.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM8D%2Byp%3D%3DDmKP0aa%2Bg6%3DP38o0v6gd7y5iV52yyDUv91qw%40mail.gmail.com.
