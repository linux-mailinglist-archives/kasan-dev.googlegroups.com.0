Return-Path: <kasan-dev+bncBDYJPJO25UGBBMV63L3AKGQEF6YPHSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2B11EC21F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:49:24 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id b5sf8801746otf.22
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:49:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591123763; cv=pass;
        d=google.com; s=arc-20160816;
        b=ocWIFNR6CUCf+tOpZl/oX82DbwQQ6UsnadNQPsPBeSkS1Rl2wAiE5UwEHWnZDhJD5e
         +3WsDAzNRnlAuqsPiXp+sWrdKeJnaW+5Fi9P5VVJBOZcBTkK3T4K3u1d2JNDoqNEgFsR
         J6dQepYHlcFqUojIVI4wiROyIb1WKajbFTXgHiM5djllgDlTLXH122wbCqQuZWELT8rJ
         6uZczJkYsmVGcV3+IPMTtjWxC7081bCfSx1jnxp0+FoSaoLVD1Dt12LleOinzebvOnJU
         3KDZYjI1twt++uZWThc73wELK3RnZkPL7H1ysJ0USTiwhmZsq4w/LXnG3lB9LYPHdgaN
         UEhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e6GLANNW57T5PyUq08u8NZoMoX/Z8VpPZzOvR/RPgMM=;
        b=kvDS5wN63J+cMF3+5EiU5HY+zVkRm+Ja+XTcihZSqr4PhfOLNzuioy33VP4v0vCi/+
         CINmTzJ1blg1VRoWsIxLZk9M/CZI2aud/luhoGfPGPqnconFZvC1RW/ZdUGqokHU0vpC
         ABA2jX6jEMpbadNywm28xo4WiT9IXpd4JqWx4L/Bicog1sDfAsanXZtv1YtCccOrO/NE
         UK+TNVp1rjZc87VGVc8ZdJBSaFQtO7Aha/454Zm6K5rJDOztSCH8ibcDwVsoJGtBWHZx
         vw1dwdzRD5jA5ZG8hbVSSbulosWGAmaTZZ3B3GHixuxJT/RklUex/c93qebAOkjpG2uD
         QcfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cmj2yrH3;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e6GLANNW57T5PyUq08u8NZoMoX/Z8VpPZzOvR/RPgMM=;
        b=gYzD7yfK9ojSgovTqiIzEiuKdrJ+RQRaqJ3LljUlgPaMI0LL7RTpHCrBktK6yZiRY7
         gYw/ScSMd1ID3ADYUAKSVq6HXQ8B1QZ5tPqALFPDFgpHLogveJaEqTFlPgzZ5/MKlDzt
         jUEMpZ0jEyW/SysZmA8baFMRa9cdCR53cBE0Glw9ubNT6rqveq+Q/etUFgQG0e/zqsJW
         H66/vKp7MXgwjxuoJx52CG0Wys3y6pXVgZ7FxfP+C3e6zKgqXyXXgsoTlBPXKCsT7G/x
         khxILiVElJFbOdyLvusJ3kHbxuUN2IsRfzC1nQY2auBgVMoXMCbn8iKrbzC7nwPgUh9X
         xmVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e6GLANNW57T5PyUq08u8NZoMoX/Z8VpPZzOvR/RPgMM=;
        b=af4V3knL2jE5lnR8OxxZode/s7YhDNfNFnV5fLoUHsHtnQ5r9xgRylod/WHVYh7OKH
         YQAZtQCL5e5ZdUTo9bqIS0Kjioe5K0f9z8ikrqEz8ricIRslrILakX5jJjU9hW22TEqL
         4MAQDanGRlc4GwC+c+1AAMRCH0OIjIpizhzk8gITZHgkbYcF1f5PiU+L76QCsE3jSo6U
         ClqtVXsMooU5qt8NUKAu9uhLmSqsAXmtAbchv/b1Tu0PANhRuI6l5V4uEGtgfkrZFgP6
         +Nn0uvM9g/7k6YUiJptVUJaCH0CCeZrEJcjhkV1aIghD9i/mn7LYxOSwzV6frKx3B7le
         KQjQ==
X-Gm-Message-State: AOAM532qlprK6UUP7wTkKpQf2DPTkv60RaZ7YMS8LXpSSHD62jFYt/rE
	pWNgb9xgEgDOVKcM/sH72+4=
X-Google-Smtp-Source: ABdhPJxG/gbrjHVR4I1UlvoRyi2niKnxcvvaBus2WXcqiqXubtAT5CflkyyOsF0O4URKtNZoJF2hvQ==
X-Received: by 2002:a4a:92ce:: with SMTP id j14mr2260429ooh.30.1591123762960;
        Tue, 02 Jun 2020 11:49:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3116:: with SMTP id b22ls2007507ots.6.gmail; Tue,
 02 Jun 2020 11:49:22 -0700 (PDT)
X-Received: by 2002:a9d:c42:: with SMTP id 60mr507646otr.63.1591123762610;
        Tue, 02 Jun 2020 11:49:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591123762; cv=none;
        d=google.com; s=arc-20160816;
        b=NEeo1Diu0beCK1cqiZhEeGLG7x/dAPDLU3tyt4OnRFSw/220EveV9Jf6y3Jkbt/cTm
         JsVGO3zfiq9mM7cLaKrkMLgKcD1j7rqWW+AzrQyr1G7aDF8I9GCyrjJ2nfiNkTt5z0hD
         pHpBLBy9kKPHCjSSy/DUlIlXRJ5xf2z/8W65nJeH2pWLdohlBTQzAapXVXNFXm4mdmoI
         XG0+G9GU6qVQujC60AS7M1bvGaL2E1533ebQ3w+wt2bqhQuaIA6R13WErcP0CAUTbFSr
         OgUZBRq4hBaFF0l7LW8uzMXzfvsiEZmsgtE7SXBmNMgDvYF1sIHQmp1Pe4r+HLILZbuW
         eyag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5xlo4rK4g8fnalu7U0lbya/uKNvvM9T5qVFKFRMeKAc=;
        b=A9GLseKcnQP4/xVsj7Vh9DMCA2pJpxzaN1YIaJrCmU97mImBh+b8ROvIi2IloUUddp
         SQikSwdAQCXUGEKmkWQ+qGyhzqHIVpsXfXa1YQysyNQil445kmbyZNYMLw9TR7JUlVmq
         1tJa2JzKhD+aM5RTlk0BkVBEls4yIzkhqcFUoHOU/H4xDu/CjujliFxGks73wyfSLumf
         bpqrwV/GKoZpg4ylqBPae0ZYk9ePusHK5zK+RE98t6m0thEIuMNzlc1aDT684HMvUCfO
         0+sY3hAarwxBUMSFMs8TkKS75ahFrvfk2Fo7crhS8NQ3netYOmobAGcErXAxNU7GlQ6O
         EICw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cmj2yrH3;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id k65si228365oib.2.2020.06.02.11.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:49:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id q24so1974117pjd.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:49:22 -0700 (PDT)
X-Received: by 2002:a17:90b:4c47:: with SMTP id np7mr601098pjb.101.1591123761720;
 Tue, 02 Jun 2020 11:49:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <20200602184409.22142-2-elver@google.com>
In-Reply-To: <20200602184409.22142-2-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 11:49:10 -0700
Message-ID: <CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi=zQy_DyzduVmyQNMA@mail.gmail.com>
Subject: Re: [PATCH -tip 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
To: Marco Elver <elver@google.com>, Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Cmj2yrH3;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1041
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
> Adds the portable definitions for __no_sanitize_address, and
> __no_sanitize_undefined, and subsequently changes noinstr to use the
> attributes to disable instrumentation via KASAN or UBSAN.
>
> Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
> Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
> Signed-off-by: Marco Elver <elver@google.com>

Currently most of our compiler attribute detection is done in
include/linux/compiler_attributes.h; I think this should be handled
there. +Miguel Ojeda

> ---
>
> Note: __no_sanitize_coverage (for KCOV) isn't possible right now,
> because neither GCC nor Clang support such an attribute. This means
> going and changing the compilers again (for Clang it's fine, for GCC,
> it'll take a while).
>
> However, it looks like that KCOV_INSTRUMENT := n is currently in all the
> right places. Short-term, this should be reasonable.
> ---
>  include/linux/compiler-clang.h | 8 ++++++++
>  include/linux/compiler-gcc.h   | 6 ++++++
>  include/linux/compiler_types.h | 3 ++-
>  3 files changed, 16 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> index 2cb42d8bdedc..c0e4b193b311 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -33,6 +33,14 @@
>  #define __no_sanitize_thread
>  #endif
>
> +#if __has_feature(undefined_behavior_sanitizer)
> +/* GCC does not have __SANITIZE_UNDEFINED__ */
> +#define __no_sanitize_undefined \
> +               __attribute__((no_sanitize("undefined")))
> +#else
> +#define __no_sanitize_undefined
> +#endif
> +
>  /*
>   * Not all versions of clang implement the the type-generic versions
>   * of the builtin overflow checkers. Fortunately, clang implements
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index 7dd4e0349ef3..1c74464c80c6 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -150,6 +150,12 @@
>  #define __no_sanitize_thread
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
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 02becd21d456..89b8c1ae18a1 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -198,7 +198,8 @@ struct ftrace_likely_data {
>
>  /* Section for code which can't be instrumented at all */
>  #define noinstr                                                                \
> -       noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
> +       noinline notrace __attribute((__section__(".noinstr.text")))    \
> +       __no_kcsan __no_sanitize_address __no_sanitize_undefined
>
>  #endif /* __KERNEL__ */
>
> --

-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi%3DzQy_DyzduVmyQNMA%40mail.gmail.com.
