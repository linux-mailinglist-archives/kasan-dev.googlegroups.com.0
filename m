Return-Path: <kasan-dev+bncBCA2BG6MWAHBBJUP27ZAKGQEUPIUDNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C3ADB16F4F1
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 02:19:35 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id y12sf105130vkd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 17:19:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582679974; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+n6PaXolVljEiC8pqUGKNEZPpayKoDcX1r4Yvj6QMunLmJhjKsB0WLeDB+oylCzVg
         IKP1v+4zNBZ3+nZyDHxfvTX9n8NV+q9v+pp5bQutXZRxjjPmKFLXg0eKdtQPKt0NR+G7
         SJdxjcP+lqtRGvlUBJW0W3Y4oetluybJ8QjV8tdAxH1XUn9OBTOMUFEalX6WxyqgkZ6G
         78Tt9KflxqTLvsZFQm3TvYI1Mvm8COCL6yN8dnOGV2IEeoe+AG60QZhUaQL0yk0keAgX
         ryc4NfrR3TFbm33nt5AritVW3VgG7kBaM7VSrHWKsgTI3g7zmtuBhYRxv89mNR7C4M3c
         0+8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Drt7B4GgU9sndN4DiFdkkiLbsOjAhyEqEkQyaGOa0Ek=;
        b=gCsbOSPFPGvhLglnHkjZN7VVCj2/h8sRA77a05NGEkvUvWBNuFbm2rmS6T3Zhg4R5R
         GLxvwetOEHjV+tzKjYW9ia2uMPIYkJSyHv4TlVd7zMo8SNe+XoAOLE0ryo7PvQ3THCy/
         gJHXugsugdNKt+HN0tsBXOxF1Q2S/aXa81O2eYtUIjhxMA7hMIu/45N1HgNyIu17Za3Z
         Z0ZWyrLqDSWoaCXkHRVzL5/4XOM0QRkX+x32APWMsflCwctGS12/wKP5qBBNlILpqScw
         Na5tCGjqHrkaK9Bpb1QDLMvAE+SAzqtSUuleZ3r9+wjUHjwZIeUbxDyeIvskWKNn2Qik
         bM8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l4604xpw;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Drt7B4GgU9sndN4DiFdkkiLbsOjAhyEqEkQyaGOa0Ek=;
        b=W4PzUQh9BFfGTbZh1ZWGxtBliS0UV2dPRuYdeCDoPjk6lOtob1+lpzFKzTMs3msuHe
         1uD4dyBbkqKa6wStkLG0Qb8EjiZiNIuyVgqlGvhg0u0pkq4R+ktgBigGuoupVll9eXbc
         RNX+4ynU798/NedF7wlb7yQCp/0r0RWsufWXdJoTpBsr3PnC78+ns2lpQ4luzo0B8Xiw
         dDLRgyNDL9W6rgDZAP0fOIU5a9efKnDvgjvxUZLTL1drVkg/pll+pqZ0ao9BJ4dSwOFJ
         0COS6XgEcOlG8Zlh/HmRlmlR7vGm1tJN2+VHo5qgJMZuTnerK0HYOU8qdahGjbonTlgK
         e9lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Drt7B4GgU9sndN4DiFdkkiLbsOjAhyEqEkQyaGOa0Ek=;
        b=PAuj5eqH7DCdUmBU/GYLSSuneXuEDr5Lk6v4C1Jz0dv7VfhknF17Yg3qejlPQVtxlF
         65BB2+nx7j1NCzDj5aauCCrLETyCITvvClwzDV3+VE0yIKA1EHKmWU3N8Snp4CCp/AxG
         5v1lG7Q2RC2RY+EUk09iUXpHyFq68rVC3RJ7e3HDc+W26ZdKLBDuEN1SiDy0fmwdbEQ4
         EFxnscglJTquQ0HsuLZGvtzInkL45LfBRPYYuPRgSiMdxVrLidQBePeu+fwCin/ew0Vi
         HnR9SPDFm4P4n88H5RLxrqGiqitmdE/992pJcht7yDudIemwEmnexPog6g79YBlbhfJy
         m5gw==
X-Gm-Message-State: APjAAAUkLdXq8i0JHdlGQKWHO78Pvg1v5EQiXa4CK9slPcBKsc/kwKWx
	JZ6GXM0d7+8FQSzrSxQ/Z+A=
X-Google-Smtp-Source: APXvYqyg2tBxZ+59M0KUcXXwG4aTwaUHS0Nnq/V6Iv112efmg3NCjLhwvQDjAQ0ia75McZcIaanSuA==
X-Received: by 2002:ab0:70b6:: with SMTP id q22mr2120190ual.78.1582679974508;
        Tue, 25 Feb 2020 17:19:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:804:: with SMTP id g4ls178344vsb.11.gmail; Tue, 25
 Feb 2020 17:19:34 -0800 (PST)
X-Received: by 2002:a67:fa4b:: with SMTP id j11mr2045799vsq.168.1582679974146;
        Tue, 25 Feb 2020 17:19:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582679974; cv=none;
        d=google.com; s=arc-20160816;
        b=lh9NKvyQqMrXEQGYlIfNOiBGrJt7G/8IQEsEDoskjrX0EZA+9rahpGNZGO+mWWXF5V
         quZy44D826Wa3LBbEwWvyKCQ023Fz6PDWmG6KgcoGlfn2NH7UwE6vMaBPFwUZwK3RtjZ
         il9MjPUSTwvysW62EoobIFSRHj/jED5qibpT04TrC/SG7xmNQW5CjOpIolSCgHmV0X4j
         FSGyU/7RzI48TbziE5vFuvsoBgxyzD3nao46fxpe6zGDTExUl3EUb3xat6PTMHDgrJiY
         gaPP3rcDj63pO9pTFok2miAAUtKeJ2OtaNr4+4mQgSznh3Ng9A16KI6O/GU07kcpTmdv
         1zUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V+WJdtiodK7smJaw6cytKeNqvxCywC6JW8awTtYsnT4=;
        b=C1cUmPHRqE7hFWdyaLx89Uf6b2+8INHfteIU3OYRjVDOe9EROiGAE4dRwrdt12Yiw6
         LHvyC3Q9MaxMKStbLHVYoGpUcXRJu+VZD5V/GEYd/Hm1UI9tEjUadoJq6wiUT+nMUtc0
         dQML4LFBQtv6b9NqFC0vSWQ6UGwwQl1qFB7bQuAPtGzRy9ZVQagNSuAuQ17w33ZpbYBh
         ncj7/jJLfkDmM8O5z4HMPvJTO4GfSWRaAeAuWeGPNmelSLMQhAbFNVNhRvRnM0w4PLPR
         Bho6FTaOaR+IxNO4dk17pRX+7MT0jkrG2vd3I6iLJKTGo9Llr4XG6Y7RopLedVNBUTZ2
         1cpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l4604xpw;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id o19si75254vka.4.2020.02.25.17.19.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2020 17:19:34 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id n7so543451pfn.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2020 17:19:34 -0800 (PST)
X-Received: by 2002:aa7:8545:: with SMTP id y5mr1551644pfn.185.1582679973137;
 Tue, 25 Feb 2020 17:19:33 -0800 (PST)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
In-Reply-To: <20200226004608.8128-1-trishalfonso@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Feb 2020 17:19:21 -0800
Message-ID: <CAFd5g45gqZcJ6v3KSDuBffgBzfZ+=GJ2oCuSurYehoMHBK0Grg@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, aryabinin@virtuozzo.com, 
	Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>, 
	Johannes Berg <johannes@sipsolutions.net>, kasan-dev@googlegroups.com, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-um <linux-um@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l4604xpw;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Tue, Feb 25, 2020 at 4:46 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> Make KASAN run on User Mode Linux on x86_64.
>
> Depends on Constructor support in UML - "[RFC PATCH] um:
> implement CONFIG_CONSTRUCTORS for modules"
> (https://patchwork.ozlabs.org/patch/1234551/) by Johannes Berg.
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the
> KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
> space, and KASAN requires 1/8th of this. The default location of
> this offset is 0x7fff8000 as suggested by Dmitry Vyukov. There is
> usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> The UML-specific KASAN initializer uses mmap to map
> the roughly 2.25TB of shadow memory to the location defined by
> KASAN_SHADOW_OFFSET. kasan_init() utilizes constructors to initialize
> KASAN before main().
>
> Disable stack instrumentation on UML via KASAN_STACK config option to
> avoid false positive KASAN reports.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

A couple of minor nits (well one nit and one question), but overall
this looks good to me.

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

> ---
>  arch/um/Kconfig                  | 13 +++++++++++++
>  arch/um/Makefile                 |  6 ++++++
>  arch/um/include/asm/common.lds.S |  1 +
>  arch/um/include/asm/kasan.h      | 32 ++++++++++++++++++++++++++++++++
>  arch/um/kernel/dyn.lds.S         |  5 ++++-
>  arch/um/kernel/mem.c             | 18 ++++++++++++++++++
>  arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  lib/Kconfig.kasan                |  2 +-
>  11 files changed, 104 insertions(+), 5 deletions(-)
>  create mode 100644 arch/um/include/asm/kasan.h
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 0917f8443c28..fb2ad1fb05fd 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -8,6 +8,7 @@ config UML
>         select ARCH_HAS_KCOV
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN if X86_64
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -200,6 +201,18 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x7fff8000

nit: It looks like you chose the default that Dmitry suggested. Some
explanation of this in the help would probably be good.

> +       help
> +         This is the offset at which the ~2.25TB of shadow memory is
> +         mapped and used by KASAN for memory debugging. This can be any
> +         address that has at least KASAN_SHADOW_SIZE(total address space divided
> +         by 8) amount of space so that the KASAN shadow memory does not conflict
> +         with anything. The default is 0x7fff8000, as it fits into immediate of
> +         most instructions.
> +
>  endmenu

[...]

> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..5b54f3c9a741 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -125,7 +125,7 @@ config KASAN_STACK_ENABLE
>
>  config KASAN_STACK
>         int
> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> +       default 1 if (KASAN_STACK_ENABLE || CC_IS_GCC) && !UML

Up to the KASAN people, but I think you can probably move this to
arch/um/Kconfig. There is some advantage to having all the UML
specific Kconfigery in arch/um/Kconfig, but there are also already a
lot of things that specify !UML outside of arch/um/.

>         default 0
>
>  config KASAN_S390_4_LEVEL_PAGING
> --
> 2.25.0.265.gbab2e86ba0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g45gqZcJ6v3KSDuBffgBzfZ%2B%3DGJ2oCuSurYehoMHBK0Grg%40mail.gmail.com.
