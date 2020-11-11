Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXM7WD6QKGQE6VLMVRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B39A2AF627
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:22:54 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id f8sf793769vsr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:22:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111773; cv=pass;
        d=google.com; s=arc-20160816;
        b=TdieFQMMG0Z0nGx/ux1bFqE3Osz7bHmzPTg4t4bKdJ93lb4NTpWqzcjPabEDNHhUP3
         IAb6XEvZOaYLrwjrGbwvs/2svWapJkdBnTlcaXoYrrUaTrBuLSmM4hj7YJxmt2A6F7hU
         sXmmdVy8aNUml62jEzf/5eAZYUc7tO1AnrcpDu3asX4H2kbxcatqrkm/L41OU+M1pYao
         t+j7N/MHLt4LyRXxh5ovE3E48r2ZTh62yCz9OcEodtrnVigSIUuBk4J31TCYqh/Lj3Ey
         qd3B5dDWp1Asy1qLeZpPThNuZubLSphK0/6dEmnJ1RQy/9g8f1xYXu8QeOq8hjZp2GvW
         kPjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DdS00VZOKrhBV/dy7fVVLqAsXB1EHKq/TojOiVzjAgw=;
        b=AmfqxFQ50agGwHsXkuteXfQJgW4VlpKmi/J+1xpC9SXjgIN+l7mUnJAkd/eyFb4kDl
         oof/ihJ9YW9YUnTP4y73t0L4spBwGoPUoh+WpHKeaIcKOVfyC1vCMUJATUg6Wl96Bw+9
         cTLJ/FBhR5DTzaFQfGEr/tJOXEjygAygNjhQi+OYMj+kgHSHOha6/pQYK/VJGszQh5Xe
         lWGZOeXab7Ww4w1oY4BPoXQ2ak7b+MKFyqeFiEub0nLmKT2pJkm3gEzPov8/fyX9X6IC
         kGmNym7nNflmhf1hZJiuA2qlMjmdEcZuHqH6v62ykOIsUpgXdqI804T7EPzNFMYLvgSL
         ziOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9iQSPUg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DdS00VZOKrhBV/dy7fVVLqAsXB1EHKq/TojOiVzjAgw=;
        b=eKTeClJ9Dcwca7s/w8CbULG02ua6hxBSWQCnkfZNbxxa7llZ4Hr+eeF1CsLQvgjQJs
         FEYy0JurQNjrrhcIzDOl8I8QwSbxtAewh2VCVX8weNEww/jfBLWTKWFO3BgUOJjeAKmu
         4yaUw8g3WtkM+q/34E+QIxwuKodJEaYoXoPGK1F03erzfDf1j78ScY3MfmtOAKp9FuxZ
         MaQWPUJRC8lZWVcwq8ql0Wbbho2DN8H9QdY7HwM2iQoBymmZnkM0N7izvtkbZTmMZi1u
         FNcwm8RLc6/v/DxJq+9hUYCVeRdBKll5Ma+GmL/xYPkZ8o9OF6iLy3+ls4DO/7aMryeR
         Sa+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DdS00VZOKrhBV/dy7fVVLqAsXB1EHKq/TojOiVzjAgw=;
        b=fsfpdAXOeJxWfcWW8IWX6TukGrk+FgWYtLYNVIakf2uyv/+bG//YjIlWV0QhA9V+GU
         qzmB6tHXGSctAO7ejZGshut/wMClBkPZqz1H03a91ZyefEncogfsIageC1P4gr3gzjaU
         Bh0Wt+qvqWCDlflni3D2vCaW36StLGCViwO+G+5PyI5F2zj7M9Rbxj6WbkDHGjBpZGGR
         1McBgY0m1eY0StFXr8DdX2tY7+WPmu9HWvsaQyrVyjUFRdyylJuPYTeTCDcC9T1eSEQD
         fU1+CKsiUaw1bW4fdHL5nGa44tLGVT4/CYyngmhF+lYdwU3zBJcchjc2Z8EI6AAhck14
         uyGg==
X-Gm-Message-State: AOAM532lB2lVNQAYGGRBWGaSDBvroLwCelVrg2WpuDIU/9tpOk2yxQiL
	iGOdHeNNBFAMDIjcYkb2QDs=
X-Google-Smtp-Source: ABdhPJySAyCGfKgCQLGHmBwAxeQCrOUrctnuzZD/7a1WEjWPaG7tArIaiA3ms77NH7pSuXiHenqfCQ==
X-Received: by 2002:a67:6dc6:: with SMTP id i189mr15855429vsc.24.1605111773585;
        Wed, 11 Nov 2020 08:22:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ef8c:: with SMTP id r12ls53949vsp.7.gmail; Wed, 11 Nov
 2020 08:22:53 -0800 (PST)
X-Received: by 2002:a67:f593:: with SMTP id i19mr16116821vso.16.1605111773077;
        Wed, 11 Nov 2020 08:22:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111773; cv=none;
        d=google.com; s=arc-20160816;
        b=Dbs0xNF6gC/9fi1vrjwi275FOvReIl1GysA9nSuHKArKsMEiR/VlP+DaBPXQAISYaX
         raaH24zqYkfNK4lsvsMC31+kc/aq5I+BS6aAuk4y/wdn6b5VW2ybt4RvLrtoiC2U5xR8
         UgP97JEvV8GxBBfWfiNyERDf+we4YzKsCBd0F7QJR/rBEb17wKa7GrM8hb7d28EeINEN
         FS3tG8PiSywcKnctY0PKJnm5PWtje+bb7UmA6b9ophlGyoYqnzt4zI7j54vjNkNpXgEQ
         /KkinMZ4mNAHCf0b1hkHITnrzeyLFfTRTW0qJidz1ZSNzUUJaIQ2lvJ4M+6pLiJM32u1
         4O6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4pxKBBNtw3w8bZtwKeY4uxxTPtkqCJlv14cZKnd12N8=;
        b=Y1NLWZa2R1k5fKtz/oBDd3gz/B2gywD3HArI1/uFUG93PMpK7T5soAfP28tzOJbzES
         0rnNrNHg32DwjBcaXfKTxIuPVrLr5+ow43kx3FJGsdZwchcTs9/PlagSYx9fgyrKwXqr
         PlkJABxYWS6eB4AY/8ah4ikjsLQYRqouPMo47VgwhNmYwMchQaiAfteQS/9YgCcyJeXe
         EqBlYXRhVE2H2ZHCUcQ6Sw9Hw/KUsxl3U4Q8TtYE81gbBvk57F9+tJlN8Y1Jyamja6hi
         piGP9bYK52bGxILmBJKy0Nk80HImGst+yj0tjOMkIjR/dAaQ/vg417OXUnprPhvq6UDQ
         Rrvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9iQSPUg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id y17si139241vko.2.2020.11.11.08.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:22:53 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 11so2186724qkd.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:22:53 -0800 (PST)
X-Received: by 2002:a37:b545:: with SMTP id e66mr8830539qkf.392.1605111772271;
 Wed, 11 Nov 2020 08:22:52 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <0fd556cf79c3eb44f3c22a63b9ad70d07d8e1045.1605046192.git.andreyknvl@google.com>
In-Reply-To: <0fd556cf79c3eb44f3c22a63b9ad70d07d8e1045.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:22:41 +0100
Message-ID: <CAG_fn=X_Suw5LALHm9f9s=ZgNSVZgHAjsghL5MLBPZ4EK7ghWA@mail.gmail.com>
Subject: Re: [PATCH v9 38/44] kasan, arm64: expand CONFIG_KASAN checks
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s9iQSPUg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Some #ifdef CONFIG_KASAN checks are only relevant for software KASAN
> modes (either related to shadow memory or compiler instrumentation).
> Expand those into CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I91e661e2c1627783cb845d877c6371dfc8779505
> ---
>  arch/arm64/Kconfig                 |  2 +-
>  arch/arm64/Makefile                |  2 +-
>  arch/arm64/include/asm/assembler.h |  2 +-
>  arch/arm64/include/asm/memory.h    |  2 +-
>  arch/arm64/include/asm/string.h    |  5 +++--
>  arch/arm64/kernel/head.S           |  2 +-
>  arch/arm64/kernel/image-vars.h     |  2 +-
>  arch/arm64/kernel/kaslr.c          |  3 ++-
>  arch/arm64/kernel/module.c         |  6 ++++--
>  arch/arm64/mm/ptdump.c             |  6 +++---
>  include/linux/kasan-checks.h       |  2 +-
>  include/linux/kasan.h              |  7 ++++---
>  include/linux/moduleloader.h       |  3 ++-
>  include/linux/string.h             |  2 +-
>  mm/ptdump.c                        | 13 ++++++++-----
>  scripts/Makefile.lib               |  2 ++
>  16 files changed, 36 insertions(+), 25 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index c84a0e6b4650..456741645f01 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -330,7 +330,7 @@ config BROKEN_GAS_INST
>
>  config KASAN_SHADOW_OFFSET
>         hex
> -       depends on KASAN
> +       depends on KASAN_GENERIC || KASAN_SW_TAGS
>         default 0xdfffa00000000000 if (ARM64_VA_BITS_48 || ARM64_VA_BITS_=
52) && !KASAN_SW_TAGS
>         default 0xdfffd00000000000 if ARM64_VA_BITS_47 && !KASAN_SW_TAGS
>         default 0xdffffe8000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
> diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
> index 50ad9cbccb51..0b31a3f06f15 100644
> --- a/arch/arm64/Makefile
> +++ b/arch/arm64/Makefile
> @@ -141,7 +141,7 @@ head-y              :=3D arch/arm64/kernel/head.o
>
>  ifeq ($(CONFIG_KASAN_SW_TAGS), y)
>  KASAN_SHADOW_SCALE_SHIFT :=3D 4
> -else
> +else ifeq ($(CONFIG_KASAN_GENERIC), y)
>  KASAN_SHADOW_SCALE_SHIFT :=3D 3
>  endif
>
> diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/=
assembler.h
> index ddbe6bf00e33..bf125c591116 100644
> --- a/arch/arm64/include/asm/assembler.h
> +++ b/arch/arm64/include/asm/assembler.h
> @@ -473,7 +473,7 @@ USER(\label, ic     ivau, \tmp2)                    /=
/ invalidate I line PoU
>  #define NOKPROBE(x)
>  #endif
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define EXPORT_SYMBOL_NOKASAN(name)
>  #else
>  #define EXPORT_SYMBOL_NOKASAN(name)    EXPORT_SYMBOL(name)
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 419bbace29d5..656aaddb7014 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -72,7 +72,7 @@
>   * address space for the shadow region respectively. They can bloat the =
stack
>   * significantly, so double the (minimum) stack size when they are in us=
e.
>   */
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #define KASAN_SHADOW_END       ((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT=
)) \
>                                         + KASAN_SHADOW_OFFSET)
> diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/str=
ing.h
> index b31e8e87a0db..3a3264ff47b9 100644
> --- a/arch/arm64/include/asm/string.h
> +++ b/arch/arm64/include/asm/string.h
> @@ -5,7 +5,7 @@
>  #ifndef __ASM_STRING_H
>  #define __ASM_STRING_H
>
> -#ifndef CONFIG_KASAN
> +#if !(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
>  #define __HAVE_ARCH_STRRCHR
>  extern char *strrchr(const char *, int c);
>
> @@ -48,7 +48,8 @@ extern void *__memset(void *, int, __kernel_size_t);
>  void memcpy_flushcache(void *dst, const void *src, size_t cnt);
>  #endif
>
> -#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> +       !defined(__SANITIZE_ADDRESS__)
>
>  /*
>   * For files that are not instrumented (e.g. mm/slub.c) we
> diff --git a/arch/arm64/kernel/head.S b/arch/arm64/kernel/head.S
> index d8d9caf02834..fdcb99d7ba23 100644
> --- a/arch/arm64/kernel/head.S
> +++ b/arch/arm64/kernel/head.S
> @@ -448,7 +448,7 @@ SYM_FUNC_START_LOCAL(__primary_switched)
>         bl      __pi_memset
>         dsb     ishst                           // Make zero page visible=
 to PTW
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         bl      kasan_early_init
>  #endif
>  #ifdef CONFIG_RANDOMIZE_BASE
> diff --git a/arch/arm64/kernel/image-vars.h b/arch/arm64/kernel/image-var=
s.h
> index c615b285ff5b..4282edd2fe81 100644
> --- a/arch/arm64/kernel/image-vars.h
> +++ b/arch/arm64/kernel/image-vars.h
> @@ -37,7 +37,7 @@ __efistub_strncmp             =3D __pi_strncmp;
>  __efistub_strrchr              =3D __pi_strrchr;
>  __efistub___clean_dcache_area_poc =3D __pi___clean_dcache_area_poc;
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  __efistub___memcpy             =3D __pi_memcpy;
>  __efistub___memmove            =3D __pi_memmove;
>  __efistub___memset             =3D __pi_memset;
> diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
> index b181e0544b79..e8e17e91aa02 100644
> --- a/arch/arm64/kernel/kaslr.c
> +++ b/arch/arm64/kernel/kaslr.c
> @@ -151,7 +151,8 @@ u64 __init kaslr_early_init(u64 dt_phys)
>         /* use the top 16 bits to randomize the linear region */
>         memstart_offset_seed =3D seed >> 48;
>
> -       if (IS_ENABLED(CONFIG_KASAN))
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> +           IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                 /*
>                  * KASAN does not expect the module region to intersect t=
he
>                  * vmalloc region, since shadow memory is allocated for e=
ach
> diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
> index 2a1ad95d9b2c..fe21e0f06492 100644
> --- a/arch/arm64/kernel/module.c
> +++ b/arch/arm64/kernel/module.c
> @@ -30,7 +30,8 @@ void *module_alloc(unsigned long size)
>         if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS))
>                 gfp_mask |=3D __GFP_NOWARN;
>
> -       if (IS_ENABLED(CONFIG_KASAN))
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> +           IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                 /* don't exceed the static module region - see below */
>                 module_alloc_end =3D MODULES_END;
>
> @@ -39,7 +40,8 @@ void *module_alloc(unsigned long size)
>                                 NUMA_NO_NODE, __builtin_return_address(0)=
);
>
>         if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
> -           !IS_ENABLED(CONFIG_KASAN))
> +           !IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> +           !IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                 /*
>                  * KASAN can only deal with module allocations being serv=
ed
>                  * from the reserved module region, since the remainder o=
f
> diff --git a/arch/arm64/mm/ptdump.c b/arch/arm64/mm/ptdump.c
> index 807dc634bbd2..04137a8f3d2d 100644
> --- a/arch/arm64/mm/ptdump.c
> +++ b/arch/arm64/mm/ptdump.c
> @@ -29,7 +29,7 @@
>  enum address_markers_idx {
>         PAGE_OFFSET_NR =3D 0,
>         PAGE_END_NR,
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         KASAN_START_NR,
>  #endif
>  };
> @@ -37,7 +37,7 @@ enum address_markers_idx {
>  static struct addr_marker address_markers[] =3D {
>         { PAGE_OFFSET,                  "Linear Mapping start" },
>         { 0 /* PAGE_END */,             "Linear Mapping end" },
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         { 0 /* KASAN_SHADOW_START */,   "Kasan shadow start" },
>         { KASAN_SHADOW_END,             "Kasan shadow end" },
>  #endif
> @@ -383,7 +383,7 @@ void ptdump_check_wx(void)
>  static int ptdump_init(void)
>  {
>         address_markers[PAGE_END_NR].start_address =3D PAGE_END;
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         address_markers[KASAN_START_NR].start_address =3D KASAN_SHADOW_ST=
ART;
>  #endif
>         ptdump_initialize();
> diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
> index ac6aba632f2d..ca5e89fb10d3 100644
> --- a/include/linux/kasan-checks.h
> +++ b/include/linux/kasan-checks.h
> @@ -9,7 +9,7 @@
>   * even in compilation units that selectively disable KASAN, but must us=
e KASAN
>   * to validate access to an address.   Never use these in header files!
>   */
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  bool __kasan_check_read(const volatile void *p, unsigned int size);
>  bool __kasan_check_write(const volatile void *p, unsigned int size);
>  #else
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1d6ec3325163..b6fc14b3da53 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -237,7 +237,8 @@ static inline void kasan_release_vmalloc(unsigned lon=
g start,
>
>  #endif /* CONFIG_KASAN_VMALLOC */
>
> -#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> +               !defined(CONFIG_KASAN_VMALLOC)
>
>  /*
>   * These functions provide a special case to support backing module
> @@ -247,12 +248,12 @@ static inline void kasan_release_vmalloc(unsigned l=
ong start,
>  int kasan_module_alloc(void *addr, size_t size);
>  void kasan_free_shadow(const struct vm_struct *vm);
>
> -#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
> +#else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN=
_VMALLOC */
>
>  static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
>  static inline void kasan_free_shadow(const struct vm_struct *vm) {}
>
> -#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
> +#endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASA=
N_VMALLOC */
>
>  #ifdef CONFIG_KASAN_INLINE
>  void kasan_non_canonical_hook(unsigned long addr);
> diff --git a/include/linux/moduleloader.h b/include/linux/moduleloader.h
> index 4fa67a8b2265..9e09d11ffe5b 100644
> --- a/include/linux/moduleloader.h
> +++ b/include/linux/moduleloader.h
> @@ -96,7 +96,8 @@ void module_arch_cleanup(struct module *mod);
>  /* Any cleanup before freeing mod->module_init */
>  void module_arch_freeing_init(struct module *mod);
>
> -#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> +               !defined(CONFIG_KASAN_VMALLOC)
>  #include <linux/kasan.h>
>  #define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
>  #else
> diff --git a/include/linux/string.h b/include/linux/string.h
> index b1f3894a0a3e..016a157e2251 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -266,7 +266,7 @@ void __write_overflow(void) __compiletime_error("dete=
cted write beyond size of o
>
>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FO=
RTIFY_SOURCE)
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  extern void *__underlying_memchr(const void *p, int c, __kernel_size_t s=
ize) __RENAME(memchr);
>  extern int __underlying_memcmp(const void *p, const void *q, __kernel_si=
ze_t size) __RENAME(memcmp);
>  extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t=
 size) __RENAME(memcpy);
> diff --git a/mm/ptdump.c b/mm/ptdump.c
> index ba88ec43ff21..4354c1422d57 100644
> --- a/mm/ptdump.c
> +++ b/mm/ptdump.c
> @@ -4,7 +4,7 @@
>  #include <linux/ptdump.h>
>  #include <linux/kasan.h>
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  /*
>   * This is an optimization for KASAN=3Dy case. Since all kasan page tabl=
es
>   * eventually point to the kasan_early_shadow_page we could call note_pa=
ge()
> @@ -31,7 +31,8 @@ static int ptdump_pgd_entry(pgd_t *pgd, unsigned long a=
ddr,
>         struct ptdump_state *st =3D walk->private;
>         pgd_t val =3D READ_ONCE(*pgd);
>
> -#if CONFIG_PGTABLE_LEVELS > 4 && defined(CONFIG_KASAN)
> +#if CONFIG_PGTABLE_LEVELS > 4 && \
> +               (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW=
_TAGS))
>         if (pgd_page(val) =3D=3D virt_to_page(lm_alias(kasan_early_shadow=
_p4d)))
>                 return note_kasan_page_table(walk, addr);
>  #endif
> @@ -51,7 +52,8 @@ static int ptdump_p4d_entry(p4d_t *p4d, unsigned long a=
ddr,
>         struct ptdump_state *st =3D walk->private;
>         p4d_t val =3D READ_ONCE(*p4d);
>
> -#if CONFIG_PGTABLE_LEVELS > 3 && defined(CONFIG_KASAN)
> +#if CONFIG_PGTABLE_LEVELS > 3 && \
> +               (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW=
_TAGS))
>         if (p4d_page(val) =3D=3D virt_to_page(lm_alias(kasan_early_shadow=
_pud)))
>                 return note_kasan_page_table(walk, addr);
>  #endif
> @@ -71,7 +73,8 @@ static int ptdump_pud_entry(pud_t *pud, unsigned long a=
ddr,
>         struct ptdump_state *st =3D walk->private;
>         pud_t val =3D READ_ONCE(*pud);
>
> -#if CONFIG_PGTABLE_LEVELS > 2 && defined(CONFIG_KASAN)
> +#if CONFIG_PGTABLE_LEVELS > 2 && \
> +               (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW=
_TAGS))
>         if (pud_page(val) =3D=3D virt_to_page(lm_alias(kasan_early_shadow=
_pmd)))
>                 return note_kasan_page_table(walk, addr);
>  #endif
> @@ -91,7 +94,7 @@ static int ptdump_pmd_entry(pmd_t *pmd, unsigned long a=
ddr,
>         struct ptdump_state *st =3D walk->private;
>         pmd_t val =3D READ_ONCE(*pmd);
>
> -#if defined(CONFIG_KASAN)
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         if (pmd_page(val) =3D=3D virt_to_page(lm_alias(kasan_early_shadow=
_pte)))
>                 return note_kasan_page_table(walk, addr);
>  #endif
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 94133708889d..213677a5ed33 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -148,10 +148,12 @@ endif
>  # we don't want to check (depends on variables KASAN_SANITIZE_obj.o, KAS=
AN_SANITIZE)
>  #
>  ifeq ($(CONFIG_KASAN),y)
> +ifneq ($(CONFIG_KASAN_HW_TAGS),y)
>  _c_flags +=3D $(if $(patsubst n%,, \
>                 $(KASAN_SANITIZE_$(basetarget).o)$(KASAN_SANITIZE)y), \
>                 $(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
>  endif
> +endif
>
>  ifeq ($(CONFIG_UBSAN),y)
>  _c_flags +=3D $(if $(patsubst n%,, \
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX_Suw5LALHm9f9s%3DZgNSVZgHAjsghL5MLBPZ4EK7ghWA%40mail.gm=
ail.com.
