Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL6UQ6BQMGQESEFLZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD67F34D2E3
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 16:54:41 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id w15sf9266402otm.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 07:54:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617029680; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6VfVlFSS8ZQN5SFCvWwKV83+DsvGcQiZQJkeBpR/GkiAG+QyT978GLJgqga1mY1wD
         /1yOVIzYcHpCwOpEnHZuW9kUFSQL475N2DlSrqhb6xcRX9epL9fI3eJWPuuAmpZGqdW0
         gS0YUaOuE7izJOGvIfv8LGZdUxg2kh5P5NdniuF5Yf3/CAyhJX2WuhKlNLPLx6Wo5Y+H
         KO0j7SXEaVzjGRGzFNXerT34Mqj8pJI4bhUURdhyd2sfMunCGImj4zYK6kU5HGMIcvVy
         4vqI7iU9gn6rbmh+8hYqHvV+jFAgLzlb++7e/YWdQiQ+MOr3s54N8d5+2L08SaBzPcQS
         dEyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xrwq3fCkmcBKgrd1DDBsF8xlDt547KLjDT7fXifYZaI=;
        b=cV+rl3n2ntlkNa7jwALngxDnFbtoQ6gHuP0/ruNpGxU3dPd/0pJoqMQQVHWz6/ERvB
         mZ5qem8N6Aj930VjLWahr5cCDKUc4sNsWnwrUbnQAc+iwDOR57DLSkPGTTRxRKKQqSxg
         ZM8x41kRYgjKg3nwbD8bzXvtLs8j/79k4XGCOH81WMe6sC/ucPmxUrdXdlgnoZRBIGhO
         yjUzKlCL6Mb7srUiIIVsx6phgmtKRjrjSj+1/BdWdKpa0pEjKUMqz2J8bjKawlQVO7xs
         MofqRsyB98cbfnpOIH0DURVKbUngnTQ87mzvz7Y1H5ZSJS9yEhTdqbHUBHMnLFouSvS+
         ks7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iSXU1lHc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xrwq3fCkmcBKgrd1DDBsF8xlDt547KLjDT7fXifYZaI=;
        b=rgg7FDrOW2R3p0ogH2jthqere4vOg/lF7EKjhvlC38iCHLzXf7y/mWyg/t4Hgwc16G
         f+5HoMRjNLci5VbppR3tQKH7kLUN95CCVS1XvkQvFXUmu57RVstOZvDY2SlFoSFWzDb0
         GD5sVkfTFeW74dsQna+ONLTJwYFze0SzZp5EZ7CApgiPOVEhJy8GhqT6jeaMMcvXV2ND
         wQmQfnt2u53d6JjzhfemOn7Y8u2Q6YoHb1GRlqOE2AIDIEqf3F9pon+V9LZmYgonQvYA
         TdUEXnZd6EMR2ZNd28vZiuVVNNowhrOqwmAhBykpu53nzoqect629B3KAjGxNpaQBO4p
         6Y9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xrwq3fCkmcBKgrd1DDBsF8xlDt547KLjDT7fXifYZaI=;
        b=ujsXpzZ5V+YdHJx5OuBVT543l82XvpwWq7aKzfQjeFp8NYGntQAhkZ8y6dCPzN+yiz
         aVwSqiH5RmeEjqKtW/xd6g7IF2QT3MqPzf6FGINJ63U1RYr73Saf02LKQvwOGplAH2M1
         HdgDQ/Tn40nSkjgiuai7d8q307Dd1zYqqy8hoCpB4VMjQLN8eUY95il8Tl+CgatAJzex
         Jip1JJ6Os9N6SA/C9S4uJVT6xC5kTdnip5Ahd4WD5Tpa5dbCxKd5gg8CtRdReZZ8M+0W
         qeuV+I4fwExTPvDrFMDWcy9dqqTWx7v8swgQsRsWx2D7SqJH46mV7gnSnnDNyUrtetrz
         wdhQ==
X-Gm-Message-State: AOAM531aWi4qXjTWj7THvo1AdUBZGGJ5AeXQFCaSarfxt13tPFXySgyX
	JF4HXAgIR9TIZ3Q+ydxTkx4=
X-Google-Smtp-Source: ABdhPJxICjehp98PfxYoNVbUGZGsa/fz32ZQPEk28aFAEZYPMiOH++7J86RNMtimG1ht5Uj7xSFf8g==
X-Received: by 2002:aca:408a:: with SMTP id n132mr19116214oia.70.1617029679355;
        Mon, 29 Mar 2021 07:54:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd2:: with SMTP id k18ls2490542otn.5.gmail; Mon, 29 Mar
 2021 07:54:39 -0700 (PDT)
X-Received: by 2002:a9d:638b:: with SMTP id w11mr22834987otk.273.1617029678979;
        Mon, 29 Mar 2021 07:54:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617029678; cv=none;
        d=google.com; s=arc-20160816;
        b=KjwFvp5i4Ebbp0AHw6TfJMd+Z1D7Vq0Odr/HjMxrOqMyQ9kvtizWErOLXtIidyN8nw
         lCj/FeHKfMsiXaQXHN9r+nzImqR9GoMZDPmIvvWzsH6v/F6498Ts9572rbyrWXAR3xiX
         wvbndD4rRlngSgruMoTApmv5p/OmMPTAStLq/MHNHBvOJW9QSDMoEcrzWu7wjX8nGgVF
         olmVJ0qUXC6KMo+bG5P0QUb36Ca6LgN97bJtGvf86X5Teo+Bz/3MmOzgIMkYti6IoVkW
         upZGcnYKuNTZCjBEHjWo88EO2aXPgzR/vg1V1BxQOF9+u0nmYkzJq/ArQpAF7n8rfn3T
         H6xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5MEBgMlFtr+qxbmpKO8IW3rS99OFMlWLKykyxAuuxkw=;
        b=k7GawJo69yWpZ3BMBDG2DKcbOTeEbmPNnnbfUEn+0EYwGRx5tHvMSw2HU73k8PeSPu
         87eIpMMhscAKyt27r8TcFMA7L9CXtuxWSVdFl7/cFM8r3Nu2nyW9tgbVq2RvfB8OhuaV
         HtdU8GWjH0UQghTN1OphUao3QLrEouqH3orltjKpAJvVmOOefQBFQid25Uk5fzr+do91
         rXRDpYAOyOgzZB16uv8vojRfsUmAccmR2WMnzkFJXf05DeDmmISqMByzfrWV3Jn0U8JE
         dbLDUd88U01vbLcVEKSoC9GWlWvIy1lIgvfdty4xQ+CdT2GJxd7eeQECBBniM1xi2f35
         pwEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iSXU1lHc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id z24si1058076oid.3.2021.03.29.07.54.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 07:54:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id f10so9554530pgl.9
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 07:54:38 -0700 (PDT)
X-Received: by 2002:a63:d841:: with SMTP id k1mr9886568pgj.440.1617029678142;
 Mon, 29 Mar 2021 07:54:38 -0700 (PDT)
MIME-Version: 1.0
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 16:54:26 +0200
Message-ID: <CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iSXU1lHc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 26, 2021 at 2:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN stack
> instrumentation, but we should only need one config, so that we remove
> CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable.  see [1].
>
> When enable KASAN stack instrumentation, then for gcc we could do no
> prompt and default value y, and for clang prompt and default value n.
>
> [1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>
> Acked-by: Arnd Bergmann <arnd@arndb.de>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>
> v4: After this patch sent, someone had modification about KASAN_STACK,
>     so I need to rebase codebase. Thank Andrey for your pointing.
>
> ---
>  arch/arm64/kernel/sleep.S        |  2 +-
>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>  include/linux/kasan.h            |  2 +-
>  lib/Kconfig.kasan                |  8 ++------
>  mm/kasan/common.c                |  2 +-
>  mm/kasan/kasan.h                 |  2 +-
>  mm/kasan/report_generic.c        |  2 +-
>  scripts/Makefile.kasan           | 10 ++++++++--
>  security/Kconfig.hardening       |  4 ++--
>  9 files changed, 18 insertions(+), 16 deletions(-)
>
> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> index 5bfd9b87f85d..4ea9392f86e0 100644
> --- a/arch/arm64/kernel/sleep.S
> +++ b/arch/arm64/kernel/sleep.S
> @@ -134,7 +134,7 @@ SYM_FUNC_START(_cpu_resume)
>          */
>         bl      cpu_do_resume
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>         mov     x0, sp
>         bl      kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index 56b6865afb2a..d5d8a352eafa 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -115,7 +115,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>         movq    pt_regs_r14(%rax), %r14
>         movq    pt_regs_r15(%rax), %r15
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>         /*
>          * The suspend path may have poisoned some areas deeper in the stack,
>          * which we now need to unpoison.
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b91732bd05d7..14f72ec96492 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -330,7 +330,7 @@ static inline bool kasan_check_byte(const void *address)
>
>  #endif /* CONFIG_KASAN */
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  void kasan_unpoison_task_stack(struct task_struct *task);
>  #else
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 624ae1df7984..cffc2ebbf185 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -138,9 +138,10 @@ config KASAN_INLINE
>
>  endchoice
>
> -config KASAN_STACK_ENABLE
> +config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> +       default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
>           causes excessive stack usage in a lot of functions, see
> @@ -154,11 +155,6 @@ config KASAN_STACK_ENABLE
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
>
> -config KASAN_STACK
> -       int
> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> -       default 0
> -
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
>         depends on KASAN_SW_TAGS
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b5e08d4cefec..7b53291dafa1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
>         kasan_unpoison(address, size);
>  }
>
> -#if CONFIG_KASAN_STACK
> +#ifdef CONFIG_KASAN_STACK
>  /* Unpoison the entire stack for a task. */
>  void kasan_unpoison_task_stack(struct task_struct *task)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8c55634d6edd..3436c6bf7c0c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -231,7 +231,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size);
>  const char *kasan_get_bug_type(struct kasan_access_info *info);
>  void kasan_metadata_fetch_row(char *buffer, void *row);
>
> -#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
>  void kasan_print_address_stack_frame(const void *addr);
>  #else
>  static inline void kasan_print_address_stack_frame(const void *addr) { }
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 41f374585144..de732bc341c5 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -128,7 +128,7 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
>         memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
>  }
>
> -#if CONFIG_KASAN_STACK
> +#ifdef CONFIG_KASAN_STACK
>  static bool __must_check tokenize_frame_descr(const char **frame_descr,
>                                               char *token, size_t max_tok_len,
>                                               unsigned long *value)
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 1e000cc2e7b4..abf231d209b1 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -2,6 +2,12 @@
>  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
>  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
>
> +ifdef CONFIG_KASAN_STACK
> +       stack_enable := 1
> +else
> +       stack_enable := 0
> +endif
> +
>  ifdef CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_INLINE
> @@ -27,7 +33,7 @@ else
>         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
>          $(call cc-param,asan-globals=1) \
>          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> -        $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> +        $(call cc-param,asan-stack=$(stack_enable)) \
>          $(call cc-param,asan-instrument-allocas=1)
>  endif
>
> @@ -42,7 +48,7 @@ else
>  endif
>
>  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> -               -mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> +               -mllvm -hwasan-instrument-stack=$(stack_enable) \
>                 -mllvm -hwasan-use-short-granules=0 \
>                 $(instrumentation_flags)
>
> diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
> index 269967c4fc1b..a56c36470cb1 100644
> --- a/security/Kconfig.hardening
> +++ b/security/Kconfig.hardening
> @@ -64,7 +64,7 @@ choice
>         config GCC_PLUGIN_STRUCTLEAK_BYREF
>                 bool "zero-init structs passed by reference (strong)"
>                 depends on GCC_PLUGINS
> -               depends on !(KASAN && KASAN_STACK=1)
> +               depends on !(KASAN && KASAN_STACK)
>                 select GCC_PLUGIN_STRUCTLEAK
>                 help
>                   Zero-initialize any structures on the stack that may
> @@ -82,7 +82,7 @@ choice
>         config GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
>                 bool "zero-init anything passed by reference (very strong)"
>                 depends on GCC_PLUGINS
> -               depends on !(KASAN && KASAN_STACK=1)
> +               depends on !(KASAN && KASAN_STACK)
>                 select GCC_PLUGIN_STRUCTLEAK
>                 help
>                   Zero-initialize any stack variables that may be passed
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210226012531.29231-1-walter-zh.wu%40mediatek.com.

Hi Andrew,

Looks like my patch "kasan: fix KASAN_STACK dependency for HW_TAGS"
that was merged into 5.12-rc causes a build time warning:

include/linux/kasan.h:333:30: warning: 'CONFIG_KASAN_STACK' is not
defined, evaluates to 0 [-Wundef]
#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK

The fix for it would either be reverting the patch (which would leave
the initial issue unfixed) or applying this "kasan: remove redundant
config option" patch.

Would it be possible to send this patch (with the fix-up you have in
mm) for the next 5.12-rc?

Here are the required tags:

Fixes: d9b571c885a8 ("kasan: fix KASAN_STACK dependency for HW_TAGS")
Cc: stable@vger.kernel.org

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzyv1%3DkXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA%40mail.gmail.com.
