Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPE76L7QKGQEOXWZBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 291C22F1D03
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 18:49:50 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id q21sf80975ios.14
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 09:49:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610387389; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbIEM7U22lwYcoK9/qM6U0PeF0lryczxZm9FhEfmzoNGYeV4WYEpwWQdiABsv+pbhG
         +rZdrIsXYc6inboV5j3q5TQxg1AtJzEWoljzGt7gxWo+7r2Y73Wz4L4qx+gLh7/Hv16w
         v+u/7A/h4wHXa0sqvx3aFpeOgKkdsIUWsGu48QndfQHPXhNOK1JOJXQ0QN8wwueTlzD+
         MQGHmfQUlPjKpkWsoOI3+LUetaPmLaMlAR5vnpwwK2esRqSob6B2D9YWiF+LgksGFxEL
         tim1pmleFc4v6CMVEmdv97PT2RvkpNaeow++sYSDbKr/Dmn9ZIKm6nTtvCAL9DpdlrcI
         ahzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V73jSD8+fUgoFcREBMDmYuNO8v7ofF57q6sOO5cEVwg=;
        b=FM/RfKrksHzyzh9qT6fA9LPq4tl38n/gXS2I/UUWIWIblxF3T7ux8S0vD1442C5Cut
         SNc5oXCninIraXMKGyU4WdxWsFaU75dioG6j1b83iYXqB/oYi1wSkvY2kQ/OdBrl8lo5
         9OOopFKcZt5lOwszfnjKhEUN0KxqOsh0u56lhJY9nFPao4llGcEhjRubjVl8VcAGDPsK
         mICTKfQwdG1Vn6HHBQd4G5ego2ZxyDttwK8aOBbRY/WfrrdcjO5CzXNW8l044XrPhXXO
         Et1IF56Crm9VdurCZWC36fWHfjYTU3kmjt+omqjddkANEMKpAc9NHROwTX58i2vFNLws
         d0Sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jMYiq4Ns;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V73jSD8+fUgoFcREBMDmYuNO8v7ofF57q6sOO5cEVwg=;
        b=Dcq7Gzx8oRNSnVSDfqG+g0yD2goXTHDkJnqHhre6XHuMEr5zHU6HwnSRO3GHPDN6qI
         k8PbhJzXWTixpnzFr59RsLq9gkl58mnBOFxniiFQZiuk5XLSWyPahWI+NHxzQrA6ol2b
         TgOqyAirlqiV/d6j0jRyhGuF+cPtX9/9scmMag4m0tKspejWaPH3F4ZAPIcUnidEbftz
         csVhdzq6jU4E9kTXg25Fp3pDxuyUZ8L5SppouWJQs3alaO88QFRpgdh+WZZ4xuqKKReL
         WE2ABrVws2jEtUGUfDgUaUdFCR8ty511+C57l+jB58uTGVgQa3y7jGXkc+M8P605yn2n
         Ba4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V73jSD8+fUgoFcREBMDmYuNO8v7ofF57q6sOO5cEVwg=;
        b=PGqltlRhz6EMANyl5NqXTIhSbdFXBMyM71NbJr9WmfMAm8plhgPuZwrRXaErlwEZ9K
         p3d5NqrZTUrAK3Q3aNr8MDVwoqW0PDbn8+tQzlkWj9hIV8cl3eMM+C4oT3jdxVhGQLEH
         wjwotvET8W9qTpkQa+GBpw5JmXXovfdb6jHuL590uVjPz0K8iPDASeC+cHw8bzXc9M/j
         6o6zayrDAOEbrbq1bMNI7ds8yRSvs5rDtIXdHpRYwXk88IslANTh7dRuMteyumjDZ7ge
         1ESqToo7qC+wDz7Zl+71Wgd1O3wEVQh5y49smGwoPoVgQ/9+3qoJ7ZdmtM8FhjJISNkr
         5A3Q==
X-Gm-Message-State: AOAM532TLr4FoS4At3hjB7A/Phu+ZP8KFjkq1maRUeRGC6wrsH5wxuz2
	/eT/cdsKZvQnWbxl+l0J8xs=
X-Google-Smtp-Source: ABdhPJyjBmacedac7mCnf7CSxeLrQ5aeUQ6nPW9w4iuNxOPVxO6kSzcn5CGynjh9S9VEK9ttqeNNQw==
X-Received: by 2002:a6b:f112:: with SMTP id e18mr296035iog.195.1610387388886;
        Mon, 11 Jan 2021 09:49:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:13c5:: with SMTP id i5ls105922jaj.1.gmail; Mon, 11
 Jan 2021 09:49:48 -0800 (PST)
X-Received: by 2002:a02:b011:: with SMTP id p17mr806095jah.114.1610387388526;
        Mon, 11 Jan 2021 09:49:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610387388; cv=none;
        d=google.com; s=arc-20160816;
        b=gvNSXQqOa9gomtVa3Zd6vcw0QwUhwhDRtUR2GjAKgsCk4ng5I2DTAap6jcFPOomdr7
         2vH1vjK3L5ls82ISR8InVKZqrSKk4yfu5jcAZT1CjZA5zUGxy1oCvT9qm+kgPlwWEslt
         7BRifR7vIEgIaXdDWHUFLltCQYR6EIJABn9rJ8tfIKuF8g9kfolrHa1Us7IlDlMa+jEh
         oC1UTC/GGZM6lOJk2DCTCNKRz9ZENicwqX3qlFgZS6aykqibFsHys8FWNO45Tc/OwRv2
         ATu18yD22k3lGZL5eo2dxWzbqrlc7qzEu7vLDAUvc6mvG1jgbLnnMGoGJmZwqQmPoQen
         dv9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fhyTFo90HM/Knf/tmKOVy+wV54av0vENkrqrVl/EzaY=;
        b=D2WNPWuNYdA3FcJDtlU9qtCb2kL8252BK/PUnkFcOHJ7AXbInJIGcT+Qc9OvZwxb/H
         lRaJc9fNu/1hELM62QUtErTwuPtx3w40NZbgqL7yrd4258lyE+4evwFWLhdrW7V4Teoe
         m52oRRuRYW/WwWky1wj1LIQk3JlJ3VVih1CVJ77NFZL5Y+dMhaLgV4nSLdkGb+catZ3h
         vf26qjcDh53uy8YG56T/MP6E15DIFKJX/fZGH7GC3yHXD98/zHBwFSTFZEhEGrKOeE3u
         dssMzxzzYeI32XpUTuPk2N4DH94ZaX78jqCMjXxan02kXxqxBciHPfXdYsO68hSt80o+
         47RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jMYiq4Ns;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id d13si15203iow.0.2021.01.11.09.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 09:49:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id x12so213148plr.10
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 09:49:48 -0800 (PST)
X-Received: by 2002:a17:902:c144:b029:dc:292e:a8a1 with SMTP id
 4-20020a170902c144b02900dc292ea8a1mr837255plj.13.1610387387989; Mon, 11 Jan
 2021 09:49:47 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 18:49:37 +0100
Message-ID: <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: remove redundant config option
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <natechancellor@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jMYiq4Ns;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62a
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

On Fri, Jan 8, 2021 at 5:09 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN stack
> instrumentation, but we should only need one config, so that we remove
> CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable. see [1].
>
> When enable KASAN stack instrumentation, then for gcc we could do
> no prompt and default value y, and for clang prompt and default
> value n.
>
> [1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Nathan Chancellor <natechancellor@gmail.com>
> ---
>
> v2: make commit log to be more readable.
> v3: remain CONFIG_KASAN_STACK_ENABLE setting
>     fix the pre-processors syntax
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
>  8 files changed, 16 insertions(+), 14 deletions(-)
>
> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> index 6bdef7362c0e..7c44ede122a9 100644
> --- a/arch/arm64/kernel/sleep.S
> +++ b/arch/arm64/kernel/sleep.S
> @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
>          */
>         bl      cpu_do_resume
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>         mov     x0, sp
>         bl      kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index 5d3a0b8fd379..c7f412f4e07d 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>         movq    pt_regs_r14(%rax), %r14
>         movq    pt_regs_r15(%rax), %r15
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>         /*
>          * The suspend path may have poisoned some areas deeper in the stack,
>          * which we now need to unpoison.
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5e0655fb2a6f..35d1e9b2cbfa 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -302,7 +302,7 @@ static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
>
>  #endif /* CONFIG_KASAN */
>
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  void kasan_unpoison_task_stack(struct task_struct *task);
>  #else
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f5fa4ba126bf..fde82ec85f8f 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -138,9 +138,10 @@ config KASAN_INLINE
>
>  endchoice
>
> -config KASAN_STACK_ENABLE
> +config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST

Does this syntax mean that KASAN_STACK is only present for
CC_IS_CLANG? Or that it can only be disabled for CC_IS_CLANG?

Anyway, I think it's better to 1. allow to control KASAN_STACK
regardless of the compiler (as it was possible before), and 2. avoid
this "bool ... if ..." syntax as it's confusing.

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
> index 38ba2aecd8f4..bf8b073eed62 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
>         unpoison_range(address, size);
>  }
>
> -#if CONFIG_KASAN_STACK
> +#ifdef CONFIG_KASAN_STACK
>  /* Unpoison the entire stack for a task. */
>  void kasan_unpoison_task_stack(struct task_struct *task)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cc4d9e1d49b1..bdfdb1cff653 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -224,7 +224,7 @@ void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  void metadata_fetch_row(char *buffer, void *row);
>
> -#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
>  void print_address_stack_frame(const void *addr);
>  #else
>  static inline void print_address_stack_frame(const void *addr) { }
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 8a9c889872da..4e16518d9877 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -128,7 +128,7 @@ void metadata_fetch_row(char *buffer, void *row)
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
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210108040940.1138-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BweY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ%40mail.gmail.com.
