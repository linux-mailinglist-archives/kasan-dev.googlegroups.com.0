Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7OO6L7QKGQEGWMG6YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A8F82F1F61
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 20:31:10 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id t23sf351241ioh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 11:31:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610393469; cv=pass;
        d=google.com; s=arc-20160816;
        b=lg4EQ57ZatXZebY2rh3af/zB/gxAip01cFYsjbZ3czFExYmQiTD/GDgUZtf5C0wffe
         rcIYlT5n0GdSE7pvlGxcjHkrR/kDwH67+YVTDKz9o7NB4hO6xTUMAIBdu7LZul9NHupX
         29PF3POB9dA9ncDuheq5faEYSKzTJU8o1Shn+ZMLbGfFJgIXITVO6oT6ECpzt8/VOn2C
         c0Dj7RhdI4xzm2jD6sYm/4swpQROV4tbp0WDdXfDOO0poFhg1bOmtR57QoyBpL8P2L7P
         gfGeGzRYfoeHXCM9VevpksFMaD7m5RkLCn3chW6qVXm5m2PURec8MqDH8j/1DU6M/3tX
         HeUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r7P4J4t0hAowHKVsQzS6dRcA0YsSppONWpJj4yTX+8U=;
        b=qh3mKp7MXT/G9iFQaSkuHudtxi8XxOPbheZnNXUags8BvNjdWH+CQgCy++AXiTU+DC
         igNP6ptC5hQqsw9p/S9h//srwEA63BhA3sLPKGGJMwaT6o10LsPYLRX4PJbYrqi2SrDn
         L3sjAUJZ+SrA9tL7pgq7drZFLZW9GT2wLq04UEKkGNTiqnJ9RbBeZIB2jOc4EtHpDD3E
         hZh5sscYfCs1o7LKPzR6mhlPHk5gZnU84x8Y8CEABLEWCpqYTM3bgVs3BC9IUguVNOFe
         ctrzJynGqVb1ekASoMXHdJakoet/tS9yn7oWj+S57C7hW+qCwczLyaKXbb0iAhVyIt4O
         qnUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GKW7GVsW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r7P4J4t0hAowHKVsQzS6dRcA0YsSppONWpJj4yTX+8U=;
        b=h4yHszR8jnBvFIWy3a1h0YQoHUB+ItD1ybUWfhOBKA36N/ue+elf35hJmTLT04i1nZ
         4422FkHyjoHaCITtfSnDvL6hClKN0Y3i0/nHWgZLnU3pqHQn9yZml1G+gGbVvabq8wX+
         901eWpWj4vG0GlHD30ZQTSgFRfWmKVCq6rEHnPYuZ7M6OEcYcn8+arUEXGgJF/7gsoUi
         r7N8lM9edh32cR3/UOeYCP1y5sfed6i3lGGLERw+g8+n3f3zh1vaYBE/4dvQaCMS/PkS
         DuymCR6qQmYDDoAy4FUFztE6GO1V04PwihNH2GeCpaFpl4Eu0sxFEFZTV76Ure0PSjbw
         abLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r7P4J4t0hAowHKVsQzS6dRcA0YsSppONWpJj4yTX+8U=;
        b=I3SWU9JimxE2TQ9ztbhPEo9ulwDB91q+srQyOKTivzX3S+U6zYUSX/mWtNTccppg9x
         3iUzGtoMT5RBQrTaPCWkeMG3eB0SEGv2wTGWFkz0I2wmRjT6xCFLWpkE2p31+d0ylTrY
         c1Pr6yAtMTlni4msP+D23XP+yk6KAyJmULgP4Sn3T2+7kYNvviT9SD9p/2jQApqR5pjN
         PdB9gw5XAs624HsB6Eu8CWHAz9P+W080/1gx94VM1uPSj8cIvLs3+nv+syJzdY1pCRhG
         2fLYZ6bhiSkaOc0/A9ujHkddX7O1wpI3RLorImG+/lBjjY25bnnea3tp/D+70RqraIfD
         aMrA==
X-Gm-Message-State: AOAM532BeUjCpMV6wtzZ0Cq/GGnUsJ6PPHRNG7xu9+4+WiWfghCMiom2
	4RgK+awMqQZjxzmaPo3sJMI=
X-Google-Smtp-Source: ABdhPJweiR5EWoUvbdv/7KX2RKsZJL9qQ9KpTgLN6eNJYoZeWZiYgwLpeul6II69W4vb3PbibvsSEg==
X-Received: by 2002:a92:ba55:: with SMTP id o82mr651774ili.202.1610393469488;
        Mon, 11 Jan 2021 11:31:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:d81:: with SMTP id l1ls152919jaj.2.gmail; Mon, 11
 Jan 2021 11:31:09 -0800 (PST)
X-Received: by 2002:a02:7152:: with SMTP id n18mr1095343jaf.127.1610393469067;
        Mon, 11 Jan 2021 11:31:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610393469; cv=none;
        d=google.com; s=arc-20160816;
        b=DK4O6S2nRwwedqO3ObeJm4+qe2C5IB6CO2KUbtG+6ZeXFB2cQ0Rv8M4xqmfWchTTPw
         kMF42Ox/NuVkcgw399uDJUasubLO8V8tGlFS+SIqdyJhOnnZ4oS+gi79C+Ov1jdxJdXR
         /xSqjDVZkyGSHm40gLVTLft8r+t2/6N6zZUWKJ5WZdekUbs4nMEfj/MGCV8WeXw2b60g
         viVT1TlTcbpHiRsH1aj6K0McS2EBLtAOtEJbPK9xKn38PxpopEym7VX+zScMGvgYpGlQ
         ap/Uv7unFCh1Pq9Iir1J398eZNSXC7cDgvJXTi2Htp6yV26LQUIlbzErCB8D+mdESCNt
         NPcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JWD+nFSR/xfAM7TWdR83eQ5PdQdXQ0ay3ZjvrSFsCR4=;
        b=IO384PVyvz+SjONuiuZvhiAbvRHj2U9mrw7y8FsJi+ej5aHSX8mQ3VC946Cdtx4+cg
         yMJDyYZrYgB4pVVHLe+AWE2eCaVF2xq+gFLvuxcRk/fsobKvr3/J/o+GM8J8XtKHnw3/
         g7UK8UqIFwcRGHpDy8j/qK7TxKFWQdLLbNwZqpYfF1cxtEx/UC99/+K0h5WdbLPNSES1
         +NO8dCj5NGqwRvcapcXA/BsLbVicXWOD9ZbYN5PruLFVP8pd2FcG1af47X6KiZm4N9hG
         ThD81bLCgcXAaMd+dLzL1vxz3d5P2hfpa8gkUSQ0kogRzdKTuIdd+wNOF3Q4aXCMDikU
         HSKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GKW7GVsW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id p16si64583iln.2.2021.01.11.11.31.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 11:31:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id a188so531872pfa.11
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 11:31:09 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr1047244pgq.130.1610393468521;
 Mon, 11 Jan 2021 11:31:08 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 20:30:57 +0100
Message-ID: <CAAeHK+waK5WLsfroNfXEWwAYVyzqVAeUhyn+RDdZjeVbpVFjHQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=GKW7GVsW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
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

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwaK5WLsfroNfXEWwAYVyzqVAeUhyn%2BRDdZjeVbpVFjHQ%40mail.gmail.com.
