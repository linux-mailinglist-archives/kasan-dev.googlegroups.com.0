Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYGV4L7QKGQEBAI74UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85FB42EF7C0
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:56:33 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id m9sf5985120pji.4
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:56:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610132192; cv=pass;
        d=google.com; s=arc-20160816;
        b=QEmGXDj00p4Dl3CPU6hORc+CtQ/v0vOQ27zgbhsyGuj1+LaJV1Bf+pb+ZvrGUq/DTM
         8EpRBC82TrdEx/9IuVGbNGFVMmPClHwZTbdWa52p3oYw5We4hFNQ5FDWq1L87ZGSW/qE
         GCSSXsL2FtLhcL3Q2AK9xVMTIECtCdlHqaZCDV/iKrttbX+n54cu8BKzQoQ+7dskamPI
         XMwOmr5DXk6lar2FA2Sg4fyo0SS3hc4bD1zxDyuXfTLF5ZEznPRlNIr+JCaFvoLWy8pT
         tMvpmwFxgbn6d9ae8EGLk19hfrFW3nLNf9XN6s4EZUbYtneBcJQWDLPwItHkcVRsb1Ce
         iYsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8s0KWhvZYS+wKgo576ibMpTajuv0T/hOR35a/bJWb6w=;
        b=NJURFMfOzR7KH3EsyqE7SEf3avy5hI0XzeYjHmA1fdLSMpojRWjfnKCiI8YvOFjyN+
         xfvQn5z+dF5tAmadmtRXVb/nKH+tYJlgPdew0c833RGLQxfn+IQMLqQiGfQv3FAeNlD0
         LEtaB5jNZiGtqOgb+LHTpOQ0bwTWrOjbXgelxnPa1hiqBhmmjNMMnsvzFaENuTLi99Ko
         /24yvqvck96PEdcPdE66N2txHayDNsI5+g8tFZNnRApcclq33+OYseLhFrXbwuruX7Vg
         N0e2iKt8jTo9ahgOU9kDWqQsa8yIhuR3zfaipITwvLWlndMTQxFjeLyo0U0MWRciK/8X
         zz2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rI9Nkb8R;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8s0KWhvZYS+wKgo576ibMpTajuv0T/hOR35a/bJWb6w=;
        b=sQUbVMt1PZnzwSI4ihJVCk34fwxvtpvTMj/BiFoHcRQYQRRzPeP4/9o4MYz1yKJKsJ
         OmzAP+Lzk/F57AX5bIh/Bm+hk3WwfXEUZ8vq7HC0pRGhuLVEgxPzUabn7n4V+b3VTgMU
         JXflOpZraO7nvMOpYFfun35lVN66ACdfpixnJj/Q1bEAJL0JRmDOt4Hin2bA1Hij2rJN
         IYaD5GwtmhVVh36Qv6mlgUbxdYrYwMgR6idGZ0GY+piUDPAPaRV0ASZOpVBnNpitdMHI
         efuRDD2WfhMAElUzmfXm3Y9TPPFnXWAZ6cmgLtm3ZDkA7Y4BiQWiyonwbHQ+X/VOZGjl
         zRYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8s0KWhvZYS+wKgo576ibMpTajuv0T/hOR35a/bJWb6w=;
        b=E9geQJ18Kl7f7mO9FYac8hsL0Alukp7V7DHDpTGCSMFIDEAIT/FtqK4l2oZO8JNkvh
         L/af4O+5sSaTaXc37AuUC4nE4ctaaHYbWsLYNL/OMC7nWM1TaSfLB3Yt7fhDCBVxIHMN
         urpsgEbvpQ84Z4UnD8qP6QmVn3/Ts0bAHYx0++DQkl9tBZvEwLtVPsU9Vvh57his6Tgy
         H4eydlbxkLOtRk1rjdRgXco+8VzvEwolE8Qau6KcyRwrrE5RGMZ3QOU/Oluxc98B3uQY
         paxtpFLD0g1BoLZOMUxc+sVvjptO22fNO+dhw6YFEGWZRkC2zzPYTi6DeXTcx3ALq0rB
         yRBg==
X-Gm-Message-State: AOAM531YCTrYe3LZKzoxPHGORZCaDjpRx2ZBJWFMKGTCPU+yyy9P/KVe
	l/NmDNhzgJC1ubB68qUi2ow=
X-Google-Smtp-Source: ABdhPJxVQVZIuOESvkROVine/MSf2zXsqzVFuVruMJS0RH4VwFDbbZ+9pge+5vibjBqM2nIx26YpqQ==
X-Received: by 2002:a63:656:: with SMTP id 83mr8402193pgg.222.1610132192317;
        Fri, 08 Jan 2021 10:56:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls4698415pga.5.gmail; Fri, 08 Jan
 2021 10:56:31 -0800 (PST)
X-Received: by 2002:a62:7f4c:0:b029:19e:23d1:cf0a with SMTP id a73-20020a627f4c0000b029019e23d1cf0amr4986332pfd.67.1610132191696;
        Fri, 08 Jan 2021 10:56:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610132191; cv=none;
        d=google.com; s=arc-20160816;
        b=R0aFgyEAPQeZ9jhbJROi4vMROcIAR6UZWMZrIEqhIPDgj7tlhq3W4684Akg2d4btc9
         URtNBsJJRkKX2/x7chrZ0+0aW/gZXGDK6Gz/YtlateG5dM6O5Rrt+fn9a6NVtsI/TZqt
         hKNRrlUbKbkx5ArIHb3zOZIBw21uEDKyHh2fH10xCxH7081PI5/n/YRLvjVGvFpzYREd
         iNnBoU82LtLq7rG7aEcLVHUnJ3UPFjYeWXkSJXgup2IptdV53+ZAOnKlyKtN++sK2GPB
         vEC5XCgmACqNBbWzVIUqYDKCkwE22pD9WZmdl69H+AaQunlcPDooilA5WnruNutpUB/9
         T92Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GU+9P9R4Nfik1tMFFGFZP2iMEdTwiDCN49DQfnWs2Fg=;
        b=FTz6v+FMf84afA3KOb+FmMNQ70zKSs8i4MGyUmM0uMhVBWfThlXbjrJJi5epPZ5Hsk
         Dr8gjJobDUR9133Qq7vDPyROP1+ee4BW7CF3qaJxMVmek2GEbKvuVH9WMSFBN0f2rsZI
         geiWPRkiWEhW+/p4WvpqEpTfwrGtgyBWo7CFmzJekCiNmTBbaqjcbApK67UZSSd7xz+p
         nhGK8ax1s+HrICIWLB9oyVOQGFV6slJUhFNNrY6RBqoZ+mhoCW6rIcn60D7fjqB1SEzH
         0pSktDoFD4PcTy67eTC6HgGFWiq7fA3zEjfwlcKuNXSvk3RVNdOyqnvQGGu5A99BCFH5
         55bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rI9Nkb8R;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id r2si814219pls.2.2021.01.08.10.56.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:56:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id 11so6814740pfu.4
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:56:31 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr5032496pfh.24.1610132191222; Fri, 08 Jan
 2021 10:56:31 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:56:20 +0100
Message-ID: <CAAeHK+wW3bTCvk=6v_vDQFYLC6=3kunmprXA-P=tWyXCTMZjhQ@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: remove redundant config option
To: Walter Wu <walter-zh.wu@mediatek.com>, Arnd Bergmann <arnd@arndb.de>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <natechancellor@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rI9Nkb8R;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42d
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

AFAIR, Arnd wanted to avoid having KASAN_STACK to be enabled by
default when compiling with Clang, since Clang instrumentation leads
to very large kernel stacks, which, in turn, lead to compile-time
warnings. What I don't remember is why there are two configs.

Arnd, is that correct? What was the reason behind having two configs?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwW3bTCvk%3D6v_vDQFYLC6%3D3kunmprXA-P%3DtWyXCTMZjhQ%40mail.gmail.com.
