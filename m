Return-Path: <kasan-dev+bncBCMIZB7QWENRBMVM4D6AKGQEY6EQQWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16A0E29AC68
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:44:36 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id 18sf847500plk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802674; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTg/mXUOXP/gO07edR++hgpaPyQ/f1Dt4bMKI+VlDJi1pseilfdEMBlvm6h2MHS3p9
         ZP0Wf49Nm3k6cRgyaxX3loSOXvGQnj6vekbVFiReuHkhzLEAz5gUWoFve8qQDYv3EG3x
         6Z6/yae1isrJMGn2ur1gciGCjaAkB9/mvzgD3OIOy5uVeEm3inryyYu8OJ21bymwhSCI
         GQ5vWfC0UE9hs+tsndI3y0PozCz001stibLxMJRMxDXySRAYZSRNEaYdJAykxKZY15gs
         FygugUZAR5lGp+0UIIO7M6qAd1LVvxh13odZF/FRqAFcHdp2czf3E+YderV9rShD/94P
         Q5aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MndPC2Q0th2EmePSD0AXi8WI5ge9BXqljAfQTopY95s=;
        b=UevfanE4+D4Ysna6f55swRdvz9+eH/AYoNuc/BTim3aXqt559M5QE585udq40l4ESc
         11NWO+qAtzMxoBYraiQmKNOkpegC/nu02PkyBqwefbJbaHS8OlYyMuRxTmp7Fy9yD7Ow
         2DUok1TVzDgOU7eRnj9dKDuCJ9OCft6R0M2udZ/aO/pLxGo5CY+iquUmp1ep87DcW5HP
         B0GSUppFQ7s/UgCzBel/J8vYAlhwHySY2z1KTHAvK3RPifbNho+e27AJCbjsWmcmnsZI
         HrCfIgUVxvZaONzQZ1HfsggzHxs7Svnao/bxer9FQfKbxPtoAmVgRQdFxfSCQJDt2xkl
         Yo9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SZkHXu8h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MndPC2Q0th2EmePSD0AXi8WI5ge9BXqljAfQTopY95s=;
        b=q+lrRRDS8UrbxZggxo3k1SJavvp1h5fmOrJBjvYtMorpdTnxO7XmevoKdtBK82BWL1
         cFl/2FeL+lW3u+EhCEsdqKQkvlNrrs+Mc69t6K0WuiJltSLOFz+l7NxYe4IK/fGWyyFm
         gyyrY0VbtqU663VY9ebSVshpKmH4iyhwyJTq1nfdWqU+pGpsbk8ij49dKtCzVS7YeouT
         P49geE0yGMsKtiCPc/s474A/jUPp2rb9mSqaCOrlYjoqd2CDbj93ohi1vUzHJEhEiW+h
         mNCiUyBxXvDJHKus1Bd+YbbbIsZP4J0ys7Wmvm4Su01sqJYtj9XxgkebweMz/6H5k+6q
         j4nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MndPC2Q0th2EmePSD0AXi8WI5ge9BXqljAfQTopY95s=;
        b=HjjIOBxJa9t5geGPIZSsA3ntGEg7F6oJUhAMVDcSa1HffxAHzemi8giLzT0zvmKAuy
         +x9KSMuBUgE0vC5/gbCJ10383Gw90jVhN7qA7wNxpGauw1GcfRA1DDzKKBSI04RAvaZY
         5hfFuF8VQGW3/BhmIxn0m/quj50AEYgpQgQgrIRjRfN/ZJhSIemMBXRP2WHF9RMgHkL/
         XgcpOXNa0ShngfbVb9aZwd+TBQ836HB5hohUrN3ILZ3rURLBApdnoLHrTi6uryikaN5a
         iXfbvItln8J+aXIUTX9wQyWeCA6rKgPGV3brvnExRhoX7C3GJwgZEupV3gzcad8RXxng
         bueQ==
X-Gm-Message-State: AOAM533sGGEJYKH4mKmV4+h9PtmqWDNJ2w1oYbVrSx5BjQD+jntfBmCX
	TEKzAAlwGgUsAqOIUQpj+yM=
X-Google-Smtp-Source: ABdhPJzsrL/ShFOSRkD2aBJEONNOeuSQYFCpuuklhPzSBErge0lelRi+cMm+zetV5MGIBGnrNu3WXg==
X-Received: by 2002:a17:90a:7f81:: with SMTP id m1mr1963840pjl.197.1603802674812;
        Tue, 27 Oct 2020 05:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4486:: with SMTP id t6ls810663pjg.0.canary-gmail;
 Tue, 27 Oct 2020 05:44:34 -0700 (PDT)
X-Received: by 2002:a17:902:d904:b029:d3:d2dd:2b36 with SMTP id c4-20020a170902d904b02900d3d2dd2b36mr2190345plz.32.1603802674260;
        Tue, 27 Oct 2020 05:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802674; cv=none;
        d=google.com; s=arc-20160816;
        b=U6vwhpWUYfglFaZP0sLoJqV4H2i0JmpeDyWidrukafrZZzE5UwSrsNGGHSVYx7VJkt
         MG0BhB3upVBVsuZOn59pcllK6ZRVMDcR0BlreAnQT/wzxzBtvIdX6YN0wyfCkT8qAPfA
         0BYk/FLmsxjXDFT/jQDpf6XZrlbEwvzg8Xdp9fNc7GN7+gvTQ8MxUe/QRGB5SIitzofX
         1wevdMAVGabjmVRBJAxYccVRq1geUnR2cPZkI2pGK97e9dyz6yrHkPofZTmc597j367Y
         ZOYr++cLpr2WBcQb4lgpWbdnbowk5MzyD9qn50fqN3CGUkEuDFgNZ9gZ3xsEpixq2Bc5
         WaEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MOEEMcwz+wOCi9BVmbcGJ1vQkzTsdFXXOfPV2diYyTk=;
        b=BpE3MAQCiUoPHBAqflPlN6Ttx9bBwOHwRXKVRSRJ05Xjvs6nUQrUrvGjHToTtJXrh8
         fShHImFBjVJeQL+Aol99MPt5hg34am82PneT9kJnBVM9/83VaahV+p5ku8G4RsSZhzxq
         42tvncAQty1oUWz9C2kUZvlgIQgfaz4d9QpnEhlVVzAS0Q3velU+fKqXmbyBlTWMlrJb
         cDSA6dczI4OlXicRJGqR9S9dtdvEvlFTG24ccV0XEit6ifJ4LLXFmvTrtv5eVSiSM42R
         sTY4KLv3f82ibII6g2OeDTfdcYft+Kag+FtsVjthtFTRZcSjFbWg+CXWfKBby0ohFuZz
         JOzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SZkHXu8h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id l11si95480pgt.3.2020.10.27.05.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id r7so949325qkf.3
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:44:34 -0700 (PDT)
X-Received: by 2002:a05:620a:1657:: with SMTP id c23mr1953011qko.231.1603802673106;
 Tue, 27 Oct 2020 05:44:33 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
In-Reply-To: <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:44:22 +0100
Message-ID: <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SZkHXu8h;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> There's a config option CONFIG_KASAN_STACK that has to be enabled for
> KASAN to use stack instrumentation and perform validity checks for
> stack variables.
>
> There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> enabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> ---
>  arch/arm64/kernel/sleep.S        |  2 +-
>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>  include/linux/kasan.h            | 10 ++++++----
>  mm/kasan/common.c                |  2 ++
>  4 files changed, 10 insertions(+), 6 deletions(-)
>
> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> index ba40d57757d6..bdadfa56b40e 100644
> --- a/arch/arm64/kernel/sleep.S
> +++ b/arch/arm64/kernel/sleep.S
> @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
>          */
>         bl      cpu_do_resume
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>         mov     x0, sp
>         bl      kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index c8daa92f38dc..5d3a0b8fd379 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>         movq    pt_regs_r14(%rax), %r14
>         movq    pt_regs_r15(%rax), %r15
>
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>         /*
>          * The suspend path may have poisoned some areas deeper in the stack,
>          * which we now need to unpoison.
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 3f3f541e5d5f..7be9fb9146ac 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
>
>  void kasan_unpoison_memory(const void *address, size_t size);
>
> -void kasan_unpoison_task_stack(struct task_struct *task);
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>
> @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
>
>  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
>
> -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>
> @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>
>  #endif /* CONFIG_KASAN */
>
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK

&& defined(CONFIG_KASAN_STACK) for consistency

> +void kasan_unpoison_task_stack(struct task_struct *task);
> +#else
> +static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> +#endif
> +
>  #ifdef CONFIG_KASAN_GENERIC
>
>  void kasan_cache_shrink(struct kmem_cache *cache);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a880e5a547ed..a3e67d49b893 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -58,6 +58,7 @@ void kasan_disable_current(void)
>  }
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> +#if CONFIG_KASAN_STACK

#ifdef CONFIG_ is the form used toughout the kernel code

>  static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
>  {
>         void *base = task_stack_page(task);
> @@ -84,6 +85,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>
>         kasan_unpoison_memory(base, watermark - base);
>  }
> +#endif /* CONFIG_KASAN_STACK */
>
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZys3%2BVUsO6GDWQEcjCS6Wx16W_%2BB6aNy-fyhPcir7eeA%40mail.gmail.com.
