Return-Path: <kasan-dev+bncBCMIZB7QWENRBWVXZH6QKGQEGSFZJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A272B41C9
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 12:00:43 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id b199sf5780555vkf.8
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 03:00:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605524443; cv=pass;
        d=google.com; s=arc-20160816;
        b=MelPuWQlnfP6k6R+m6s/k0SxcRlVBM5KN6pdAQptvCd9SvzSJZ1kQT1SfN7eNB1jAf
         aAu46wk7EJ60ClCAfTOzOvjUFLk22MCYcQGSZZyETBbtZkqUlOEEh386Lz8UDzHJaXoS
         I0tA0WEQYn2CfVLPCOgxXOYpLnjOzRjR/PNnBG7CvkyuwMj5GOuj6CFXHvzJW46haIYn
         OmjuGX0SSCcJq0oTCHVCwLMbdhsqzBW1rmazLmQ9gdHLtaogH0ngkOjT6VnGAs3wOZRs
         pVuMF2UZLUvjdCUyqA/0/qYaFhuTpJsyT+tX/hZKa8c0zihBwYk5T/VNZQFRoD8AWUdX
         kV7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1a1bGVxRAfLMzQZtbEuYD4gSHeE3XuNN+9WKmsbPleA=;
        b=EJKids3+utxedn+g/bXWDx/yGaJ9WdpvLkhB43qqAIeTrmi9iqhIH6nTxSCHnVOjA3
         +2G+RwMP6p77h91EQNQ+AlY3gJ6Dy/qA/q80d0VL0XD+EJQrmEdQTbcZHrX8gA0//2rF
         mwJJWqcrTU4CZgZSOP6K7hItFnItAcE4wqeV+dWvgNw4WXk+aL2FIHYLsxMPrcoPcGpD
         Xc7mmNeoHuwiMzyTGin3N6EJHPryF9YTdFGfiDAwl0CKCA/9xqDb2iUzsQ8CohLM9jQ1
         aO0ygmdAKoYrobp/k4RYUczMfLmEZ7db2c+h6c3QhFE8dCpDMbGRrhTAHpyqS7Sg0LBq
         bKag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ojt003Ul;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1a1bGVxRAfLMzQZtbEuYD4gSHeE3XuNN+9WKmsbPleA=;
        b=cQi9IrGNjb8i6X/IK0V5hEuEWu90Fg0ECsI9sXndum4mmiRrHsSuCxTGGDxMnvvGP1
         tkC3nLiRqYRTGAHDV74/XJEYxqTp6TyoNgCiJ+ahQl1UzQGrtkdSfoOEFt48qGZci+LE
         wVHOaApdjvrd1XS+RE6usemwRISFcr8lVzGD815CZqmrrQLggQ8T0fP1RRISxVG865HD
         8TGKntW8nXN/jM/Obm6RX6Or6j5NupG8wDGGlhSn0f/NDPZP/X/tDi03Laz8nvgp6PvF
         NQKJq7lWt8/BgNIJMuAaaTgb8NgE2of4ygU3Bx4+05GwIff/QN8OxLJOslVFYvEM2FjV
         VjJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1a1bGVxRAfLMzQZtbEuYD4gSHeE3XuNN+9WKmsbPleA=;
        b=lFYS/hnrulYiDlQUp3ttdIMZUB8zQp7ug6jKvjvQSSTx2rZNUrckeOW2NIrPHbQF6N
         Hw//RY5NDxSHdi9rZlBhJlcsFxX9CM7rYmjSs+Nrrp88xVWfU3HkjTCJc0IQxHRyDKMR
         67CE+PpqF8Be/cQqkkBG2KAnMBGNvgCFtcuA0UOAnvmUcgtE5OVF7DIAaWaNYdYPiKPz
         enzO3q3XYuHpznfiWJBQviEQf3oLpsTYspVMZFsfK7Sj/TczUI5dx/gdxffDaLMCyKlL
         Vup8sAK7p+RYXYyy/4PqUBpbRPMC4En5sLGBhJZm38xPV2frl5uIDfH1AHiNEBEgIbQ7
         0V/w==
X-Gm-Message-State: AOAM531FfGTRiqdAJz81yWrKdajZrsdWll7cTHwj3us2UIXccQG/nMaL
	aVuP0eup/ijMGGxcS/1dcik=
X-Google-Smtp-Source: ABdhPJwBkfPsrAsYUrN2Ga7eQ1PAYqRmtiNsNhU2REYUlNxblFlW3g21SQN3TdyO92yBQU4lA7UISQ==
X-Received: by 2002:a9f:35ab:: with SMTP id t40mr9207579uad.127.1605524442837;
        Mon, 16 Nov 2020 03:00:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1cc3:: with SMTP id c186ls635636vkc.4.gmail; Mon, 16 Nov
 2020 03:00:42 -0800 (PST)
X-Received: by 2002:a1f:b291:: with SMTP id b139mr7375411vkf.0.1605524442226;
        Mon, 16 Nov 2020 03:00:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605524442; cv=none;
        d=google.com; s=arc-20160816;
        b=LGWgqwMCU4UonpSO6dhGbEGEiCwrKSkYvm1C8BcD0pXC6TxR1Scbb4XgvYbVxAOw11
         hgMGIF1luhVS2F3f83cXjx9D0JBi16eujahn7zNuQt6jLL11XtbmJnsTHdkP767qBonD
         pZL8HRxRqxOhdLk/B0bwgFPSW9EvoH35abknZx0pDqy4E0L28+CXVd3B9p/x6IfgKtmc
         Z0wX0KLPu7ZpPsSL8Jujo34fLChK0LKEF8ZMAmeNsisoCgXMVrdeUpT7EOfGNSw5T5RC
         ivI1HaFI5Kd8T1xgQgrXEjepOS2MpI/JuKQ5+1r8W0eb22alirI1D60zLF4NGPyzVMAf
         yvgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FX8GD+b8oMZGG7RMfkMYcB2Sb5EDK5FE7PKEweB+0bg=;
        b=cB4Gk64F6ybX8YrL265yYLrqh7yBTpLucgxbsPwkA6sQjApEeWBVTzXM38Y6ZNXDPu
         cD0l6pTfBYeuppPU5KSPeLvVZTCQ9+Nr3FUNc6X/hRKFg65xLaZ64uWuUrXKdkyB6oZi
         vO5zxml4MMBGYM+q9NH7oetNp592zERXXjrvsHHdS9ilqe1TB0lUVnhwwKZL7uXkHUMI
         ydL4YxzlaTMry9J3C5STXYcXSWtyXm+6tx7dUkRJdeYUu3BB2u31OUblzAW/mcgcyIHN
         gKv0ztjX0vne7ZZWYoM/B7W4xwPzN5i5IDsUAYJ3fMUnp6WDgwY+RkzUmC+V6Zen6jZC
         SdOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ojt003Ul;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id c124si1069360vkb.4.2020.11.16.03.00.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 03:00:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id m65so12475398qte.11
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 03:00:42 -0800 (PST)
X-Received: by 2002:aed:2b47:: with SMTP id p65mr13025705qtd.337.1605524441642;
 Mon, 16 Nov 2020 03:00:41 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <d65e2fc1d7fc03b7ced67e401ff1ea9143b3382d.1605305978.git.andreyknvl@google.com>
In-Reply-To: <d65e2fc1d7fc03b7ced67e401ff1ea9143b3382d.1605305978.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 12:00:30 +0100
Message-ID: <CACT4Y+a4ZoBm3jC308kradyeYcXKMMux4uTSgs4cWkby5Th+bw@mail.gmail.com>
Subject: Re: [PATCH mm v3 04/19] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ojt003Ul;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, Nov 13, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> There's a config option CONFIG_KASAN_STACK that has to be enabled for
> KASAN to use stack instrumentation and perform validity checks for
> stack variables.
>
> There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> enabled.
>
> Note, that CONFIG_KASAN_STACK is an option that is currently always
> defined when CONFIG_KASAN is enabled, and therefore has to be tested
> with #if instead of #ifdef.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
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
> index 0c89e6fdd29e..f2109bf0c5f9 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -76,8 +76,6 @@ static inline void kasan_disable_current(void) {}
>
>  void kasan_unpoison_range(const void *address, size_t size);
>
> -void kasan_unpoison_task_stack(struct task_struct *task);
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>
> @@ -122,8 +120,6 @@ void kasan_restore_multi_shot(bool enabled);
>
>  static inline void kasan_unpoison_range(const void *address, size_t size) {}
>
> -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>
> @@ -175,6 +171,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>
>  #endif /* CONFIG_KASAN */
>
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +void kasan_unpoison_task_stack(struct task_struct *task);
> +#else
> +static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> +#endif
> +
>  #ifdef CONFIG_KASAN_GENERIC
>
>  void kasan_cache_shrink(struct kmem_cache *cache);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 0a420f1dbc54..7648a2452a01 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -64,6 +64,7 @@ void kasan_unpoison_range(const void *address, size_t size)
>         unpoison_range(address, size);
>  }
>
> +#if CONFIG_KASAN_STACK
>  static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
>  {
>         void *base = task_stack_page(task);
> @@ -90,6 +91,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>
>         unpoison_range(base, watermark - base);
>  }
> +#endif /* CONFIG_KASAN_STACK */
>
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
> --
> 2.29.2.299.gdc1121823c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba4ZoBm3jC308kradyeYcXKMMux4uTSgs4cWkby5Th%2Bbw%40mail.gmail.com.
