Return-Path: <kasan-dev+bncBD4NDKWHQYDRBPFZ377QKGQEGDLRLQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 21D4D2EEC53
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 05:17:02 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id u8sf7324615qvm.5
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 20:17:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610079420; cv=pass;
        d=google.com; s=arc-20160816;
        b=BFc0Yg4UvDc4Mojekc2VUivN4NoumafMX/G0l+k2FAQ+l/wVMCXYFcAGFpazJcJbP/
         xFVCw7H12J4mTmSqOyq3XwBUT01tNL7Y0VMYX4MtRBFersbzMth3KF3sMe0OZ7bbccT3
         JZGfh4/m+hsBUzohDxYxVOaOdz37Trpqj/RpQGF64aipg6Mzhk4hfq0edkc5eKMNShMk
         y8EN9/1q3/WIWGh9KsgoO8oLZabjwNS/7kDpswJqiV6Cj9fvUnU2HolU550HK5E1HrKl
         nx828h+euuMAjGCkz3SRxHSUNrkZkFiu01jpR0ePncosJ5yEhR3Hus60L4bsQHQE7lyi
         P+5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=vtjzz2p80eNRyE6vLMyl5uLMnVzVrc8WdgyKA5bQBoc=;
        b=GA3Xf3UwNr9XD4VoAwPbm4UHqaPsK88K/QlvJ1ftmNe8oGn03IrCO/ZRUnmYNE5Zu7
         Eae7Wi+oIdCozwf4UZx+x59W/1LVREZu/9rT0+w0c+6RqMdYYkiq36IUYL6vAyj9gyRS
         nLDJyNz4SlGs4ln+hZm0vLPZRCYQLsQ7ON1dfvPGQf5GruK2RWdKSS3ezJ0aTyTbpqt5
         CsNvAPrIL8uv7TkqlU4TG2unznYDCXtFIR/QZVMbugxVx+Cgn7lJKztJzf7P7lqYprJg
         Q8t4sPfg5uBDTGiu21BCbu4XP2lRn90hGDscZVK1DUXt/PeU4J1tSYJ9YBzBpsYtMkWS
         Fvkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EC1OMQpp;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vtjzz2p80eNRyE6vLMyl5uLMnVzVrc8WdgyKA5bQBoc=;
        b=miVcdMdPWhr3EQ+pz6vXRBVVSjDgMxd2HCwGnYcnEvMejhpWNRGzK+1jlM/9YaMU1H
         sUysjHwQZ6cejpqEBPOdzcwzRjxTEYsmrvrXq92yAfqDCShi5aHmA25KI8GmuHaQsty3
         LfQaGlEIpAALH0bT9jldRs/PNp4Za+kNvJwLWyXaorQB58uy2IbTznlptzmV7501B/t0
         YTtE2uWqDXJmc6w3zaFox+Q32nmfsYgO/Z1pD3aAy/4/EBV6/oL7VZ4MBNQDqSPkh6OC
         VpcRJFh8xNOZ2hTTVRrNwMOAy49zEcrAfKNw4Ov8zUgz4ORxHE+s7phJOaje/7oXd51k
         J8bg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vtjzz2p80eNRyE6vLMyl5uLMnVzVrc8WdgyKA5bQBoc=;
        b=ecSDbqW7t1QYqPANHBbsBO99fbJdI+fSfH5srZZMkPV6grJ4DIh8WIG18/pbJCarVC
         C5O7/vNDZcQL6tERQVzY4jBcn9/rK2UZQfjd8X2unKHHuJS9xmK1vz5vPKmzlF38HvFt
         vkG2kElsGV+jSr+vIAsofSez2ymlA6cbbFIsFCRyJmZwzOM0dIcJLYJbDwvA9LkQpw8G
         W/z/ZEeuL9L1GDcrElrACAYkzWIb+AU5adw/HNNmlCzTGhWR1G++dkqY7Z7It7TBo7lQ
         dGgEurkhJm4XqxqHtsSFlNyJe0qms/PBtNazvKvLxfO8is2Pt6JazjWDrv1Be37QSD9m
         tWSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vtjzz2p80eNRyE6vLMyl5uLMnVzVrc8WdgyKA5bQBoc=;
        b=hEaGRrxQz3KjsO/F3aNpjMbN9iuTOE9e91gzXxRGRlM7JUSpdgsf7X7EICy5athVaE
         57jxxxIpmPu7SXWFuknedXG8NToxXxos97GQeIhn0CTEQqNNE1KE9bxHewRDbrGaPkuq
         PC19ycMUWiRuUK37xkXgGBvPFG5uLXMWhwllaORjU39NE68Ciq0/wBNkX94b5xwj5ZiW
         lTxmNVtuV8iApwFBYuAWw2XTwuKfJ+gmJr1J8YsjtyRRNZyQhkCMbMDo6cj2N4nEY7IF
         qCoOIDmVBNwwXcKTLWGKEP8NAuHAKpppQ4Ys90l+RS0hzmwBpavm8/X2TG3mjuqyFdwA
         69tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hHJlAtlUWNl6RXMuDB2+7RKi/0VO8OySXd8Sh4aGJd/s4x2OD
	i3gk/7qADPCsIsJBXNIkL9I=
X-Google-Smtp-Source: ABdhPJwzZsnyZKLAaKl3INSdqA7OclCiuKcNyKqqBzvz7IKOJjz0AsFdU8wWGvM+CRakZkd96ymFKA==
X-Received: by 2002:a0c:8203:: with SMTP id h3mr1980691qva.0.1610079420629;
        Thu, 07 Jan 2021 20:17:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea19:: with SMTP id f25ls4982816qkg.7.gmail; Thu, 07 Jan
 2021 20:17:00 -0800 (PST)
X-Received: by 2002:ae9:e308:: with SMTP id v8mr2187787qkf.339.1610079420095;
        Thu, 07 Jan 2021 20:17:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610079420; cv=none;
        d=google.com; s=arc-20160816;
        b=kfMozX1Sa/sAxSUklfkFyRLO08eDQFJczQQlOJiV7XkbiE+Htjfbqc0CVXNGlzaAm2
         SD2zhRBNHFZ9MHyAbmGFGyApUImklLgVEfoUw1xaNKi23meGpRWn+xbcGfQMEpo6wxDa
         38AonlrffWu2HyyxmhkeCZzS+Xu1yXI7nHsVNYICrSrUaQ/CyKGXtpz38pxYkmE1DWlW
         lnaNaW1/T6SlE6yRJZpeAcT9ftfZo1W+BhePOP2a+DqbE6Y7R6xi+noD+zDL52bUrOoQ
         MCuDkAt7NeJOc5GO0AmJkdTHQ+gsyvHZa1HNWjvzeSeboJm4dOtiGg/U5FTj6c8F+QMK
         MuOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zx0d6MSUcYWK+im6j4aQFprWATgh0hiLgWJYR9X2G+I=;
        b=sbOgVyFCPs7JaCvE+fL1HE0EoAtGlZTku770WLsVw62Fov9ek0TNYmzsaVa7k4iJca
         9H4JczgaLEBhF19vfIyyfEFYv+lK4UPSbnAo68YxBVM20lbhM/+fhBriYmsAlimVSlxA
         fR1xT9faNPUXd9XsZ2hhjN5uQaXKQ9+O1CwNF9aRJcmXLUanvhCRDwpw+5zbANJE1wrK
         1c3Ob+0/vgOBOk5R9jl2EFCzwRjD2m3aAEuExhlNoJ+eMRK/10L8qBxtIs7pTBo4KuVz
         a6Zzq27floArqkwqYSEhtc8YCCX7pVMBgnVIEk2Nn6KyC4BrLwC15a4GWO1YXsucmaEa
         uP1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EC1OMQpp;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id z94si1264585qtc.0.2021.01.07.20.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Jan 2021 20:17:00 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id d9so8523336iob.6
        for <kasan-dev@googlegroups.com>; Thu, 07 Jan 2021 20:17:00 -0800 (PST)
X-Received: by 2002:a05:6638:2243:: with SMTP id m3mr1688386jas.115.1610079419408;
        Thu, 07 Jan 2021 20:16:59 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id l6sm6476419ili.78.2021.01.07.20.16.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Jan 2021 20:16:58 -0800 (PST)
Date: Thu, 7 Jan 2021 21:16:56 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v3] kasan: remove redundant config option
Message-ID: <20210108041656.GA2479132@ubuntu-m3-large-x86>
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EC1OMQpp;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jan 08, 2021 at 12:09:40PM +0800, Walter Wu wrote:
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

Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>

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
>  	 */
>  	bl	cpu_do_resume
>  
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  	mov	x0, sp
>  	bl	kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index 5d3a0b8fd379..c7f412f4e07d 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>  	movq	pt_regs_r14(%rax), %r14
>  	movq	pt_regs_r15(%rax), %r15
>  
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  	/*
>  	 * The suspend path may have poisoned some areas deeper in the stack,
>  	 * which we now need to unpoison.
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
>  	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>  	depends on KASAN_GENERIC || KASAN_SW_TAGS
> +	default y if CC_IS_GCC
>  	help
>  	  The LLVM stack address sanitizer has a know problem that
>  	  causes excessive stack usage in a lot of functions, see
> @@ -154,11 +155,6 @@ config KASAN_STACK_ENABLE
>  	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
>  	  to use and enabled by default.
>  
> -config KASAN_STACK
> -	int
> -	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> -	default 0
> -
>  config KASAN_SW_TAGS_IDENTIFY
>  	bool "Enable memory corruption identification"
>  	depends on KASAN_SW_TAGS
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 38ba2aecd8f4..bf8b073eed62 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
>  	unpoison_range(address, size);
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
>  	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
>  }
>  
> -#if CONFIG_KASAN_STACK
> +#ifdef CONFIG_KASAN_STACK
>  static bool __must_check tokenize_frame_descr(const char **frame_descr,
>  					      char *token, size_t max_tok_len,
>  					      unsigned long *value)
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 1e000cc2e7b4..abf231d209b1 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -2,6 +2,12 @@
>  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
>  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
>  
> +ifdef CONFIG_KASAN_STACK
> +	stack_enable := 1
> +else
> +	stack_enable := 0
> +endif
> +
>  ifdef CONFIG_KASAN_GENERIC
>  
>  ifdef CONFIG_KASAN_INLINE
> @@ -27,7 +33,7 @@ else
>  	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
>  	 $(call cc-param,asan-globals=1) \
>  	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> -	 $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> +	 $(call cc-param,asan-stack=$(stack_enable)) \
>  	 $(call cc-param,asan-instrument-allocas=1)
>  endif
>  
> @@ -42,7 +48,7 @@ else
>  endif
>  
>  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> -		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> +		-mllvm -hwasan-instrument-stack=$(stack_enable) \
>  		-mllvm -hwasan-use-short-granules=0 \
>  		$(instrumentation_flags)
>  
> -- 
> 2.18.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210108041656.GA2479132%40ubuntu-m3-large-x86.
