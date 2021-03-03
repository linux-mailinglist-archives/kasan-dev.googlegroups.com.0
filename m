Return-Path: <kasan-dev+bncBDGPTM5BQUDRBB7P7WAQMGQEN5UWWVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DAEB32B797
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 12:48:25 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id b20sf4412713pjh.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 03:48:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614772103; cv=pass;
        d=google.com; s=arc-20160816;
        b=amnk81BoambbHeU+xQTyjuRM65mTEWkSEOFNESuLDl8kHsyAK4WvRsB84uGXc6ATJ7
         V1pBuMYA1HUefGdVtXs0yGVPhc7kqjQuskzw6rBuczArjepSuAhPhXnmY13BuuaFEf21
         lUC/Kcx5MzC1xitvwmFz4u7GNpXjBbBH/hqL2u/gzvkF7KGh5/gkUDKy4Ua2CzK1pcKu
         oqGt0XAk3RHWdDPH+BOdkXAo1cTRBX6tN/LQ3e6PFI5RrfXSlXeaq6WTqzZVFzuM1VxU
         DbCLbBlCrP+oRqK0fVg3zePmi14lXFaSBsq9yr6llFG/0sw6ULnZM6KSciYQY2CSoxtp
         1MMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=lDIgz0CAoZBReoQNoUdFxgECWw3IDle2JCIrw5OupkM=;
        b=ru+HVjpcyzxoQZUmoC3cKd1FuwhxVThOz8mB1TVOXSp5BtQZqEmO2LHR75ylPaQsYj
         uJwWB5uxXihCHJELaB9ovt+gNbTz0FDAzQGz3PPFGaUIuxrwD5j2pnA2zRw8w1suo3TF
         zy7MgX0+TkW3vuo6vvo1GvMtUYHQFf/sedgZ2Oh3VFnhbr/RADZzaRMZ+TBgIMTF6NjX
         FaTdXHkoA28pMUNoeLtTz6a7D4KPjozSXXCpBeTyuNjJoemz/t0Kx87oOr7ij3nZg7fF
         S+gYzknSlQRyTnNtwt7QE+o+nMj6hFezEFrB41vHVA4LZJWEiZOAicAUw2OnZT+Nz/dP
         kiyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BbGfO3XY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lDIgz0CAoZBReoQNoUdFxgECWw3IDle2JCIrw5OupkM=;
        b=H75YSNGsba5mJgJdDVxWD5bKOKDtzXDmtXthGRspLFcVRqRl95inrnnCHUeQ+BMWIQ
         HxJJfzkt/p15Utez3sMozFkSmkiR35y8G7g0QEhpUHWOeHMksBRV0DjBCmPvunq7KlLC
         dl77QR91cQd+e3+NV6pzyfqLhMN1xo81nj/vX+JuqeoNr9QGlfU0gTohf1+45JFsJ3c4
         VdQAQ/Ms3iVjPOiAU+w9freg+cdgq6jPD00RbgoxFYE8fNQN+7IycM5gQ3OF3dIUMjyV
         ydftyVrgdkXg6o23ySDtFGqjMS9IKFBi0zQQOcqz1RO25LRQ3CiKKWJgVvetjTvkvuU1
         i8mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lDIgz0CAoZBReoQNoUdFxgECWw3IDle2JCIrw5OupkM=;
        b=pFRsMT7GYu7Ncjf03w4MY+8v+kUL9aczk15oQyBxu7BEtMCYiIo+WUqFdT4a3f3gBq
         Uozol/i7C0hYkiHCWmcy8yH4EyNanLD0lBja6vQRxUaXxXW4LxAXNfuuxPSzwYdb8YE9
         lJOdhjl2poP6wcYZCs9J1meHaBUqClBmovWanllToBBVFW+1RQ7TP4ZrpIyKvs5bCkzQ
         3OPKFAjIiRc8lOg46Rhsm71V1AI8gFB5Q9U0NsHb6YUfRDwP34INFcH7/NAZN4Dj+2ZZ
         8ziqjCkIYQXjfUjAUX0Nw0DW7tb3iJZVYXwDZpYnrjx5fvkkJlb3kwWx8DBIqHU83c80
         2vtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533En7KS8HE+PYsit9aT3fSUEa9V9yiVO4RHShihncHlmrT8zagU
	hiMmj4kPcPvLD9KYxrZ5Fsw=
X-Google-Smtp-Source: ABdhPJx7LTEECaRPCikTy/9knwMP+9NJtWVl9OxB6rbH04/JnYU4K4ECI1cXE5OxVyq+PNEzFXFsRA==
X-Received: by 2002:a63:150c:: with SMTP id v12mr22786404pgl.39.1614772103383;
        Wed, 03 Mar 2021 03:48:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e281:: with SMTP id d1ls1224973pjz.0.gmail; Wed, 03
 Mar 2021 03:48:22 -0800 (PST)
X-Received: by 2002:a17:90b:1c03:: with SMTP id oc3mr9557636pjb.124.1614772102894;
        Wed, 03 Mar 2021 03:48:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614772102; cv=none;
        d=google.com; s=arc-20160816;
        b=z21t2wxYciP0tmIh2IVXvr/OI5U5WJMr0PZNwBas8VF9fL3Xf0yaytJqkJYXtsdUqz
         7ewKKAPr23Ghgx4HqF/XTyVkE5gQ6x8Ul759lHKgDOAi3xDxPFe+vr1sbAEO7u0PhOak
         CgvSG5x0D/BLPueqNmc9VdgxErjj/+bO3wfrLZJTOMj2ldCyQBC4Qb+doLX2b7QN73ol
         1GmEZu/Nug1KFQbhBTv+UrMDkliL4FFdSi3Kg7Qkx4XBCElT4CHsF/bkcVDZACKqBK3O
         CKMOwK1QJyDJDFNtXTjB72kantNAhL+ISATWPHN1Tk7y9zcelgkftnjWGM7mYRGeZ2mP
         T9aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=AWzLvF5Mphj2LxOTWlI1vkLJVO/ce4uOqjBNnFlwD1A=;
        b=Cm4zlryKnrqoCbfRX15lsN2nAMzS8LTGLGOOPbXohVM7Mbyw4VtXI0K0QGZDOjyj7/
         HshknpOxAtF5Xlo1a1FNemhjEwUR0wPdDfAKnwxXU8HPWT4cWNIn1qy9DfRCJd9nEW/X
         w2ko3oeOP+3uX6brSibw/FnMrO79igWaABvWL4C48Kh6FR0bLOjRb/Z3OQvbrNUFxro2
         2GT/H5JZcIrHz+OtQBK/3vGB9SdhINtyeQiH/CDkREV44qpP4uqViT0W2Hm3hXAIAm5t
         zW/Q4B4lce9btHSE5bRZSlQm2PYskwbDryRwfv6LwYme6UKOpyAzodHjUaTy/TNjufNR
         +UMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BbGfO3XY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id r7si640024pjp.3.2021.03.03.03.48.22
        for <kasan-dev@googlegroups.com>;
        Wed, 03 Mar 2021 03:48:22 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: bf94fc6dbc884a68af9043a4831a3edf-20210303
X-UUID: bf94fc6dbc884a68af9043a4831a3edf-20210303
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 304542194; Wed, 03 Mar 2021 19:48:20 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 3 Mar 2021 19:48:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 3 Mar 2021 19:48:19 +0800
Message-ID: <1614772099.26785.3.camel@mtksdccf07>
Subject: Re: [PATCH v4] kasan: remove redundant config option
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>, "Arnd
 Bergmann" <arnd@arndb.de>, Andrey Konovalov <andreyknvl@google.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>
Date: Wed, 3 Mar 2021 19:48:19 +0800
In-Reply-To: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BbGfO3XY;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2021-02-26 at 09:25 +0800, Walter Wu wrote:
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
Hi Andrew,

Could you pick this v4 patch up into mm?
Thanks.

Walter

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
>  	 */
>  	bl	cpu_do_resume
>  
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  	mov	x0, sp
>  	bl	kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index 56b6865afb2a..d5d8a352eafa 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -115,7 +115,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>  	movq	pt_regs_r14(%rax), %r14
>  	movq	pt_regs_r15(%rax), %r15
>  
> -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
>  	/*
>  	 * The suspend path may have poisoned some areas deeper in the stack,
>  	 * which we now need to unpoison.
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
> index b5e08d4cefec..7b53291dafa1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
>  	kasan_unpoison(address, size);
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
> diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
> index 269967c4fc1b..a56c36470cb1 100644
> --- a/security/Kconfig.hardening
> +++ b/security/Kconfig.hardening
> @@ -64,7 +64,7 @@ choice
>  	config GCC_PLUGIN_STRUCTLEAK_BYREF
>  		bool "zero-init structs passed by reference (strong)"
>  		depends on GCC_PLUGINS
> -		depends on !(KASAN && KASAN_STACK=1)
> +		depends on !(KASAN && KASAN_STACK)
>  		select GCC_PLUGIN_STRUCTLEAK
>  		help
>  		  Zero-initialize any structures on the stack that may
> @@ -82,7 +82,7 @@ choice
>  	config GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
>  		bool "zero-init anything passed by reference (very strong)"
>  		depends on GCC_PLUGINS
> -		depends on !(KASAN && KASAN_STACK=1)
> +		depends on !(KASAN && KASAN_STACK)
>  		select GCC_PLUGIN_STRUCTLEAK
>  		help
>  		  Zero-initialize any stack variables that may be passed

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1614772099.26785.3.camel%40mtksdccf07.
