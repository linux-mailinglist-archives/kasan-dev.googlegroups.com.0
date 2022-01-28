Return-Path: <kasan-dev+bncBD4NDKWHQYDRBKXY2CHQMGQED2SOCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F59F4A0084
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 19:55:39 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id s190-20020a1ca9c7000000b00347c6c39d9asf3337023wme.5
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 10:55:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643396138; cv=pass;
        d=google.com; s=arc-20160816;
        b=CcFHfWCtXZL3iVBNAqgBiDI2dUkEPBs7sbCZonCZKXJNC6JgbQMg6Q9Cfjt9MwQFZl
         GRmR6AHVpR2VKT+Ly0g2Tz/FoijuyeZb72FXm6NhL8W2Hm+XmwW3B+fmGCWSQAuPcKAG
         5RFzaOxuR71kUIeGxGb8oMWvtviriUadp5BampyDMI/RXfTVjONuZJpIXcKoFZ0LyN3E
         zUNsDDB/JZlUb0dM7zooaNHhEdQUGyCWw6p7BmvMTyKfAYF+KaoSx7YQ5I6dwm4ETT5W
         Q7P6TfyfRzHMiGJSBS4fh/6Enhj74f+wcuB26DF7ywpoMrNfsNDQkJzw8Cset3Wzg7WE
         CBvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JXAwmGK/61jgKN+yCFYnyao6BJJj64Xvk4IHcZwXdEI=;
        b=sljVKgxrT1SeDctQelULlqkfuRGo+G5ltDFKII4eg49+9jYvJMLzJ+K8so3O+gTqgb
         xO5/eDUYr/0KYTz2ZpfmkJEv/J8RoGkr8ptDapbDJIXDeFF7k4e2r1HwT8fMdBvpRFJB
         iwkitosnhBVKHYlCNblm+FUbnAcJWANBEz0rbE04kBbh9S/aOsRJmJDK8EptzuNG50uD
         AYBnvUASKmZZV0o6iuihBLHWouLCRXDeTRHaVFkLqgFHzI0XHW6pxdwqd6LlRRM+G76W
         0c1dO/BHWIHc53vyjxKWj0MmP4OpIAW0t7Y8I7FLBbdYe0Pxgfv4UWCeo0qG9Rtu0ka1
         lsjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nn+lKmbj;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JXAwmGK/61jgKN+yCFYnyao6BJJj64Xvk4IHcZwXdEI=;
        b=FAY33kNyDKNKawKoCF20M56dqBxPxDj9rzqauXcvvExx3c5XlvQGPOxz2y0Ysryp5S
         s1Xt4atxl2Q40GYPr3Q16rOj4frCEPXfrZgxOmApHQ7/DIDg5FM6tSeBFTK0ii3cyuSg
         PNIQRY+CbTzvMoNTWkfB/DvD78GpqDM6HPtkUQdDlKMm/AoewQfykt3QcLiNj2PAt2hJ
         z8dyelsGeim1yePGDN+4UI4Er/jg9f1zPLsM9ih/zN5YA3TptRY6YALftOg3IlmpiIz0
         Hgc6+C7YcPmfy1iPI1sffF/MLN4kH9fMkmXzdWdBFnCqUG41R9YbHMRcgfAGA2+y8xi7
         F6SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JXAwmGK/61jgKN+yCFYnyao6BJJj64Xvk4IHcZwXdEI=;
        b=VRYfd/PgA/ylL07pqlO7gzYoCeEO3FyUX+gv4Ge0AAQpHOaKI7M3BjtUgGRl1V7v/C
         Jzr729ixhtQrJC/lcixhvGLfWMnOBqxag4bqTZTkTxMu6mNtyh9ipRR3Xd6IFGRNAjNy
         AwYBxFnWfK/7iiw60WXdi51GMUOsFc3Qd06k0pGZTTzjOoNgGlg1kTsybwF8vUxHml3t
         wQ9alHU0tTOM6cdNv42ZKmpQ89DL5KAPygMaPv3N3UnkoY1aDl9jOpsHPAYTmryufN4H
         iVMR45EAwX1XnaWxb5KVVw223UkeqjyyHkZlEz27ybTchKkl/3pM3rNi3RUzu3hk16cP
         LD+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tTxB32AZcbAPEU9JmMnGPkBCbjYk9TQgiIT2YvRr/y1XDuUiO
	Mntmrg67HnpgemKm8tuYf1w=
X-Google-Smtp-Source: ABdhPJw941D7A6o5d/9Z9oE1b1IX0/3W4GnmiG3HAIFhlXF1scafNSqX4IrsWNrluHD+Epha11OTMA==
X-Received: by 2002:a5d:64c1:: with SMTP id f1mr6006279wri.5.1643396138642;
        Fri, 28 Jan 2022 10:55:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a1c5:: with SMTP id k188ls5055252wme.1.gmail; Fri, 28
 Jan 2022 10:55:37 -0800 (PST)
X-Received: by 2002:a05:600c:2d52:: with SMTP id a18mr9955566wmg.69.1643396137814;
        Fri, 28 Jan 2022 10:55:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643396137; cv=none;
        d=google.com; s=arc-20160816;
        b=DC6XSRAIq4wmCIcp4LP/Rw8tafXVTXRIG6fSOPrC1Kr9XXruknbQ6+P35KeK/GhVE6
         Y3pPOX1HyJx4nHrCVSjXn0U4s65Hf/lX0VCpFvZ04ZZDC+cwDYBhBAgTIqZeyyeM1Nry
         mnNlR8u1Rgi6rnNca9hPqdJeQ8xep+6A6lhVB4Bk38kFHJCBt+ascycaupJoruG0RIiv
         zUdVumj59I9oLJWD3bRaKOiWxVRMLNNcjmkRzU6u0EHahOKvzjS0DyeC/7x3humvjb4G
         5GL0oK3zW9rVhx8gSKKUvN/xTC+69SlGuiZpNKVBQSmKXHGuE1YraSTp82EXyZKqFKoA
         srhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OaTA37KIbmHKMpPx1e9xIm9b7MSTfLWaiU3weM/ROY8=;
        b=DjwIIfCN/YyKfA4Iq7+TWGApemy2HYw4tnnSqz1zsAC2N64q0QS5CZLx63TGEuxGti
         kDig4MFe+vl6dlXNRLAcq5/bETASTuraim1TP6NfizEN6T+/dngxPACzhlEws2qpBVHl
         UwC5Tp6ktoiRaeXpMWERaYYQ799cgxgrBVv14mYFUuVHAZgpOlXQGYlZPDc8BJG3xfZr
         qYYYHJHYwU0FZwn5YWpXR2fuodLp+zJCg+Ek/UVFgyZLvG0ydXVVJ9XOxYPWyXUW54Mu
         tBZx4gj7+Bard1UyU44iA2M7n7qzYma/xDqkWisQqXrDc8QO0wOSZfiCMIC9uOiY7wkW
         cnNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nn+lKmbj;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id e5si1383849wrj.8.2022.01.28.10.55.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jan 2022 10:55:37 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6C921B825E4;
	Fri, 28 Jan 2022 18:55:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1F4CDC340E7;
	Fri, 28 Jan 2022 18:55:33 +0000 (UTC)
Date: Fri, 28 Jan 2022 11:55:31 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] stack: Constrain stack offset randomization with
 Clang builds
Message-ID: <YfQ8IwCSzbtAhC3B@dev-arch.archlinux-ax161>
References: <20220128114446.740575-1-elver@google.com>
 <20220128114446.740575-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220128114446.740575-2-elver@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nn+lKmbj;       spf=pass
 (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Jan 28, 2022 at 12:44:46PM +0100, Marco Elver wrote:
> All supported versions of Clang perform auto-init of __builtin_alloca()
> when stack auto-init is on (CONFIG_INIT_STACK_ALL_{ZERO,PATTERN}).
> 
> add_random_kstack_offset() uses __builtin_alloca() to add a stack
> offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> enabled, add_random_kstack_offset() will auto-init that unused portion
> of the stack used to add an offset.
> 
> There are several problems with this:
> 
> 	1. These offsets can be as large as 1023 bytes. Performing
> 	   memset() on them isn't exactly cheap, and this is done on
> 	   every syscall entry.
> 
> 	2. Architectures adding add_random_kstack_offset() to syscall
> 	   entry implemented in C require them to be 'noinstr' (e.g. see
> 	   x86 and s390). The potential problem here is that a call to
> 	   memset may occur, which is not noinstr.
> 
> A x86_64 defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> 
>  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> 
> Clang 14 (unreleased) will introduce a way to skip alloca initialization
> via __builtin_alloca_uninitialized() (https://reviews.llvm.org/D115440).
> 
> Constrain RANDOMIZE_KSTACK_OFFSET to only be enabled if no stack
> auto-init is enabled, the compiler is GCC, or Clang is version 14+. Use
> __builtin_alloca_uninitialized() if the compiler provides it, as is done
> by Clang 14.
> 
> Link: https://lkml.kernel.org/r/YbHTKUjEejZCLyhX@elver.google.com
> Fixes: 39218ff4c625 ("stack: Optionally randomize kernel stack offset each syscall")
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

One comment below.

> ---
>  arch/Kconfig                     |  1 +
>  include/linux/randomize_kstack.h | 14 ++++++++++++--
>  2 files changed, 13 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 2cde48d9b77c..c5b50bfe31c1 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -1163,6 +1163,7 @@ config RANDOMIZE_KSTACK_OFFSET
>  	bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
>  	default y
>  	depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
> +	depends on INIT_STACK_NONE || !CC_IS_CLANG || CLANG_VERSION >= 140000
>  	help
>  	  The kernel stack offset can be randomized (after pt_regs) by
>  	  roughly 5 bits of entropy, frustrating memory corruption
> diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
> index 91f1b990a3c3..5c711d73ed10 100644
> --- a/include/linux/randomize_kstack.h
> +++ b/include/linux/randomize_kstack.h
> @@ -17,8 +17,18 @@ DECLARE_PER_CPU(u32, kstack_offset);
>   * alignment. Also, since this use is being explicitly masked to a max of
>   * 10 bits, stack-clash style attacks are unlikely. For more details see
>   * "VLAs" in Documentation/process/deprecated.rst
> + *
> + * The normal alloca() can be initialized with INIT_STACK_ALL. Initializing the
> + * unused area on each syscall entry is expensive, and generating an implicit
> + * call to memset() may also be problematic (such as in noinstr functions).
> + * Therefore, if the compiler provides it, use the "uninitialized" variant.
>   */
> -void *__builtin_alloca(size_t size);

Is it okay to remove the declaration? Why was it even added in the first
place (Kees)?

> +#if __has_builtin(__builtin_alloca_uninitialized)
> +#define __kstack_alloca __builtin_alloca_uninitialized
> +#else
> +#define __kstack_alloca __builtin_alloca
> +#endif
> +
>  /*
>   * Use, at most, 10 bits of entropy. We explicitly cap this to keep the
>   * "VLA" from being unbounded (see above). 10 bits leaves enough room for
> @@ -37,7 +47,7 @@ void *__builtin_alloca(size_t size);
>  	if (static_branch_maybe(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,	\
>  				&randomize_kstack_offset)) {		\
>  		u32 offset = raw_cpu_read(kstack_offset);		\
> -		u8 *ptr = __builtin_alloca(KSTACK_OFFSET_MAX(offset));	\
> +		u8 *ptr = __kstack_alloca(KSTACK_OFFSET_MAX(offset));	\
>  		/* Keep allocation even after "ptr" loses scope. */	\
>  		asm volatile("" :: "r"(ptr) : "memory");		\
>  	}								\
> -- 
> 2.35.0.rc0.227.g00780c9af4-goog
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YfQ8IwCSzbtAhC3B%40dev-arch.archlinux-ax161.
