Return-Path: <kasan-dev+bncBCF5XGNWYQBRBHX72CHQMGQED3NPLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AFBCB4A00A6
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 20:10:24 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id o187-20020a625ac4000000b004c8fc6b9707sf4086040pfb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 11:10:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643397022; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z3xf9NLuwMKl5xYJPB4bwwoH9oSt2OnhAuAckrDfz+mY132NQAPPQPUVEtfe/ftzLq
         jv5JQgtdwitkQixXKzyW8MEK48p/KDmjc0H3pMAaMsF3jMTLmQgILdx+JCOMV7U6ejUP
         DFroVJMz6DvHawJfWx7H7sI6o/cPnKZsYPNAuYZY6crBJjM+OQH1nT8M5mi5N5U/UI0B
         Gr985KMUv3phpCM3oXEu1VNGMya1MHJ3RR2gIr3OfsHQGQZuvJ4uKN0dDBufnzARmDvt
         brKyaLeDA7LEElNDAuqRMQwG2UKiJLdxL3m31px7nE5+u0Z8pRnU9SdKb2WlmDdHsT4v
         pVPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6HQIp2J4kXytO1YKqxmg3ybeFLOa2q3Is2GMOyyFIZE=;
        b=I5j8FFQl8azFuDflDGbHVTAB6JddBZ63cdtYulYW5AZa2T0Wd0QgC737YYK+5sd2aw
         Vl6CpOMyrnGSkWDQOVsB1X2iFnSrefbgKipjJ0I1aC0ZPHCWB3U8eoOEkWabHREEfsYf
         mu1Awf6DLkQ8hVTcRAa2R5TVYolBGUDa1TqS8oukakYUCeKY/Ft6RaTeGXv+mKYR6qK1
         Pd8YB+QPEOugL2GtS5bF8TzCuBPjAkFs38FtpVZ8TgEZCXiiM+Oy/rWEIUr0lwDNBGul
         D5vMczflYMbAETFcQCd51Zi6/7G+9kQfQlDznkbwIw8+VC1fSQzV4FqTzR5m1BDfIHiv
         93MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eCZT8ZHO;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6HQIp2J4kXytO1YKqxmg3ybeFLOa2q3Is2GMOyyFIZE=;
        b=p/d5PEBt7v3ADoHVm84fVLNswQPxiibCKIipSzGFpV2xyz8twIDByD5vMSaXnkEWpU
         Q0EVlUOmPscTS3s099yPepzyu7IqaPk8m+OJnAkJNDu7svYuv35lGBT9CJCD8zOfRhx3
         pwx75cZHadsh0/GitUKsyMNj4aU+M8Pnn2DVLO3cJEM+EM6Fd0eYK+kFlpc2YvP+Vv2s
         4MFTUgOB9aLU1gnvMuj/h/yb4Tvh67cqWtYW2tGQmUBMoFmudZYomTitUS5s2iE4dGoU
         l5Xhrs+qNGEo7sxhK3iw0qMg68+kXRB6fI8jH+2eW/gA4xkYijfxGh4hT9sgiR8axt+F
         Vz9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6HQIp2J4kXytO1YKqxmg3ybeFLOa2q3Is2GMOyyFIZE=;
        b=j0DGd5w/gCleqqvqy8ghrWViZfIA5XPG5im90csDEcZbXGne7umFpoo67YSSlGGm37
         kLV+WZ/pnH2UqB7KZzI3FlvovUJ8NlFBB9TlGyP4PQPK3urouReKtUyjdErJYRfw8NuP
         0hrVGtAfeMPZNK9nnJuLgJ1vlekxTdrEx4n88+upyW+T8MBJZrvjLlFuPDpDmu3JLo5q
         +tNLD79AX8h/jmg/UcdScyr3j45OPenOJ80qsY4RtKSbh7fI/iCF462tJjNocyjNLYXm
         MB7STaxRHNXfp0kqn48NHnMOs3LIes9oPVBYtJG5/Qd2sRL0Vz2Q746QgrHdSMvnjaH3
         wghQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326ZuXXIMCNEJlYISRiglL6x2o7m74i8zTOhqCVXi1iN3+ajG9r
	5OX/99pTr+XWzGyOLi8i57w=
X-Google-Smtp-Source: ABdhPJw9+BKGB6h1IzudPSVPi7IkzbOZXItJ4oZO/iw1I0nBk6fRNmIsvHxPFSg1ECQYxT+m+2V0Zg==
X-Received: by 2002:a17:90a:2c0a:: with SMTP id m10mr21084560pjd.183.1643397022554;
        Fri, 28 Jan 2022 11:10:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls3235172pgu.2.gmail; Fri, 28 Jan
 2022 11:10:22 -0800 (PST)
X-Received: by 2002:a63:58d:: with SMTP id 135mr7631342pgf.188.1643397022005;
        Fri, 28 Jan 2022 11:10:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643397022; cv=none;
        d=google.com; s=arc-20160816;
        b=fvW/2wazlHc/wflGuhpG36wK6cG66VpH4+NOPtMvdmXWiZo3J82TtRIRTge/tWdVbi
         qWYy6BkncPxcv1TPFNXEqf4p6rX0keLn2YKk7JkWFuOH7IR3PGGlw7plHMRQKwTXBxio
         f1mhDgobo3IaJLpT73ljOoDIP3X2VKq3c5gqbxJy4P9e62Yzgy4T045l1kPr0W+MBu86
         +AptURsL+B88RgG97F3uRZrhNqSm5+QgVYhjQsojIjRl6vHrVxz5fdvjS7I5XUvbfi6y
         pgjn0CH11DkYhooomcqidaiAFOcyoh3vwgQ3SnpQH6i7Z3S+uGN38X57hu4iEa0mLdJr
         ietA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qBrhGKhqGDo3ZZGcfTOvBOKxFA+ZreyYbNcf2efMXZM=;
        b=sjuoAdLf6juZjIuFokpkYHrxI6JCs7OI7Pvli6xQvjyuf+ADmAZNbrTcF1oMerfvZ/
         crLhi+1aavp4BNC8rPqLcvm07hAwD/gx6lw+FyutBHG0f7jfLawMpUryvL0DVc08dp3W
         Wb9xlUSNqqfhprqsfRHMhyIr4deNF+7mQR480hrVwmVX7IgoaYFnOPc1wtUKCBq4l4i2
         8/X+kIeokcI/RSVWiAsmz1eNwqeMaB4XoFDZVYrRGz5uG7QXcVKJDIGCVtmPV0dJCgfU
         dExGK/mPIF54EMV7qg8Ju6ezSdyNZa5bJXkHqpuIipaVp9/U5d9ddDQqgqMh5HBrsWgg
         furA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eCZT8ZHO;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id g15si605846pfc.3.2022.01.28.11.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 11:10:21 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id nn16-20020a17090b38d000b001b56b2bce31so7215122pjb.3
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 11:10:21 -0800 (PST)
X-Received: by 2002:a17:90a:5890:: with SMTP id j16mr11399493pji.185.1643397021641;
        Fri, 28 Jan 2022 11:10:21 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d2sm3142742pju.2.2022.01.28.11.10.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jan 2022 11:10:21 -0800 (PST)
Date: Fri, 28 Jan 2022 11:10:20 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] stack: Constrain stack offset randomization with
 Clang builds
Message-ID: <202201281058.83EC9565@keescook>
References: <20220128114446.740575-1-elver@google.com>
 <20220128114446.740575-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220128114446.740575-2-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eCZT8ZHO;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

This makes it _unavailable_ for folks with Clang < 14, which seems
too strong, especially since it's run-time off by default. I'd prefer
dropping this hunk and adding some language to the _DEFAULT help noting
the specific performance impact on Clang < 14.

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

Can you include the note that GCC doesn't initialize its alloca()?

Otherwise, yeah, looks good to me.

-Kees

>   */
> -void *__builtin_alloca(size_t size);
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

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201281058.83EC9565%40keescook.
