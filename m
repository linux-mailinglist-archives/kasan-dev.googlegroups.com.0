Return-Path: <kasan-dev+bncBDV37XP3XYDRBV7GSWJAMGQESZBHW7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E259F4ED6BA
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:24:39 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d17-20020adfc3d1000000b00203e2ff73a6sf6296289wrg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 02:24:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648718679; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJshV5Z55Xjnds+pMSG7eJe53OQNn2Ai183tLU8qJ9txc84y4Bvy8BgCLufvM+T7WB
         sISp+BlyqHKA9TJGrZIwY/QMkTRaoRQWQjfR1BYnjqpLdsbm55EtuVigiNTI/7DGbPHN
         1xESXVHnkbGiPcl3QN5OAz/P/ZHbs2gBEUPPfc4Hy0oA36O8bmNYp15LMa1VbrMX3lBW
         Xxd0JlY/Gq3uPJBh7v8tp0cJToR7jhf+b6Yzt2UsaC8C9gaoAxuEECWOyew3HYSoSk07
         EOj5+lIk3VBUi25Ad1Pgkkoj6/uzB6M535y54LWIBquyB1HTw31vY4HqCVddJPEoep8R
         6k/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EyQXWnGu13J61X73s7YVnoAJiSl4ZgiMvlxBta5iFAs=;
        b=i8xw+Chy+NcE5QOUja+B5B55wZxEGvilrJHMnOgqExHd05JysmUhSxJHZcl9opqrIe
         FppAtEmvnq3CP24KuM/eitMKY76XGGnjYJVr/3Z54NfK/Qr5JjWQyFVyPqEtjXJ7OPKE
         v1LNXnBVDGEI/Djj+FI239ZbFEbpZA1XG8ngO/cxNxmIRmU3KZ6W8B9k2cnaKia5kEtu
         lU/EREvHG+I3th3wSR5mWR0Wpzi9yXy0G7+wiS4y/wNAYmbnNxS41Nm6MhS1mC5Eigue
         Sd0ioH7L846ZAOR2WyXv7uTw9jyaQK/MKMxmOcEhu5KzeeL/Uxi0ZDaV6cv9Ro+DpT34
         2K0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EyQXWnGu13J61X73s7YVnoAJiSl4ZgiMvlxBta5iFAs=;
        b=nvuT6ny/mJkqwXktUyqdeqdLvltLpFD50o91CLh4ri6xNfJ+TfKxEI1QOt+1tqXy1y
         N6zxP0mpwdkch6oHKLO05/dpDxwDjRaXovQ5QVpVTYOSZtadpBRAPTumzIuxHfJcux5F
         u28do8fA1kKRsdASzUnc49wVKPLfR74Nbe7FoOX1AsTtzuwNyh+QGGsv+UWGaZHhGPsB
         e+f+rL3YWYe65CJvp75vH/Z15KYUN5dPVWfXbtSQwGerrI1ikNgNLIIw8cD9fxfh3TQV
         wA59AtuKyoIbHLS0/s8dsoKuDuJk3YLtXOxGh8jFx7+/5h8C+QDkyzg56SZ2aqMYSHar
         W6eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EyQXWnGu13J61X73s7YVnoAJiSl4ZgiMvlxBta5iFAs=;
        b=Ilvu1F5qu0TDOZOsGQW8eW8plNFlCu2Tp+ger7Roj1+jqQRilCgQ5VQzfzzrEI9+Zm
         d6jTsGLZbhhSJAsi7fs2xOKD0aFEm9l2t8FC5Q74uti2V2gvqnvdXNGelvjSxY8Xy9Xg
         HSrrd2d48mRSSjCo7ZHgSArJaxbtjLZxlQCPTN60ilPSJloASJvEM1bF0C2LAaOxh4+s
         aFTvqJHaE+uSOTH2fHxK+lDWp05TE6CwdDuC5jBOBSVe1AMJjW84BWwpt80a3G0LgERR
         kEYp0qlKNUL2+UvrRm5rBIMWspdf51dnhWVbWe+XHlp4241RDVj9FOARAFNkJW9yq+Qz
         3knQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rB3U75N34aaAlRyei7uS1Q0yHUD/aeao/JmOJusC6CpcrA1K/
	GwJ+YGG13Hnq6vB4efRYp7Q=
X-Google-Smtp-Source: ABdhPJwqBO3K5Lb7ILhLCo2RhpGghFNg6P/Eczfbd2R7U3ewz0eFUBryc6mwC7tuYi5hU9hk5Ok2UA==
X-Received: by 2002:a05:600c:3b08:b0:38c:c8f1:16ca with SMTP id m8-20020a05600c3b0800b0038cc8f116camr3987001wms.192.1648718679540;
        Thu, 31 Mar 2022 02:24:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:15ce:b0:1f1:dc97:d9c4 with SMTP id
 y14-20020a05600015ce00b001f1dc97d9c4ls580578wry.3.gmail; Thu, 31 Mar 2022
 02:24:38 -0700 (PDT)
X-Received: by 2002:adf:f7c7:0:b0:205:abbb:a455 with SMTP id a7-20020adff7c7000000b00205abbba455mr3467907wrq.429.1648718678531;
        Thu, 31 Mar 2022 02:24:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648718678; cv=none;
        d=google.com; s=arc-20160816;
        b=QSQP+eHjtFU6iHq7VD+r6/zQmdn1rfr/RiQAEUhDOJb9F6Iv/wDYVuzH2PszG7J1XD
         Jw4LD0TY4vted7wzXsQ8yj4YBpRD1Scu4Tf1E2Tz9sWBNbCtcZ+mj3GM6540PUzMl9ut
         6bXuF0S7LlAKr0hibNcvgE+ik+YFR9tRxuv9FpoqxfbY9qoG2hwErze7Ir9voglx/401
         C1Ihc7Z9jh1AkUoHlNEwV8SGB7yCahyKXXJ0ZUonZksltEUhgEfJGoroR5cCmHYW7AlT
         kmORXpnWTRsDO5JjtHJQAVidVRd01yBhhuuR44B+w0wql43LwjiZft9ys0PxpVwFlcug
         AOKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=T7U0We7pYK0IOOdtOV6mbGk2ngHkrzqqC1EIyZeTNKM=;
        b=vEH6deXZIF4MxFI6Ps3Gu7FQiJBSb0ZGhLiuHyGyW1Z7AXHX9DdAKttUVnzkh1MnQU
         u7e0kf9htdYIEXFDDhIXn2CXXS7H0MVFtHRBVJEj3NzhzNowGwZeLQqwS/AwGm8hkI6s
         zxxFtd99oLCB1vuP877zHH4eFE5ldNa+o0G4aMYZmbfn1l8OVKP1ZDD7NhAXfqX1/wne
         zC/nzwwm7le0DsmZcdhsOpPeTNluspAuvnFHnoebD/NAdl6xOY3UjZvlR5eFoBwieQyf
         KsFg5V47jBmzGOBbXHGgAeJArDmDPYwVPG9plDxFAGN8rsmOfmbbcPb3gLowcfod5CGh
         MYzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d14-20020a5d644e000000b00205d2ebbae8si367319wrw.7.2022.03.31.02.24.38
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Mar 2022 02:24:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id ADE1223A;
	Thu, 31 Mar 2022 02:24:37 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D258A3F718;
	Thu, 31 Mar 2022 02:24:34 -0700 (PDT)
Date: Thu, 31 Mar 2022 10:24:29 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 2/4] arm64, scs: save scs_sp values per-cpu when
 switching stacks
Message-ID: <YkVzTbafttTHWETU@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Mar 23, 2022 at 04:32:53PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> When an interrupt happens, the current Shadow Call Stack (SCS) pointer
> is switched to a per-interrupt one stored in a per-CPU variable. The old
> pointer is then saved on the normal stack and restored when the interrupt
> is handled.
> 
> To collect the current stack trace based on SCS when the interrupt is
> being handled, we need to know the SCS pointers that belonged to the
> task and potentially other interrupts that were interrupted.
> 
> Instead of trying to retrieve the SCS pointers from the stack, change
> interrupt handlers (for hard IRQ, Normal and Critical SDEI) to save the
> previous SCS pointer in a per-CPU variable.

I'm *really* not keen on *always* poking this in the entry code for the
uncommon case of unwind. It complicates the entry code and means we're always
paying a cost for potentially no benefit. At a high-level, I don't think this
is the right approach.

For the regular unwinder, I want to rework things such that we can identify
exception boundaries and look into the regs (e.g. so that we can recover the
PC+LR+FP and avoid duplicating part of this in a frame record), and I'd much
prefer that we did the same here.

Thanks,
Mark.

> Note that interrupts stack. A task can be interrupted by a hard IRQ,
> which then can interrupted by a normal SDEI, etc. This is handled by
> using a separate per-CPU variable for each interrupt type.
> 
> Also reset the saved SCS pointer when exiting the interrupt. This allows
> checking whether we should include any interrupt frames when collecting
> the stack trace. While we could use in_hardirq(), there seems to be no
> easy way to check whether we are in an SDEI handler. Directly checking
> the per-CPU variables for being non-zero is more resilient.
> 
> Also expose both the the added saved SCS variables and the existing SCS
> base variables in arch/arm64/include/asm/scs.h so that the stack trace
> collection impementation can use them.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/include/asm/assembler.h | 12 ++++++++++++
>  arch/arm64/include/asm/scs.h       | 13 ++++++++++++-
>  arch/arm64/kernel/entry.S          | 28 ++++++++++++++++++++++++----
>  arch/arm64/kernel/irq.c            |  4 +---
>  arch/arm64/kernel/sdei.c           |  5 ++---
>  5 files changed, 51 insertions(+), 11 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
> index 8c5a61aeaf8e..ca018e981d13 100644
> --- a/arch/arm64/include/asm/assembler.h
> +++ b/arch/arm64/include/asm/assembler.h
> @@ -270,6 +270,18 @@ alternative_endif
>  	ldr	\dst, [\dst, \tmp]
>  	.endm
>  
> +	/*
> +	 * @src: Register whose value gets stored in sym
> +	 * @sym: The name of the per-cpu variable
> +	 * @tmp0: Scratch register
> +	 * @tmp1: Another scratch register
> +	 */
> +	.macro str_this_cpu src, sym, tmp0, tmp1
> +	adr_l	\tmp0, \sym
> +	get_this_cpu_offset \tmp1
> +	str	\src, [\tmp0, \tmp1]
> +	.endm
> +
>  /*
>   * vma_vm_mm - get mm pointer from vma pointer (vma->vm_mm)
>   */
> diff --git a/arch/arm64/include/asm/scs.h b/arch/arm64/include/asm/scs.h
> index 8297bccf0784..2bb2b32f787b 100644
> --- a/arch/arm64/include/asm/scs.h
> +++ b/arch/arm64/include/asm/scs.h
> @@ -24,6 +24,17 @@
>  	.endm
>  #endif /* CONFIG_SHADOW_CALL_STACK */
>  
> -#endif /* __ASSEMBLY __ */
> +#else /* __ASSEMBLY__ */
> +
> +#include <linux/percpu.h>
> +
> +DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
> +DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_saved_ptr);
> +DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
> +DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_saved_ptr);
> +DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
> +DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_saved_ptr);
> +
> +#endif /* __ASSEMBLY__ */
>  
>  #endif /* _ASM_SCS_H */
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index ede028dee81b..1c62fecda172 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -880,7 +880,8 @@ NOKPROBE(ret_from_fork)
>   */
>  SYM_FUNC_START(call_on_irq_stack)
>  #ifdef CONFIG_SHADOW_CALL_STACK
> -	stp	scs_sp, xzr, [sp, #-16]!
> +	/* Save the current SCS pointer and load the per-IRQ one. */
> +	str_this_cpu scs_sp, irq_shadow_call_stack_saved_ptr, x15, x17
>  	ldr_this_cpu scs_sp, irq_shadow_call_stack_ptr, x17
>  #endif
>  	/* Create a frame record to save our LR and SP (implicit in FP) */
> @@ -902,7 +903,9 @@ SYM_FUNC_START(call_on_irq_stack)
>  	mov	sp, x29
>  	ldp	x29, x30, [sp], #16
>  #ifdef CONFIG_SHADOW_CALL_STACK
> -	ldp	scs_sp, xzr, [sp], #16
> +	/* Restore saved SCS pointer and reset the saved value. */
> +	ldr_this_cpu scs_sp, irq_shadow_call_stack_saved_ptr, x17
> +	str_this_cpu xzr, irq_shadow_call_stack_saved_ptr, x15, x17
>  #endif
>  	ret
>  SYM_FUNC_END(call_on_irq_stack)
> @@ -1024,11 +1027,16 @@ SYM_CODE_START(__sdei_asm_handler)
>  #endif
>  
>  #ifdef CONFIG_SHADOW_CALL_STACK
> -	/* Use a separate shadow call stack for normal and critical events */
> +	/*
> +	 * Use a separate shadow call stack for normal and critical events.
> +	 * Save the current SCS pointer and load the per-SDEI one.
> +	 */
>  	cbnz	w4, 3f
> +	str_this_cpu src=scs_sp, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp0=x5, tmp1=x6
>  	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_normal_ptr, tmp=x6
>  	b	4f
> -3:	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_ptr, tmp=x6
> +3:	str_this_cpu src=scs_sp, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp0=x5, tmp1=x6
> +	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_ptr, tmp=x6
>  4:
>  #endif
>  
> @@ -1062,6 +1070,18 @@ SYM_CODE_START(__sdei_asm_handler)
>  	ldp	lr, x1, [x4, #SDEI_EVENT_INTREGS + S_LR]
>  	mov	sp, x1
>  
> +#ifdef CONFIG_SHADOW_CALL_STACK
> +	/* Restore saved SCS pointer and reset the saved value. */
> +	ldrb	w5, [x4, #SDEI_EVENT_PRIORITY]
> +	cbnz	w5, 5f
> +	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp=x6
> +	str_this_cpu src=xzr, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp0=x5, tmp1=x6
> +	b	6f
> +5:	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp=x6
> +	str_this_cpu src=xzr, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp0=x5, tmp1=x6
> +6:
> +#endif
> +
>  	mov	x1, x0			// address to complete_and_resume
>  	/* x0 = (x0 <= SDEI_EV_FAILED) ?
>  	 * EVENT_COMPLETE:EVENT_COMPLETE_AND_RESUME
> diff --git a/arch/arm64/kernel/irq.c b/arch/arm64/kernel/irq.c
> index bda49430c9ea..4199f900714a 100644
> --- a/arch/arm64/kernel/irq.c
> +++ b/arch/arm64/kernel/irq.c
> @@ -28,11 +28,9 @@ DEFINE_PER_CPU(struct nmi_ctx, nmi_contexts);
>  
>  DEFINE_PER_CPU(unsigned long *, irq_stack_ptr);
>  
> -
> -DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
> -
>  #ifdef CONFIG_SHADOW_CALL_STACK
>  DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
> +DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_saved_ptr);
>  #endif
>  
>  static void init_irq_scs(void)
> diff --git a/arch/arm64/kernel/sdei.c b/arch/arm64/kernel/sdei.c
> index d20620a1c51a..269adcb9e854 100644
> --- a/arch/arm64/kernel/sdei.c
> +++ b/arch/arm64/kernel/sdei.c
> @@ -39,12 +39,11 @@ DEFINE_PER_CPU(unsigned long *, sdei_stack_normal_ptr);
>  DEFINE_PER_CPU(unsigned long *, sdei_stack_critical_ptr);
>  #endif
>  
> -DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
> -DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
> -
>  #ifdef CONFIG_SHADOW_CALL_STACK
>  DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
> +DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_saved_ptr);
>  DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
> +DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_saved_ptr);
>  #endif
>  
>  static void _free_sdei_stack(unsigned long * __percpu *ptr, int cpu)
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkVzTbafttTHWETU%40FVFF77S0Q05N.
