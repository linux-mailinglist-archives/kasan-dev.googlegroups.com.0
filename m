Return-Path: <kasan-dev+bncBDBK55H2UQKRBBFHX22AMGQED52N6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E842092E195
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 10:10:45 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-52e9d04d773sf605426e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 01:10:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720685445; cv=pass;
        d=google.com; s=arc-20160816;
        b=FTjchTr5XCMidbOa/qG5ZYlR0dJBdtVtk5+cm1Y3YDgWfEi5mhpIY5gS5pR1nSMfVw
         pxJS2xpYbhSZdwgVj/404G0ynupE4nEqhbipvrCrR+GI41AFblbNKCKOkyDDMSChmCFi
         SVxWpzCFMCvBaxAKa3UxYRg3Zjil/6wvQiVq+RYQ0eKM5T4JdhBdghgs5Fhq+eEEC3dr
         sBcu1FaHe76Yy9/+Zq066tGWOiy7Gw+8tRqvnG3EE87ULyjZXKB8eihKQfVlHlcPJQxA
         BNj6hBbdm+irlVrZ96gdjtxkmKBogZfkbMXaHAdLnR1O7w1m8WBV3dPppksI3/AuMcRT
         Xhng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mr8Mp+zNV+xqQGZ744LomZXqfqswIz25fS/1Ugih/iU=;
        fh=9elxrkuWz1G3wFDtqT6iWz5J6TVx3XFl2ms8Nlc6lWE=;
        b=QpT64ff87kizGsG1Ce4eQNmij1yH0BE83WdU89FVTHlLMKqnKfcqbZ85fgbOAMAJ34
         wROkGXnkbgcdMZj5+D3B6Hf5mJJA0+4NWvyvb0/5esiqH6R/q1kUQjT50c529BLe4Mnb
         xzj4I67VgAnACpFRdtSA4ij0/W7hKXYqDcksSHdsxwtlFmOyAPHzPD9Ip2qo1Uv5Kpta
         6YiJ0t2PGo6waNqF50Ljm00EDWOfdTolDuuS8wM6srSaQoP+l5CbaHY0u4oiRw7bkLNN
         9MVqa2/56SuuwTv3JCXKASZLSB2qfEnpeUuUMjATfJdqKpdsjCjOOBCqgmZ0dyEXk/j7
         g9WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=b0XQmENp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720685445; x=1721290245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mr8Mp+zNV+xqQGZ744LomZXqfqswIz25fS/1Ugih/iU=;
        b=gun2sm1b9KSEiPmbd99DHarir3WokIRa84f8sL5p5wHqcgpAoSutJ1C39ZM/h25P5l
         IcpQbzE9pgIc09BiUlScpu0rqEY21a+ZL+6KmYwCHsO039nwO98kPvkrYbqRkyTX3Bfg
         A4C3Dq2ecfhE+7qTbqzax2LRxLR7IpR2Lx6AhaNoBXPHxlofqT9hnHCcAETb2OYljEO6
         o1KouCyD9lUlI0IXqq4qjq1WhxOkOUWPPoAFz+ch8KaXxDo/p46IpkQwTEuX33RBuzlp
         h9siTeRbBAji/b4umWXXbzLYYrO6OwvfUF65j9fHnmjTg+cDeYbXdJY3TBBNMJBhhlBk
         lpog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720685445; x=1721290245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mr8Mp+zNV+xqQGZ744LomZXqfqswIz25fS/1Ugih/iU=;
        b=ReavXXzxqO4f9aX+82wlWnurcI/2ou4lGE0f33m31P3ZgqZML3oOcZZI+kN3F9zDyI
         dUFCa2ASoMQMKcqBmVA9w2I33iNhD9SgpraQyWe185+tSkn7hBlTFJe+HgCrKLzuLzw1
         zK17gztvUObYtFBX4+FnuCi4/9yjnixMJzmbe5zLuFqkhoZwJhsUYpwfvaqjz7MYs76G
         1ioYOFfxYaX2lqa89FmTpkf8ZeoI/wwzc/HxKn5Q1lwlM2TPovsnzKonz9PkqC/lThxN
         q9ans3DR4CdujF/OXYDsw6kMz76fGz6snvH5ElDSRdyZx4BV28Ln99NiyhZA6HcB1xMR
         npJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8FOOytu9cjSVZ0B7O8j5Usiy6NczY40dbJnsjk8YAWUBF60pqV8+g5iNNiRVSH87dAd2rGqTSamhiW6seTMNuhgvoa2rA5w==
X-Gm-Message-State: AOJu0YzmyJmelLM+lwln5T242UEL13wQPlqO9QMzDT66+AOHM7InXP9p
	GufI4m36To9b58Eg94eFKMae8uGomM3oJN8FMcYMMlrAUCixKgNF
X-Google-Smtp-Source: AGHT+IFtubqdNNxkh9EGLbRfzdjh9AKF+3KE1NJOR0A5IgwNDFIiiWa6UcUbOZ2P069kXvj/eX4FMw==
X-Received: by 2002:a05:6512:15a4:b0:52e:9fda:f18a with SMTP id 2adb3069b0e04-52eb99d4bf0mr5810237e87.44.1720685444519;
        Thu, 11 Jul 2024 01:10:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:410:b0:52e:9a51:77bf with SMTP id
 2adb3069b0e04-52ec409c958ls285913e87.0.-pod-prod-03-eu; Thu, 11 Jul 2024
 01:10:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlnm/+JX55+/29xV2uOYNWq95f8nf7t70HD9lsPgpfkBdD1r2FiVWqF3fv+6vY894V5rTCqWq+w0197OuIZ240Dorfq3AV+aHL/A==
X-Received: by 2002:a05:6512:3a8d:b0:52c:e054:4149 with SMTP id 2adb3069b0e04-52eb9996113mr5602394e87.15.1720685441557;
        Thu, 11 Jul 2024 01:10:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720685441; cv=none;
        d=google.com; s=arc-20160816;
        b=MAVWmyGD0vpSlbcufsdmsQ2OOjfMVNUzDIDSwxPs8nvqoZCAgAmY3H7GPRi/fSoIbS
         PZ22NRYw0cv7deAeJ+8S2tygYO28bcB0rnQBFybjUuDE6evZp9H5x6CJSjrNhIUtGtDb
         /7IupN37s+2ocTAkoQ8/XH2SsxAWESiZdB/a6nEsPa3cbijFqa4AeB/YriBh504eRR+A
         QhkrhBnWepZGGAcr843bVXvhXigGyulhQRISJRLpWEdT0qoa5BmZUOuHjyjNhhIqD5j8
         j6RBL7LM9beG7azRVxVlVrhN8i3RLCggOOlnxFAJOMRRGdvelV5KAI3tA/hVRTo3b+Mx
         V38g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tDeiiGMS+Rb6GTSNg6AylsTFuSIZN3CBnV/fJ+EfT/g=;
        fh=8fuZnfB+VPrhKaTO7+z6swDs+uZVx3atQXbQJ31+n5g=;
        b=vXjUN5oW6eTcnAneImaRAFjEGj8/IjG2MRa1REplCw1yAD9baEXxz2Aa1uyF93b3Sd
         X73R7RqlI07uKrCmJDVK9n9z08bou88UAt4ksmfrHWWD9BXw4bvjje2KDiH8FEt3gGO7
         MdmtHuAfYnd3OD5pWgHtu6HYGiGEtZd/WPrBFj9670xMAhLtfNHHHCa844jIAg097+ol
         kkXlARffa4AZ5hj0CDHs6K2j/XnXGuNfss1lYsrEofwAtTt2pVCOfetsuJ8xSlDolzHw
         TL69FU/XBPpYPSxjpVdB/uzvCM8ASe6JhTFhYIMQyiozR7J9d0jDdrYMH07YDi3efvMS
         V5rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=b0XQmENp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52eb8e3389dsi109867e87.2.2024.07.11.01.10.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jul 2024 01:10:41 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sRosq-000000013Xo-1VwT;
	Thu, 11 Jul 2024 08:10:32 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D600B30050D; Thu, 11 Jul 2024 10:10:31 +0200 (CEST)
Date: Thu, 11 Jul 2024 10:10:31 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Changbin Du <changbin.du@huawei.com>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v4] x86/traps: Enable UBSAN traps on x86
Message-ID: <20240711081031.GB4587@noisy.programming.kicks-ass.net>
References: <20240710203250.238782-1-gatlin.newhouse@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240710203250.238782-1-gatlin.newhouse@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=b0XQmENp;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jul 10, 2024 at 08:32:38PM +0000, Gatlin Newhouse wrote:
> Currently ARM architectures extract which specific sanitizer
> has caused a trap via encoded data in the trap instruction.
> Clang on x86 currently encodes the same data in ud1 instructions
> but the x86 handle_bug() and is_valid_bugaddr() functions
> currently only look at ud2s.
> 
> Bring x86 to parity with arm64, similar to commit 25b84002afb9
> ("arm64: Support Clang UBSAN trap codes for better reporting").
> Enable the reporting of UBSAN sanitizer detail on x86 architectures
> compiled with clang when CONFIG_UBSAN_TRAP=y.

Can we please get some actual words on what code clang will generate for
this? This doesn't even refer to the clang commit.

How am I supposed to know if the below patch matches what clang will
generate etc..


> diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> index a3ec87d198ac..ccd573d58edb 100644
> --- a/arch/x86/include/asm/bug.h
> +++ b/arch/x86/include/asm/bug.h
> @@ -13,6 +13,17 @@
>  #define INSN_UD2	0x0b0f
>  #define LEN_UD2		2
>  
> +/*
> + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> + */
> +#define INSN_ASOP	0x67

I asked, but did not receive answer, *WHY* does clang add this silly
prefix? AFAICT this is entirely spurious and things would be simpler if
we don't have to deal with it.

> +#define OPCODE_PREFIX	0x0f

This is *NOT* a prefix, it is an escape, please see the SDM Vol 2
Chapter 'Instruction Format'. That ASOP thing above is a prefix.

> +#define OPCODE_UD1	0xb9
> +#define OPCODE_UD2	0x0b

These are second byte opcodes. The actual (single byte opcodes) of those
value exist and are something entirely different (0xB0+r is MOV, and
0x0B is OR).

> +#define BUG_NONE	0xffff
> +#define BUG_UD1		0xfffe
> +#define BUG_UD2		0xfffd

These are return codes and not related to the defines above and as such
should be separated from them with some whitespace.

> +
>  #ifdef CONFIG_GENERIC_BUG
>  
>  #ifdef CONFIG_X86_32
> diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
> new file mode 100644
> index 000000000000..ac2080984e83
> --- /dev/null
> +++ b/arch/x86/include/asm/ubsan.h
> @@ -0,0 +1,23 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _ASM_X86_UBSAN_H
> +#define _ASM_X86_UBSAN_H
> +
> +/*
> + * Clang Undefined Behavior Sanitizer trap mode support.
> + */
> +#include <linux/bug.h>
> +#include <linux/ubsan.h>
> +#include <asm/ptrace.h>
> +
> +/*
> + * UBSAN uses the EAX register to encode its type in the ModRM byte.

This is a claim, but I have nothing to verify this against. I mean, I
could go trawl through the clang sources, but this really should be part
of the changelog to explain the clang code generation.

> + */
> +#define UBSAN_REG	0x40

This is a ModRM byte, not a REG. The REG encoded therein is 0.

> +
> +#ifdef CONFIG_UBSAN_TRAP
> +void handle_ubsan_failure(struct pt_regs *regs, u16 insn);
> +#else
> +static inline void handle_ubsan_failure(struct pt_regs *regs, u16 insn) { return; }
> +#endif /* CONFIG_UBSAN_TRAP */
> +
> +#endif /* _ASM_X86_UBSAN_H */
> diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
> index 74077694da7d..fe1d9db27500 100644
> --- a/arch/x86/kernel/Makefile
> +++ b/arch/x86/kernel/Makefile
> @@ -145,6 +145,7 @@ obj-$(CONFIG_UNWINDER_GUESS)		+= unwind_guess.o
>  obj-$(CONFIG_AMD_MEM_ENCRYPT)		+= sev.o
>  
>  obj-$(CONFIG_CFI_CLANG)			+= cfi.o
> +obj-$(CONFIG_UBSAN_TRAP)		+= ubsan.o
>  
>  obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o
>  
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 4fa0b17e5043..b6664016622a 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -67,6 +67,7 @@
>  #include <asm/vdso.h>
>  #include <asm/tdx.h>
>  #include <asm/cfi.h>
> +#include <asm/ubsan.h>
>  
>  #ifdef CONFIG_X86_64
>  #include <asm/x86_init.h>
> @@ -91,6 +92,45 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
>  	return *(unsigned short *)addr == INSN_UD2;
>  }
>  
> +/*
> + * Check for UD1 or UD2, accounting for Address Size Override Prefixes.
> + * If it's a UD1, get the ModRM byte to pass along to UBSan.
> + */
> +__always_inline int decode_bug(unsigned long addr, u32 *imm)
> +{
> +	u8 v;
> +
> +	if (addr < TASK_SIZE_MAX)
> +		return BUG_NONE;
> +
> +	v = *(u8 *)(addr++);
> +	if (v == INSN_ASOP)
> +		v = *(u8 *)(addr++);
> +	if (v != OPCODE_PREFIX)
> +		return BUG_NONE;
> +
> +	v = *(u8 *)(addr++);
> +	if (v == OPCODE_UD2)
> +		return BUG_UD2;
> +	if (v != OPCODE_UD1)
> +		return BUG_NONE;
> +
> +	v = *(u8 *)(addr++);
> +	if (X86_MODRM_RM(v) == 4)
> +		addr++;
> +
> +	*imm = 0;
> +	if (X86_MODRM_MOD(v) == 1)
> +		*imm = *(u8 *)addr;
> +	else if (X86_MODRM_MOD(v) == 2)
> +		*imm = *(u32 *)addr;
> +	else
> +		WARN_ONCE(1, "Unexpected MODRM_MOD: %u\n", X86_MODRM_MOD(v));
> +
> +	return BUG_UD1;
> +}
> +
> +
>  static nokprobe_inline int
>  do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
>  		  struct pt_regs *regs,	long error_code)
> @@ -216,6 +256,8 @@ static inline void handle_invalid_op(struct pt_regs *regs)
>  static noinstr bool handle_bug(struct pt_regs *regs)
>  {
>  	bool handled = false;
> +	int ud_type;
> +	u32 imm;
>  
>  	/*
>  	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
> @@ -223,7 +265,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>  	 * irqentry_enter().
>  	 */
>  	kmsan_unpoison_entry_regs(regs);
> -	if (!is_valid_bugaddr(regs->ip))
> +	ud_type = decode_bug(regs->ip, &imm);
> +	if (ud_type == BUG_NONE)
>  		return handled;
>  
>  	/*
> @@ -236,10 +279,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>  	 */
>  	if (regs->flags & X86_EFLAGS_IF)
>  		raw_local_irq_enable();
> -	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> -	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> -		regs->ip += LEN_UD2;
> -		handled = true;
> +	if (ud_type == BUG_UD2) {
> +		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> +		    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> +			regs->ip += LEN_UD2;
> +			handled = true;
> +		}
> +	} else {
> +		handle_ubsan_failure(regs, imm);
>  	}
>  	if (regs->flags & X86_EFLAGS_IF)
>  		raw_local_irq_disable();
> diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> new file mode 100644
> index 000000000000..c90e337a1b6a
> --- /dev/null
> +++ b/arch/x86/kernel/ubsan.c
> @@ -0,0 +1,21 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Clang Undefined Behavior Sanitizer trap mode support.
> + */
> +#include <linux/bug.h>
> +#include <linux/string.h>
> +#include <linux/printk.h>
> +#include <linux/ubsan.h>
> +#include <asm/ptrace.h>
> +#include <asm/ubsan.h>
> +
> +/*
> + * Checks for the information embedded in the UD1 trap instruction
> + * for the UB Sanitizer in order to pass along debugging output.
> + */
> +void handle_ubsan_failure(struct pt_regs *regs, u16 type)
> +{
> +	if ((type & 0xFF) == UBSAN_REG)
> +		type >>= 8;

This makes no sense, we've consumed the ModRM byte ealier, this should
really only ever get the immediate.

> +	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> +}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240711081031.GB4587%40noisy.programming.kicks-ass.net.
