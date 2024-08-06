Return-Path: <kasan-dev+bncBDBK55H2UQKRBLOJY62QMGQEEJAJN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 44EB1948BB5
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Aug 2024 10:54:07 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-428040f49f9sf2267405e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2024 01:54:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722934447; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hvn0qTvZkKwSnh4ch2Ml/Sy+Fznm966O2ybYPAAKK4F5tnYP044jMdYMWgXogHtssT
         dvVUFbWaKAlXugibdNRSEeli2TYvonVyu74KSI3Y6vwy/Iz7tLw2FI6KxjJLYsAp6caK
         lhsIETDoZLifwgD/BqaOTXRsNuAS1tJpGbe2+DA5uiszsTaThaw5bz1FB1c3HNpykkRn
         CdBY03EvRDcubHy0dXugPJzelkT3QgiETo2xW2A0gv2mtyISRkz3QpfsZAAsHcXLQChc
         AOB5gp6nELdrwO79zbImHSK+giNY6w862ic3jeIbV/UE8+PmGyJfywck1ltOawgMCiqZ
         WUVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VcLnW4Ig9WVCNvuqN6ack4j20KnlnTOKJK1jZUBZHmk=;
        fh=oFpXOkkVn4fOnSXE12/VEy0WLc8s/Pb7L8D0QwMX7Vg=;
        b=purfxJwU0gAdL2iXCIfZ9qWvcIgP22SId0D5lpmgNwSlB78ywZP9HNVWLFqkAOLVmO
         Yw1g941VZbEbujGvFx8eBHMjt7l6uKrtuHFN1nAQwR0ljKDJitMvOtiHnEH9w1MAUpcL
         M2ut69RVRKL9EzRnlCs0l4oi11GoCLW1HgcWq4rz8hx51OrWTWZJGIWq9gC7fMbj0BJi
         jYIXBPXa2XxmQBQkm4QAz39CeLG8hVecYpw6cfZbNHFqnMxswgJbqbdJ3AATjZ896s3F
         4oTkBXOixR5hK073E5EOB3hZcciUwFkQaXRNxXY/BkAyfQ856cenWrRIvlm7WEoquKql
         +U/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tjy6WaYg;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722934447; x=1723539247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VcLnW4Ig9WVCNvuqN6ack4j20KnlnTOKJK1jZUBZHmk=;
        b=DPfkFt54uebe2nOMVJL1DmcCnSKC1ps+Rd4ENRDGrnvvd5npRClTwVwpg9cmtsGhPu
         Xm950nav1hi4P6+EYRvthN6gZuP/dZvvkIwqisOiKPNgrqTxw08rEeonu/LJPntXFS7i
         w9UfxkrAh2gFUAxMA2CvtZbAuDpOmcxF5heYozK3i2r3laAqxHCtftEVjRXdyeJ2LJd2
         01+0pJQMcxd9abLpmRbz/dGt47oMqsueX0dbD6z+NU7Fv2arGu2Hp1qn6cTeAetByrhO
         YPzAKeLY7x9pVlYMv/UIgNYR3LlA/84HWrnIhEXwRDDiAxVpMPTrAl8+5N7nrto8DjAn
         /dAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722934447; x=1723539247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VcLnW4Ig9WVCNvuqN6ack4j20KnlnTOKJK1jZUBZHmk=;
        b=DP2R2cxMQ55d4XTh/+svPLG9J5CNKh/IujY75O2XwDi3ZfLrwwCnSC/e4QvId64T0P
         b/8OcXhKBNqzosc7St9da3/mW0ebao3Swt7EmX95BnImclhz5ntREWSx+8h4cw2s6Keq
         nhqKnIVtmeqkkKC2R5cUt0PtmoJl59i2PKSTemBlLRp+nbCcFa75ZbgapSG4upTR5Cnh
         c4JI0I3OEREH6e728pq9IOt5qZ/WFNHOXV6f4uAKoOkQWi0oYC6xzDebHr0P4ZiwZ6u2
         e3XeefXqd5BRlPI2lKvI4DahKPPHyQSrchMAra1H1uU5loUtYkFVr0RuC1MJ+cwDhApT
         3WMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVs6j14CCJyBe80PYScrcwa2OrdYAbsaoL7mpdygE2tg0JeuQxVUVo0Hf/vzs0b2hy0uNCcBMAuWqdAg+eXyUG8epBrqFXLNA==
X-Gm-Message-State: AOJu0YyYzUQrI+2JnKjnhc1BB0UCznZl+PiE8/mM0M6WjNpN6iQsQndd
	wcKAah93EErzVuyH5cPJwI/oJKjvDSpintSlJ+d8NRKJIdPQs1x0
X-Google-Smtp-Source: AGHT+IE89xWtl8c24RIxsvWv5O9kTLIhx9Bwjy9hER/+81irfYOzgKkjv7juQSKBIHL52FsWzkfFQg==
X-Received: by 2002:a05:600c:1f86:b0:428:1e8c:ff75 with SMTP id 5b1f17b1804b1-428e6b93fd6mr82231905e9.35.1722934446099;
        Tue, 06 Aug 2024 01:54:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c11:b0:428:1007:62f6 with SMTP id
 5b1f17b1804b1-428ede2181els12616155e9.2.-pod-prod-08-eu; Tue, 06 Aug 2024
 01:54:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7Z8e8HtyWnaBPa4j3fI9kjMkU0qtp5I7JzBnfJCbD2dpgs88siW2B53yV7+Dj4a4cR4uiwbIqazR72e6pZP+1cQkWrMcQa9CBgQ==
X-Received: by 2002:a05:600c:1ca9:b0:426:6f81:d235 with SMTP id 5b1f17b1804b1-428e6b037f1mr103033995e9.15.1722934443827;
        Tue, 06 Aug 2024 01:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722934443; cv=none;
        d=google.com; s=arc-20160816;
        b=K14HCgVZWOrNVu7k3mUZxygHY49EWZEkkostAjb41PHBH9tdc6pIGVFktXaEMT20/V
         ZlYIZRBSIHq8N+seCM/TMyOesamotzBQ2i0zbb5YJNX9vMkvV/q5MzHsao+oCCprTQBM
         /ZZFJnoshivkYTwzCaeVOYZozUvX1I+dYr+eT78GoI7sPd+SQFulcxfeC3zgc6y2JvFi
         PQwCFFo5pVApVzN9A7/uGnewmVIPhatK9kvZc8gEHINGZS5ymv4yNm7mrEYqsrf7F9Cg
         ieKcwtC77mytyEzZxmc8iEXsSoLX67G/vMs/85TuFGhW6jXJebR3RNxZ9/8IUvTwqEr+
         HmQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HIsjlesZzmw9ezXsnzRMplI/3AwTb3rdOIgIkcCOhHg=;
        fh=3UGkALpx5yA+ylfvDJOS+FBUjytPnLzr3ic9SO+nbtg=;
        b=p/vr1b8U73CB8sgshwTOorMDek4oCWxtWJdzRwORHrp6lgYG9CmPNDmWm5EOZ5XB7z
         wlvZTOyn1IkXnrd+uZa/VEg3PMjeIBSJi/COW1DZOV7yQ9Yw419VCCGIJ/aCpwpGIoyU
         gI5b1m1exm9BDJdWcpIqo4o55cyRCZ3eeuGwSGNOYJQk6ewEVOMYfOrHVUpHnWLZdlfi
         fk7VANvFbDpx7RgxXU7BxqR13jQL9epl/I4FQ68fVyKDwiDQXNGMbIyp5qAaSXmSrLJg
         JWZSULmOqlyQTUUtoRUNnnl6dpqjRpjElJv3gKgijQ9hSryK0Z0/KIaZxcq/188tuOwh
         Pgyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tjy6WaYg;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-428e6e710a9si2319515e9.2.2024.08.06.01.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Aug 2024 01:54:03 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sbFx8-00000005T4F-2Mwz;
	Tue, 06 Aug 2024 08:53:58 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id E0BA730049D; Tue,  6 Aug 2024 10:53:57 +0200 (CEST)
Date: Tue, 6 Aug 2024 10:53:57 +0200
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
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Changbin Du <changbin.du@huawei.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Pengfei Xu <pengfei.xu@intel.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Xin Li <xin3.li@intel.com>, Uros Bizjak <ubizjak@gmail.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v5] x86/traps: Enable UBSAN traps on x86
Message-ID: <20240806085357.GR37996@noisy.programming.kicks-ass.net>
References: <20240724000206.451425-1-gatlin.newhouse@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240724000206.451425-1-gatlin.newhouse@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Tjy6WaYg;
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

On Wed, Jul 24, 2024 at 12:01:55AM +0000, Gatlin Newhouse wrote:
> Currently ARM architectures extract which specific sanitizer
> has caused a trap via encoded data in the trap instruction.[1]
> Clang on x86 currently encodes the same data in ud1 instructions
> but the x86 handle_bug() and is_valid_bugaddr() functions
> currently only look at ud2s.
> 
> Bring x86 to parity with arm64, similar to commit 25b84002afb9
> ("arm64: Support Clang UBSAN trap codes for better reporting").
> Enable the reporting of UBSAN sanitizer detail on x86 architectures
> compiled with clang when CONFIG_UBSAN_TRAP=y.
> 
> [1] Details are in llvm/lib/Target/X86/X86MCInstLower.cpp. See:
> https://github.com/llvm/llvm-project/commit/c5978f42ec8e9#diff-bb68d7cd885f41cfc35843998b0f9f534adb60b415f647109e597ce448e92d9f
> 
> EmitAndCountInstruction() uses the UD1Lm template, which uses a
> OpSize32. See:
> https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86InstrSystem.td#L27
> 
> Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
> ---

This will do I suppose,

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
>  MAINTAINERS                  |  2 ++
>  arch/x86/include/asm/bug.h   | 12 ++++++++
>  arch/x86/include/asm/ubsan.h | 18 ++++++++++++
>  arch/x86/kernel/Makefile     |  1 +
>  arch/x86/kernel/traps.c      | 57 ++++++++++++++++++++++++++++++++----
>  arch/x86/kernel/ubsan.c      | 19 ++++++++++++
>  6 files changed, 104 insertions(+), 5 deletions(-)
>  create mode 100644 arch/x86/include/asm/ubsan.h
>  create mode 100644 arch/x86/kernel/ubsan.c
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 28e20975c26f..b8512887ffb1 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -22635,6 +22635,8 @@ L:	kasan-dev@googlegroups.com
>  L:	linux-hardening@vger.kernel.org
>  S:	Supported
>  T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
> +F:	arch/x86/include/asm/ubsan.h
> +F:	arch/x86/kernel/ubsan.c
>  F:	Documentation/dev-tools/ubsan.rst
>  F:	include/linux/ubsan.h
>  F:	lib/Kconfig.ubsan
> diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> index a3ec87d198ac..751e45ea27ca 100644
> --- a/arch/x86/include/asm/bug.h
> +++ b/arch/x86/include/asm/bug.h
> @@ -13,6 +13,18 @@
>  #define INSN_UD2	0x0b0f
>  #define LEN_UD2		2
>  
> +/*
> + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> + */
> +#define INSN_ASOP	0x67
> +#define OPCODE_ESCAPE	0x0f
> +#define SECOND_BYTE_OPCODE_UD1	0xb9
> +#define SECOND_BYTE_OPCODE_UD2	0x0b
> +
> +#define BUG_NONE	0xffff
> +#define BUG_UD1		0xfffe
> +#define BUG_UD2		0xfffd
> +
>  #ifdef CONFIG_GENERIC_BUG
>  
>  #ifdef CONFIG_X86_32
> diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
> new file mode 100644
> index 000000000000..1d7c2b4129de
> --- /dev/null
> +++ b/arch/x86/include/asm/ubsan.h
> @@ -0,0 +1,18 @@
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
> +#ifdef CONFIG_UBSAN_TRAP
> +void handle_ubsan_failure(struct pt_regs *regs, u32 type);
> +#else
> +static inline void handle_ubsan_failure(struct pt_regs *regs, u32 type) { return; }
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
> index 4fa0b17e5043..6350d00a6555 100644
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
> +	if (v != OPCODE_ESCAPE)
> +		return BUG_NONE;
> +
> +	v = *(u8 *)(addr++);
> +	if (v == SECOND_BYTE_OPCODE_UD2)
> +		return BUG_UD2;
> +	if (v != SECOND_BYTE_OPCODE_UD1)
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
> index 000000000000..63f819928820
> --- /dev/null
> +++ b/arch/x86/kernel/ubsan.c
> @@ -0,0 +1,19 @@
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
> +void handle_ubsan_failure(struct pt_regs *regs, u32 type)
> +{
> +	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> +}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240806085357.GR37996%40noisy.programming.kicks-ass.net.
