Return-Path: <kasan-dev+bncBDBK55H2UQKRB5475KZQMGQEQ2RAM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 55AC79162A0
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 11:38:01 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-52ce42bb0efsf1447432e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 02:38:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719308280; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxPlej5iRA2/IDBJBMVX0GbgpXiRqg4es7FoKgrKQIH25gwCZtoynE/sAZ3EgXOjzm
         Kz7HUpIWd0h2YBfJTAVTNEDvzrSj4LSn99uY1crIer4eZC3+6U9IpvqzHdtrut5BKVNj
         5ZWJLDUPHfA3vbKPbCbK+CFQTBXWdVNBzQYINZQBKG66tNmwheblzY3p3uM7g5EabMoc
         UTuku2P50OKbq831MsLpAqBHgeTWMCnsE7nmz7JByY80K2vH9YtJBJPNJmssaO6jwnHP
         f9au3OsvwrxGLTyXD3lQs+Un7NgMcJSfeBVPawf9GCa+Sr4EyKgV75FvyNwfK74rypCH
         Nm0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8uLPG6Or8Cz2f7Emqi5MNEKCy8IXMHoOJks/kMaI9Bs=;
        fh=Qs/sWIB4eOXo1u1QJ9HABEGrpTQDGZ1se47WDbCKlgg=;
        b=A2LXyZyxEV16jVkCNLCCeZgu1u0xfEBrU6GFmtbxjNJnLq3yB6uVgDsM8KGGJ90imN
         VrA7iqOA9+IQeBVPIXhkNHI0Osga4Y2edyKU6D9Jv7kAD0XEd73tNyzUsJ3Qev9VcE32
         Wl/ixzuSPLvM8mRH06FUp4CtFsGnBeK/XrKrwxWhSq6laW0ZP3c3J8+J4zs4GpwgTJE4
         7o4t9EZzcbEBvdZZYfvJ7duMK/h/dmPUCH+07S/G+nIKPC7XM0qiMV68T/vp5RLNIw9q
         LAKvfAO3guCuAoZ1JRZFbfaheOCzC6i/yy8N/RWl/u1J7svj8OkheCr7w4Sbe7PFaCcm
         eRYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Xj13taHy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719308280; x=1719913080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8uLPG6Or8Cz2f7Emqi5MNEKCy8IXMHoOJks/kMaI9Bs=;
        b=b29aBTmf6fphxdTjzpqCu5y2G879wyNcFeM06igjjuQhpfstTz8qWN8AD7GsmIzjLe
         PgWIGW1Un1TNjtSRtB+6TGxysmcbw+8/yCqsIgxJYDMPi4Q+aHxTATPYu+lAoiStqkYs
         fu3W5fq2zUq3eW9nET2xVqoxUJy/WnD0rgxu3s2HhLtxKnH/jt15Us7OcM3Y6+czLC59
         RPxIRTi76j2eUHzU9GmsoLwwXEd4LaDv+9qCjm9SKtbWoEpcTTjhfu9KfgSdpmijPBv2
         yETe22ULKqRAbxhVop0bFgrIuFV/Lir5OTe/frENRb1GLNeEYQx7e8AoxmuEUwP0oCaL
         CqKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719308280; x=1719913080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8uLPG6Or8Cz2f7Emqi5MNEKCy8IXMHoOJks/kMaI9Bs=;
        b=c8jy8EsF5YbFgAVtKjQAUdZGp0wkdJKKmYCq13Q4iJVex2KPidfU73oAMp5G8GNkea
         zLAuc0SxKHL7BjBLs99qEQ87CyziIv4vfsmeH/mssUSsMvRbmrovD3peYz09LcDSyA7x
         J33IC1yXVXHGgaHdTA9I8p2lrgnG5i+nhWaDekEwI3O0kUT9w+REvjZE6cpq2abOnp3X
         KAgHWUlj5AGl/WH25+9J0nJoON1eicBFPYdnp0PZ+C6PTlIb/AJpCgkPnp3dl5mOh+9d
         jA3PxdO3Chg3nrBKC9gX+BdZWI4uGhDeNj+B1hv1zwD8DixmKPxLUTYbL7S6L1NHLl/o
         2mvw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjzv0EJxddw+Ovd7dVWFOVYI6WSSKXKnNwpvA36oonH4gXSQgJgWjE6vXFkmptluxXcGGDT9chMKi1gTL5SFGqCch1V7NhPA==
X-Gm-Message-State: AOJu0YyHgBtErQSs1F7X/8ZpJvxX6E3RMcXwEJ45imqYwSjhq4Vgweno
	dTK9J8QB4OLbXgfDwAaTp59yQFridyFQTu9nq0LKq3qalaBKrf3T
X-Google-Smtp-Source: AGHT+IF06wpDdMnqVjsMNxx2BBKK5ADTSSJecCGUX7syDaa0jHARA2jrJWGh/3WRXEZIxMbxTmla+Q==
X-Received: by 2002:ac2:5e79:0:b0:52c:e180:4eac with SMTP id 2adb3069b0e04-52ce1804fa2mr4004321e87.9.1719308280114;
        Tue, 25 Jun 2024 02:38:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5219:0:b0:52c:e4ec:ad52 with SMTP id 2adb3069b0e04-52ce4ecaf96ls779609e87.1.-pod-prod-02-eu;
 Tue, 25 Jun 2024 02:37:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8oCadX+/eXlaWx7rTPNu49mfaYOLaKAcN0a8r7yDz+YDRdqWtdlXrJbKJNlpKbQJwD2Ml0CI8gvG4HcTgvyCs+KwcvbC2T2DUwQ==
X-Received: by 2002:a05:6512:3a8f:b0:52c:dfe0:9b1d with SMTP id 2adb3069b0e04-52ce06734bbmr5600879e87.45.1719308277420;
        Tue, 25 Jun 2024 02:37:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719308277; cv=none;
        d=google.com; s=arc-20160816;
        b=AgWZFVl9GzA3CmXrxbb7ODN2rYUnXYzV7Bmgh0B1Oc1Mk6vGmc0XZq5pl0SwnOurrY
         u1pTLtU+3dZxVcQlwERhxxhlXHbkTnnpz1WCUxdXnThfN3HWcuk44FnfFtNQleowc0+x
         0g4ulMD+jgBYTVx9abkhYCcn1CUMfMYcXTed8M9G5TcVb/TarpMowJFdpnWt6AaPC7+H
         CF2NEgmkCtY5uwZXufJu/2PLl+L/eYC7ALubegGzNz1wVS6OEsipsPqOd9qYE0f9q1BB
         57m9CEyQawW/LpOIJ0VgHMGnUxiu5YMZUX/9Q43WdWExemIgr/3cmp2Gwudz54OULnIk
         grWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=p81muDELRMtjx8hyqZALP7SKcIRl8MDp2vLMju2Ho8E=;
        fh=i3BH9rfZTrewb7bgHlyevoaE4fSEsexQhZjNRmnAU8o=;
        b=TuTK9MoVKpGQUXCHZK20vOge+XdVKXXAkdIHDODdcEq4geFFBT/kkmsX1dMhjk9FNo
         ZJo5qjAFzvqGure8Eg/2fxN8cFC+1CG8cCyaFNVjSnZo+AV96CxgFULZZMpjap7bhOsK
         /x942v5E9JLFETyq/BjNMZvhlts2iQjFUiRFNvXbMz6qvW9LG0lhwF5qLgH8hZ1iN23a
         T0lkhE5a/IJPrciSsH1WMpXhx9CmpKORm7jWGrMY1w3Cnu3K5vN8FynNR9lxqDaZyNb9
         2IOQEgCwCAgtA+EuVdyGSqV8M+Me5Z7JTy2qHuqsu8NfJ+7pD75gO6wzd9yIdsmR9A0e
         mmnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Xj13taHy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52ceae2ae76si66530e87.0.2024.06.25.02.37.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 02:37:57 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sM2c3-00000008Njg-3inE;
	Tue, 25 Jun 2024 09:37:39 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7378B300754; Tue, 25 Jun 2024 11:37:19 +0200 (CEST)
Date: Tue, 25 Jun 2024 11:37:19 +0200
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
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Uros Bizjak <ubizjak@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v3] x86/traps: Enable UBSAN traps on x86
Message-ID: <20240625093719.GW31592@noisy.programming.kicks-ass.net>
References: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Xj13taHy;
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

On Tue, Jun 25, 2024 at 03:24:55AM +0000, Gatlin Newhouse wrote:
> Currently ARM architectures output which specific sanitizer caused
> the trap, via the encoded data in the trap instruction. Clang on
> x86 currently encodes the same data in ud1 instructions but the x86
> handle_bug() and is_valid_bugaddr() functions currently only look
> at ud2s.
> 
> Bring x86 to parity with arm64, similar to commit 25b84002afb9
> ("arm64: Support Clang UBSAN trap codes for better reporting").
> Enable the output of UBSAN type information on x86 architectures
> compiled with clang when CONFIG_UBSAN_TRAP=y.
> 
> Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
> ---
> Changes in v3:
>   - Address Thomas's remarks about: change log structure,
>     get_ud_type() instead of is_valid_bugaddr(), handle_bug()
>     changes, and handle_ubsan_failure().
> 
> Changes in v2:
>   - Name the new constants 'LEN_ASOP' and 'INSN_ASOP' instead of
>     'LEN_REX' and 'INSN_REX'
>   - Change handle_ubsan_failure() from enum bug_trap_type to void
>     function
> 
> v1: https://lore.kernel.org/linux-hardening/20240529022043.3661757-1-gatlin.newhouse@gmail.com/
> v2: https://lore.kernel.org/linux-hardening/20240601031019.3708758-1-gatlin.newhouse@gmail.com/
> ---
>  MAINTAINERS                  |  2 ++
>  arch/x86/include/asm/bug.h   | 11 ++++++++++
>  arch/x86/include/asm/ubsan.h | 23 +++++++++++++++++++++
>  arch/x86/kernel/Makefile     |  1 +
>  arch/x86/kernel/traps.c      | 40 +++++++++++++++++++++++++++++++-----
>  arch/x86/kernel/ubsan.c      | 21 +++++++++++++++++++
>  6 files changed, 93 insertions(+), 5 deletions(-)
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
> index a3ec87d198ac..a363d13c263b 100644
> --- a/arch/x86/include/asm/bug.h
> +++ b/arch/x86/include/asm/bug.h
> @@ -13,6 +13,17 @@
>  #define INSN_UD2	0x0b0f
>  #define LEN_UD2		2
>  
> +/*
> + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> + */
> +#define INSN_UD1	0xb90f
> +#define INSN_UD_MASK	0xFFFF
> +#define LEN_UD1		2
> +#define INSN_ASOP	0x67
> +#define INSN_ASOP_MASK	0x00FF
> +#define BUG_UD_NONE	0xFFFF
> +#define BUG_UD2		0xFFFE
> +

Please look at 790d1ce71de. Also your style above is inconsistent,
please use lower case consistently for the hex values.


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
> + */
> +#define UBSAN_REG	0x40
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
> index 4fa0b17e5043..aef21287e7ed 100644
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
> @@ -91,6 +92,29 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
>  	return *(unsigned short *)addr == INSN_UD2;
>  }
>  
> +/*
> + * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
> + */
> +__always_inline u16 get_ud_type(unsigned long addr)
> +{
> +	u16 insn;
> +
> +	if (addr < TASK_SIZE_MAX)
> +		return BUG_UD_NONE;
> +	insn = *(u16 *)addr;
> +	if ((insn & INSN_UD_MASK) == INSN_UD2)
> +		return BUG_UD2;
> +	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
> +		insn = *(u16 *)(++addr);
> +
> +	// UBSAN encode the failure type in the two bytes after UD1
> +	if ((insn & INSN_UD_MASK) == INSN_UD1)
> +		return *(u16 *)(addr + LEN_UD1);
> +
> +	return BUG_UD_NONE;
> +}

Given that insn is u16, this INSN_UD_MASK seems eminently pointless.

Are the bytes after UD1 a proper ModRM such that the whole forms a
decodable instruction? You seem to not mention this anywhere. It is
paramount that the instruction stream is still correctly decodable.

Also, wouldn't it be saner to write this something like:

__always_inline int decode_bug(unsigned long addr, u32 *imm)
{
	u8 v;

	if (addr < TASK_SIZE)
		return BUG_NONE;

	v = *(u8 *)(addr++);
	if (v == 0x67)
		v = *(u8 *)(addr++);
	if (v != 0x0f)
		return BUG_NONE;
	v = *(u8 *)(addr++);
	if (v == 0x0b)
		return BUG_UD2;
	if (v != 0xb9)
		return BUG_NONE;

	if (X86_MODRM_RM(v) == 4)
		addr++; /* consume SiB */

	*imm = 0;
	if (X86_MODRM_MOD(v) == 1)
		*imm = *(u8 *)addr;
	if (X86_MORRM_MOD(v) == 2)
		*imm = *(u32 *)addr;

	// WARN on MOD(v)==3 ??

	return BUG_UD1;
}

Why does the thing emit the asop prefix at all through? afaict it
doesn't affect the immediate you want to get at. And if it does this
prefix, should we worry about other prefixes? Ideally we'd not accept
any prefixes.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625093719.GW31592%40noisy.programming.kicks-ass.net.
