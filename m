Return-Path: <kasan-dev+bncBAABBJEQ5KZQMGQEBL4WZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF09C9161DB
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 11:04:38 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5e4df21f22dsf4461044a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 02:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719306277; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Hz3D818Cwt7Kls7PrG4BbeUvj2bWElAzxApNvXg4uzru9q+CXVdz5P1+Q2o5sQyWT
         MxMVsFH9D46yTNJQOYp4qNwNiPWN939s7wgKvsYJ533/7NdwV/F1RrsQlmVjhwDMBMn9
         x0P0VMUChhltfcl7ay7DyGkRUEwLqo4WqPJWrw1NVZaI5rt9nnJlzBBsA3uFEgOwj2/h
         6NTlkWP9dLPgtzwJxgpdGa/0qoowAqYUJldIA5D/ZaQSREw4ZVbigukM2LzYlvhAFsZg
         8X3C8uO6fIlB8xcvtfv7VXhrupq6GGghkJ08CMK93ouyECrHz1sSQXnakV8aXBE9CX95
         BISw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=Zp4vyKinm3Cw7k2WGJbp7knP6O7/242C0B/jyNwvONU=;
        fh=0+rG/4LT9VIybCWqpA2lalKNGYOO1LIQymgCvHMXIBk=;
        b=TxGU6flDd52+d/kfRpT+U2LA2hznVxfZd8dK3Xh1o/OUZU/cj8Y7004ZYnE+SiZH2F
         iwiFSv+otqDrZAfieZAIGrCEMcR569k19HuQEsTAIq9FVZFYTCcQfeKmBBHPoDEUUnza
         HfkvT7yVoFgCqUAO5y5PhRPND47VNflfS0CxFnESxKX9YvhEM4ILNiiVcl3Lr2L1ce+v
         WssyzzlyYG9J7dWa/eaXuneXbnL4Kb40W6npN/PZDmLEUZCSi1MAEG8FmKPPlQmtYFJ7
         ttxFPBv8J+qy95ADxcc2VSYHwjNOmJ6WdS0k0+eG5DqwrcC9dojJKdhbk3iM/rP5kKjN
         CQCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zytor.com header.s=2024061501 header.b="Ljo5U/s3";
       spf=pass (google.com: domain of xin@zytor.com designates 2607:7c80:54:3::138 as permitted sender) smtp.mailfrom=xin@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719306277; x=1719911077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-filter:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zp4vyKinm3Cw7k2WGJbp7knP6O7/242C0B/jyNwvONU=;
        b=cUD8utbjxnx5ulxrQzgr+eMstyJPPt76wCyItrs6ppT4X1jR/dVGC/BU8alOYIqqx+
         /YrnuCqf0fqDxqktdSxNIuFlAi6LXFobQwjBzSC8IDgibWOlgAyuLZeNEum4+RohUKRQ
         qT4+9/rWMZfe9Xos9H+gHAw9rSJUlJhsiZYygb/QlCNDwGj37EDfhy1VfchDromhyBkj
         Ij4N5CbVzCaZ8ZWl7X+1Pzuu+sak8wmn8+02fOkWzL1tjKshmP8TCuGn1a/1MStAfPFq
         AJO/cgIaZBiK9i4zSaAw6Rg7hlZVrL495IbmgeHYxzPcKrjAMOK8Nw5MFBc5pCt2yqtT
         pNDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719306277; x=1719911077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zp4vyKinm3Cw7k2WGJbp7knP6O7/242C0B/jyNwvONU=;
        b=J9RAyE344rnWkrWHi2CzuMdpsTj59vgcPKmTXwgSkgBj0nA1fVqHhJ1yjmT7BsMytl
         T3EKZiehSG0y7yAx2WPYXz4dKP//wWhG/aXbas/MvBTLzpDiqbhCFAat3um/oPLNMKmN
         qlOnz32m1mutUeLnOhPQom2w7F4aksppuPiB/K+MJColRRrmUgpUzRw0GbuN4xLCykd6
         RhRq12hmlWmHDfbApETZVwhm1wQLTpCiI8f0I25oG9rMmWbI/9EZeuS95Htzr20rscFR
         TO2+kDX678MjsmlaitR8i3plP/jDgQGB3sTzx8aaVnvyrnJpGi6PxOhzHxtvty8+WN57
         2acA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgoVwdv5lhvHmA//xmiiR6z5kmJlFZqvR2jIQvZxRY2APyeR3fgHPh5SZxKKa727hL/5CCmJ5J0P9dc++6fuTNXihIpoFSeg==
X-Gm-Message-State: AOJu0Yx37cMeKuQPl+CQuACo2zXwOsDt1HeFFYGLFOfcYC/kGQmlbDgL
	XCW1G9ClXEqJs8by2h/xvMRfmiCDSu8bqfr79JAGKvudBOB2Cf1q
X-Google-Smtp-Source: AGHT+IH0lH1zeTo5aaOkZICk6wYc0p9wukxANlmW9NxhaHBnHEcvkDJ0F1s/pWLAfUmTxrhHMaueDA==
X-Received: by 2002:a17:90a:ac15:b0:2c8:4e46:92f6 with SMTP id 98e67ed59e1d1-2c8a232d64amr4620292a91.3.1719306276534;
        Tue, 25 Jun 2024 02:04:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:69a4:b0:2c3:2bbb:673e with SMTP id
 98e67ed59e1d1-2c7b83828a5ls3125774a91.2.-pod-prod-00-us-canary; Tue, 25 Jun
 2024 02:04:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUhPIdiZLF+sI9vN2scgP9Jne1Qs65+pzIYi3oMUt+0NThmTeG0yx4lngwBKK9T8h1ObsaGtWup2He4VtMcZoXXNF9MXDxmquKilA==
X-Received: by 2002:a17:90b:33c8:b0:2c8:4250:66a1 with SMTP id 98e67ed59e1d1-2c84899e3d2mr10738509a91.3.1719306275487;
        Tue, 25 Jun 2024 02:04:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719306275; cv=none;
        d=google.com; s=arc-20160816;
        b=NdCVPLzxna/c9KVVJYCH77CEXk8KXX889W58aWB+lnnqFhHqE8aLQYR3TX0pncTwmw
         XH13F5nb9g504yKneUhYkcaOBu1gpeDV2+sbPEL+dreYbLYu32Vzrxa5LZbjrJDvfeX6
         +ABXGj+GkMEGqyR4HaGFS4YEn831LnlORL++gi2fPk8nbufHDtQWfgnsQJ3HsDecCUBq
         FgGMRMsfovBin2Z4ZdhE6Ppxm0Vw2+BbTtLNED+ctk8PsSYWM8zVBqlp+OBCISxVu2CP
         t8P+yoP28qcpZ14WKm1krYv8dXFMDa9EaoQlLA9pReplH0yxuT8gH7y8nK15RU3RbOKd
         y1tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=HetFgPvHU6ekWyKyVj2mXFyt8OvP4/sGiBkOm7u/ams=;
        fh=R8mwrQI+de0xAB4BuDPKZV/AYUvY6ExJVXRr3AutddM=;
        b=HGxoRTgYfiKlIeXvLGZjqUvbIUOJu2aQTi5GzcHRHFf4vZHjDepEopzDnlyBum9as+
         KzmALHfO96iUE5URYoAPXYjdn0X7p/liWBCEktPeJm6/we9Bu4TifXsxGOJA1MRjqYq0
         vurUUON9aO33PRC5LGOHO0bZXBcvDO7uX1p9R7Fjt8a2tBZ5x7czRzD/llkXhZQXYuh8
         7BuOcKu7qAdARyDjk4nleVk8uVTRuK+BOPl184rsDT4OFHuaGoIWGTtDve/tlsn4Lgmc
         dbaNmQxUzA6JQDYVAoQVyPcCXhxuNrXIwFkGXWF6Wsqnu0VWxZ8d1x03kvPxZBHij+Xm
         hzpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zytor.com header.s=2024061501 header.b="Ljo5U/s3";
       spf=pass (google.com: domain of xin@zytor.com designates 2607:7c80:54:3::138 as permitted sender) smtp.mailfrom=xin@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
Received: from mail.zytor.com (torg.zytor.com. [2607:7c80:54:3::138])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819a6d28dsi402739a91.1.2024.06.25.02.04.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 02:04:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of xin@zytor.com designates 2607:7c80:54:3::138 as permitted sender) client-ip=2607:7c80:54:3::138;
Received: from [192.168.7.205] ([71.202.166.45])
	(authenticated bits=0)
	by mail.zytor.com (8.17.2/8.17.1) with ESMTPSA id 45P6k05B1374749
	(version=TLSv1.3 cipher=TLS_AES_128_GCM_SHA256 bits=128 verify=NO);
	Mon, 24 Jun 2024 23:46:01 -0700
DKIM-Filter: OpenDKIM Filter v2.11.0 mail.zytor.com 45P6k05B1374749
Message-ID: <6713e17b-8030-401a-a26f-315b4d4c94ef@zytor.com>
Date: Mon, 24 Jun 2024 23:45:58 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3] x86/traps: Enable UBSAN traps on x86
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
        "H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>,
        Marco Elver <elver@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Bill Wendling
 <morbo@google.com>,
        Justin Stitt <justinstitt@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        "Mike Rapoport (IBM)" <rppt@kernel.org>, Baoquan He <bhe@redhat.com>,
        Rick Edgecombe <rick.p.edgecombe@intel.com>,
        Changbin Du <changbin.du@huawei.com>,
        Pengfei Xu <pengfei.xu@intel.com>, Xin Li <xin3.li@intel.com>,
        Jason Gunthorpe <jgg@ziepe.ca>, Uros Bizjak <ubizjak@gmail.com>,
        Arnd Bergmann <arnd@arndb.de>,
        "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-hardening@vger.kernel.org, llvm@lists.linux.dev
References: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
Content-Language: en-US
From: Xin Li <xin@zytor.com>
Autocrypt: addr=xin@zytor.com; keydata=
 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
 l75w1xInsg==
In-Reply-To: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: xin@zytor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zytor.com header.s=2024061501 header.b="Ljo5U/s3";       spf=pass
 (google.com: domain of xin@zytor.com designates 2607:7c80:54:3::138 as
 permitted sender) smtp.mailfrom=xin@zytor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=zytor.com
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

On 6/24/2024 8:24 PM, Gatlin Newhouse wrote:
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
>    - Address Thomas's remarks about: change log structure,
>      get_ud_type() instead of is_valid_bugaddr(), handle_bug()
>      changes, and handle_ubsan_failure().
> 
> Changes in v2:
>    - Name the new constants 'LEN_ASOP' and 'INSN_ASOP' instead of
>      'LEN_REX' and 'INSN_REX'
>    - Change handle_ubsan_failure() from enum bug_trap_type to void
>      function
> 
> v1: https://lore.kernel.org/linux-hardening/20240529022043.3661757-1-gatlin.newhouse@gmail.com/
> v2: https://lore.kernel.org/linux-hardening/20240601031019.3708758-1-gatlin.newhouse@gmail.com/
> ---
>   MAINTAINERS                  |  2 ++
>   arch/x86/include/asm/bug.h   | 11 ++++++++++
>   arch/x86/include/asm/ubsan.h | 23 +++++++++++++++++++++
>   arch/x86/kernel/Makefile     |  1 +
>   arch/x86/kernel/traps.c      | 40 +++++++++++++++++++++++++++++++-----
>   arch/x86/kernel/ubsan.c      | 21 +++++++++++++++++++
>   6 files changed, 93 insertions(+), 5 deletions(-)
>   create mode 100644 arch/x86/include/asm/ubsan.h
>   create mode 100644 arch/x86/kernel/ubsan.c
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 28e20975c26f..b8512887ffb1 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -22635,6 +22635,8 @@ L:	kasan-dev@googlegroups.com
>   L:	linux-hardening@vger.kernel.org
>   S:	Supported
>   T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
> +F:	arch/x86/include/asm/ubsan.h
> +F:	arch/x86/kernel/ubsan.c
>   F:	Documentation/dev-tools/ubsan.rst
>   F:	include/linux/ubsan.h
>   F:	lib/Kconfig.ubsan
> diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> index a3ec87d198ac..a363d13c263b 100644
> --- a/arch/x86/include/asm/bug.h
> +++ b/arch/x86/include/asm/bug.h
> @@ -13,6 +13,17 @@
>   #define INSN_UD2	0x0b0f
>   #define LEN_UD2		2
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
>   #ifdef CONFIG_GENERIC_BUG
>   
>   #ifdef CONFIG_X86_32
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
>   obj-$(CONFIG_AMD_MEM_ENCRYPT)		+= sev.o
>   
>   obj-$(CONFIG_CFI_CLANG)			+= cfi.o
> +obj-$(CONFIG_UBSAN_TRAP)		+= ubsan.o
>   
>   obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o
>   
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 4fa0b17e5043..aef21287e7ed 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -67,6 +67,7 @@
>   #include <asm/vdso.h>
>   #include <asm/tdx.h>
>   #include <asm/cfi.h>
> +#include <asm/ubsan.h>
>   
>   #ifdef CONFIG_X86_64
>   #include <asm/x86_init.h>
> @@ -91,6 +92,29 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
>   	return *(unsigned short *)addr == INSN_UD2;
>   }
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

Add an empty line for better readability.

> +	insn = *(u16 *)addr;
> +	if ((insn & INSN_UD_MASK) == INSN_UD2)
> +		return BUG_UD2;

Ditto.

There are extra empty lines in tglx's suggestion.

> +	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
> +		insn = *(u16 *)(++addr);
> +
> +	// UBSAN encode the failure type in the two bytes after UD1
> +	if ((insn & INSN_UD_MASK) == INSN_UD1)
> +		return *(u16 *)(addr + LEN_UD1);
> +
> +	return BUG_UD_NONE;
> +}
> +
> +

Better to add only one empty line.

>   static nokprobe_inline int
>   do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
>   		  struct pt_regs *regs,	long error_code)
> @@ -216,6 +240,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
>   static noinstr bool handle_bug(struct pt_regs *regs)
>   {
>   	bool handled = false;
> +	int ud_type;
>   
>   	/*
>   	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
> @@ -223,7 +248,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>   	 * irqentry_enter().
>   	 */
>   	kmsan_unpoison_entry_regs(regs);
> -	if (!is_valid_bugaddr(regs->ip))
> +	ud_type = get_ud_type(regs->ip);
> +	if (ud_type == BUG_UD_NONE)
>   		return handled;
>   
>   	/*
> @@ -236,10 +262,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>   	 */
>   	if (regs->flags & X86_EFLAGS_IF)
>   		raw_local_irq_enable();
> -	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> -	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> -		regs->ip += LEN_UD2;
> -		handled = true;
> +	if (ud_type == INSN_UD2) {
> +		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> +		    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> +			regs->ip += LEN_UD2;
> +			handled = true;
> +		}
> +	} else {
> +		handle_ubsan_failure(regs, ud_type);
>   	}

Add one empty line.

>   	if (regs->flags & X86_EFLAGS_IF)
>   		raw_local_irq_disable();
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
> +	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6713e17b-8030-401a-a26f-315b4d4c94ef%40zytor.com.
