Return-Path: <kasan-dev+bncBDCPL7WX3MKBB3WRY22QMGQEUJYKTJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B747994886F
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Aug 2024 06:39:12 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-8223aed78e2sf46296439f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 21:39:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722919151; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7MEm+0otJojVy8GI+O6wwbI/rNXhfj5aivV9rWsUixQOSSrZpJYg8l+Pye/LlTohm
         Zlbg8fjdfFg/3OuqXVMSDfkuwzexj7UyLBK0mg94QhMizDArJscuVfaDQUaTLmqXA2xo
         1gamZ37xCjAAKqJUBZsed95cuerloJpaHBrt/8s95vVuSPOaT5x4PFUy+DsRbXMheqTw
         JqA57sXsIPqqBZ+4fJA2rzJDgM4SSL8SDEt/ZyfjrhWzFyGbtNejnQOswu3nNC80dBVR
         xh4Tm+uGy1fLJSeJghMO05XzbxnQTpvsMn5hF8Uj1fCjS+8RMcgNPBkSRUq/9b7OyaLt
         FbKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=c6KB68Me4nytbcviSRr2glYbiMR3aTIbyu4btPAJ/VY=;
        fh=RFKGCh6KFZVql8MT9HKMo+0Ww6cUtS4GGZzyYPchU0s=;
        b=prRtW+AGfVR5TDZYEUdhoCPoQYJPL294TcJaSpjCNA50KRweQaSU+S/Nj67fz/n+cE
         1bDn/8bvGoGeyqiDOYgPeiFhxNGD8kWvQjAk0qd+JqUq9Ml/7vz3oy/802htIS7X7/Nz
         l7Bcnt3e16ODbxSRuB59Igflh9For1ugBJjqtsyxjA+9ZL+Xd9sF7dMzHUkob835xf0b
         aVvh2VxHJMDTFo8Wn5jhx3Sj7d01wObFFfH5WUgtacVyFco+blyoMxYKWRcLSFXWf2AW
         ZfpWO0PNgeZXl8b/SVzsV9gCv5NSWwoWyzEssy/tmnfWBSXry7+3b475aczXoqG36aIr
         4tbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y5kGYjEm;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722919151; x=1723523951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c6KB68Me4nytbcviSRr2glYbiMR3aTIbyu4btPAJ/VY=;
        b=dIoKG7h4EgkGXf1M3BinV8UX/TQpY6jtneGSCLwB0dlG97sySZxdW+A69Xv4XdK7Ug
         qfu4JlnoVgg1BtmVk0Rpp3Wd2KXkFNKTD2rFARE5xoC6mtXQiM/B2s+HEx1L1jMRU5+9
         3hEBhW9DywPAKFtEWRFZGcZozMqudGveMApFkJ7cCPC5Q87fx/opg4ZfPXn+90r18hrm
         k5VlhehyLrBhSHXKMBKoiA7vtHN5MYakUSHWzRsjSCFLsPm08dw858//WcTtG2b9W08D
         Ys9waV3pzYep9ddveFMf5kHS9OQB67EPTUTTv3ngviWzvuN7J4KM09pmH3k1pGfp78xY
         BQog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722919151; x=1723523951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c6KB68Me4nytbcviSRr2glYbiMR3aTIbyu4btPAJ/VY=;
        b=XIvXGJb4VFCryGmaPZW+2FLLTin/vI4iDmfb5k6wvBFTqDREXknI/yrVi4/ry3p3hT
         p1MJw1LlpY4FlvvWkm201a0SSbuqtepyD0sxgjyO7zHWzZYYgbCwRPfQ8uqljMHYzaEs
         XDblhTbAfijxuy3LIkSzVBkK8xALyqlUGP4atmqvC+Pauh3Q5rxaywvLVsqA9eNcoRHN
         xcezDzSjY6RlyKWsjd9WSNzhpSdZ5jvmFO/9p+v9UV7svtCfmrOfw0gP6eJZOqECqC2V
         vsYit6GxcKMYU8fLD3x9vUIS5n/vvQ21OTjmWK5wKaura86BWbNJnxCX5LKNQvnFK8XU
         zBDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdiRu7KI7+vtjdesKuEMm275hxAlpwgI/F7f8B2Y4/sbSrlBitLF8K6rDQ/xkwukKgSb8lV9uxrrvQ29gXo9BH/+tymAuWlA==
X-Gm-Message-State: AOJu0YwAV0OkCM8xnygB6to/uLAJZxtkl9pWZijKd5HVjmeiebcUewte
	aaPPEFeOyWaUogSDkuinR2t7gOaP3saHQLQRxrCHkuK+hIYRo+9a
X-Google-Smtp-Source: AGHT+IH9LObcwA/7y9zDCwjXo4Uq/fS/NRyh13/gIJRjjTnZEpKuYmhwnlVqXtZaOxqzRxdA4matEQ==
X-Received: by 2002:a05:6e02:ccf:b0:39b:25de:8093 with SMTP id e9e14a558f8ab-39b25de817fmr94869495ab.17.1722919150999;
        Mon, 05 Aug 2024 21:39:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d344:0:b0:39a:fa27:f0f with SMTP id e9e14a558f8ab-39b29ed545els19892155ab.1.-pod-prod-01-us;
 Mon, 05 Aug 2024 21:39:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWn8SD7bwJ76kcCTN5IUMu2qZokj1p0sjKft5YxdjZgyXDKHQDJhhdI1reVyzNCOyb9F7jCTDL/xJiWjMtgMYchN/eOTBKVJYb75A==
X-Received: by 2002:a05:6e02:1a89:b0:375:c9f0:5297 with SMTP id e9e14a558f8ab-39b1fc12d54mr182763665ab.26.1722919150100;
        Mon, 05 Aug 2024 21:39:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722919150; cv=none;
        d=google.com; s=arc-20160816;
        b=mwRg/Bft7miWBgqv+EA1NNQvc7oWv4yp+EKLrcpF+mUZDsjWHP/ZbgtvHwo3j3Xf7a
         QZPBd7eBmSSFFHqWvasJyiOQa2mdWGKFBj6Ik77aWc1vBQ+i81qcCxKuiMNu8xAOKi6L
         YdlUCmcJJwpA4fLs40m2i61odB7yavGNteLhNfb/3WnQHXAwjXxDIWuqx/49bcvWWCVW
         Or0RbwSacA5Rs8ASOuWO3fK01FSi8GiIByzT56aETpqxShMkPXx3ijswGND4ue1dxhRe
         l8nHthuwHg5dhtRvUojOqwM9pvMKBZxrzO+WsyNqh8Fn+ZojSla/uEbs5SoKRsWI9Z9W
         LXhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xzm0u0h8h/fzYLjTkhBWq7Mp2l0lj9TMrQrAgNBSIv8=;
        fh=vLhEyEHu/Y0k70QMBd3xOA4LXIl+iTwJ315V4KxJZTo=;
        b=UW5uWYaqyRvg6FwvyzCE75HdtHd1RsJ6Wd2828i0ap3yvIJky/l5i/76E5BHl+xCkx
         aiD6n8DQ6v5n88FS/SNq3xuQzhn/uDi7bJ205Kh/+4nwemo/Eu8ncIuz5uJiK/MAxfVw
         PbYn8/ZerczCBKLVMesUwsUiYile5HdDYEnoN3Qcq76ttb8+B6ynydtqto2xfxD1FM/u
         +kpOGqThOvYeFLXKwc9Dr4vnPkMyup7MJArW/0pFYuQvAryPM1KGXzyOj+rVuUhqOhMv
         b9nzNk5t1728HX31EaEy4BFhsOQnSRoit2EZc5qu+3wqKRaDrHWV8/8RY5IIQnjj7R/V
         Baig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y5kGYjEm;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4c8d6a1ff32si339955173.4.2024.08.05.21.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Aug 2024 21:39:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id E6E36CE0B93;
	Tue,  6 Aug 2024 04:39:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1E3AFC32786;
	Tue,  6 Aug 2024 04:39:06 +0000 (UTC)
Date: Mon, 5 Aug 2024 21:39:05 -0700
From: Kees Cook <kees@kernel.org>
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Marco Elver <elver@google.com>,
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
Message-ID: <202408052138.EB7B9788E3@keescook>
References: <20240724000206.451425-1-gatlin.newhouse@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240724000206.451425-1-gatlin.newhouse@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Y5kGYjEm;       spf=pass
 (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
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
> Changes in v5:
>   - Added references to the LLVM commits in the commit message from
>     Kees and Marco's feedback
>   - Renamed incorrect defines, and removed handle_ubsan_failure()'s
>     duplicated work per Peter's feedback

Ping to the x86 maintainers... can someone pick this up? It looks like
all the feedback has been addressed.

Thanks!

-Kees

> 
> Changes in v4:
>   - Implement Peter's suggestions for decode_bug(), and fix
>     inconsistent capitalization in hex values.
> 
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
> v3: https://lore.kernel.org/linux-hardening/20240625032509.4155839-1-gatlin.newhouse@gmail.com/
> v4: https://lore.kernel.org/linux-hardening/20240710203250.238782-1-gatlin.newhouse@gmail.com/
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
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202408052138.EB7B9788E3%40keescook.
