Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZEGW75QKGQEUV4L72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 328372784D6
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 12:16:06 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id c197sf1748699pfb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 03:16:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601028965; cv=pass;
        d=google.com; s=arc-20160816;
        b=TnjsJRyp23uAZM/dHlC9xNXEMfJiuUdB/97Z2xaB/qt2SUuwa6cJF5DnspuxFivQdV
         rg4vi5K6M4/XXpugNT4aT1+/HtGM9F2BGAfLCl5+naZKxT0cmIbQ5X9/wsKG8YVI5yJ0
         dxSEhNX8HjB9qtDpqLQ/ueBBnKlEj4QGp6vrXCUEIh+HuiFzGT8Yur+/aSaW1cZ1QKyv
         09PvuIrqHYMd2eXlux766lG0+gfm7UP92WP44SlqteV0GDvt5dZ7FazKomceKWdMtxUI
         4IhLWQkU9qHrfmy8OD2npyU0R8O2fgawU03jfk27kh/vAAsywclbvo4fjgfXRurK8ZQs
         jANw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=BBfpQD6G14F8Bc2xbBf8jrH40WNPo6ioVjVBCSvhBaw=;
        b=TYhKR7BdlQJka6pkHt+DxyNC+Ej0+QFR3E6Paac0h2j6bj1byRv3DGi6h8zX9LDUnC
         iprfCyyb5aWiLXrgnd44fj64buTbBLCKTvpKqCv7KMNyn6dv3zTCnpJtI99SaMIoaoNF
         uUel9IbTSkzzdWeK++5KKq/88/rWUfFuU4ysMt/fLN+ZeHZ6qyCcngnBYqJ7tB9KUKWU
         vrYxZvfc+qwZMK8EPFl1+0ra6u+OAQxQrKwOG/kPY6t0jz25aO+spOE2QLuB59xL/l7T
         yurkitg7sjGqZ00aSHv5tspzNwLkYZchbIdvX2drEM9APvSv8ED/O/c7W4JR0vUU/x2W
         bz6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BBfpQD6G14F8Bc2xbBf8jrH40WNPo6ioVjVBCSvhBaw=;
        b=P+lC5B7Vn5XhgWo7/LwYE//0R2HCL3OCrSTyJ5ok+WcZa1kcktgoj/32OqVWGEWzww
         96EPWHNcQVf5/CQYW+jcCq/g7CJQaOaWTCLPMTRzyBmY3GLbJ4p8o3hiANx4BqRcTg3q
         Dh83ZRssiiNI50RQ7F/vmVMtwLFHecdTaMnfbaSM2PBobYF1FgGd8PwMAFcs85zXu3lc
         3AFnRWB/Ve7zOeC+8LERsTw5Bw2W6JyrCLe9GpMQ7kd3edbeJY7oXaNsTRw0Uq/qxcQV
         1+1jWsYpx7BMXTf4CICAguDYi+m9C/PtnVnAK8l3Vz3uzBOmdtjHl68QEAv6VOFHg+S5
         DScw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BBfpQD6G14F8Bc2xbBf8jrH40WNPo6ioVjVBCSvhBaw=;
        b=f5S0/Z2ocj9gAf2GOj7CdOvDOV+jspoHyilE5dzreIa2VdeksUuTOlx41yNMPXxWP5
         0nP+UFaYUH+TOV+3YwOzJ5w3/so2VjD85CjPBR6iJV9DxGl89az0P0AHUN64PmHBNz8C
         6vCIyHVF5b3lihri4f9I06sWDrQH2m6uCVamD+VyoloMqwr+HdSiFIHkOlh0rGwZORqq
         kMN+FZtlVT4+oFQzANDUvQqcFyLSV/dcLnCHsWxeRZEMdjgiyWIMVQg0rSXppeIKcrBQ
         bzLum+iZXgWhRJT08tqzC+HB3ACiXWDRa0ZDxOcxla0wUffbsUz9gXMCmvQpPUnNdnkN
         +TXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fC3IA6EJipHI1rzkvzs5teEFY3CbNu54oVKP+dh+2rBbyqGDE
	vpOAKBPmggfxLom6+dMtiNE=
X-Google-Smtp-Source: ABdhPJy4F/g94c+TzS0xx/bn03a0M22x3FAw9csSz17tMZ5F2iriRqD7uhbG1brias5XpjzQ8Htemg==
X-Received: by 2002:a17:90b:b8f:: with SMTP id bd15mr2004453pjb.65.1601028964829;
        Fri, 25 Sep 2020 03:16:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e303:: with SMTP id x3ls1101483pjy.2.gmail; Fri, 25
 Sep 2020 03:16:04 -0700 (PDT)
X-Received: by 2002:a17:90a:448a:: with SMTP id t10mr2025830pjg.19.1601028964193;
        Fri, 25 Sep 2020 03:16:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601028964; cv=none;
        d=google.com; s=arc-20160816;
        b=YcUiNAHWpfqF+MEVHb3Ru6wKp/Vx+bVh3aEcrXFbR3dSwT1uemsvuThwztvYnb3Z4j
         +yS5mWgvmjy+y2+82Djzy1Kvvuhy2PgYuoYXlXQ8BIdCo+BqhoAuFZXuRmJhaRAtQAXP
         faY+Hb8qFUZmR7GbSYleIA/Upx+5IGaVjVkvccCilawApZ5XFEZQbDt9GHujb8oryv+L
         LmNtJ1ud+3895uID0EqQCcSNjC0+2UdrNoN4eLM3SDhn0+GHJi5DCpAldLglX8ETNYA/
         p6Vj8mQC6KqwlFsaK7dHoBiJ8DuNAay7TGRtB6cy6R7hAPJ6YizoGbxoPzBXewMRKb2F
         5uBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=vW1h8GDdFY7AuUhpUT6LrDC3lRvlVMvIfBGM+Ie9teE=;
        b=bShaynRZRIUdR4pzE31bKjMu7/LBNmICZL39aWmoauzz0Ez4euiUIsphF7/lItHEvz
         IICmeOMAUr7b+WPfWC6g1hwi4D9cGnx5ctz5/fNqDe9GwBIbrLV79E3BU/c+H6q7h+D3
         jK5hXySPNvBsGT68h/w6gUOlmOyzyeR3YmEWOIGJo6zRR67hKzeDXmA+3iaBWUmPs+hs
         2D2iuZcjZFm90x1wFZBwa8yreI9fWb5WOJtPnl7NDrstdWrg693vl2lwCfN1dLPaAs6O
         NOBUy0SpC33atJu0WwBJBDiXl8DcrjhRl8ewU2h4/+OvP1+hL62+aN5TpsmCaHdox3IV
         U/0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lj12si149358pjb.0.2020.09.25.03.16.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 03:16:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4201620717;
	Fri, 25 Sep 2020 10:16:01 +0000 (UTC)
Date: Fri, 25 Sep 2020 11:15:58 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 24/39] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200925101558.GB4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:50:31AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
> index 035003acfa87..bc0dc66a6a27 100644
> --- a/arch/arm64/include/asm/esr.h
> +++ b/arch/arm64/include/asm/esr.h
> @@ -103,6 +103,7 @@
>  #define ESR_ELx_FSC		(0x3F)
>  #define ESR_ELx_FSC_TYPE	(0x3C)
>  #define ESR_ELx_FSC_EXTABT	(0x10)
> +#define ESR_ELx_FSC_MTE		(0x11)
>  #define ESR_ELx_FSC_SERROR	(0x11)
>  #define ESR_ELx_FSC_ACCESS	(0x08)
>  #define ESR_ELx_FSC_FAULT	(0x04)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> new file mode 100644
> index 000000000000..b0f27de8de33
> --- /dev/null
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -0,0 +1,60 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Copyright (C) 2020 ARM Ltd.
> + */
> +#ifndef __ASM_MTE_ASM_H
> +#define __ASM_MTE_ASM_H
> +
> +#include <asm/compiler.h>
> +
> +#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"

Can this not live in mte.h?

> +#define MTE_GRANULE_SIZE	UL(16)
> +#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
> +#define MTE_TAG_SHIFT		56
> +#define MTE_TAG_SIZE		4
> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)

I'd still like these MTE_* macros in a separate mte-hwdef.h file. The
only reason I see they were not in mte.h is because they need to be
included in asm/cache.h. They are not KASAN specific.

> +
> +#ifndef __ASSEMBLY__
> +
> +#include <linux/types.h>
> +
> +#ifdef CONFIG_ARM64_MTE
> +
> +static inline u8 mte_get_ptr_tag(void *ptr)
> +{
> +	u8 tag = (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
> +
> +	return tag;
> +}

So this returns the top 8 bits of the address (i.e. no masking with
MTE_TAG_MASK). Fine by me.

> +
> +u8 mte_get_mem_tag(void *addr);
> +u8 mte_get_random_tag(void);
> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> +
> +#else /* CONFIG_ARM64_MTE */
> +
> +static inline u8 mte_get_ptr_tag(void *ptr)
> +{
> +	return 0xFF;
> +}
> +
> +static inline u8 mte_get_mem_tag(void *addr)
> +{
> +	return 0xFF;
> +}
> +static inline u8 mte_get_random_tag(void)
> +{
> +	return 0xFF;
> +}
> +static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +	return addr;
> +}

Maybe these can stay in mte-kasan.h, although they are not a direct
interface for KASAN AFAICT (the arch_* equivalent are defined in
asm/memory.h. If there's no good reason, we could move them to mte.h.

> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 1c99fcadb58c..3a2bf3ccb26c 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -5,14 +5,13 @@
>  #ifndef __ASM_MTE_H
>  #define __ASM_MTE_H
>  
> -#define MTE_GRANULE_SIZE	UL(16)
> -#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
> -#define MTE_TAG_SHIFT		56
> -#define MTE_TAG_SIZE		4
> +#include <asm/mte-kasan.h>
>  
>  #ifndef __ASSEMBLY__
>  
> +#include <linux/bitfield.h>
>  #include <linux/page-flags.h>
> +#include <linux/types.h>
>  
>  #include <asm/pgtable-types.h>
>  
> @@ -45,7 +44,9 @@ long get_mte_ctrl(struct task_struct *task);
>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>  			 unsigned long addr, unsigned long data);
>  
> -#else
> +void mte_assign_mem_tag_range(void *addr, size_t size);

So mte_set_mem_tag_range() is KASAN specific but
mte_assign_mem_tag_range() is not. Slightly confusing.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 52a0638ed967..833b63fdd5e2 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -13,8 +13,10 @@
>  #include <linux/swap.h>
>  #include <linux/swapops.h>
>  #include <linux/thread_info.h>
> +#include <linux/types.h>
>  #include <linux/uio.h>
>  
> +#include <asm/barrier.h>
>  #include <asm/cpufeature.h>
>  #include <asm/mte.h>
>  #include <asm/ptrace.h>
> @@ -72,6 +74,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>  	return ret;
>  }
>  
> +u8 mte_get_mem_tag(void *addr)
> +{
> +	if (!system_supports_mte())
> +		return 0xFF;
> +
> +	asm volatile(__MTE_PREAMBLE "ldg %0, [%0]"
> +		    : "+r" (addr));

Nitpick: do we need volatile or plain asm would do?

I wonder whether we'd need the "memory" clobber. I don't see how this
would fail though, maybe later on with stack tagging if the compiler
writes tags behind our back.

> +
> +	return 0xF0 | mte_get_ptr_tag(addr);

Since mte_get_ptr_tag() returns the top byte of the address, we don't
need the additional 0xF0 or'ing. LDG only sets bits 59:56.

> +}
> +
> +u8 mte_get_random_tag(void)
> +{
> +	void *addr;
> +
> +	if (!system_supports_mte())
> +		return 0xFF;
> +
> +	asm volatile(__MTE_PREAMBLE "irg %0, %0"
> +		    : "+r" (addr));
> +
> +	return 0xF0 | mte_get_ptr_tag(addr);

Same here.

> +}
> +
> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +	void *ptr = addr;
> +
> +	if ((!system_supports_mte()) || (size == 0))
> +		return addr;
> +
> +	/* Make sure that size is aligned. */
> +	WARN_ON(size & (MTE_GRANULE_SIZE - 1));

Doesn't the address need to be aligned as well?

> +
> +	tag = 0xF0 | tag;
> +	ptr = (void *)__tag_set(ptr, tag);
> +
> +	mte_assign_mem_tag_range(ptr, size);
> +
> +	return ptr;
> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 03ca6d8b8670..aa0ab01252fe 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -149,3 +149,22 @@ SYM_FUNC_START(mte_restore_page_tags)
>  
>  	ret
>  SYM_FUNC_END(mte_restore_page_tags)
> +
> +/*
> + * Assign allocation tags for a region of memory based on the pointer tag
> + *   x0 - source pointer
> + *   x1 - size
> + *
> + * Note: size must be non-zero and MTE_GRANULE_SIZE aligned

Doesn't the address need to be aligned as well?

> + */
> +SYM_FUNC_START(mte_assign_mem_tag_range)
> +	/* if (src == NULL) return; */
> +	cbz	x0, 2f
> +	/* if (size == 0) return; */
> +	cbz	x1, 2f

I find these checks unnecessary, as I said a couple of times before,
just document the function pre-conditions. They are also incomplete
(i.e. you check for NULL but not alignment).

> +1:	stg	x0, [x0]
> +	add	x0, x0, #MTE_GRANULE_SIZE
> +	subs	x1, x1, #MTE_GRANULE_SIZE
> +	b.gt	1b
> +2:	ret
> +SYM_FUNC_END(mte_assign_mem_tag_range)
> -- 
> 2.28.0.681.g6f77f65b4e-goog

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925101558.GB4846%40gaia.
