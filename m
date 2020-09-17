Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVGRRX5QKGQEMA3HY3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF1226DD06
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 15:47:01 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id l24sf528075vkk.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 06:47:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600350420; cv=pass;
        d=google.com; s=arc-20160816;
        b=bRl7JIZMugd8MXgEvBeqhgT/1kZBbDIMNt7QN1/d7i/lvV/ZDlgKrPetym9eXAZEtT
         v3axpbwMJo0WsARR6tRrKkzcdFPcR0fFICPegXDvlImwcn0IgWA8ae5qijtdZ29NSST/
         dsCp2mxkdWmEJtgoKOe6dZQ0DHJASqRYcldcj04F92b+w3+SDywJUz6TnYO3ca7I/d4d
         jGzDtf8ibjoO5CW29eYJFv4EyWjIU2mfNPVBpiEuai0ve3mTMHBSRxs2iWRW06NFoVYm
         Bqm/JSsFr8XmpE/afG4WZOW2q+8f8iga6SHLV7pULuKSMsZkpAgFiys242uprjyqKskQ
         0oWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=el01Rr5b6WQf9WP5uMeqEcPGxUgLnNanVcBkGFX3xkM=;
        b=t8aDYYy0JQPe3GyQntTdRLreoJY750fkM+YF5jMO2BAT3a0a8tcNwsBd2v5hijvS78
         TaH9R25efJQ6IOCnA1Kim/wBAJNZ6avPKM+ldWDuH5+k8X91XrFlspJfMeIBZ7544azv
         axN+W1bwtFge+PU9+Tsdga4CygQJ0RRDLVU/+770r5XFkFRiawDEbJDmQ0SKLmaVUi5O
         jW4ycrAd3F2iPzhQVwGRpltPVUBcVzJR5ESOo8Dowqgl7bL0shBZ8vBm2kZ9zaoT6UOc
         ZUhg5/7p2UGT+c/pfEPPVCdXWPxJQ2Mim9sxqNmU+l1HNXHnQnZKJf7I6/NkwO5BpQEn
         vwKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=el01Rr5b6WQf9WP5uMeqEcPGxUgLnNanVcBkGFX3xkM=;
        b=MQnvjPGcqF56uBX+fuD6+517JhLj/ziDiFoY63plCMZkDjyswE2n1eaPbgO5pvisyJ
         uEzxm/+pGq0kh+8ueMr5Jvv0QnHJTT8Yi4n802mRFOr1mK/jpRY7NI0KfYacycKtPTqy
         nygIvOsaajsxqCjizqMWWwRl456AJoIGEAy+sVkWLFdV9iEKvPoyb+B5YSHMmh1AsxgW
         nTXwS1CGS8gHSHKeReOAulBN7S6qZOxaS6yqfT+FGAo383bEs1hotnmM0IoW+98v/bta
         PM7S3ZTeYFEUlt0jPcfsnggIP5Spck8NqrBhg/zjvnwH5uUncocQG9Cmknpy9Z/PduRy
         q2SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=el01Rr5b6WQf9WP5uMeqEcPGxUgLnNanVcBkGFX3xkM=;
        b=cRANO1+O0HuvhZYcxjOhpsDJvbI3tKA0uDHEQRGtGL8WXCa3ILi+92MglhSidb5RlM
         R356svH1WtCH7+PlnQ/o2yDPVFb7tYUkChCp29MPlk8OM0c9POqQtRbcboK+OEADkKfo
         CJaUcfdJ5ZvXyMxnz0v7hCBbyfMOO2yaDRtuzBP/fJW4fubmIh/1eRiJVYPcX0/QmO0V
         exmvzSNf+kxcSl//eAuT2j1YtxuZrLnj5ssKmHLsExz+2ZVxd370P0hVmGCpSmhTaJtr
         HOUbx8kRJoXtumoseZWloehwIBGK/r1jHbX22qHVI2lmy0F80Gz5S6jbFpYsGy0qelr6
         aJYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530w2iSQuhNjMYbFPm4P7MTM2LuMRtItBZWVpRRvUJLjVKlXav65
	gowD5d0xKWuYgxULE1dAZO0=
X-Google-Smtp-Source: ABdhPJzIY6SxqNxqa5CiHfpx95zGi5HHEvHEsofTePcR3VJOOJysfmQhzF6NCOZ6nvcesitwk9kbdA==
X-Received: by 2002:ab0:2e85:: with SMTP id f5mr14849347uaa.89.1600350420525;
        Thu, 17 Sep 2020 06:47:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c899:: with SMTP id n25ls111315vkl.1.gmail; Thu, 17 Sep
 2020 06:46:59 -0700 (PDT)
X-Received: by 2002:a1f:95c4:: with SMTP id x187mr17749601vkd.10.1600350419923;
        Thu, 17 Sep 2020 06:46:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600350419; cv=none;
        d=google.com; s=arc-20160816;
        b=luVjqJwSaEN65O+re88RekxexZN1F72G5oFDJnR6aywBWFbFAdufkyHJCxoZVdSrd/
         O94UAI/rWzY2y9jlB2nuRwXaM+1fzCNaUdxFlxGZOk8D9oxYQT/+znN52YBfnL0d2DO3
         tMWtvAi1kp7DOEiWC6T2s/SjtyPYV+iBDmG5db7ilN2CczJF56GxA40Rsop0A6YW/WCa
         x8qK/8QVeGKohb0eygNU2T7llpMsw9fKtwJKCt531r+QAgMjafW9ZEgbnf+6gdccpg15
         VhKCnJml2YsPM02TIiDHKmaItJbTIm8Te0GkSYf5PSG8onLGASGI7FaHnI9Po8FqvR7a
         88JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=KI/XpJJHDCr9FLBvF9XxL5sp6B7yUUk4gIFqT0xGFLQ=;
        b=a2403LNNLexw80NFwSlsiGTD8MwPjiNvirZVA2p2BeV2T3+3AqxL/URX5dV0PNVNp5
         K3ITmeZsydH/AHGfzSHgRB+raQySNSFKNGqx0WXS6F6nGczV1RtTTOXbmlHc+h8rWyef
         o0vzWvI7RaylMVF7AOgEc3BAK/Y6ZmJ/+MCohiO7diccs+TEQ7ctCbGguCnEwrUjtx+P
         8tcrnyGnuy82FE4ERws1UEh5g1eTLC198gv7VnYgOaFcl8CorX7uL8j17aIhPwVAq9Al
         YvIyC4Go8jR9w60Y3Rwbenof1zL6wy5RAU6qYTpraDCdTBxwLFClB0BxgC04k2ofOiye
         fLhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p129si1316418vkg.3.2020.09.17.06.46.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 06:46:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E42FE206DB;
	Thu, 17 Sep 2020 13:46:55 +0000 (UTC)
Date: Thu, 17 Sep 2020 14:46:53 +0100
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
Subject: Re: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200917134653.GB10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
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

On Tue, Sep 15, 2020 at 11:16:04PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/include/asm/mte-helpers.h b/arch/arm64/include/asm/mte-helpers.h
> new file mode 100644
> index 000000000000..5dc2d443851b
> --- /dev/null
> +++ b/arch/arm64/include/asm/mte-helpers.h
> @@ -0,0 +1,48 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Copyright (C) 2020 ARM Ltd.
> + */
> +#ifndef __ASM_MTE_ASM_H
> +#define __ASM_MTE_ASM_H
> +
> +#define __MTE_PREAMBLE		".arch armv8.5-a\n.arch_extension memtag\n"

Because of how the .arch overrides a previous .arch, we should follow
the ARM64_ASM_PREAMBLE introduced in commit 1764c3edc668 ("arm64: use a
common .arch preamble for inline assembly"). The above should be
something like:

#define __MTE_PREAMBLE	ARM64_ASM_PREAMBLE ".arch_extension memtag"

with the ARM64_ASM_PREAMBLE adjusted to armv8.5-a if available.

> +#define MTE_GRANULE_SIZE	UL(16)
> +#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
> +#define MTE_TAG_SHIFT		56
> +#define MTE_TAG_SIZE		4
> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)

In v1 I suggested we keep those definitions in mte-def.h (or
mte-hwdef.h) so that they can be included in cache.h. Anything else
should go in mte.h, I don't see the point of two headers for various MTE
function prototypes.

> +
> +#ifndef __ASSEMBLY__
> +
> +#include <linux/types.h>
> +
> +#ifdef CONFIG_ARM64_MTE
> +
> +#define mte_get_ptr_tag(ptr)	((u8)(((u64)(ptr)) >> MTE_TAG_SHIFT))

I wonder whether this could also be an inline function that takes a void
*ptr.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 52a0638ed967..e238ffde2679 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -72,6 +74,52 @@ int memcmp_pages(struct page *page1, struct page *page2)
>  	return ret;
>  }
>  
> +u8 mte_get_mem_tag(void *addr)
> +{
> +	if (system_supports_mte())
> +		asm volatile(ALTERNATIVE("ldr %0, [%0]",
> +					 __MTE_PREAMBLE "ldg %0, [%0]",
> +					 ARM64_MTE)
> +			     : "+r" (addr));

This doesn't do what you think it does. LDG indeed reads the tag from
memory but LDR loads the actual data at that address. Instead of the
first LDR, you may want something like "mov %0, #0xf << 56" (and use
some macros to avoid the hard-coded 56).

> +
> +	return 0xF0 | mte_get_ptr_tag(addr);
> +}
> +
> +u8 mte_get_random_tag(void)
> +{
> +	u8 tag = 0xF;
> +	u64 addr = 0;
> +
> +	if (system_supports_mte()) {
> +		asm volatile(ALTERNATIVE("add %0, %0, %0",
> +					 __MTE_PREAMBLE "irg %0, %0",
> +					 ARM64_MTE)
> +			     : "+r" (addr));

What was the intention here? The first ADD doubles the pointer value and
gets a tag out of it (possibly doubled as well, depends on the carry
from bit 55). Better use something like "orr %0, %0, #0xf << 56".

> +
> +		tag = mte_get_ptr_tag(addr);
> +	}
> +
> +	return 0xF0 | tag;

This function return seems inconsistent with the previous one. I'd
prefer the return line to be the same in both.

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
> +
> +	tag = 0xF0 | (tag & 0xF);

No point in tag & 0xf, the top nibble doesn't matter as you or 0xf0 in.

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
> index 03ca6d8b8670..cc2c3a378c00 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -149,3 +149,20 @@ SYM_FUNC_START(mte_restore_page_tags)
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
> + */
> +SYM_FUNC_START(mte_assign_mem_tag_range)
> +	/* if (src == NULL) return; */
> +	cbz	x0, 2f
> +1:	stg	x0, [x0]
> +	add	x0, x0, #MTE_GRANULE_SIZE
> +	sub	x1, x1, #MTE_GRANULE_SIZE
> +	cbnz	x1, 1b
> +2:	ret
> +SYM_FUNC_END(mte_assign_mem_tag_range)

I thought Vincenzo agreed to my comments on the previous version w.r.t.
the fist cbz and the last cbnz:

https://lore.kernel.org/linux-arm-kernel/921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com/

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917134653.GB10662%40gaia.
