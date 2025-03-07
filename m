Return-Path: <kasan-dev+bncBCZP5TXROEIMJ3VKXYDBUBA5DMEWG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id D91F6A5633B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 10:07:17 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5f8d5e499a5sf1200979eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 01:07:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741338436; cv=pass;
        d=google.com; s=arc-20240605;
        b=CUR/raVTT9B2zW8RnltCPHnYroUvCKLbRmm9TxJTwU9d05IVHk0tUeLaMk2WXMzzUl
         8qKPkv0N7PBOu99bKjgonA3LHDvvEdNcWANSzpkCie/VTUM3d6LD222hcAA03FflGuSs
         gK27DLBrqJ3SDWC392WyMbV4PO9CNgliyquyycPZL2LD32fhvQoPf3sv58PLDkKIF30q
         4S0W2WUuknSt1bPijSnV8ROMyShaBDKppcRxWB3JfOoshk35KA91XPaxOQA7xLsndctZ
         p3sZr/TjZz/+6W3VkIoDW/xjP7QrlKwFaCEyxYlWpRFWAL0QU8lAnKnQh75MTsDEnjSG
         kYFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=RHCMFiB74CJR5ddjUo1wnzslaZSbjYEbBNY14ncQwjc=;
        fh=fXoLWTKt4nAacZHmcpsWKB+opnhR3i2Z0OMCz0xhfCI=;
        b=YGQVqBcKA8XSxKIrSWSwWNqGW42Vy3s/hGMorg/wGo2qKFQnVA2bYMNEwoZUiM7sDT
         ZwiMuohzo2XEY5PdS2rHfU7pYUBf/qCud1ee63vXZGwYrFL09wOtHuWyk22QJ0+5JAOm
         l/HXlSlUJ338mZmvL4YYOaBV9I5jle9krlmAmzXSytLqjFiG9jRHw+8gONtcq/uxvN51
         8aa7fVLC1VtBYbgI2h2j3C0hPHe1H9mTQpMP8eb2Em5wz9geVP3muJ0oIQVTYNdNdsbM
         aPeJJ3aoFECP5efUepmWGf83fkyG679g46nlAxyWCs//fqE0Agzw72Gyo0EWlBdauOe+
         5MCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741338436; x=1741943236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RHCMFiB74CJR5ddjUo1wnzslaZSbjYEbBNY14ncQwjc=;
        b=Zwqddk8ShbM2/tuy5yio9CczHL0xEGjtrAKCM4vcQxhS1MXft/qQ3HmJH8Z63ulCTR
         YLlZJhMgcFk8JA2RvpYumq6Ov/trwCq2/csUy++h+ol4LlChK5XMo7Ox/WPO5Cj2+CTw
         Gfby0ZsbFG9DY351Ud+WPDuFk/puaEwpT0IRRk8vU7FVSQyLG4sW8Fn3weCgsA8aye53
         JoMqXpmfUfRnG80vkJrdds/aANZ4QU9F4rc8makbv+BtQDkhjPCk4I6rLJ9kpdX14Qe/
         MivE3CY4ZqcE6QrcoaG/0iDf+DHAeoNH6zHpK8XGMb7CeCb0iAbA190ZLC9yDdoJ5D0x
         hDZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741338436; x=1741943236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RHCMFiB74CJR5ddjUo1wnzslaZSbjYEbBNY14ncQwjc=;
        b=lezjc36HNEtqh2IO0SoRe5Nd7jKiF0D8dFz3cWIFiINXoQnrdFCpKlwUqyEHlvRhGj
         thsYfE8lq3yRoMMrqdPE/jQLfq3lkl0+lDXfTHWlgONEklWHbHVpJAoxxxQyomdQPltk
         iuc8K0+vtjD0ENbXlhJclUc575tAiEylHdfKnBWkrg2YJMsJpNCESYIWpiy/OqeQogdj
         FWFZo82Q343nJHUNWIyD4oy/67DCs/tWnu8gBHrSoYI3ZqJM+Hkqfy2TJOhuaAz7JbUi
         p5t2AeGhwFsGFou1BhDMwLhEWYpGl8xQGEgKm+J2OFdhZWjijHn89NLwmRJWTeqzJYWn
         aPhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEoOXx05f4rc91rRSclE6pZOIZ3uV/oOqnMD8Hqd9pj2Uu1s1hbiMLJ/pLlP/1prM6ZwwkZw==@lfdr.de
X-Gm-Message-State: AOJu0YwNyA+7DU09HKOtVLkJlKh6aw5kLlGWCw/RobkqHSdAj4nxTftm
	v6iqcexFJXd43bQd6MtbYh1Hl5mqYI0FsylnKXwyWuD+WXANM0Jk
X-Google-Smtp-Source: AGHT+IHsHQHuI/TQHw1AaC6HMudi5PxtEDPbD6vVI+3IaloIe6HDJxyyjxv4OFtpUbPY80v9yDOLTw==
X-Received: by 2002:a05:6820:3094:b0:600:22bc:c1fa with SMTP id 006d021491bc7-6004ab31ef4mr1384790eaf.7.1741338436439;
        Fri, 07 Mar 2025 01:07:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGfrLBSdhp9QTspB0Qa/pLZfpy1rskeni00YkYm/VnUMw==
Received: by 2002:a4a:d518:0:b0:600:33e3:2af with SMTP id 006d021491bc7-6003e8f62e4ls521083eaf.0.-pod-prod-08-us;
 Fri, 07 Mar 2025 01:07:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNPWtyC4uZ7ntC4JREQEhmBgnQ7qsHVkH2PWB9wQ5gqEnTkl4+SMdjiWspSKpa8CZGDtl4I8otkqs=@googlegroups.com
X-Received: by 2002:a05:6808:1892:b0:3f4:1b5f:9336 with SMTP id 5614622812f47-3f697b644cemr1406338b6e.10.1741338435596;
        Fri, 07 Mar 2025 01:07:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741338435; cv=none;
        d=google.com; s=arc-20240605;
        b=TYpiCC4c58LNYBHo5TMG+yEkyAsWQBHLUFB4aT5Wp0PcRflAwCxpU00st7EgH1SXCn
         q3cMSWv2tYETiv/PzO3lsaxVzXh/RKDo98rcHFcX6mX3GRN+eVL49+pr/IV4+09C9W6u
         9B6oEtMzkWhlRgQgedHi+TiT01Lg65jAb87E0jC6GHvmPswIegh23WjGYVXGrjDc+nx4
         waeOX4uV1uRoerwa7jGlssENIz/X5zHLuxqSIN8RuqeknsKmW9YATQyiNSM7lwJxi9KS
         9yPpph4t5bI7qPtIDACmOX9sIL3jRhqFea65n2VWClYjHNLHBEqihDqSSq2kfNxEk5vd
         ji5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=WHf5FFAAcATTZsznptblZdtF/anAAwBJP/EZERYjSoI=;
        fh=WQ/4LlNvRYk7GpW6Y67Fysgqcy+1C3BQj2nMT7+mA3M=;
        b=KyYF/xyov93Jp+x0rq5wekDFuApAXwHn5fmO5FHyKyMVcrn9/fFqNbuLEeLN7VXqLi
         4pcX1SxAmnICFQdeUExXmzdZiM3KNp4+fgDDA13MYCPMPCAJWmXRePoV/A3Q/MWsvMVw
         UY2vmqFgbBNdEH/X683jd8mbrmcAcjsC1jR7f7IJAkuECmtejeZRB1Tp3ikg7CAqomMN
         X2eQdT9uL1ozuxFjK1AW3oZD7B29v+Lbg8BJ8nq12OafjSQ3PIaMstpz1JdV5+DxsLJj
         UqPANaC8ZPWxNUkfI4BOPwTnJQGgN6E1O9D2eW/MgOCZ8uZlyqY0+vn78U5AGrEPTarb
         S28w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 5614622812f47-3f68ef944fbsi137359b6e.2.2025.03.07.01.07.15
        for <kasan-dev@googlegroups.com>;
        Fri, 07 Mar 2025 01:07:15 -0800 (PST)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BAC561477;
	Fri,  7 Mar 2025 01:07:27 -0800 (PST)
Received: from [10.57.84.99] (unknown [10.57.84.99])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EF7E83F66E;
	Fri,  7 Mar 2025 01:07:12 -0800 (PST)
Message-ID: <17931f83-7142-4ca6-8bfe-466ec53b6e2c@arm.com>
Date: Fri, 7 Mar 2025 09:07:11 +0000
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
To: Anshuman Khandual <anshuman.khandual@arm.com>,
 linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
Content-Language: en-GB
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20250307050851.4034393-1-anshuman.khandual@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
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

On 07/03/2025 05:08, Anshuman Khandual wrote:
> Address bytes shifted with a single 64 bit page table entry (any page table
> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
> is not very readable or easy to reason about. Besides it is going to change
> with D128, where each 128 bit page table entry will shift address bytes by
> 4 (aka 2^4 = 16) instead.
> 
> Let's just formalise this address bytes shift value into a new macro called
> PTE_SHIFT establishing a logical abstraction, thus improving readability as
> well. This does not cause any functional change.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: linux-arm-kernel@lists.infradead.org
> Cc: linux-kernel@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>


+1 for PTDESC_ORDER

Implementation looks good to me so:

Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

one nit below.

> ---
> This patch applies on v6.14-rc5
> 
>  arch/arm64/Kconfig                      |  2 +-
>  arch/arm64/include/asm/kernel-pgtable.h |  3 ++-
>  arch/arm64/include/asm/pgtable-hwdef.h  | 26 +++++++++++++------------
>  arch/arm64/kernel/pi/map_range.c        |  2 +-
>  arch/arm64/mm/kasan_init.c              |  6 +++---
>  5 files changed, 21 insertions(+), 18 deletions(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 940343beb3d4..fd3303f2ccda 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
>  	default 18
>  
>  # max bits determined by the following formula:
> -#  VA_BITS - PAGE_SHIFT - 3
> +#  VA_BITS - PAGE_SHIFT - PTE_SHIFT
>  config ARCH_MMAP_RND_BITS_MAX
>  	default 19 if ARM64_VA_BITS=36
>  	default 24 if ARM64_VA_BITS=39
> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
> index fd5a08450b12..7150a7a10f00 100644
> --- a/arch/arm64/include/asm/kernel-pgtable.h
> +++ b/arch/arm64/include/asm/kernel-pgtable.h
> @@ -49,7 +49,8 @@
>  	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
>  
>  #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
> -	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
> +	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
> +	lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)

nit: not sure what style guide says, but I would indent this continuation an
extra level.

Thanks,
Ryan

>  
>  #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
>  	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
> index a9136cc551cc..43f98eac7653 100644
> --- a/arch/arm64/include/asm/pgtable-hwdef.h
> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
> @@ -7,40 +7,42 @@
>  
>  #include <asm/memory.h>
>  
> +#define PTE_SHIFT 3
> +
>  /*
>   * Number of page-table levels required to address 'va_bits' wide
>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
> + * bits with (PAGE_SHIFT - PTE_SHIFT) bits at each page table level. Hence:
>   *
> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTE_SHIFT))
>   *
>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>   *
>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>   * due to build issues. So we open code DIV_ROUND_UP here:
>   *
> - *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
> + *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTE_SHIFT) - 1) / (PAGE_SHIFT - PTE_SHIFT))
>   *
>   * which gets simplified as :
>   */
> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - PTE_SHIFT - 1) / (PAGE_SHIFT - PTE_SHIFT))
>  
>  /*
>   * Size mapped by an entry at level n ( -1 <= n <= 3)
> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
> + * We map (PAGE_SHIFT - PTE_SHIFT) at all translation levels and PAGE_SHIFT bits
>   * in the final page. The maximum number of translation levels supported by
>   * the architecture is 5. Hence, starting at level n, we have further
>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>   * So, the total number of bits mapped by an entry at level n is :
>   *
> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTE_SHIFT) + PAGE_SHIFT
>   *
>   * Rearranging it a bit we get :
> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
> + *   (4 - n) * (PAGE_SHIFT - PTE_SHIFT) + PTE_SHIFT
>   */
> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTE_SHIFT) * (4 - (n)) + PTE_SHIFT)
>  
> -#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTE_SHIFT))
>  
>  /*
>   * PMD_SHIFT determines the size a level 2 page table entry can map.
> @@ -49,7 +51,7 @@
>  #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>  #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
>  #define PMD_MASK		(~(PMD_SIZE-1))
> -#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>  
>  /*
> @@ -59,14 +61,14 @@
>  #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>  #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
>  #define PUD_MASK		(~(PUD_SIZE-1))
> -#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>  
>  #if CONFIG_PGTABLE_LEVELS > 4
>  #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>  #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
>  #define P4D_MASK		(~(P4D_SIZE-1))
> -#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>  
>  /*
> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
> index 2b69e3beeef8..3530a5427f57 100644
> --- a/arch/arm64/kernel/pi/map_range.c
> +++ b/arch/arm64/kernel/pi/map_range.c
> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>  {
>  	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>  	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
> -	int lshift = (3 - level) * (PAGE_SHIFT - 3);
> +	int lshift = (3 - level) * (PAGE_SHIFT - PTE_SHIFT);
>  	u64 lmask = (PAGE_SIZE << lshift) - 1;
>  
>  	start	&= PAGE_MASK;
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b65a29440a0c..90548079b42e 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>   */
>  static bool __init root_level_aligned(u64 addr)
>  {
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>  
>  	return (addr % (PAGE_SIZE << shift)) == 0;
>  }
> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>  	 */
>  	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>  							: vabits_actual;
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>  
>  	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>  }
> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>   */
>  static int __init next_level_idx(u64 addr)
>  {
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTE_SHIFT);
>  
>  	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/17931f83-7142-4ca6-8bfe-466ec53b6e2c%40arm.com.
