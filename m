Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQGT56AAMGQEGN3Z5QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7868830F337
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 13:34:09 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id l12sf1618130otq.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 04:34:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612442048; cv=pass;
        d=google.com; s=arc-20160816;
        b=N/aZP7Mxvr6sJceAqYALIfmTWEnamfhKsFq8s4pv9tKzaWh3Qhe+Lr77Rt5fzJgdn4
         IG110qReO4XpYO9NeJBJyiJ/mLjUPj5amdPxFqyTQ8fU5XMF6LMgonsAzFuixv2CG4j7
         SLTV2wRlwyBkrvVBTr3pogf7vVB4WupxIYnS378SCgSZ0IFkwQLS6l0uDV7k/BCypngo
         NkGKCvZBwUwfaLlBseH17EuomCSV2fy6CXhf9CyfQYtviGBch8+SCq4YA5/v2p3Cpzp6
         hIp80DrGDhNRskm0Wnt16MzY+KWCZ5NC9qFG3abH6oHhjJH/a4dR8lWEiU0STs8Z8b7M
         ttnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GMVJWD50Av1029Unyk6KBJ/88agZIx7wFKUWABrQqoo=;
        b=hF6i/qtHbO0Jqnfv4K2ArsoV6T/8qtzOyr4pCKFGWp82ZjuAgttTNyHwNHyW/1+5aP
         1DQ6KDu7Ib8qGAlGXPfoMcOvNN7wSP0i0Oj+TD4JqY2ifYU4xMCAu/TdwVDc98sgDBJS
         7FDdUvJiNDRE74LbhlqCPD3BGJeF7bzxU3T8CajNmRmQ5FjK54AQWfNpmRJXvbn07pn6
         6slyyP2xXJ1T73w1FcScwgkSSs6IC7O0v40A499LKekgBfDN4Xsibb9m6FHC8V/5O2XZ
         hxljz9Y6jOtC4lZ/K9+CnmP/xwTh1IwPFwM+0cXw3u70hXgvEQU4EusHlEQm6xzgwKMC
         WlFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GMVJWD50Av1029Unyk6KBJ/88agZIx7wFKUWABrQqoo=;
        b=fp3D1TcuQg2aShl85mcHopJURTaEUpR7Z6eh2Tqf1IyqWwxZyP65FwGA8mNkBTLs08
         mXF90lzCnrSHNJlJvKnx7EPmjPMz1rQD8uASsfb9/oLk7Wa3An/vbRqeqDAFXUuOTppL
         c4J0L+PpjEoj17AoazOnzh+cyT20BGKjHNKOZQlgjiYYp2ikq6wZEgqOEyWoOTZK9EX5
         LremY+vLHQhQSWrB9LZH75YaUsb3SnCBySUm5yTx+TeDH9VicRJ44NxgHuNueKT4DXa0
         TLuLuaf32g0WlH/DgB9CIRLcJXefVItHmZyjXeuf8mXHHk/INbfZiicxePGsoyCk75M4
         TRyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GMVJWD50Av1029Unyk6KBJ/88agZIx7wFKUWABrQqoo=;
        b=IW8wcFSvYJQSh/WiJ5ebm6E74XzCRGZK3rEAIbud1Jg6wQt5o2bM4XNCJE+1Ws/Zjw
         BPJkeg7DoSTvurC/LX1cHXZNkTKGX6cmSroJHYD/NKwaXAy8is/S9A+p+nYLVofIVrqk
         rBSZsOKO1ae8/HdyZis5WQFscu7yb3infOG9QJizOsJNUAVNjpxRSZRZNYbi9HFb8JS3
         XP+dK8opAISCpNQUDmw8O1viC5wNrfpoC3xojM0eTPAkKjwawXdY1mNOC34y7+HF+dRu
         y6OWpsO1hE4n1WzPR5iCZpXRccjGiGeDTdVAV+6EqZSMnP7AvVXd11o0OIPTkJFi+mUt
         wPeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331kZ3h38m+/B9/CXAJP0HHYBnuxGn8rO+WEm2OgxBjLdGuzP6p
	2W8nvXWlrZIQrYV517ogPkU=
X-Google-Smtp-Source: ABdhPJw0o/wGfuz0ShiPPE3jX9YO5/a9FAkh1ednlRg54atDaE4jTsS+QdbhQpMu6+VtoH+3lzGeeA==
X-Received: by 2002:a9d:5d02:: with SMTP id b2mr5479448oti.148.1612442048435;
        Thu, 04 Feb 2021 04:34:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd82:: with SMTP id b124ls1273786oii.3.gmail; Thu, 04
 Feb 2021 04:34:08 -0800 (PST)
X-Received: by 2002:aca:5e84:: with SMTP id s126mr5175750oib.175.1612442047994;
        Thu, 04 Feb 2021 04:34:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612442047; cv=none;
        d=google.com; s=arc-20160816;
        b=kQqtBnR+cSQB5lT1ysKv1u4sd+DLJj/CGHXmDSzHxg5Fur0VWOmLqRgXz/AGyM/XzN
         cboECHeXB4m8D9HUY1Q3k6XYiRc62ZtDf4L1nY9f4UBwlNKs+n5ZW2Bo8XJGYFQaoEdw
         FoNGmPvLpUJmZwVAG3OkIi2MHVz1vlkvTmLg1ZBi2j7MllPKzrbal0Ta2j0mmU+r9yuE
         tMwEoQ5tmc7ZV9ORwZnt+CWXcC1PtUMjCYQpXG9ucXJ3vCaCufMiB8olA6hLUVqKW+Rj
         MAHo5lJnC6kEvS/3Mb6OS+GLnrwB6kqAtIdTpAiaOIqOUd60L4U0fa05v4tLyzjbfo8n
         jxJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ICxUQcV5dxjenJtM5BYXjOsCd+9HPE1AnzJLSoAy1MI=;
        b=Ys5zijZMfxTM/ROr276OPYvwEzJ0s0+S8Bma7aF7WblmtMZIGgd7jCSN0ZTz8muoVW
         L/WzBOL3FQNYK58qP/ZP2hMcHmSqlsgtFRKi+hlygXekdTKu5eQ3JWox+MyRonhWc7wV
         efxqLOKbC6C3o6R6Zhp9u5Fe+L2Zd2tnUpx4N4+O1ZciRxFdfkI6yjBrri4ITJl+oKVx
         Ga8fjCfrvoYLkeXZc4yakrNlqWOZYDCXdtRjldyov32XnMQPlJuuCPCl4Y114Nhg8474
         rTo9L8xyB3N5of9THk1uLTT5P5jq7XM1DdYfCBzggD5yMusIhqfjGKEl58y7pP6AtjNA
         wOzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e184si456187oif.0.2021.02.04.04.34.07
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Feb 2021 04:34:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C759D6E;
	Thu,  4 Feb 2021 04:34:07 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 60DA13F73B;
	Thu,  4 Feb 2021 04:34:05 -0800 (PST)
Subject: Re: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will.deacon@arm.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1612208222.git.andreyknvl@google.com>
 <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <074b893e-beea-8fcc-75df-778d29331236@arm.com>
Date: Thu, 4 Feb 2021 12:37:46 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 2/1/21 7:43 PM, Andrey Konovalov wrote:
> This change provides a simpler implementation of mte_get_mem_tag(),
> mte_get_random_tag(), and mte_set_mem_tag_range().
> 
> Simplifications include removing system_supports_mte() checks as these
> functions are onlye called from KASAN runtime that had already checked
> system_supports_mte(). Besides that, size and address alignment checks
> are removed from mte_set_mem_tag_range(), as KASAN now does those.
> 
> This change also moves these functions into the asm/mte-kasan.h header
> and implements mte_set_mem_tag_range() via inline assembly to avoid
> unnecessary functions calls.
> 
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/include/asm/cache.h     |  1 -
>  arch/arm64/include/asm/kasan.h     |  1 +
>  arch/arm64/include/asm/mte-def.h   |  2 +
>  arch/arm64/include/asm/mte-kasan.h | 64 ++++++++++++++++++++++++++----
>  arch/arm64/include/asm/mte.h       |  2 -
>  arch/arm64/kernel/mte.c            | 46 ---------------------
>  arch/arm64/lib/mte.S               | 16 --------
>  7 files changed, 60 insertions(+), 72 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> index 77cbbe3625f2..a074459f8f2f 100644
> --- a/arch/arm64/include/asm/cache.h
> +++ b/arch/arm64/include/asm/cache.h
> @@ -6,7 +6,6 @@
>  #define __ASM_CACHE_H
>  
>  #include <asm/cputype.h>
> -#include <asm/mte-kasan.h>
>  
>  #define CTR_L1IP_SHIFT		14
>  #define CTR_L1IP_MASK		3
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
> index 0aaf9044cd6a..12d5f47f7dbe 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -6,6 +6,7 @@
>  
>  #include <linux/linkage.h>
>  #include <asm/memory.h>
> +#include <asm/mte-kasan.h>
>  #include <asm/pgtable-types.h>
>  
>  #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
> diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
> index 2d73a1612f09..cf241b0f0a42 100644
> --- a/arch/arm64/include/asm/mte-def.h
> +++ b/arch/arm64/include/asm/mte-def.h
> @@ -11,4 +11,6 @@
>  #define MTE_TAG_SIZE		4
>  #define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
>  
> +#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
> +
>  #endif /* __ASM_MTE_DEF_H  */
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 8ad981069afb..1f090beda7e6 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -11,13 +11,16 @@
>  
>  #include <linux/types.h>
>  
> +#ifdef CONFIG_ARM64_MTE
> +
>  /*
> - * The functions below are meant to be used only for the
> - * KASAN_HW_TAGS interface defined in asm/memory.h.
> + * These functions are meant to be only used from KASAN runtime through
> + * the arch_*() interface defined in asm/memory.h.
> + * These functions don't include system_supports_mte() checks,
> + * as KASAN only calls them when MTE is supported and enabled.
>   */
> -#ifdef CONFIG_ARM64_MTE
>  
> -static inline u8 mte_get_ptr_tag(void *ptr)
> +static __always_inline u8 mte_get_ptr_tag(void *ptr)
>  {
>  	/* Note: The format of KASAN tags is 0xF<x> */
>  	u8 tag = 0xF0 | (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
> @@ -25,9 +28,54 @@ static inline u8 mte_get_ptr_tag(void *ptr)
>  	return tag;
>  }
>  
> -u8 mte_get_mem_tag(void *addr);
> -u8 mte_get_random_tag(void);
> -void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> +/* Get allocation tag for the address. */
> +static __always_inline u8 mte_get_mem_tag(void *addr)
> +{
> +	asm(__MTE_PREAMBLE "ldg %0, [%0]"
> +		: "+r" (addr));
> +
> +	return mte_get_ptr_tag(addr);
> +}
> +
> +/* Generate a random tag. */
> +static __always_inline u8 mte_get_random_tag(void)
> +{
> +	void *addr;
> +
> +	asm(__MTE_PREAMBLE "irg %0, %0"
> +		: "+r" (addr));
> +
> +	return mte_get_ptr_tag(addr);
> +}
> +
> +/*
> + * Assign allocation tags for a region of memory based on the pointer tag.
> + * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> + * size must be non-zero and MTE_GRANULE_SIZE aligned.
> + */
> +static __always_inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +	u64 curr, end;
> +
> +	if (!size)
> +		return;
> +
> +	curr = (u64)__tag_set(addr, tag);
> +	end = curr + size;
> +
> +	do {
> +		/*
> +		 * 'asm volatile' is required to prevent the compiler to move
> +		 * the statement outside of the loop.
> +		 */
> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +			     :
> +			     : "r" (curr)
> +			     : "memory");
> +
> +		curr += MTE_GRANULE_SIZE;
> +	} while (curr != end);
> +}
>  
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
> @@ -47,10 +95,12 @@ static inline u8 mte_get_mem_tag(void *addr)
>  {
>  	return 0xFF;
>  }
> +
>  static inline u8 mte_get_random_tag(void)
>  {
>  	return 0xFF;
>  }
> +
>  static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  {
>  	return addr;
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 237bb2f7309d..43169b978cd3 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -8,8 +8,6 @@
>  #include <asm/compiler.h>
>  #include <asm/mte-def.h>
>  
> -#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
> -
>  #ifndef __ASSEMBLY__
>  
>  #include <linux/bitfield.h>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 7763ac1f2917..8b27b70e1aac 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -19,7 +19,6 @@
>  #include <asm/barrier.h>
>  #include <asm/cpufeature.h>
>  #include <asm/mte.h>
> -#include <asm/mte-kasan.h>
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>  
> @@ -88,51 +87,6 @@ int memcmp_pages(struct page *page1, struct page *page2)
>  	return ret;
>  }
>  
> -u8 mte_get_mem_tag(void *addr)
> -{
> -	if (!system_supports_mte())
> -		return 0xFF;
> -
> -	asm(__MTE_PREAMBLE "ldg %0, [%0]"
> -	    : "+r" (addr));
> -
> -	return mte_get_ptr_tag(addr);
> -}
> -
> -u8 mte_get_random_tag(void)
> -{
> -	void *addr;
> -
> -	if (!system_supports_mte())
> -		return 0xFF;
> -
> -	asm(__MTE_PREAMBLE "irg %0, %0"
> -	    : "+r" (addr));
> -
> -	return mte_get_ptr_tag(addr);
> -}
> -
> -void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> -{
> -	void *ptr = addr;
> -
> -	if ((!system_supports_mte()) || (size == 0))
> -		return addr;
> -
> -	/* Make sure that size is MTE granule aligned. */
> -	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
> -
> -	/* Make sure that the address is MTE granule aligned. */
> -	WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
> -
> -	tag = 0xF0 | tag;
> -	ptr = (void *)__tag_set(ptr, tag);
> -
> -	mte_assign_mem_tag_range(ptr, size);
> -
> -	return ptr;
> -}
> -
>  void mte_init_tags(u64 max_tag)
>  {
>  	static bool gcr_kernel_excl_initialized;
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 9e1a12e10053..351537c12f36 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -149,19 +149,3 @@ SYM_FUNC_START(mte_restore_page_tags)
>  
>  	ret
>  SYM_FUNC_END(mte_restore_page_tags)
> -
> -/*
> - * Assign allocation tags for a region of memory based on the pointer tag
> - *   x0 - source pointer
> - *   x1 - size
> - *
> - * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> - * size must be non-zero and MTE_GRANULE_SIZE aligned.
> - */
> -SYM_FUNC_START(mte_assign_mem_tag_range)
> -1:	stg	x0, [x0]
> -	add	x0, x0, #MTE_GRANULE_SIZE
> -	subs	x1, x1, #MTE_GRANULE_SIZE
> -	b.gt	1b
> -	ret
> -SYM_FUNC_END(mte_assign_mem_tag_range)
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/074b893e-beea-8fcc-75df-778d29331236%40arm.com.
