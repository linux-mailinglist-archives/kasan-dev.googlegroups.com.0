Return-Path: <kasan-dev+bncBDDL3KWR4EBRBFPATGBAMGQELSXZ3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 298BA331665
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 19:42:31 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id s4sf8220013ilv.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 10:42:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615228950; cv=pass;
        d=google.com; s=arc-20160816;
        b=gMyyKnqcepwtaVaa6ZRv/AcVXSvuHHdt+RejXeLydF3dslKEGaUeFWXNKgnu3OKfKY
         J7Z9Fc+KBWIcHdq6FHQfrqfQoba+3Cf3hoNONaxX/lZKfPaKXdyA71Y4MJFy48pxLdXR
         vJsAobcfZ0qcNPTGX+LJ2DXx9HGcBHZ6u43bMqlclcFinoeGHaTDc/rUSQlbALeI4Gen
         vtNGSitnQijXh3va5QDZTVh6WadMAwZ5gKkPafkfweNf07MQboFTXlPnAKCW+h924lqK
         l/ZSknXSRo9+iCCj1TwcOuABtzsC+iZl6uoSYteyJa0G6+c3jmnI9zuH0tJikIwxweSe
         vpOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=f4dKemzTRNoVloD7YDuRx9M5XYCZQkQMLq/xojz7WCk=;
        b=tnd6bDXrV7W8uLpccwxWNMiEu7lWHvR7VhcDrCFtptW/M6VFqWOtaW3nBgstpuL/qD
         suU5rDe9kFpWcDJNRmN81YQwIPzQ7Y7K4G5T5rRD1V5Ncax3xx+kS25V0r0MX2hweOm5
         LBNp1BDqHM1FEvdQxI9YKBKaJsI03aFpafD3BwmsbYh8Caqs5QerkN0DEhT9cgKqNHcg
         duAGDpUjBK98OxLiJk7iw5N5mv2JqLUl6qUcP6s6+5aEbRwgH0J+1NjDx72UyfF7wZad
         GAoDmc3pwLYwijA6Vi0a2MQnzHuLz9E/FpndLmLLgdGPFX7M8V+9qU3ErOZXmep4I1zQ
         Th7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f4dKemzTRNoVloD7YDuRx9M5XYCZQkQMLq/xojz7WCk=;
        b=JVVmaknFoTzuLfzlPyhCpyXbsmlEf0Yp2gqsp5xlooIa/+8EVAhutoV5/VCuzzQupT
         UPm8slqSn5T7HRepXHrmgskDDM/XVKHFYDgf7IHFqSHC4JRd0oQIPwXBTsMk7YDXZXJF
         uNX/kVxACXI+9h9/V20ifgNzpwZ7pFXkVktAMw66ogpY58x5aFx1SVcItoexIMuIcT02
         72nbCXMSqyikdy+z1V2lQiq7wdt9R0t8jXjIsEKv7chsYKAGNCRyl1EiP63CNSK5q0rL
         uzN248x+SFpMYLbkk11N8FfQ8zKw8HzIE+58CIjUsHLawDn/Iu0jJEI4Wp4eLHDLEN7J
         OWzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f4dKemzTRNoVloD7YDuRx9M5XYCZQkQMLq/xojz7WCk=;
        b=VzySD6pdj8zJqU/cBDnpeExNdAbaLNfWHtDLdw9OnAbu3IpBr/1999FmUmJI/p0EsM
         QYO7jnMZygBpzAGXiGp5FqseyoPpVIax0Vf6fyCWGVBv7rvUZ6bZXTiD75+JzbvrHcMa
         aQZSwsCZ3ZKoz38XPcFhetzbsvp/00yRtM6Ux1xDj3IUGmsPRAtB4d2zBGZf+70AnxSL
         e/XcDu+4c1CH5i46DjaGcFkf3YYeW9OcuDfIkSQ3HH2yw+p1ksn6ShClYb48SXcUuxu8
         znOjt/H4wnIpc5r5dKxTDxdnA/5Dbrgn90f9hPUlX1jZM0/s/JDvgpbU4vHcyQqNnWB/
         6exA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327nw+SO2+/3wFcIeEE6lvPCvMMWQBG7i5qJUWdm0BhaayE9IE4
	yWERHH2Lx8Xdfk21tzcBivI=
X-Google-Smtp-Source: ABdhPJzxIVUeGjhGX0lDulmn9cemezBW0pn+hbW60i+nTvpOxeVvO0uTfhRVgiuM9fqWix4i2j6cRg==
X-Received: by 2002:a92:cccb:: with SMTP id u11mr21062516ilq.44.1615228949966;
        Mon, 08 Mar 2021 10:42:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cd4b:: with SMTP id v11ls4580703ilq.1.gmail; Mon, 08 Mar
 2021 10:42:29 -0800 (PST)
X-Received: by 2002:a05:6e02:1c2a:: with SMTP id m10mr20755943ilh.17.1615228949615;
        Mon, 08 Mar 2021 10:42:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615228949; cv=none;
        d=google.com; s=arc-20160816;
        b=epS/aV+YFdi9jbE6ImsLTsvU7z/YAAiyIp+7G/Dkwq9jbgbItCVJGVP+0P3LZuKYZX
         UFlEjXjmetuvlxkM1ul2IVzCU2rMT7EoSAL4F3Q2GIAYdDOlFUFXza9ihcMt3vUuCavm
         nBPj34Td0D63Aq7+xxJYS6mBJrwbXo8i4dY3afloOJmO3gRbb30ojkM5PZzFLpMW6gIe
         14iYrb0YIgBV25zb6iDnlGL96+ajVnRJQhkgoGZgcfI9Q7eCwGOvKtOuAZ5o9JDBHWE/
         9C2J9CpxEJnre/zu93gO1rIxk3OUyPbdlvQNrHFNHJVV/UdB+uyuoyEBTyPBar1qXp4F
         5FDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=OORbzGHCLuxPX3mwV2Y6Yuqx8wzB8Q3EOgudPr6B89o=;
        b=ai4TGLDKrrYGg3pYvafdn/bDUiyKYEkwJ0682FNifO1ys7mjwvwjdchwh+8lLcF8am
         MNz6npXLQ5eRzhIrLDJDs87RHXmODge1XRH5W1oBYoxHxNSif0y2T00+3yF6Nbs+D6Ls
         nZbiXr/BytEqetaa3poppell7wlNC0s2VPs0mnWvq4CxhvIYRtZNHJBnyZ87Hjp/s+Tc
         RkMfDuUL+VEZYYBGnTqEueuiaYijyOWe/g1DenE2Q+f4clUE02kHY83SqwZOOFeU+bCm
         dYuYsJmzqxPujLqY/WmE+tf2yqh7lM8F0XHA/9KE16rKt2b5We3HoFwkEO+GID+KsRKm
         pGkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i2si734625iov.2.2021.03.08.10.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Mar 2021 10:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 27C406521D;
	Mon,  8 Mar 2021 18:42:26 +0000 (UTC)
Date: Mon, 8 Mar 2021 18:42:15 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH] arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
Message-ID: <20210308184214.GI15644@arm.com>
References: <4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 08, 2021 at 05:10:23PM +0100, Andrey Konovalov wrote:
> When CONFIG_DEBUG_VIRTUAL is enabled, the default page_to_virt() macro
> implementation from include/linux/mm.h is used. That definition doesn't
> account for KASAN tags, which leads to no tags on page_alloc allocations.
> 
> Provide an arm64-specific definition for page_to_virt() when
> CONFIG_DEBUG_VIRTUAL is enabled that takes care of KASAN tags.
> 
> Fixes: 2813b9c02962 ("kasan, mm, arm64: tag non slab memory allocated via pagealloc")
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/include/asm/memory.h | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index c759faf7a1ff..0aabc3be9a75 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -328,6 +328,11 @@ static inline void *phys_to_virt(phys_addr_t x)
>  #define ARCH_PFN_OFFSET		((unsigned long)PHYS_PFN_OFFSET)
>  
>  #if !defined(CONFIG_SPARSEMEM_VMEMMAP) || defined(CONFIG_DEBUG_VIRTUAL)
> +#define page_to_virt(x)	({						\
> +	__typeof__(x) __page = x;					\
> +	void *__addr = __va(page_to_phys(__page));			\
> +	(void *)__tag_set((const void *)__addr, page_kasan_tag(__page));\
> +})
>  #define virt_to_page(x)		pfn_to_page(virt_to_pfn(x))

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308184214.GI15644%40arm.com.
