Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WIWD6QKGQEOIMCNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B42942AF797
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 18:50:46 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id j9sf1158855ljb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 09:50:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605117046; cv=pass;
        d=google.com; s=arc-20160816;
        b=WC+MUTruvoM0Aggfe4RLqJaElBRanJqYGNNa/2utOX3piOIacxRHu5iWwlZY14Ffxo
         epRNdXvaUPneDETX8Cg4qsfrYgc2SWkZD1rnmibeKKOtiCgPOHDDHZSCUO0Th2rjaoMm
         t7KIM/mSQXztUWMfuyA6hPqQRccqvru3wtAFAWH7ZNnlnxFy9iFvikTA9I99zA359O21
         QSxm6dNUMwvHAjwRKJTy8cRCK9MNIYse2va2qnP/9lBRvyE3nkCbNN9UNh/nNQ0k3H2Y
         XLSyhA2cz7asarz9zCznPVJd9B9n7SCezpW7Aklf5frzdPhVkmNelFy6LS7Osk2Z0RRv
         rEWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=wZhH1GT4dRtSPlFtQFI/Kh8Oyjh9BlpBzYNocuh+EIg=;
        b=e0tacnzhofbYbDO0HeNbnuaGbJzO6zVFB4e5YkHTFA0ZRYKkVCbMb9dBEFS/bOF34n
         ZwZdjt+nv6rbyi7eQUWmObtTp8VvSZ33a5XgRIjkay18QwmUKnS4ZYAe4601UAZvJyhc
         4JMdqXk4XPBJPvYVWB/r0l7TyPRcKzrJUiFCGqm/5ci3sYb1NCLaKrCRuJtdLFUcWCFB
         Dpf2s1qO09+hngQWOy42BMTULkuPjGSrJ4/4ogPOGtGOEDHyacFJV/J/mkH/r5icbiKg
         DN8rQi/DjIjbCJha5MVzxa1OW5F99zu4BWqkFNj06rdGWXycp/DPLOPBYm7PL9V4pAsp
         bVgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fAVKGBzK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wZhH1GT4dRtSPlFtQFI/Kh8Oyjh9BlpBzYNocuh+EIg=;
        b=IGHrwcRWGF0TJ6bmQ8UxgQ6yK8s62l0dlRdPdbeUlNpH9REOJ0ejG+j9fTGVeIHL/O
         QYAb9D7ty0Vkp0bOcN4a6HQss5mx9pnjQ4RdQflxdN95JuhcZ0Cm7KAtAVqU8gjWCnkA
         7PBXaiBJ1L31IEN3MPbbDEWs1wP7mXvjQyUuwBf6XW2PNN6GUVRPUYZjkCht2DTwyPSs
         9AQRqK37scfz4WWmscxHHlA8cCRuth8YokNLW7mywqhvLS3cWjx47Y9gpGl9RWHJRnsf
         BLXKcMUt4bhs56V2HTvgmViD7kmRSw9BH4RufQLNR7F12wyo2sIZQA9bV46/GWm7EpdC
         ECZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wZhH1GT4dRtSPlFtQFI/Kh8Oyjh9BlpBzYNocuh+EIg=;
        b=r+NBmLSj1dcGyqP8ml6VziME/RuQ+9/+koPA7W5mK9qk1+cXXfDLgdyBnQ/X/pDAgT
         iBcjLVwwA5jE0zPhD4vfLlzFqxGfRo6MBEAGAV0o3Ueq3YiUOpevou1PnJG9wEwTmhlf
         KGnEFfHOZBxMbjPVPHwgH/dCcuExISb81jvV7/3uXpgr8Hz6OP7AF+Ynm5Yt3Io8lP3m
         mc7WpW8bCgdm13Zz1eYGtbqsJq0HOAZxHHM6LQrVqwWr8ziFF053rahczQyQPQ19Cbf/
         mur5nPC0E0HyLWOMfZlJ1UYGmsthWpnueKPKpOXP9UpSPAAqoouorIHnpivswJu95t8e
         epcA==
X-Gm-Message-State: AOAM5330l7Q4ehnJ0SW5TFRGifxaNcVP6+Tn2uQE8PaLhnZWE6NcCwXT
	RqHdFDiAlELWjdn1KaEvMwU=
X-Google-Smtp-Source: ABdhPJwU3bZ8y2vsP7XJYp0fZFE5D2fyJHrygo2427xI+UVUKY3zFetcRceHyBV0l4q/XMUC9TM1Wg==
X-Received: by 2002:a19:2291:: with SMTP id i139mr6855546lfi.592.1605117046276;
        Wed, 11 Nov 2020 09:50:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f48:: with SMTP id v8ls61359ljk.9.gmail; Wed, 11 Nov
 2020 09:50:45 -0800 (PST)
X-Received: by 2002:a2e:90c1:: with SMTP id o1mr6787287ljg.130.1605117045080;
        Wed, 11 Nov 2020 09:50:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605117045; cv=none;
        d=google.com; s=arc-20160816;
        b=cUYRuBGn1yMm4g6xwOGrnxmo1lRRhBpCPPoSyf0gKkjUxPC6EyWoLpnH6Cw8NWs+Rk
         3Enf5cmOg30hLbyQV5ssg2MoFC2Cw/zXKP1FBMGfMjqFVhtvnlToCrRTPs1Acb8/UM3s
         3k3sx/RTgtPLE7NIJWQy8gYi4SUPBgu1dhtWbEZqxFuk9Ab6y/xgRXBGEt+wz1iV1dNl
         xHCuYA9DZjLaIccbmqvdD3cXdMsNK2vceSPeapTYeeeNjQXVBTKeodV48fbq18azkTr9
         ye8PJlvQ9zUhzesF9mvU11RPYoppOtjVG9u3nVT999NHI2iKvu7nbXEuFpEP4YtaL3Y0
         86/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pMy5H5o1v+WngKr1b+qy1lo8XFp3TrTTXnTQCqUhuZg=;
        b=KKzWqggTCCyES5odkSSxJrdLwLehaSZYKLM4YmPX083vcQCWrmN4xbA/a2vOtEk7V1
         NHUs5vCp7XZzMey2BuYHp3GnNMHjfLvzdZDVa3qIR6XSA+ov8K8w8Dzv+Kls7zQhEPBC
         UeYZonfCb3p4orRrbh61nd9mFuUlYQFNb4VXMibp9KqfaLZf54giyBT7s5OJVDflgFfF
         tF2heruyU/GmhG8GbrivWNt2pJgigam1QnbPz5wki7I24xgWFyoVBWb6gjMOIBNlBGw9
         +4PsKMr5PcHjybJOMhZM/Op48rqbKsdnMTgsoIpF+PltyoojaG7TU45/m35AXkcOQcp4
         Qxsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fAVKGBzK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y17si92902lfh.4.2020.11.11.09.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 09:50:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id a3so3101496wmb.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 09:50:45 -0800 (PST)
X-Received: by 2002:a1c:7e87:: with SMTP id z129mr5390876wmc.176.1605117044596;
        Wed, 11 Nov 2020 09:50:44 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id v8sm3346969wmg.28.2020.11.11.09.50.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 09:50:43 -0800 (PST)
Date: Wed, 11 Nov 2020 18:50:38 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 09/20] kasan: inline kasan_poison_memory and
 check_invalid_free
Message-ID: <20201111175038.GL517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <e14ac53d7c43b4381ad94665c63a154dffc04b6b.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e14ac53d7c43b4381ad94665c63a154dffc04b6b.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fAVKGBzK;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 10, 2020 at 11:20PM +0100, 'Andrey Konovalov' via kasan-dev wrote:
> Using kasan_poison_memory() or check_invalid_free() currently results in
> function calls. Move their definitions to mm/kasan/kasan.h and turn them
> into static inline functions for hardware tag-based mode to avoid
> unneeded function calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
> ---
>  mm/kasan/hw_tags.c | 15 ---------------
>  mm/kasan/kasan.h   | 28 ++++++++++++++++++++++++----
>  2 files changed, 24 insertions(+), 19 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1476ac07666e..0303e49904b4 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -30,27 +30,12 @@ void kasan_init_hw_tags(void)
>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> -void kasan_poison_memory(const void *address, size_t size, u8 value)
> -{
> -	hw_set_mem_tag_range(kasan_reset_tag(address),
> -			round_up(size, KASAN_GRANULE_SIZE), value);
> -}
> -
>  void kasan_unpoison_memory(const void *address, size_t size)
>  {
>  	hw_set_mem_tag_range(kasan_reset_tag(address),
>  			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>  
> -bool check_invalid_free(void *addr)
> -{
> -	u8 ptr_tag = get_tag(addr);
> -	u8 mem_tag = hw_get_mem_tag(addr);
> -
> -	return (mem_tag == KASAN_TAG_INVALID) ||
> -		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> -}
> -
>  void kasan_set_free_info(struct kmem_cache *cache,
>  				void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 7498839a15d3..ab7314418604 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,8 +153,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  						const void *object);
>  
> -void kasan_poison_memory(const void *address, size_t size, u8 value);
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> @@ -194,8 +192,6 @@ void print_tags(u8 addr_tag, const void *addr);
>  static inline void print_tags(u8 addr_tag, const void *addr) { }
>  #endif
>  
> -bool check_invalid_free(void *addr);
> -
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  void metadata_fetch_row(char *buffer, void *row);
> @@ -279,6 +275,30 @@ static inline u8 random_tag(void)
>  }
>  #endif
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
> +static inline void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
> +			round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +static inline bool check_invalid_free(void *addr)
> +{
> +	u8 ptr_tag = get_tag(addr);
> +	u8 mem_tag = hw_get_mem_tag(addr);
> +
> +	return (mem_tag == KASAN_TAG_INVALID) ||
> +		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> +}
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
> +bool check_invalid_free(void *addr);
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e14ac53d7c43b4381ad94665c63a154dffc04b6b.1605046662.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111175038.GL517454%40elver.google.com.
