Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6URTCBAMGQEEOMS27Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 03B3C330C32
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:22:35 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id u4sf4157527ljo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615202554; cv=pass;
        d=google.com; s=arc-20160816;
        b=KtpmCUtpE1ftG7Haucp5QoQX22I9vZddyEGnrUNQDAf+d2LIejH6x1QLJVIi+wpmeh
         ghSoR4n2f21gh8ROAAzFE5qlIqAU0PKqni47d2yI92csjXLZ6cJUqc6IFwwSWd/sh7UW
         RCUfvbPKd+xrDBlZo/mE/wNmzYxCUCpzVJFa4n9n7ooMvYFHa9vBebNucPA3lsovy6+u
         On+wDKDmI0wcKOjEdX87/CM8REECD52jY51Pcen4bk+ZQ3tynPNKhdrEx7aKLNGCiBSd
         f0KDzF7j65QTPFG6XhxrAcOcGBmJ5SkIvomoISHRAmGbr8KF22c1oR/wYIn1rHhw9hCC
         qbVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=klGFMAohR/lm29mYhxN353KKBT8817a3fZHLtEhVzRU=;
        b=zplKpHmnjRMrA4r1lUGFUrMNkHBI0e9ozo37S0XzPKoYNLy/Jhw4Rv9aGLUcPhBKu5
         x0gXdCH3ZFoOf8JfyToyWHe4qzxHbq3sTZIP/15YNoS+asbf3zSyB7iV9++3gHhCEVSK
         apmLY01y73LoQa/pauJf5cYwZ6xdRBSOtfq0pKBkDAisLK/H3/gjR6YDSuJNLsdckp7W
         9dXJYw+n+Gi/Y532Z9fLQ7cxxqkgwPyAHFfoMGwDo9/rAiTYnc405NB+1P7zDFotEuHZ
         wvy7juvb/DwO4C66Y0iCuHfRC7rrRAUQfy8WwolF3UsfRYj7WlIYDqcnSkb+w+KvxDFD
         V4rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fXimUib1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=klGFMAohR/lm29mYhxN353KKBT8817a3fZHLtEhVzRU=;
        b=PYP3jq4Wz3VeED/2yGo2CyZU977ke/8L5Qv3f1tjFpqKpsxoFquFqngYKkxdfE860Z
         zdmeRfiEC2MAzAwkksw7Y0xTdEQucLRifqmzKDuFdOKzsZqAp+dJVKcNHCumN4AC70E/
         5nzBEiEgpFCtSurExIJnpwTako7/ChKSsRV50pQ9UXaGLoNASFqRdctK9a8emkzHct1/
         9yxesL1K0jI+Y+ahJ/ZUTYekAtIswH53APDU0crY/S//3Sm128zh5d1e9J7BepEqUfkU
         NSes3QYP+qQ+6DV2qsnWph7kfT3gG79sky0UgH41cLZh/W2bb5ZN9G5XF9fEwtoCDIbS
         MOTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=klGFMAohR/lm29mYhxN353KKBT8817a3fZHLtEhVzRU=;
        b=CkQkqYrYUGfQ1c5jU9UXJxTIWJw64NrwY5CUTSZVB8rF0iW7B8cXp6SBBzM/8eh2CB
         n6vIhB2BZzhQHJV2E+iQWyFhPKBRPwRB5+OGyH7VvApGTiwgLEHPlFYcMvitKpy0DGT1
         BLWQmRn5nl7Q5ksvTySdKyCo/+OWjXj8aliA08kZnmWKp3GA4eGiwriuiso4qzWLdXJL
         FCvqXPqtRZIc3rNxBGz2rUDOv7lGUwe7cqoD9xSOgNVPQ5YdeSiUKuOLYR7LGJplhv7C
         HhZJRzttXGJ/Gz9kLpW5/Pn0hMbUPGRkGeg5j3NST6CgPnycX+T1V/fNHvkLVw5Eu4xi
         LSYA==
X-Gm-Message-State: AOAM533S0JGqS22Mig7MCpaaIFVKpK5rgg3MsQoTOqY22PAHy4U1x0t0
	Nf010vb9VcUMOSURKUf1D1A=
X-Google-Smtp-Source: ABdhPJxEWXOsg54xPc+UB0vRCPwkIR5pIGVsVXsNcVFC30u3wLhwM2/b9oSWiiXy+ErIE2OoR5B0sw==
X-Received: by 2002:a2e:7a08:: with SMTP id v8mr13940856ljc.344.1615202554595;
        Mon, 08 Mar 2021 03:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls287239lfu.3.gmail; Mon, 08
 Mar 2021 03:22:33 -0800 (PST)
X-Received: by 2002:a19:513:: with SMTP id 19mr14354408lff.528.1615202553423;
        Mon, 08 Mar 2021 03:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615202553; cv=none;
        d=google.com; s=arc-20160816;
        b=yeTizmYlK9ewEiSZDizon0KieKsg4GdUbFvH1ZpuijPbwkG0BW1h8w42NCAX9YDe2m
         byRFplZwLp7knzhS3dL/SmWI/WvdYLwkjJQIgcGAd4fsVzucTxgwc/wRqYq8gQUHBbjJ
         zICrz8kiPDgkn0b/LfACkXh7svMkm91AnGv/Dr1SD8lzB9RicrU0bIiDEKMnC9+te+xH
         0XZsRUoUqtg9F6WcET40kpG8AFKNzNiu+LQhTnqC5Qgq3s7Q/Q6Z5NyyVjwwB84ykyK3
         ljOIeh4HlkCiVP6mWQdJw/l1novxRNbqLQdx+n4+LcOyAM2k1JIwAzlRAmwiDwZFM9aW
         sN5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jdrzG39EB3vDtExSyNYnnHyOb0pzwYrAbQOXS4G/YIk=;
        b=jHMnx0LkiPEnvTTtLWQcy+qlLM/6WnesIC4dP7p2xVLFbf3/auV8xtbeWqcuCFOJtB
         iwAxCnwW/hvWgJH9KnMT3lf2cvsggifwNh0j7A3GmDvWgLVXyCWQ7mRErXhl/glGyspR
         Ta6NiX2m4EgjyKF9Paa5GsDtpsMq6S9T7w14OdEkdSMLbtfGpMb46wxEiKEfMvbSxVsk
         CVhF4EMPB2dTiKONVsnS4i/2B9ePzB2b+0uuc02dEVD1fHTGCq4Jue3SJp2FIuVnXJjU
         FzpGoe/BOENk2UnHW483AcO2r2fzh56bTxWAipINGTGV9f7ZgT2r9/tyaijn1pgsOWP2
         A0QQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fXimUib1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id m17si430530lfg.0.2021.03.08.03.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id a18so10978861wrc.13
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:22:33 -0800 (PST)
X-Received: by 2002:a5d:6446:: with SMTP id d6mr22094155wrw.328.1615202553053;
        Mon, 08 Mar 2021 03:22:33 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id u63sm17942821wmg.24.2021.03.08.03.22.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 03:22:31 -0800 (PST)
Date: Mon, 8 Mar 2021 12:22:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/5] arm64: kasan: allow to init memory when setting tags
Message-ID: <YEYI8Vimo90TLaRs@elver.google.com>
References: <cover.1614989433.git.andreyknvl@google.com>
 <e43afadb507f25dfb1abfcb958470a3393bfdbf9.1614989433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e43afadb507f25dfb1abfcb958470a3393bfdbf9.1614989433.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fXimUib1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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

On Sat, Mar 06, 2021 at 01:15AM +0100, Andrey Konovalov wrote:
> This change adds an argument to mte_set_mem_tag_range() that allows
> to enable memory initialization when settinh the allocation tags.
> The implementation uses stzg instruction instead of stg when this
> argument indicates to initialize memory.
> 
> Combining setting allocation tags with memory initialization will
> improve HW_TAGS KASAN performance when init_on_alloc/free is enabled.
> 
> This change doesn't integrate memory initialization with KASAN,
> this is done is subsequent patches in this series.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  arch/arm64/include/asm/memory.h    |  4 ++--
>  arch/arm64/include/asm/mte-kasan.h | 20 ++++++++++++++------
>  mm/kasan/kasan.h                   |  9 +++++----
>  3 files changed, 21 insertions(+), 12 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index c759faf7a1ff..f1ba48b4347d 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -248,8 +248,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
>  #define arch_get_random_tag()			mte_get_random_tag()
>  #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
> -#define arch_set_mem_tag_range(addr, size, tag)	\
> -			mte_set_mem_tag_range((addr), (size), (tag))
> +#define arch_set_mem_tag_range(addr, size, tag, init)	\
> +			mte_set_mem_tag_range((addr), (size), (tag), (init))
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
>  /*
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 7ab500e2ad17..35fe549f7ea4 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -53,7 +53,8 @@ static inline u8 mte_get_random_tag(void)
>   * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
>   * size must be non-zero and MTE_GRANULE_SIZE aligned.
>   */
> -static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +static inline void mte_set_mem_tag_range(void *addr, size_t size,
> +						u8 tag, bool init)
>  {
>  	u64 curr, end;
>  
> @@ -68,10 +69,16 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  		 * 'asm volatile' is required to prevent the compiler to move
>  		 * the statement outside of the loop.
>  		 */
> -		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> -			     :
> -			     : "r" (curr)
> -			     : "memory");
> +		if (init)
> +			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
> +				     :
> +				     : "r" (curr)
> +				     : "memory");
> +		else
> +			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +				     :
> +				     : "r" (curr)
> +				     : "memory");
>  
>  		curr += MTE_GRANULE_SIZE;
>  	} while (curr != end);
> @@ -100,7 +107,8 @@ static inline u8 mte_get_random_tag(void)
>  	return 0xFF;
>  }
>  
> -static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +static inline void mte_set_mem_tag_range(void *addr, size_t size,
> +						u8 tag, bool init)
>  {
>  }
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8c55634d6edd..7fbb32234414 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -291,7 +291,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_get_mem_tag(addr)	(0xFF)
>  #endif
>  #ifndef arch_set_mem_tag_range
> -#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
> +#define arch_set_mem_tag_range(addr, size, tag, init) ((void *)(addr))
>  #endif
>  
>  #define hw_enable_tagging()			arch_enable_tagging()
> @@ -299,7 +299,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
>  #define hw_get_random_tag()			arch_get_random_tag()
>  #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
> -#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
> +#define hw_set_mem_tag_range(addr, size, tag, init) \
> +			arch_set_mem_tag_range((addr), (size), (tag), (init))
>  
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
> @@ -343,7 +344,7 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
>  	if (WARN_ON(size & KASAN_GRANULE_MASK))
>  		return;
>  
> -	hw_set_mem_tag_range((void *)addr, size, value);
> +	hw_set_mem_tag_range((void *)addr, size, value, false);
>  }
>  
>  static inline void kasan_unpoison(const void *addr, size_t size)
> @@ -360,7 +361,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
>  		return;
>  	size = round_up(size, KASAN_GRANULE_SIZE);
>  
> -	hw_set_mem_tag_range((void *)addr, size, tag);
> +	hw_set_mem_tag_range((void *)addr, size, tag, false);
>  }
>  
>  static inline bool kasan_byte_accessible(const void *addr)
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEYI8Vimo90TLaRs%40elver.google.com.
