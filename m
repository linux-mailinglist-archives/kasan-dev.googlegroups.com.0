Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVNZL6QKGQEESFS5AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7816B2B48C1
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:11:35 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id z19sf5571822lfg.11
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:11:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605539495; cv=pass;
        d=google.com; s=arc-20160816;
        b=nPeXn17XYQbbphCD8fb9UhYrFu7xUXOa+4oReGq2H0xcYd5JNjKkyrd5pQTXwHJBJV
         eevLN0UNi9ZKK2ZfB4bIUAN8E/1MLNt1b7B7QBxg2MktNZeWicggSIem1i6jycNDZBEE
         Kax62Z2s9Fyp0in7ZrP4gPjC5F7nkSJjJvXk/vxOgf9TatC4+YY8eo4Z/ZZlod33rTsH
         411k/2pDI+oEEQSfisvJOch9meJex46VTewutIdMeBxlDu8a5IhDMPT7X9DBvXJKdn1r
         jXY1qoPltqTfqXYpAQ9BUQRfeApQ8JT5+EnYHfaKAUK7sziDSWag9ecga01JWRmtZ5Ct
         pOkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CNupOrH3+Yuu1S3c3xPZX1gsGcQgPGgolGWg2UBB+40=;
        b=X1eTp2gtg1VONnmK4HcUcuU9w7OIlMy6XUG6B/u85RBq+XAU5XQpfWs/bgVLXVVi1f
         RtVTXJwkAXMAH0+rQt+R9n3STT27iVAf3RYsDoY5XLIIfd9at4n41pBmUzXt8L/9Aj4Z
         Lm8hDBSFSuTUP2VDd7Pg7Kpf2XZrdGfneXHJiKxgRvlF/MIZePfP0VOuLuyArpubofSv
         P6gr8n4pJpFbN0MwGinMd2wqVKayxO4ApEiOURPr+I92ARme7eok697Ktn3QVylRmsz7
         HZxIpt4cUcSjp3KU0QGESudSx4rZx9wXapql8tKjhoP/uykiPR3M/en0ytWW0n4QhPl3
         3y6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqv5T6oy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CNupOrH3+Yuu1S3c3xPZX1gsGcQgPGgolGWg2UBB+40=;
        b=ONTdlHbBWZ7w+3IwlUemK42bdc4VKn0503g4CWF/T5NnbewPYboiXkzW9HB7b6cuhp
         n6aajrDBp/ijzUuvYnQNJ1VSinEwTj98Jsg4JGsjN0Ucd0/rFoPhlaadXyZDtUpzi6Id
         TAKOMQXF/ED8TUOKrWKbdpkWOzVVWWmtW+6KLeE0sLc6qSxl2cfW+ViltZZuQuqG7vi+
         E/wKG8ILASUihVVBmXDNqO1z8Sk2+tq9/1BYza55fC6+elOn6++Z6ASuwM/UHtYhcGwE
         FdyH3F9jy1bdPGMYH791BjyHNfrQ4fwjE2D1+21x00/elNJiJlNOkQUH0GFv0Nawfv8m
         ahgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CNupOrH3+Yuu1S3c3xPZX1gsGcQgPGgolGWg2UBB+40=;
        b=DQcmH8I2GYFRh4igrcMHgsadgcXAAad9BhJqGj6t/E5XCtdrTysjvJx5zUMc5Y7fIj
         lHE2tkohqq8cwWj8U/MOdr553jutyeZpwnCxuBexsYdzdwH4O3+JoUsF2TNHWaJtXQch
         C3jnnVXAmldcw+wKjDaAqz7NPSajY/k/iasFxGBqkbVvHS4Wajf2urAKZWIsWJnph19k
         7bpqmtObHDdsstdYlywWd+C4XTbsCBw1+IXm6U999HwGmxlHuEd6DSa4LO8U47N8hzKv
         gM6E2Ddb0zr3ilYygUcwRcfgpbqkyxU8QGU5ps+TIQp7rhK4HuHVySqFJEIV5EZeqR0G
         p8gA==
X-Gm-Message-State: AOAM531Qi6/h2C/GBhWAvjdPZGqwCS8X9QZiDv0agfp/VCJwOMofjhgZ
	xRlsKLIK7ZO44mzWIlfaim8=
X-Google-Smtp-Source: ABdhPJw03wov6XU+9FdtIIoAMcPRlEPUQugJXI/O5SBmZwGh7F2XY1f1CfxAzYQ9w1+q5tYjxqGjvA==
X-Received: by 2002:a19:c897:: with SMTP id y145mr5984810lff.214.1605539495002;
        Mon, 16 Nov 2020 07:11:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls8810071lfa.1.gmail; Mon, 16 Nov
 2020 07:11:33 -0800 (PST)
X-Received: by 2002:ac2:4c22:: with SMTP id u2mr5629504lfq.596.1605539493774;
        Mon, 16 Nov 2020 07:11:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605539493; cv=none;
        d=google.com; s=arc-20160816;
        b=F34CuP6X1af9brpSNvRt1UKLnw3jLy3DMxtb3mVdi+3vfExnzxU6A/goaLjnj2mYSq
         yB4L39fFrW5MRJ5L0HPXbHi1SyTAe0ljQYiRy/g2EC6KyodaBBXpHlwXNQ0Pd9adG2c7
         gKQeGI9DNibvqYWA/imUClEHLMZpH+SybMFvTm7IoLHj1xRS1NBt1BCmdTVxGm2xhQpV
         QrVwg7k192Y76z5LndwgJx/iiUCBOos7DZ+vtPlKDP8QvbdZUI1eADTl9fqwPFw+3Hno
         2JmkGULznEOLKFeZobXyrwHUWBkO6AxXEVAUo0+qKlc9/Vqvjn010lY4RgC8FHOiK5Au
         8M5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ph474WBwjZPtIC8WXwer+eWtTufIJgCo5S0VZjhhIPE=;
        b=Hw+1akIKZiOZJXzeaGEqyrquZPhcQdOn48tQvX0yIE9i98r/LDs92LwGcFe+X/0xRV
         x5fwGamRbq7PtIo3ydsEMNP2O+YIVWt29p1Sw4LpReaPH11Hz79saZKrHZrQYAkawc3q
         cUna/+UwBU1p2ZCfYSTpMtI1wxjNliCnB1qknheZjJsyeqBPbIPHxStcgNDCXz/B5xa2
         FK9OPSCQ614HcQVr9sIU4hif1I9MIWdGVXEqERYhHtvMQjqQbOSSDnwkKGoVZ5CvJPxM
         YyNmBgVnj+q+xLD6SL8J6bxliJaGp1s9gSZffJIG50XSHM3mStkEKhqAZrSdT9660Ygp
         47VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqv5T6oy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 26si637189lfr.13.2020.11.16.07.11.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:11:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id o15so19058217wru.6
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:11:33 -0800 (PST)
X-Received: by 2002:adf:8521:: with SMTP id 30mr20230790wrh.265.1605539492993;
        Mon, 16 Nov 2020 07:11:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id t136sm17495991wmt.18.2020.11.16.07.11.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:11:32 -0800 (PST)
Date: Mon, 16 Nov 2020 16:11:26 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v3 10/19] kasan: inline (un)poison_range and
 check_invalid_free
Message-ID: <20201116151126.GB1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <cc8bea6e21d1cba10f4718fb58458f54fce0dab3.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cc8bea6e21d1cba10f4718fb58458f54fce0dab3.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fqv5T6oy;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Using (un)poison_range() or check_invalid_free() currently results in
> function calls. Move their definitions to mm/kasan/kasan.h and turn them
> into static inline functions for hardware tag-based mode to avoid
> unneeded function calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/hw_tags.c | 30 ------------------------------
>  mm/kasan/kasan.h   | 45 ++++++++++++++++++++++++++++++++++++++++-----
>  2 files changed, 40 insertions(+), 35 deletions(-)
> 
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 3cdd87d189f6..863fed4edd3f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -10,7 +10,6 @@
>  
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> -#include <linux/kfence.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
>  #include <linux/string.h>
> @@ -31,35 +30,6 @@ void __init kasan_init_hw_tags(void)
>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> -void poison_range(const void *address, size_t size, u8 value)
> -{
> -	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> -	if (is_kfence_address(address))
> -		return;
> -
> -	hw_set_mem_tag_range(kasan_reset_tag(address),
> -			round_up(size, KASAN_GRANULE_SIZE), value);
> -}
> -
> -void unpoison_range(const void *address, size_t size)
> -{
> -	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> -	if (is_kfence_address(address))
> -		return;
> -
> -	hw_set_mem_tag_range(kasan_reset_tag(address),
> -			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> -}
> -
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
> index 7876a2547b7d..8aa83b7ad79e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -3,6 +3,7 @@
>  #define __MM_KASAN_KASAN_H
>  
>  #include <linux/kasan.h>
> +#include <linux/kfence.h>
>  #include <linux/stackdepot.h>
>  
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> @@ -154,9 +155,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  						const void *object);
>  
> -void poison_range(const void *address, size_t size, u8 value);
> -void unpoison_range(const void *address, size_t size);
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> @@ -196,8 +194,6 @@ void print_tags(u8 addr_tag, const void *addr);
>  static inline void print_tags(u8 addr_tag, const void *addr) { }
>  #endif
>  
> -bool check_invalid_free(void *addr);
> -
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  void metadata_fetch_row(char *buffer, void *row);
> @@ -278,6 +274,45 @@ static inline u8 random_tag(void) { return hw_get_random_tag(); }
>  static inline u8 random_tag(void) { return 0; }
>  #endif
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
> +static inline void poison_range(const void *address, size_t size, u8 value)
> +{
> +	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> +	if (is_kfence_address(address))
> +		return;
> +
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
> +			round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +static inline void unpoison_range(const void *address, size_t size)
> +{
> +	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> +	if (is_kfence_address(address))
> +		return;
> +
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
> +			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
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
> +void poison_range(const void *address, size_t size, u8 value);
> +void unpoison_range(const void *address, size_t size);
> +bool check_invalid_free(void *addr);
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116151126.GB1357314%40elver.google.com.
