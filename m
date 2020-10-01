Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNJ3D5QKGQELURS54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FF6E2805A4
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:41:10 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id y1sf2498927edw.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574070; cv=pass;
        d=google.com; s=arc-20160816;
        b=sigrgJ3f/WnifU1u5fSQzBxwxObbAYvHfDmwTCpOt12SUTE+zNymvHkx38xCidtcH6
         Df8pmd8CoqSOTXH8KgdPyJ7D1GX6SiGGii+jScNcghbWr0C8WKbIwOptjK08jDX2kRT6
         YKGpGyzwOxaWquYRnZkSKDlgg3b/my+BsoSE7yqrXu/y80hAwWOLuvh71urajTnadqbb
         j3+40sFrPUC55cdUvu5ovJ+Kh2zKif7sb67pQsLiA9rFK1vY8JdsrmY+ZZWS+UZou+Pl
         gYX7S6LiS0FXtjaUtYz7xB2hzm21nPHZJjzAdB3G2bvkHo8xFndG8J+1Jv+g0+t2VlFh
         Wn5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EsmLlrTd5apKwWpzLmNsjL08u7h+zlTAzmM8x5cHE2g=;
        b=o2xOqCP48BMgGWaXTAuCn/ejHWCPrToC2YVFTBfhgaygtpix17HD6s6j2m8Z7393+w
         8eQyPEgbPE0nT480KRHQqW0xtFsZWbsKml/UoZS3/5j76oHn7oinyflUXHCSFO8HHAnb
         2fKf3WNA4cKAL3KYS6M+HfgOleNelQAxOS6rWclZ3piIvomESllTqMIGTG3NcmdrzVmA
         1q/KDdUFGumIZV62K8ADzVN4+ZeAoBd2e2H04dR3dchL7KtxeF2yGjp9yUNwvCym1PbK
         aAG40DPlhDtUvRyUJfzGhcrWadJ4z2pNYnIRz55MavuNCHz/jDFlOFjvj+s0KqyUf/0F
         1UPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MdZ/sCH3";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EsmLlrTd5apKwWpzLmNsjL08u7h+zlTAzmM8x5cHE2g=;
        b=OIGDbL3ZEUcleCKlvrnxzUSwTMSiUTBw9ZFou4FhhAQCRVuf3g/PTPcOlDJaa09uD8
         iP0wL0i3qUBlczcMFrGaLF3YXjpWwR+FEWVrxAY7aYqEyMKShEFS8LA4wbh+WOtgbDcc
         yV4f+0c+x2TXMb8OLENi5qFd+7Rh6aeaHDLc0DOFOsQbw/qwvobZrHlw9/zx7MIX3Ujn
         HdATT1AvPZBSMbvHhkybcDcgu9rVpz4f6/etR5rR+jvcorcq1TcpukgXiWO1eTUiiMFe
         oVpuMALYX823yHUsUuYMyuLnRjCv7GdoSXvW4eV/r8jexdUsG6ARFRU5j7VJ3BjxQNlD
         vq8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EsmLlrTd5apKwWpzLmNsjL08u7h+zlTAzmM8x5cHE2g=;
        b=gs2daBNpoOCJKL/52BbGRxs9v2c9QzpH0JfnD+BhLHAKR0h5Wsq0fL5Owz+OryN/fa
         1h2V6jc0LL+12GwBLRk8Pz+4p06br2YrIXQDJrHw8yiVPl41O5DT3iMeeNLW4GyeiMH/
         p1HxpGgKmzL84KDyJ9MWLc9sanUuDNY6WPDnFEZEokmoNkG7oLRVBTFZFfTfKmLk8lDQ
         GJOtCTggIZ3CPMt3LThdD98WRaG32Gb/2HxMq/oYOalQoaIoscCIntekQww0zSHlVgsq
         sQzG7fLsKpXWapHmQG20wdw11YpMeuk8Ap6caDrLp36yyqOkGsDVFa6NMiEtrJhSV5NH
         TY8A==
X-Gm-Message-State: AOAM531zvUW1EOvCcw6Q4ZRjVFHXwib+hl2vW8H7EbxZQFcNTGPI/o7b
	EtlnSbMNHH1iHg3QuB200Fc=
X-Google-Smtp-Source: ABdhPJzTQalH01jvRpjZggr3xzN+uM/1uFTSeHrSgxzw4exx1pSN9MWshxyTpXuV+lCp4r2kun1AHg==
X-Received: by 2002:a17:907:648:: with SMTP id wq8mr9655086ejb.291.1601574070028;
        Thu, 01 Oct 2020 10:41:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d40e:: with SMTP id z14ls2213606edq.2.gmail; Thu, 01 Oct
 2020 10:41:09 -0700 (PDT)
X-Received: by 2002:a05:6402:1711:: with SMTP id y17mr9564928edu.345.1601574069009;
        Thu, 01 Oct 2020 10:41:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574069; cv=none;
        d=google.com; s=arc-20160816;
        b=u5bgvj12O45SXc9c+PEfXee2GcEtFWSIfufO5g+ce6Mn2iHm1+fnFLbyL2p60xZqGW
         rRkLb4JPZcY93I7RNNTxTNPkunYGUF6oW/BmAN8+e0NxuNusVny6uF+YX4hCnemcYr8J
         m/8uGbBJzsAasi6MgAl+M5gjXDN2RL7yHY8hAraB8I3vOiFhrgnWIoGKLc9UBd76GOmK
         gUj9v2m9qlQFBV+iPyaj7TQqbd3OXRhfx2/Xhvs/AyvUmFjeQBVNUn+H9ibLpewfILxX
         cWmS1aaK3a3Si+nZy47naejSax3uLcL4cFD2bgMw1wsy0roxHFBTnxg4Kf7WrCzEdQ4n
         w/rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JNSzrX1KLD1Jr1oOxkhpqopu9WU4zuQEXx0vLg9N7lY=;
        b=YQgk1HQS8wLXjfqN3K1eHT7WdB5PCjo7UBIDnMCvfF/M181OK98EQ8U+hI+aKA5HKM
         4u9uIFkz939Zh4YU1mLAim1boNpajrnlnfgu2F/fsiKDSNtcdK+U3RVta2qM6YXnjY4N
         a8xFlQFEEI3VUPb76jACQKtjhBL/87lb75/C2bVMjzAWe6WitvHLR9hDYW/4OxL5xTKW
         mDhAwLXIh2xSWk6mLSrs1qoVzVmZhLzp2eHPrwi2nyBBtyEreXXLKXBkKDDYbIG0Z52O
         pXpq6QX2a4PFMi1Ri8FXy9nEzoqePKrYbicxmLRZocA2BRkempSN9b4Z1wf9789vCw+V
         jlOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MdZ/sCH3";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id r17si57269edc.4.2020.10.01.10.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:41:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id w2so3775575wmi.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:41:08 -0700 (PDT)
X-Received: by 2002:a1c:5685:: with SMTP id k127mr1161718wmb.135.1601574068516;
        Thu, 01 Oct 2020 10:41:08 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id o194sm1074973wme.24.2020.10.01.10.41.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:41:07 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:41:02 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 12/39] kasan: hide invalid free check implementation
Message-ID: <20201001174102.GJ4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <c1cef2ae4f4c5640afc8aac4339d77d140d45304.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c1cef2ae4f4c5640afc8aac4339d77d140d45304.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="MdZ/sCH3";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> For software KASAN modes the check is based on the value in the shadow
> memory. Hardware tag-based KASAN won't be using shadow, so hide the
> implementation of the check in check_invalid_free().
> 
> Also simplify the code for software tag-based mode.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
> ---
>  mm/kasan/common.c  | 19 +------------------
>  mm/kasan/generic.c |  7 +++++++
>  mm/kasan/kasan.h   |  2 ++
>  mm/kasan/sw_tags.c |  9 +++++++++
>  4 files changed, 19 insertions(+), 18 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 123abfb760d4..543e6bf2168f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -272,25 +272,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
> -{
> -	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> -		return shadow_byte < 0 ||
> -			shadow_byte >= KASAN_GRANULE_SIZE;
> -
> -	/* else CONFIG_KASAN_SW_TAGS: */
> -	if ((u8)shadow_byte == KASAN_TAG_INVALID)
> -		return true;
> -	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
> -		return true;
> -
> -	return false;
> -}
> -
>  static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  			      unsigned long ip, bool quarantine)
>  {
> -	s8 shadow_byte;
>  	u8 tag;
>  	void *tagged_object;
>  	unsigned long rounded_up_size;
> @@ -309,8 +293,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>  		return false;
>  
> -	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
> -	if (shadow_invalid(tag, shadow_byte)) {
> +	if (check_invalid_free(tagged_object)) {
>  		kasan_report_invalid_free(tagged_object, ip);
>  		return true;
>  	}
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index ec4417156943..e1af3b6c53b8 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -187,6 +187,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	return check_memory_region_inline(addr, size, write, ret_ip);
>  }
>  
> +bool check_invalid_free(void *addr)
> +{
> +	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
> +
> +	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
> +}
> +
>  void kasan_cache_shrink(struct kmem_cache *cache)
>  {
>  	quarantine_remove_cache(cache);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 1865bb92d47a..3eff57e71ff5 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -164,6 +164,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip);
>  
> +bool check_invalid_free(void *addr);
> +
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 4bdd7dbd6647..b2638c2cd58a 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	return true;
>  }
>  
> +bool check_invalid_free(void *addr)
> +{
> +	u8 tag = get_tag(addr);
> +	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
> +
> +	return (shadow_byte == KASAN_TAG_INVALID) ||
> +		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
> +}
> +
>  #define DEFINE_HWASAN_LOAD_STORE(size)					\
>  	void __hwasan_load##size##_noabort(unsigned long addr)		\
>  	{								\
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174102.GJ4162920%40elver.google.com.
