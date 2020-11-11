Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFWIWD6QKGQEMZGCZDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C5412AF78F
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 18:49:11 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id r6sf732765lfc.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 09:49:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605116950; cv=pass;
        d=google.com; s=arc-20160816;
        b=VM5cugaQb+x7A1AGRb3EvcQrIdwAIeRh2Y+WyzIPQ7XBOsy/iyhzStMHq6UMsESFJP
         vCj3+U8osB/s4dFe8pJn2foDb6zGCsssp0zePibIySdeL1+VDjH6XVgbe4cz+6sst42V
         mo4okSC/0edYEraECWBz5ylf13NVzpKyHH8ijzaDx6MYvQjlvrBmqCV0/kHnJ8vruEy3
         3C7VLSJUYByny2G470nX2lBj7GfM9AbiYYGT7FUjFOTMhmufQgjk5WKeQM5N4V46xBme
         /Ozyi3A4uL76eZMGcoEFbgKLfWN7BXOdUn7Du7UrOu8dOCpjdPCnJELnnfbkOIceFYVu
         Zbgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lKUWyPoB47WsZ39+pfvAOmC5OZlwIpIi+PimtxxZmg4=;
        b=uoNftTXjNFuNmaR5TLTAwW/HKg57Xi3CAZKbhYZzu+EK8rs85oD2ygzOrzu4GS5W1Y
         aQKDtHOpIaWMq70b0xJsTZyjH8G+JrvGLWIqIkIAdw1y/gmiYFiSIdjNXWoUsdNM9kSl
         UA2Ji4DDbDke71ZhBueVBHo5nL0aLYgEeU50y+OnokPB7h9tdDgE+n7mm5CE0Ll0psNX
         B1ebHpX8Anpz1lrwcPd2Imwgi9n+VLbqNGbC+TPklkzPwG2liYL9NnyJbQu/qkqxFOFh
         I6YcWfAW4VEyBnIL+VCIvWMlas5nga5yQhGVX/2MgXSjSY/gDSuHT61xfGnLx2rKbLjq
         pyzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OkPFBQNY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lKUWyPoB47WsZ39+pfvAOmC5OZlwIpIi+PimtxxZmg4=;
        b=A0BeZ7x9Cxc4JgyZNV500sABo2Jelgzm26fHWNkM83cDu5gFnB6tJq2PHh8lryAr+C
         uz+O/IqyzlIQPbOJdnYArHJkis2kFZbqb05IquhlM44YwNDRn1Jo4HVCOiv0WKtiRfBK
         wy8o1l1WriISujGC0BWtYU6+ssz2VlZl8JGumqjEkzNIyVEDt0cWpaAgZXmrojNo30iw
         8VhjKfI6D/7i97x0QsLDt+FZVWL4FfZTWjtSX56EImfV6NrkN9cyDaWfCvEiZbmfEwHR
         kR5WdFl3onCuJ/B856wXCI2Izqsr+hXnWfYNfdBF0Js1CdWlcf09C3OLVSw+Ta4Bi+AI
         p3ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lKUWyPoB47WsZ39+pfvAOmC5OZlwIpIi+PimtxxZmg4=;
        b=gkw9/LYTypwdlSPFyTg6Nj0TuCaYsmIdE59eCN8HYhecOin0pkZFFsviRthVyFHUZ9
         uxh0n6xKEQ1H5iM/wrNUKxTIAGaMZO0atowGZQShB4ZXcMc4U0b3h/a14YRevrzjNpnF
         ZSAfVhqPyXcyscB8YmpuyYN//rJAzOfoipqcsi3rbtj4vSmFA6PR7TdpXQw80xJXdOAF
         XoWpyvrPnbbTNxqxIn6koZk1BN7nmWFlc3E5W5Zct9Zt5rrhHn8K9ap8op8Psid2kCsH
         iRgkJyDKgDsbziNxbA38QI1WrKY6cEnLOxy6H3TFeSkwXnDHTJuCzAbfRDIApFMny3dB
         g0WQ==
X-Gm-Message-State: AOAM53259dOxxYe/+P8o/zxOqdF12JS5kW/hhz/wPLXGV6gMMRfIgV5Q
	0h+20VRP9vNImHnk2bXWbvc=
X-Google-Smtp-Source: ABdhPJx8G/lEWfcW7skOwI0ggFi1W7UaxNi7cUmgenGuAEWge7GnMsVygglaDLIddMriYq3oPagUBg==
X-Received: by 2002:a2e:8013:: with SMTP id j19mr6702599ljg.114.1605116950609;
        Wed, 11 Nov 2020 09:49:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls209036lfn.0.gmail; Wed, 11 Nov
 2020 09:49:09 -0800 (PST)
X-Received: by 2002:ac2:55ac:: with SMTP id y12mr3348821lfg.240.1605116949345;
        Wed, 11 Nov 2020 09:49:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605116949; cv=none;
        d=google.com; s=arc-20160816;
        b=p56UGEFyrpkprLL60EaAK8zdzLg/9vBnesrkDAvskr6vQfW1rqcPKTL6NwQ1hhjjo3
         ZuxF1QBps/ajX49bK1C6jkRchJH1tIYO50b0pBncO3ZjYl4SljzHAUKkAO5isk0D/FLL
         GVxi+d00VY5wtsHp2nVdKgq6hvNLNoSdFVkO7v4cJTRvypgFMgSJSo9tkLo7sNepzKMg
         6FciLNh8dIHlepuco1a96k4QfjE5hE6qJPOe2BTcsEQd4Z01qX2w6fGuatCjIb6q2G1p
         b+lXl2U2IgmAzcHmZFY2viAn1SPExml+kek2nknepQlEWdVc9Qy0pjnzoLaTmcPEVsK0
         KBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dxflwy28eDhlYIu6gOleg6G31J7w566728A9aheIIzc=;
        b=xfWQYaGDt7uXRyiRWtxPPenET2q4EDGVJ8DY2FJNEp5ixp91kvkeGyrNPSBF5xwHTR
         R8NaqCpOi3M0Mgc0ROB0KqIzodTDB02vRQA/yThAQDsw8FnQhfUNfMlvfCjeoLYpVgdB
         Yq8/HOmT4SW3+a9jisGfXVXy8jyuTPKcyKNtdEzHSnGZ0Z9wFexfi4Q9mJlD+0RbVTmz
         CfIWQQbanTuIVqT4oNuD62sHlaQWFBnr+832GAAmKyp1jiSvO1tglcyK8nYuAEgf1vDh
         G/bFdIPkVOx7/hoysLZX7xZ6oCtl7q3rGQh7GdYrpezMiYdhAUFzdUnkttJGlVGr9Ik+
         HKIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OkPFBQNY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id 26si103580lfr.13.2020.11.11.09.49.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 09:49:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id p22so3032800wmg.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 09:49:09 -0800 (PST)
X-Received: by 2002:a05:600c:2119:: with SMTP id u25mr5258800wml.53.1605116948480;
        Wed, 11 Nov 2020 09:49:08 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id v19sm3486601wrf.40.2020.11.11.09.49.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 09:49:07 -0800 (PST)
Date: Wed, 11 Nov 2020 18:49:02 +0100
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
Subject: Re: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
Message-ID: <20201111174902.GK517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OkPFBQNY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Currently kasan_unpoison_memory() is used as both an external annotation
> and as an internal memory poisoning helper. Rename external annotation to
> kasan_unpoison_data() and inline the internal helper for hardware
> tag-based mode to avoid undeeded function calls.

I don't understand why this needs to be renamed again. The users of
kasan_unpoison_memory() outweigh those of kasan_unpoison_slab(), of
which there seems to be only 1!

So can't we just get rid of kasan_unpoison_slab() and just open-code it
in mm/mempool.c:kasan_unpoison_element()? That function is already
kasan-prefixed, so we can even place a small comment there (which would
also be an improvement over current interface, since
kasan_unpoison_slab() is not documented and its existence not quite
justified).

> There's the external annotation kasan_unpoison_slab() that is currently
> defined as static inline and uses kasan_unpoison_memory(). With this
> change it's turned into a function call. Overall, this results in the
> same number of calls for hardware tag-based mode as
> kasan_unpoison_memory() is now inlined.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
> ---
>  include/linux/kasan.h | 16 ++++++----------
>  kernel/fork.c         |  2 +-
>  mm/kasan/common.c     | 10 ++++++++++
>  mm/kasan/hw_tags.c    |  6 ------
>  mm/kasan/kasan.h      |  7 +++++++
>  mm/slab_common.c      |  2 +-
>  6 files changed, 25 insertions(+), 18 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 53c8e8b12fbc..f1a5042ae4fc 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -74,14 +74,15 @@ static inline void kasan_disable_current(void) {}
>  
>  #ifdef CONFIG_KASAN
>  
> -void kasan_unpoison_memory(const void *address, size_t size);
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>  
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  			slab_flags_t *flags);
>  
> +void kasan_unpoison_data(const void *address, size_t size);
> +void kasan_unpoison_slab(const void *ptr);
> +
>  void kasan_poison_slab(struct page *page);
>  void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> @@ -106,11 +107,6 @@ struct kasan_cache {
>  	int free_meta_offset;
>  };
>  
> -size_t __ksize(const void *);
> -static inline void kasan_unpoison_slab(const void *ptr)
> -{
> -	kasan_unpoison_memory(ptr, __ksize(ptr));
> -}
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>  
>  bool kasan_save_enable_multi_shot(void);
> @@ -118,8 +114,6 @@ void kasan_restore_multi_shot(bool enabled);
>  
>  #else /* CONFIG_KASAN */
>  
> -static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>  
> @@ -127,6 +121,9 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
>  				      unsigned int *size,
>  				      slab_flags_t *flags) {}
>  
> +static inline void kasan_unpoison_data(const void *address, size_t size) { }
> +static inline void kasan_unpoison_slab(const void *ptr) { }
> +
>  static inline void kasan_poison_slab(struct page *page) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>  					void *object) {}
> @@ -166,7 +163,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  	return false;
>  }
>  
> -static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  
>  #endif /* CONFIG_KASAN */
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 1c905e4290ab..883898487b3f 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -226,7 +226,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  			continue;
>  
>  		/* Mark stack accessible for KASAN. */
> -		kasan_unpoison_memory(s->addr, THREAD_SIZE);
> +		kasan_unpoison_data(s->addr, THREAD_SIZE);

... this change would become unnecessary.

>  		/* Clear stale pointers from reused stack. */
>  		memset(s->addr, 0, THREAD_SIZE);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a266b90636a1..4598c1364f19 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -184,6 +184,16 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>  
> +void kasan_unpoison_data(const void *address, size_t size)
> +{
> +	kasan_unpoison_memory(address, size);
> +}
> +
> +void kasan_unpoison_slab(const void *ptr)
> +{
> +	kasan_unpoison_memory(ptr, __ksize(ptr));
> +}
> +

This function is so simple, I think just open-coding 

	kasan_unpoison_memory(ptr, __ksize(ptr))

wherever required is much simpler, also bearing in mind the changes that
are coming to the rest of this series.

>  void kasan_poison_slab(struct page *page)
>  {
>  	unsigned long i;
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 0303e49904b4..838b29e44e32 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -30,12 +30,6 @@ void kasan_init_hw_tags(void)
>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> -void kasan_unpoison_memory(const void *address, size_t size)
> -{
> -	hw_set_mem_tag_range(kasan_reset_tag(address),
> -			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> -}
> -
>  void kasan_set_free_info(struct kmem_cache *cache,
>  				void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ab7314418604..2d3c99125996 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -283,6 +283,12 @@ static inline void kasan_poison_memory(const void *address, size_t size, u8 valu
>  			round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>  
> +static inline void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
> +			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +}
> +
>  static inline bool check_invalid_free(void *addr)
>  {
>  	u8 ptr_tag = get_tag(addr);
> @@ -295,6 +301,7 @@ static inline bool check_invalid_free(void *addr)
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
>  void kasan_poison_memory(const void *address, size_t size, u8 value);
> +void kasan_unpoison_memory(const void *address, size_t size);
>  bool check_invalid_free(void *addr);
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 53d0f8bb57ea..f1b0c4a22f08 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
>  	 * We assume that ksize callers could use whole allocated area,
>  	 * so we need to unpoison this area.
>  	 */
> -	kasan_unpoison_memory(objp, size);
> +	kasan_unpoison_data(objp, size);

... this change would become unnecessary.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111174902.GK517454%40elver.google.com.
