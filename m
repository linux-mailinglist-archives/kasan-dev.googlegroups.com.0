Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7R4WAAMGQE65JGPIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3359530C4DC
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 17:06:32 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id z5sf11702619ljo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 08:06:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612281991; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0kcAkyhMOTd+FwlTa0p2m/3pMbTXDWb1n/eztDcglVQGquKzrPIw/uAYUQWvy6mYZ
         Ch0KwVr+F4Ze4sp5qmfdiVvKo/mUV6ewgLVKpEOV1lddZ8irGCfsITKexsQTgHri1lR2
         0muuDE/wPBtApq7QwiXqVmrx1+4AsTi4FZOIP3Lz/HewPd1tRdk6QxwIvJ3CwDIEIoMy
         pkzSa7v6JD1M1APK2a3Zr+VeZKrLkjrzBnl3alqZ9cxBAROwcj/pYJ4CETxVr/WTopzg
         B/J8J83/UyBfB2Oaut4wvmA71tg5mBcbqBH38DUn42nxI76P2GhdSFcGgrZTGZqfJfHg
         gIAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=BwCFyb4xm2lPK6CPMWN1hQOQJTSJR1TCqf0xA41vJAQ=;
        b=Ji8xM0fRvgfsqiwWWCr22xFbkM2emg2PowEyFcPkaMuAVtx2rdErI+fAm+CnZabGpg
         IApm0ACmZ23aL3LXth7xWnE/9LxfKCBE6ovESMFlLXvFvmXDSxlBWabne/uakwYg2mJ2
         VJudhpsK3ldyczH9lZp9LqDpHz5hrAgFx/K9hEWvbEIe95MGzr8cXum8NGjrJQqFjD5A
         6QYihyNwZmdv6/Bmssl8Qu6N7ydvHHRliyVswX3muR772xKCnZ1Q38cAWsQTsUavubb7
         DJ8DBd9M26yKq1FW53jtHbAZwF2AsawOZtx7T2kyyWwAjfZNusoZmXifqJNkTTNUrvFo
         CYwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=noluI+hT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BwCFyb4xm2lPK6CPMWN1hQOQJTSJR1TCqf0xA41vJAQ=;
        b=kUEpR4NfvaeahFd+dmiR80QBN3wWZeIVYW1sF5NGY/k0EgUli0RCmbJHPez9Xcw2rd
         i/3+HiId+olGVmEMaDoEk+b6kKOxcUm1kpmRv7sw0mYmvAp19YY1NxJoj5xngyZnY8EP
         QypRMcxOVzya2ML5hpreVHtqFI11a5MIbtT928sDEifr6P4tJ0CahHJhXT0O37d/C8cI
         llD07mkD0gTppFthkUD7diwGDm8kODNDnRcsjaDeExO9Ocur4djk3Cs+1vFkDefDAPG3
         cvIwWdLWNq4YbRDr17vvfaZED4RvxpF0Up+lf0gQKnfm18oDlgy6ttT6v3x+NP0Ma/kc
         wfdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BwCFyb4xm2lPK6CPMWN1hQOQJTSJR1TCqf0xA41vJAQ=;
        b=YCiqqQp0zcjilW9Rtgl7gZfv7KJMSpjSdTt4KaW14sRCsLNIN0ii4ZI5eFhdZgV4gv
         9g6cZtEUxTtsDsmw6h5kJmDip062QMR93EYh7QzV4jGMBU+gNFF/FGMeGoB3ixbJuZju
         SOFEwJi2A9jebDC4jBlf7uTHJ6AQHw0m1CXCcJivWoYyfSNPfUBgJQGcTX9ZUEKRs6Lm
         aQuhE9wvqVvm3UYGG2n4uACzwstpY/GTw3/lHzbVLh3m3Xfi6fwyGj2bFBoYNfoEBBOx
         dDta3ZVn24V3skk0mTWYR4vI8GQIaTESFeAxbum91n8lgLFS3eKC/z9qG/xLv8YKn0Hr
         VUxw==
X-Gm-Message-State: AOAM532IQylGRbAp8CyT61nHSSbNVGf45R1hQU4OW8Ks4DqR6voYeQMC
	Pjz7ddJUzib4Q+fv5qwh+2A=
X-Google-Smtp-Source: ABdhPJyJizVajcDWYEu3voqyYczWEOSHxnNDYF+h6QyYXHi75im9i3FtLo+vc07IPIytZM8qUSHufQ==
X-Received: by 2002:ac2:42d1:: with SMTP id n17mr11056435lfl.76.1612281991718;
        Tue, 02 Feb 2021 08:06:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1314:: with SMTP id u20ls1666136lja.9.gmail; Tue,
 02 Feb 2021 08:06:30 -0800 (PST)
X-Received: by 2002:a2e:760e:: with SMTP id r14mr13506806ljc.490.1612281990261;
        Tue, 02 Feb 2021 08:06:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612281990; cv=none;
        d=google.com; s=arc-20160816;
        b=CYd4SF2NanLK9PPnKL7IEEw3voC0GbzfQ2HYYg+xooT7dNcaR27K0RbhFzpopP8WbV
         dITmOjKM3qwr5vt0DNlqOevCeUzIRl/q2ts0MRKulfB2VKfTkS43diqeRz6X5cEILqgX
         2Hjfq/s1qtKa3Zx+zN7B6HuAH8l4kkxa2ubzbkKvgxhHTZ9zZwh6zmxCcTyYNPqfpu9s
         5Vsj/YCT8HBtKwdiCEEizYHmlFhQRfKbbg23XftXHi7M0BX3bEHkOrF2NLw53z5waFx+
         SqLfhKESsjmY8kSsD1aYk5E8HPnFsrlaXKNgFPEOJ4KoRnn7qI7AJtrkhtLDnOFvQlKE
         +roA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BQvmEctZ12mZ6s6zRO2SwQ7wsNfTEyJ3Wk+6Hh+PUyE=;
        b=mJJlP7eEocvohyQH6dnTCq/66KAR/8IYmIRPYNrVt8UirF6+it18o/lgyao0aYM1is
         G1x80SH9nl4+EmylUBlnyCGQ6MRzpz3zyMCEcj6GsppqPpRMIoyuTWF4mNsO+Gc50bHF
         jzHSVLMr0wte1Isab9xg8T2oLY1JZtV3iYCdGhNa0yLyo72RMeJy04xBlZNMhZqexhu+
         bmp5CyXoq0nONwq+32f932pMN6/5OAWKYafJwb665I3zgSOsqYjTDuWZseJyVAfYBe+D
         GkmLshXJC01paUdg/B7AeyX/MOKWXLljNHZ9smeL3DUoGJ99IFg9UUmoa7mbl9gFnPMf
         lmpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=noluI+hT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id t21si717807lfe.3.2021.02.02.08.06.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 08:06:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id q7so21012356wre.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 08:06:30 -0800 (PST)
X-Received: by 2002:a5d:47a2:: with SMTP id 2mr24388073wrb.393.1612281989503;
        Tue, 02 Feb 2021 08:06:29 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id i64sm2377327wmi.19.2021.02.02.08.06.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Feb 2021 08:06:28 -0800 (PST)
Date: Tue, 2 Feb 2021 17:06:21 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 01/12] kasan, mm: don't save alloc stacks twice
Message-ID: <YBl4fY54BN4PaLVG@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=noluI+hT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> Currently KASAN saves allocation stacks in both kasan_slab_alloc() and
> kasan_kmalloc() annotations. This patch changes KASAN to save allocation
> stacks for slab objects from kmalloc caches in kasan_kmalloc() only,
> and stacks for other slab objects in kasan_slab_alloc() only.
> 
> This change requires ____kasan_kmalloc() knowing whether the object
> belongs to a kmalloc cache. This is implemented by adding a flag field
> to the kasan_info structure. That flag is only set for kmalloc caches
> via a new kasan_cache_create_kmalloc() annotation.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h |  9 +++++++++
>  mm/kasan/common.c     | 18 ++++++++++++++----
>  mm/slab_common.c      |  1 +
>  3 files changed, 24 insertions(+), 4 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6d8f3227c264..2d5de4092185 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -83,6 +83,7 @@ static inline void kasan_disable_current(void) {}
>  struct kasan_cache {
>  	int alloc_meta_offset;
>  	int free_meta_offset;
> +	bool is_kmalloc;
>  };
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> @@ -143,6 +144,13 @@ static __always_inline void kasan_cache_create(struct kmem_cache *cache,
>  		__kasan_cache_create(cache, size, flags);
>  }
>  
> +void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> +static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
> +{
> +	if (kasan_enabled())
> +		__kasan_cache_create_kmalloc(cache);
> +}
> +
>  size_t __kasan_metadata_size(struct kmem_cache *cache);
>  static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
>  {
> @@ -278,6 +286,7 @@ static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>  				      unsigned int *size,
>  				      slab_flags_t *flags) {}
> +static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  static inline void kasan_poison_slab(struct page *page) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index fe852f3cfa42..374049564ea3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -210,6 +210,11 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  		*size = optimal_size;
>  }
>  
> +void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
> +{
> +	cache->kasan_info.is_kmalloc = true;
> +}
> +
>  size_t __kasan_metadata_size(struct kmem_cache *cache)
>  {
>  	if (!kasan_stack_collection_enabled())
> @@ -394,17 +399,22 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  	}
>  }
>  
> -static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> +static void set_alloc_info(struct kmem_cache *cache, void *object,
> +				gfp_t flags, bool kmalloc)
>  {
>  	struct kasan_alloc_meta *alloc_meta;
>  
> +	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
> +	if (cache->kasan_info.is_kmalloc && !kmalloc)
> +		return;
> +
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
>  	if (alloc_meta)
>  		kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>  
>  static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> -				size_t size, gfp_t flags, bool keep_tag)
> +				size_t size, gfp_t flags, bool kmalloc)
>  {
>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
> @@ -423,7 +433,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  				KASAN_GRANULE_SIZE);
>  	redzone_end = round_up((unsigned long)object + cache->object_size,
>  				KASAN_GRANULE_SIZE);
> -	tag = assign_tag(cache, object, false, keep_tag);
> +	tag = assign_tag(cache, object, false, kmalloc);
>  
>  	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>  	kasan_unpoison(set_tag(object, tag), size);
> @@ -431,7 +441,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  			   KASAN_KMALLOC_REDZONE);
>  
>  	if (kasan_stack_collection_enabled())
> -		set_alloc_info(cache, (void *)object, flags);
> +		set_alloc_info(cache, (void *)object, flags, kmalloc);

It doesn't bother me too much, but: 'bool kmalloc' shadows function
'kmalloc' so this is technically fine, but using 'kmalloc' as the
variable name here might be confusing and there is a small chance it
might cause problems in a future refactor.

>  	return set_tag(object, tag);
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 9aa3d2fe4c55..39d1a8ff9bb8 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -647,6 +647,7 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
>  		panic("Out of memory when creating slab %s\n", name);
>  
>  	create_boot_cache(s, name, size, flags, useroffset, usersize);
> +	kasan_cache_create_kmalloc(s);
>  	list_add(&s->list, &slab_caches);
>  	s->refcount = 1;
>  	return s;
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBl4fY54BN4PaLVG%40elver.google.com.
