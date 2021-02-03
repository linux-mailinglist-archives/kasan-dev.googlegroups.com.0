Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6EM5OAAMGQE2OOHKLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31CC730DEAC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 16:51:21 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id n18sf31659wrm.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 07:51:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612367481; cv=pass;
        d=google.com; s=arc-20160816;
        b=IwWGwZ2rQgG8+VEjL0UEr27SznyzsAT2W5pM1xnkd5k98BxfHV8UMpRtIKsYgjUyeO
         dh2oPNOAyt5L3lRTGu9w7FljbKK4cOCYi+KHTq3FYklowSiGrOPTTYESWJf2WZfFUPVC
         mf6fMkbe7hAmlyHK+4QI8kIzUnWvNYGDESfHrJahYMUMBeLdzFpvNqsBSMDqoTG0V+tq
         sdoNqEnCWF7RoNkgSyvjnefWhDOWVuQ6zMxYzYpyI3BG0kTKT2sSf+zvjkZgQf2T6jgl
         PQAI3BbtKoNBLuW1k3yZEhmiyPoaXycM8Fpm7EriwcNcchSAq3KwxeBz1JK05iHGKyqe
         b2+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=H5uuDC6WdZLqkCJZ8cOraNu8cs/8smPg6XHEUTOu4Qo=;
        b=TMbLKIFQHBeHqJ+gTj4zi4FJ3KqiawhSJGucI6tIT4U8emUMtVeulcQ+4TschNd3+P
         GVeZScnsL5W6mF/ekkLhtWOYKBIJlj54bs/DiBhNBf4/h+YIdf9CIqdUp6MGy6oSSgAS
         xYsBl6BO7yMr/jz79uh3vXDK1MgqlipFXaHKOATrqYrCUAjwgc/aBh5CX3H9qDpCAPlS
         tdHh8juEVIxZx+iGy5TP3U+2EncYY2Mv5xEIvT+xJlXkygQDClUc5hu1WSjeUhDDLVVt
         tIVmDILEahgC9bo7uVVP9mbORw6qadTu3xtiVdEVQ87WOFN59N9/0Da4nhpQFe1TLPFj
         4Aog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=opmr3FHE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=H5uuDC6WdZLqkCJZ8cOraNu8cs/8smPg6XHEUTOu4Qo=;
        b=ZQ11RLA0bVMvMno7c2pu+GIWT4f7OXwAM9E3IlGjhrRqEsyZX6MnuBdOfNIBtpsjye
         JuXKwjdrLnGeTKobi1ivo7nNGDqDjrDc/vYioItEeyYbZu1iKeMyl/hy/VfZnuYjUzmm
         kPAVzsJeBHxK5fXXoskhyEior6iMca05AMgFxaR00gXmCXGl6JTJIP52scH0XvwA1mm0
         4i0wBuI0F+jmYrmIaHFpD81GQDJOC6eAs4fAPGqPTx2TKDS2amKsRWEvPOM3lADY2i0/
         uumk6sBFOhpc2JHdSZUHjorWgr595zqw2skgNds4qlw1haB5siCsGmILCPyWCPKin1df
         9fYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H5uuDC6WdZLqkCJZ8cOraNu8cs/8smPg6XHEUTOu4Qo=;
        b=NKASTDzWIJo/UqsDdBaGb/RCg3OXIF/YE5QDSRlTys/GeFFPtCnjZoSlhriectzgCp
         1eH/pVAc+KaMetkHbTQKsqSz8FoKsrJOhuZ3wnLJ0IlXMAQYGM/oRPZIsTSs0H2w0V/9
         grrSlIyQskdPwRefYhYtSMavyJmOtNval6ayhnFuJPPUP/iVL7M4CKKM8DsS5gTcwH2E
         W/nXbQz/EAaWYQhe90alSQLsN7kjbqkYSY9XLMqdFkLolFN1dPQapHL9QSfCgCGhsc2Q
         ngHqglv6NOo6mn3P262Onz6ocVa3Ykh2RSFmnFOyztDKWa+hlhUAfAwHjxqtRjY5J0L8
         2eJA==
X-Gm-Message-State: AOAM533kpOpgZAg2kRsgA36V5x1ab2HpNciiGVzEkZpI6BPqq7r/vTfS
	3cI/9hagtOtpWcHK7X16abs=
X-Google-Smtp-Source: ABdhPJw2grIJzAZDfdHhIlIuBidYjATCtbhbXwwR30RuVIEMkWZbS6WiwaIR/9PdaU9K+j34XJTRpw==
X-Received: by 2002:a05:6000:1841:: with SMTP id c1mr4185617wri.278.1612367481007;
        Wed, 03 Feb 2021 07:51:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls3208416wrq.1.gmail; Wed, 03 Feb
 2021 07:51:20 -0800 (PST)
X-Received: by 2002:adf:ba49:: with SMTP id t9mr4288569wrg.183.1612367480148;
        Wed, 03 Feb 2021 07:51:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612367480; cv=none;
        d=google.com; s=arc-20160816;
        b=DVA4cqQuwgV3BMNbf6k6moDMKp/Px1APJGysUe5jG33VsM0yMljB+cOllnGctepN/P
         Kx4I96w1otAQxiSL6I3wICjK02qtTacZaP6IDoRgVxPuAX2GHpEhW3UgcvA2TPJNt/Gk
         uV2WGd4K9vE0aPCTEiER0oEkPVI+818vl+heiw+qLONKi9L7+zdJPovSgfxnPn3cJcbH
         jNprxDanWS+Wz9cwY1b/b/B2++AplWu8Pn4U8QaiCeN2SoE3OPod4cPP4ytYw1reZJyf
         2OE/VORfhwkIwW9fDh838ImvF0xRB9XYKJp7Gups9erRtDMDn3+vgKQJE0BoCuRfOVTJ
         Y3HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=u/vTmytfnHf8bSBtRdC4NPN+aY/KtT7liekrT8jCTRw=;
        b=FLOVg/EBzQpWfBvAZKJVnQUlhwK3Ady4ZORO5V35byOtSTUlenGQXQHkHEThVXY2EQ
         0mHMwh7XGf9elRpaTAOOhBtHGJVashd/Jb+Msl3zuIupnbalN/lAhBcVIrRUvN3o18uQ
         iClzpopTCDISKxscbH+OYjglnhktpeSqeM/991HWNh3fkF18Ue7NsQ+Jo4fXchgohuPJ
         /fvPXMwTa6i7TZW3MJPN0atLuU9PJN8dAVCwxiqJDk8u+Awae1rU/qeUytz15wToRTt+
         Y/SqQv54XwNurtT8UHkRC1VYivhOOZBuELgYgerXsedxBUMT145+BEnzmxCUiGrhVjnl
         P83A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=opmr3FHE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id b5si102101wrd.4.2021.02.03.07.51.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 07:51:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id 7so24964368wrz.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 07:51:20 -0800 (PST)
X-Received: by 2002:a5d:5686:: with SMTP id f6mr4193118wrv.257.1612367479798;
        Wed, 03 Feb 2021 07:51:19 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id p9sm4481682wrj.11.2021.02.03.07.51.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 07:51:18 -0800 (PST)
Date: Wed, 3 Feb 2021 16:51:13 +0100
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
Subject: Re: [PATCH 11/12] kasan: always inline HW_TAGS helper functions
Message-ID: <YBrGcY/DS1GnilYo@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <05a45017b4cb15344395650e880bbab0fe6ba3e4.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <05a45017b4cb15344395650e880bbab0fe6ba3e4.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=opmr3FHE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
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
> Mark all static functions in common.c and kasan.h that are used for
> hardware tag-based KASAN as __always_inline to avoid unnecessary
> function calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Does objtool complain about any of these?

I'm not sure this is unconditionally a good idea. If there isn't a
quantifiable performance bug or case where we cannot call a function,
perhaps we can just let the compiler decide?

More comments below.

> ---
>  mm/kasan/common.c | 13 +++++++------
>  mm/kasan/kasan.h  |  6 +++---
>  2 files changed, 10 insertions(+), 9 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 5691cca69397..2004ecd6e43c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -279,7 +279,8 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>   *    based on objects indexes, so that objects that are next to each other
>   *    get different tags.
>   */
> -static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
> +static __always_inline u8 assign_tag(struct kmem_cache *cache,
> +					const void *object, bool init)

This function might be small enough that it's fine.

>  {
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return 0xff;
> @@ -321,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> -			      unsigned long ip, bool quarantine)
> +static __always_inline bool ____kasan_slab_free(struct kmem_cache *cache,
> +				void *object, unsigned long ip, bool quarantine)
>  {

Because ____kasan_slab_free() is tail-called by __kasan_slab_free() and
__kasan_slab_free_mempool(), there should never be a call (and if there
is we need to figure out why). The additional code-bloat and I-cache
pressure might be worse vs. just a jump. I'd let the compiler decide.

>  	u8 tag;
>  	void *tagged_object;
> @@ -366,7 +367,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return ____kasan_slab_free(cache, object, ip, true);
>  }
>  
> -static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> +static __always_inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
>  {

This one is tail-called by __kasan_kfree_large(). The usage in
__kasan_slab_free_mempool() is in an unlikely branch.

>  	if (ptr != page_address(virt_to_head_page(ptr))) {
>  		kasan_report_invalid_free(ptr, ip);
> @@ -461,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  	return tagged_object;
>  }
>  
> -static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> -					size_t size, gfp_t flags)
> +static __always_inline void *____kasan_kmalloc(struct kmem_cache *cache,
> +				const void *object, size_t size, gfp_t flags)
>  {

Also only tail-called.

>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 2f7400a3412f..d5fe72747a53 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -321,7 +321,7 @@ static inline u8 kasan_random_tag(void) { return 0; }
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
>  
> -static inline void kasan_poison(const void *addr, size_t size, u8 value)
> +static __always_inline void kasan_poison(const void *addr, size_t size, u8 value)
>  {
>  	addr = kasan_reset_tag(addr);
>  
> @@ -337,7 +337,7 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
>  	hw_set_mem_tag_range((void *)addr, size, value);
>  }
>  
> -static inline void kasan_unpoison(const void *addr, size_t size)
> +static __always_inline void kasan_unpoison(const void *addr, size_t size)
>  {

Not sure about these 2. They should be small, but it's hard to say what
is ideal on which architecture.

>  	u8 tag = get_tag(addr);
>  
> @@ -354,7 +354,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
>  	hw_set_mem_tag_range((void *)addr, size, tag);
>  }
>  
> -static inline bool kasan_byte_accessible(const void *addr)
> +static __always_inline bool kasan_byte_accessible(const void *addr)

This function feels like a macro and if the compiler uninlined it, we
could argue it's a bug. But not sure if we need the __always_inline,
unless you've seen this uninlined.

>  {
>  	u8 ptr_tag = get_tag(addr);
>  	u8 mem_tag = hw_get_mem_tag((void *)addr);
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBrGcY/DS1GnilYo%40elver.google.com.
