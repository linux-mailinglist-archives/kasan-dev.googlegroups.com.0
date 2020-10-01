Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FT3D5QKGQE677VTFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A83028062B
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 20:03:37 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id b14sf1132648wmj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 11:03:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575417; cv=pass;
        d=google.com; s=arc-20160816;
        b=uB3OfU1xxtvQnAZdgdYMBGMCRccb5gr57KIHrZfLkGovHhvmW/bSHBUy74xLtTshOj
         22SbtjaM+nmGtsXW7cpn6XDZDNv8TNzEG4X51ACK8vdrvFzC8xflr1AtZszp6aPXIQEv
         FepNNmOoA3FZGTA1YNHkTQcgL4+4n7/A0yHbnqb+aS1lYTGq0PL6qNoagFu2LEm0qIr7
         aBCj7olR+1Y6wrJT4JyTKkA1XNPlhzRF4OHek329wa52CkiOqqQMgLu6DNzGb/PFV0cd
         rFZke7O5G0lVpNKYhHYQUyjmfvLKsz3Az5+oDL9eQdUH8lOvVZ4BTnyOLA3GuL1qyZ5W
         1PqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tKQF9EvSAUvPmD5Qde4wRxTvbMwsN96Kbc5+KintbX4=;
        b=yOxgnTFpM56kgeJ1T67Pl/HL32zmiKYpm2PwVgvflH9TF9RTRxexR6i+QmAHpQNc5d
         rPTA6oc3ORg339BuYFpzSF8Er3xjPt8QIuOPY2eGeTNJ7NCPwAH3zw6xPDqDNCg+xfQo
         fwuDFI8rY/MW1PtSSXz4iem68QTlaiwC2DuGUTYkkCN4K/3cRqdJ8VTS0Xxm8HMxFVu0
         fwfEGN3IsOnYmb3eMWr3I8E9tqPEpqZXZcU/eaG63fgVV9hIBfAIRNkcqnN06vuLevZ6
         rOxtK92lhaKJiHFVdh/Wp0LBYlP22sckx4Pj5yIq6MtRflCxj9LVRGsdIXEAyF73Am5u
         37PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g857Ar4O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tKQF9EvSAUvPmD5Qde4wRxTvbMwsN96Kbc5+KintbX4=;
        b=FLvhCfSXkNCNGy4AMMSUJwFwrI8kG3OLXS1QR1V/YdJvs/LIu9eimZ80sMnh7d2rWI
         rkfh/kItx6i6gi+RUkvqSSKLEGDuEGKZzguI6qpjD+P6JMLVubiBU72fzEzZ0KhfFmW8
         OJ2C/YjjyIJuov97xh3aYS21NAECmnuPdu94qh7bnfimlPYWTQP2mO79M8kZu6iA78eJ
         dK30v93JuUq/tPwia4+x2UTD8aOyuK0prbUr+tmug8UwmjVVhILyFF2Ehs1dS/20Ucw3
         WRwy9HUx2QvkqB6agb+A9sStHJlh5wfTilnhMC5cI5rmvuC+gl6hEmpQ1Yeb5q/3dMxW
         JDRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tKQF9EvSAUvPmD5Qde4wRxTvbMwsN96Kbc5+KintbX4=;
        b=oPGbN5pIsY0TiYTKmj495j94w2o+RS8wh+44+JN7YJ4SDyzLBcNDvbo1Y52FtotG2h
         mmOLd/ExDAE+cs91LlI5wTeibQ+Troj7iRe1FLqrbeZE+H3ETvmikaCPMVzu7N9JVon+
         55yjXUUMbBcUL0RVpmLxMyB/WqaR2lcemqWEezvHbksMCF2XMAKviTPtmv8mW+8xkO8A
         toPOsA4hbGuPOqIXzvU5yUKNmOtTGwUAjzJyHlGwPEqmPfRWdI1xtOcaIBXyy+UBunZ7
         Lk1ifkJP6qO/OfwqQDbprflxVC167z8qcoAsaKc8J3fz6Dahe5XpnMQ3jPinYet6Pxdt
         p7ow==
X-Gm-Message-State: AOAM533K+Z+ZPCL86ceCNZrLjw2Zje+jgscYqOJ9qxY6ZYtiI6ilZGeo
	EpSuwQ6sOCHySlbeFkAAF8I=
X-Google-Smtp-Source: ABdhPJzkRcI/d6HV7tnNj10w1SvDPGIpJybjEo682mZ8zTc1AIZsK9zAwcdWG6Tr78fGknjjQBQEjQ==
X-Received: by 2002:adf:dfd1:: with SMTP id q17mr11383301wrn.347.1601575417018;
        Thu, 01 Oct 2020 11:03:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls3317793wmo.0.canary-gmail;
 Thu, 01 Oct 2020 11:03:36 -0700 (PDT)
X-Received: by 2002:a7b:cd06:: with SMTP id f6mr1309487wmj.66.1601575415974;
        Thu, 01 Oct 2020 11:03:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575415; cv=none;
        d=google.com; s=arc-20160816;
        b=eVpLYCWGHXeyngW0Eio19jq4LvOUO4jrKUE1CbMzh326oo32vWQ122xK0gzNstNXpU
         77504W0hYXA5z2pMBZz3qVuGZcmEo6oZpiYh+eDYx6qcYCnDT6x+hK6UyuwMXG5/rYIu
         0ljRgWbBcFFrtECqz1Ti1yJOSCgGy6S/J8PVhXmNNK3mxCH9iDL+d8Y9B+TvbEoia9jf
         8CJGRbiskPaJgY16t2xPGcAzS9qfuibm4Od7kZuCTABeV+QrTDCRoUxuDSWa28Qv3qKQ
         1uUBgfYqwW7dx6Ov3lKdl11HgTENWhQfQy8/cJfI8Z7NOKO16k3YYWuci23eRg8eHB7x
         FNVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4RuJhY/87VL3JhPEf+faiXyRb2FdU2wNNWjiTAoQeOk=;
        b=CRKIjY+uaHdwvsvsmdLPIlfG40B6OgGIUm+sEgaUD/li162SCpNjmNloEZORIThW3p
         3rHsAcJ3EFyebCWvv8O6cIRU7d2br0fXeySpQPxzYrm3wNHeYl7+FTBZ1nOCv7MpwMca
         BiOGJWd54QB02wiaQ6oiwUpCtrpcG/noPfYBj2FKcCdus14l6vqnwZn1pgssBd6bDFLY
         FVrtb93WQdDXXvZpg6THQhsIfj/YOvIUoG5jfO3jFYNgAONi+mbHlt0CVuLlMzA3G9a3
         lAmy8QyB0NCXfEIPoExTEWoNrJObK1RO/ENETO8+EXjhjgH0HHg41tYeOGMoXFM34E1o
         XHlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g857Ar4O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f3si112746wme.3.2020.10.01.11.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 11:03:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id q9so3836798wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 11:03:35 -0700 (PDT)
X-Received: by 2002:a1c:b7d7:: with SMTP id h206mr1284905wmf.159.1601575415423;
        Thu, 01 Oct 2020 11:03:35 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id t4sm10525373wrr.26.2020.10.01.11.03.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 11:03:34 -0700 (PDT)
Date: Thu, 1 Oct 2020 20:03:29 +0200
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
Subject: Re: [PATCH v3 37/39] kasan, slub: reset tags when accessing metadata
Message-ID: <20201001180329.GV4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <a9229404628ab379bc74010125333f110771d4b6.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a9229404628ab379bc74010125333f110771d4b6.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g857Ar4O;       spf=pass
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
> SLUB allocator accesses metadata for slab objects, that may lie
> out-of-bounds of the object itself, or be accessed when an object is freed.
> Such accesses trigger tag faults and lead to false-positive reports with
> hardware tag-based KASAN.
> 
> Software KASAN modes disable instrumentation for allocator code via
> KASAN_SANITIZE Makefile macro, and rely on kasan_enable/disable_current()
> annotations which are used to ignore KASAN reports.
> 
> With hardware tag-based KASAN neither of those options are available, as
> it doesn't use compiler instrumetation, no tag faults are ignored, and MTE
> is disabled after the first one.
> 
> Instead, reset tags when accessing metadata.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Marco Elver <elver@google.com>

I assume you have tested with the various SLUB debug options, as well as
things like memory initialization etc?

> ---
> Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
> ---
>  mm/page_poison.c |  2 +-
>  mm/slub.c        | 25 ++++++++++++++-----------
>  2 files changed, 15 insertions(+), 12 deletions(-)
> 
> diff --git a/mm/page_poison.c b/mm/page_poison.c
> index 34b9181ee5d1..d90d342a391f 100644
> --- a/mm/page_poison.c
> +++ b/mm/page_poison.c
> @@ -43,7 +43,7 @@ static void poison_page(struct page *page)
>  
>  	/* KASAN still think the page is in-use, so skip it. */
>  	kasan_disable_current();
> -	memset(addr, PAGE_POISON, PAGE_SIZE);
> +	memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
>  	kasan_enable_current();
>  	kunmap_atomic(addr);
>  }
> diff --git a/mm/slub.c b/mm/slub.c
> index 68c02b2eecd9..f5b4bef3cd6c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -249,7 +249,7 @@ static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
>  {
>  #ifdef CONFIG_SLAB_FREELIST_HARDENED
>  	/*
> -	 * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
> +	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
>  	 * Normally, this doesn't cause any issues, as both set_freepointer()
>  	 * and get_freepointer() are called with a pointer with the same tag.
>  	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
> @@ -275,6 +275,7 @@ static inline void *freelist_dereference(const struct kmem_cache *s,
>  
>  static inline void *get_freepointer(struct kmem_cache *s, void *object)
>  {
> +	object = kasan_reset_tag(object);
>  	return freelist_dereference(s, object + s->offset);
>  }
>  
> @@ -304,6 +305,7 @@ static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
>  	BUG_ON(object == fp); /* naive detection of double free or corruption */
>  #endif
>  
> +	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
>  	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
>  }
>  
> @@ -538,8 +540,8 @@ static void print_section(char *level, char *text, u8 *addr,
>  			  unsigned int length)
>  {
>  	metadata_access_enable();
> -	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
> -			length, 1);
> +	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> +			16, 1, addr, length, 1);
>  	metadata_access_disable();
>  }
>  
> @@ -570,7 +572,7 @@ static struct track *get_track(struct kmem_cache *s, void *object,
>  
>  	p = object + get_info_end(s);
>  
> -	return p + alloc;
> +	return kasan_reset_tag(p + alloc);
>  }
>  
>  static void set_track(struct kmem_cache *s, void *object,
> @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
>  		unsigned int nr_entries;
>  
>  		metadata_access_enable();
> -		nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
> +		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> +					      TRACK_ADDRS_COUNT, 3);
>  		metadata_access_disable();
>  
>  		if (nr_entries < TRACK_ADDRS_COUNT)
> @@ -747,7 +750,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct page *page,
>  
>  static void init_object(struct kmem_cache *s, void *object, u8 val)
>  {
> -	u8 *p = object;
> +	u8 *p = kasan_reset_tag(object);
>  
>  	if (s->flags & SLAB_RED_ZONE)
>  		memset(p - s->red_left_pad, val, s->red_left_pad);
> @@ -777,7 +780,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
>  	u8 *addr = page_address(page);
>  
>  	metadata_access_enable();
> -	fault = memchr_inv(start, value, bytes);
> +	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
>  	metadata_access_disable();
>  	if (!fault)
>  		return 1;
> @@ -873,7 +876,7 @@ static int slab_pad_check(struct kmem_cache *s, struct page *page)
>  
>  	pad = end - remainder;
>  	metadata_access_enable();
> -	fault = memchr_inv(pad, POISON_INUSE, remainder);
> +	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
>  	metadata_access_disable();
>  	if (!fault)
>  		return 1;
> @@ -1118,7 +1121,7 @@ void setup_page_debug(struct kmem_cache *s, struct page *page, void *addr)
>  		return;
>  
>  	metadata_access_enable();
> -	memset(addr, POISON_INUSE, page_size(page));
> +	memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
>  	metadata_access_disable();
>  }
>  
> @@ -2884,10 +2887,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
>  		stat(s, ALLOC_FASTPATH);
>  	}
>  
> -	maybe_wipe_obj_freeptr(s, object);
> +	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
>  
>  	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
> -		memset(object, 0, s->object_size);
> +		memset(kasan_reset_tag(object), 0, s->object_size);
>  
>  	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
>  
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001180329.GV4162920%40elver.google.com.
