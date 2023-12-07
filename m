Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB56CYSVQMGQECSF3E7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AC20807DF7
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 02:35:53 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-67aa6e60d0dsf4845766d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 17:35:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701912952; cv=pass;
        d=google.com; s=arc-20160816;
        b=NhKVghO0Jhib/XAafdMg8TRkQBJUfGiBLCTEdwt1pc25/2aeiRgiqGeIwz0zt+gGzz
         1bCX8yiSTSM3RSrVVnYTua1vTyN1JzERk9B2XIqY+r73DoOJYpMQjQC/3I6t6F+thdUG
         w+cEDXPfuNkathg4mhZ9gl68BlK00Fu32L4iw6SUddbZK85E93LgYUt5xifA3nQQnPxa
         j4+3MClof0EGl9N0oiyJfNR+Ar4o5dBpCXGdzO+iWXk40fXgKcXxc+fRNqDX6bsfiAbQ
         Qaqv4GlqEqUFcrfEOVlI5pompTS6G7LZoTEYH/77ukjadfFDi3rMS9yhVthVpVwRU5kY
         ctZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Ajs+QNHy3S/R0MsAuZN6imvt+qqShq8C8UHWUrvPmh0=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=CkFaulNmukGsawWZ/QlEh2FZxJfGSAOVgADCWuvNDu96Ovh9EKmzGDxhpSCNXFjg30
         ziSqvO5/+d//xfELbqV3ypvLKuAi84AtknEMrEhfgY5VxcXQ8ieuQ+mRskILOUah4Qd6
         CCW6wKyg1J9yliC4nR/udpZpiABexQbIQ5u2/k8Z4LCHdCZNfkNIVNYA2X2W+sCAYuan
         AIBUzTPdUxvDpW2BIj2RqkX021KjsUZbLU4SwKC9O7NQAli+IIXnJJzIz0hKRgfewjf0
         tkwg9ApZdkNe3xV0q2YmSD6rioYyqqqOZcqF2FMFj7VhlFcXZnI+tWqWSofUs2hqRYfL
         ycxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TYkIs32s;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701912952; x=1702517752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ajs+QNHy3S/R0MsAuZN6imvt+qqShq8C8UHWUrvPmh0=;
        b=RrN5VKw1SvCvRMZgln62+8QWLfQKt3NPo+6jJVYC7uHhRDkLwEtiv9bYrPRr2IIzOl
         /cHQ9vIKY3Ybfrlvb5a/5LaLGwlvgfV4eF3dM2ax9Fo4q12GlSCHJdGEtBNHXTIIMBOO
         cRdvu9luLqCGmmqWSppMb511m0di/7eAW/hdMScWUJJ09fjHxZaif9D02qYzLzKijdLB
         f/UDUZUz3P5+lzPeB4KeB0uF/Q+S0kSO3zy8GXPfBcSjBPezLdsH1DI2Ci3IuuzHg8c7
         hxs7Myq9+mCfDBJMFxeKFburbzmL/UNeAWWHOrlrWYACXmDcf8ICotq9MmPJxpbP+tQP
         uYdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701912952; x=1702517752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Ajs+QNHy3S/R0MsAuZN6imvt+qqShq8C8UHWUrvPmh0=;
        b=CucxEWKQ7JvXNaFJ/H9JR6e10iCIIVQFhk6p8IvJURaE6OtsYY0RblMfcQnIXXCE7Y
         X7Du1tQsra5pwrFPp1ck0uVnFSnY/opFityBj4yoOAkSW1jbR9zq1wxBcY81T3meqOUd
         dXHRD6j1FsJCzmZ3vp6CuSNYvlkVjffpVFlwzb4W80HbbS+PYsqYWd7JsG5cdsnNPyDq
         4TCXFW0UobfXgWz9eUvHZVnp2KOIRzFw6h6gLF40V/1TiwldDjzWYKCKVvhjrrbf6kdJ
         TpC25yKXLkWMLz1hPJFNiWeGRBNYPT66zOVIPSE3EI/oIMy1hO5ESI3aRlMHS1eeiumw
         wG3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701912952; x=1702517752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ajs+QNHy3S/R0MsAuZN6imvt+qqShq8C8UHWUrvPmh0=;
        b=ZH412o//rAS1JUpSr8gJBJpPoHnqZzEpIPKPaWs+UEsGdsaDC3CzF618YpCwHr53Fb
         14QYEmJUPITlVqQzE0U7ySCYHI8CkWRWINFH4PfgeyExLpIZur0KOV63kWeolZLCGAN2
         XWVBQOVB5koio0ZGqZXv1mgCQGwf2UV22tVNiiZIv4vocFC1eSEv0OwERcUAbDKlifVo
         v22CMwu39JogKDN/jfORif1z8ObTTW9NbbIKC21WIzxIYovxTQhUkr6cIWx4sZxtanvz
         U8NUPdNOm/jwk3jF0ib8rCv+s01UmO2kUzXmqsbhFobkX5wnh0WA6Ghn3hMb/H2fXC74
         v4cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTS0KxYanuO1LI/NisZl25Wpyap6zeXU6dKkI0j7/7r8GMqMNr
	mDCrhHesUU2YVA82u97t62k=
X-Google-Smtp-Source: AGHT+IHARTK6c5rJuRPUPa47cIKak+/h4mwZmc1WI68o2HXFqLBLpSA9x/X5XVXCIDBoo9jnYsKHsg==
X-Received: by 2002:a0c:fcd0:0:b0:67a:b592:458c with SMTP id i16-20020a0cfcd0000000b0067ab592458cmr1786157qvq.9.1701912951966;
        Wed, 06 Dec 2023 17:35:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee26:0:b0:67a:b34a:6626 with SMTP id l6-20020a0cee26000000b0067ab34a6626ls394358qvs.0.-pod-prod-05-us;
 Wed, 06 Dec 2023 17:35:51 -0800 (PST)
X-Received: by 2002:ad4:5692:0:b0:66d:65a9:8a17 with SMTP id bd18-20020ad45692000000b0066d65a98a17mr1904295qvb.2.1701912951126;
        Wed, 06 Dec 2023 17:35:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701912951; cv=none;
        d=google.com; s=arc-20160816;
        b=GABIeMPRiHm6i+5A/aHqUUAw/Hfz4yiQ16NCRSeZGrgfKvdwwIBeZropO4bYEllzTj
         B0K1bdWY3/c6iEj+EtyY5kHRBYLKh2+gKbX8A4OZtS77kisakBl+Dbg/+e+hYr6bCBeY
         UOeKk7RRdKo9gYEMc0qBLIvcr2mgb2mGdRXtyBfywlfGqaAUQf/88RA0b/I7G+MDNois
         o+7xx45HXKLLIpFwIR1hgAgP+v5Yj2FukzxYt3mbpxSVuBPzJsgIlQHG2uXsKyt0xlUL
         wyiJAbsn5fNbPv0uOF/jZDSqPMCsyWqV2xWCsmDXVE+3cKdmhN5TXkwvFUDKn77iIO/z
         1KAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=d4xrwcnzIgg/3xKCyJBP6G5sTr9I0S6hKhfLAnFc++o=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=YQDKdhYyoyGCa0/tyy6oyOsRb/qt4x0bLgGVPc7toewDLpTCBvuIdGs4nWh766X9rf
         ShqKfj/baIvAS9i6kqeo56QEi71FmON0PVlRPwTQQIrfyKEaMwupetl7kFWJQgwnYgII
         KtS2BLnkRp5S0fLU9rtaZOr0Wc0cdfR6RPhHWgTMVdDy4pugkfMTOBn6/MzZ45nY0n8R
         zJ5DkrsmunYk+ZCRvvrES/6xKy9HBdgNnRQMiJqaEYBrwpY0ebzyZtc3GcHqTCx9h+vH
         WF7sGWUtwP0+VmmyIj+tWhlufcxm41lp9ZP7vfxK4iPlkBP7x7Ps5pELSrYLUrFFz5hO
         HJwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TYkIs32s;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id qf2-20020a0562144b8200b0067ab24a47a9si19045qvb.2.2023.12.06.17.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 17:35:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 006d021491bc7-58ce8513da1so95011eaf.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 17:35:51 -0800 (PST)
X-Received: by 2002:a05:6359:2d96:b0:170:17eb:203c with SMTP id rn22-20020a0563592d9600b0017017eb203cmr1939426rwb.37.1701912950403;
        Wed, 06 Dec 2023 17:35:50 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id g3-20020a056a0023c300b006c0685422e0sm149828pfc.214.2023.12.06.17.35.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 17:35:49 -0800 (PST)
Date: Thu, 7 Dec 2023 10:35:41 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 19/21] mm/slub: remove slab_alloc() and
 __kmem_cache_alloc_lru() wrappers
Message-ID: <ZXEhbUL371iZztHQ@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-19-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-19-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TYkIs32s;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c2b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:30PM +0100, Vlastimil Babka wrote:
> slab_alloc() is a thin wrapper around slab_alloc_node() with only one
> caller.  Replace with direct call of slab_alloc_node().
> __kmem_cache_alloc_lru() itself is a thin wrapper with two callers,
> so replace it with direct calls of slab_alloc_node() and
> trace_kmem_cache_alloc().
> 
> This also makes sure _RET_IP_ has always the expected value and not
> depending on inlining decisions.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 25 +++++++++----------------
>  1 file changed, 9 insertions(+), 16 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index d6bc15929d22..5683f1d02e4f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3821,33 +3821,26 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
>  	return object;
>  }
>  
> -static __fastpath_inline void *slab_alloc(struct kmem_cache *s, struct list_lru *lru,
> -		gfp_t gfpflags, unsigned long addr, size_t orig_size)
> -{
> -	return slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, addr, orig_size);
> -}
> -
> -static __fastpath_inline
> -void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> -			     gfp_t gfpflags)
> +void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
>  {
> -	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> +	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE, _RET_IP_,
> +				    s->object_size);
>  
>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
>  
>  	return ret;
>  }
> -
> -void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
> -{
> -	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
> -}
>  EXPORT_SYMBOL(kmem_cache_alloc);
>  
>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>  			   gfp_t gfpflags)
>  {
> -	return __kmem_cache_alloc_lru(s, lru, gfpflags);
> +	void *ret = slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, _RET_IP_,
> +				    s->object_size);
> +
> +	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
> +
> +	return ret;
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_lru);

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

>  
> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEhbUL371iZztHQ%40localhost.localdomain.
