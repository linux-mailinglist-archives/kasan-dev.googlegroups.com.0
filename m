Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FNQSAQMGQE57ZVFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4769A312F66
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 11:48:09 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id u3sf12661039wri.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 02:48:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612781289; cv=pass;
        d=google.com; s=arc-20160816;
        b=hLpZ9TBcK9qH6CcwSQoRVPiUWxeE5DbsT9XTWN/j8W+BmqHzHmbcxDBYKy+ilZlSdj
         cOOpBQATfc6pUNFvazGrL10DIAcohgAHgU2XVtb65yekBwljGFjatPELzmhBcQElImSB
         iWYqrotzuPssUta4jr1tIyvSewlSAk5FEb25JdmOZ6sa8GR2vbz6+RTx1r1NnPChFpMw
         PQS8K7EEePIq+1Ulskm3duMyeAVYKIGNLi8zdgpDJwgpwDL17SMNRdohVTDhqit4N5pa
         cnUztzXStZc2wn3bQ/jYA/d0qAK3q4/UzhGhRURgEgHG5dQ0H1ejSoQHjBrIo/ODdytT
         KZbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Nxh0QrHZ/8UzzwSXBp+AnOPmU/LU4VKHdUvKlXbk+y0=;
        b=SuSF8R01GJwQQc3c3YEDZkU4RsMHjB1OEBHh30OHOjsxUyvfoSaDnC64G2yX6jQD1Q
         Oc/47UxsQcDnk+TD6Mt2juNY+wQueiCkKMbzv4LG+5yli8PUeyETeeTmjVLsUg5TjB9K
         Wa35YL0wC2V1CiMPyW25vHVSH8rOIZW7TIXBM44aw4I9ncrwju+yj/EGYcKWyIv4OZ9G
         KGNdD1mMqdYw+2pVcnk3GJY3DpTni5VYarmYCegkUfZBO3Wst4Ug76gJMwg8Gjnlqwqm
         0Nd6jokpqbXe8x47t/XBsZxB9yNoafpyaXGCLwww04YwyCLMBix9sqEqpQ108qvW1ZXQ
         NWDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QhK5ZJAG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Nxh0QrHZ/8UzzwSXBp+AnOPmU/LU4VKHdUvKlXbk+y0=;
        b=XUOuG+nTp1Zm2wa/fUlT3752abHNCku/FJR7dNUGWYUsgUXKSRAxUfq8DBisuADHSQ
         Tj1lU9nS6klqSGNgL+zwsSgaCYjEOYnK6UdfLX5Kn1Zmpw2BT7p943RgHbzPZL/JmDQw
         TwZeJ4Y1znbv0d+/yzCupyMyPnxRXHyhdkD+Mbdv6jk7tPlwM5S0eGZiLEX1BHy26lfJ
         PZI9kfohmnYDggLQN5n70+9h8o8fdJCr3OuBzdJ7pYDslhNrpASTCGbJk5a7DgqVgYx+
         BkMOJA6oKKnCZoY0Ru1a1PnAMC1eaNt7Rtv7depe/i9aWZgP/WJEoR+/zG+VXVrZSDVJ
         Iq4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Nxh0QrHZ/8UzzwSXBp+AnOPmU/LU4VKHdUvKlXbk+y0=;
        b=aRK8kIr/ltMG/BjuENLA3iHip+SXG+/wa4fpwqDy2dBrruLk27k62OjP37nB+f+M/q
         umu5llGyGgYl906oLoc7OJMDdO6J5Dasg4jeuA+h4CTtrK2Aj36SFxjiYpMzif/LrOzm
         D/RmphbjIdmxzbMjVDPQtAdG8+u7qv2/GbiPHvgNpCKs7Gi8+1DsBXZl2WiWDL1XbVv7
         qOBvTNBChkf26fia2rNhG0wkTkrPhCNI/SaQtNexcGIbg+od6fX+fQ9ZgJCo6+ETXFmH
         jUaCDr74Q8jV5O8Xj9JWndYy03L3/N4ZFjOY7gPxQ78vXvjFDQPy+j0mxVwmulv0u5T3
         qnGg==
X-Gm-Message-State: AOAM532fHPYvxrw9UAn/o0vU7GasZnvIKvJo9WXEda9xrbUf+CRRscCF
	QaNdKEFm1cdGHAHGzp+zcKw=
X-Google-Smtp-Source: ABdhPJzsJd5zYkmZyodlyHzwVs0h9jWwHB0+ZDOIAPH+8r2qSXFYRAwGaXkaNnqg7AeC9ktFEBBufw==
X-Received: by 2002:a5d:4ace:: with SMTP id y14mr6845098wrs.165.1612781289033;
        Mon, 08 Feb 2021 02:48:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2ecd:: with SMTP id u196ls7103436wmu.1.gmail; Mon, 08
 Feb 2021 02:48:08 -0800 (PST)
X-Received: by 2002:a7b:c95a:: with SMTP id i26mr14139170wml.164.1612781288136;
        Mon, 08 Feb 2021 02:48:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612781288; cv=none;
        d=google.com; s=arc-20160816;
        b=TCwPeVm3LJRFErd7iaOY/El3KDuNfodeq+6dFEqM2Hebp0mR6OVOHOCc7nJFExwd+P
         YkR30J1b1g3We/0OsXTF16EBpGzQxdvbC+bc94+kTPkibk2Ydz0c7n6sD+htVtBpYs9A
         5NFR26GDkoGAo7kb0LuT1OQ+XmlM7d2mqlF0SjcR/oaFeD8X307hrcZ/26RxG4r8vEDj
         cbuU4lt2C7lSejJPrGtQg6N1KoKRi4DgfA33qCMHxAST6662/mcvrEeT7sIuS1XZAPfp
         TF1ZwcBjW2ME1t19qeX7vaEdFDPGaeGbvXOSjerIONue74jyz2QYg2LYz9nGjIvtvYkb
         GjgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lgGm4PB5m4Er0st2+IAu2ADnhULDfoFDJ2Jsf0woe9E=;
        b=kNWROUJk4QNgjL3l/s5nz92PF6Q+fycU6BgkhjLhs90p4wovyc/GZFGwgC4SSoDOuC
         L8FhXWrcQYDcmbTol76NsgPNX2Td2jquyAvOmTDBEOd3Rg76Vs+2JVqRJ0ovpQIXAoZD
         ov91Bu2wony2taXW6s1Bu//Xf2W+eRtFqOdL2bHdX69Z+XONkmPuv9ZTcV0RAynwINDn
         H9byBNdoXBbdNz0fBRlkfidamAbl04OUJ4F/rjPTyPHO/SF/M4oFsfpIQ8pvYi2H1Gh+
         1j1hWqALUTRmcnNRD9KwtxWAQcRLoXQKOGSA05m6sfisaehPxjL+tor+F23BPh+A8kXz
         nSeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QhK5ZJAG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id n13si109870wro.2.2021.02.08.02.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 02:48:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id j11so12131885wmi.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 02:48:08 -0800 (PST)
X-Received: by 2002:a1c:7905:: with SMTP id l5mr11809452wme.171.1612781287598;
        Mon, 08 Feb 2021 02:48:07 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:4037:8827:dcff:a9da])
        by smtp.gmail.com with ESMTPSA id u142sm20991623wmu.3.2021.02.08.02.48.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Feb 2021 02:48:06 -0800 (PST)
Date: Mon, 8 Feb 2021 11:48:01 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 mm 08/13] kasan, mm: optimize krealloc poisoning
Message-ID: <YCEW4SNDDERCWd7f@elver.google.com>
References: <cover.1612546384.git.andreyknvl@google.com>
 <9bef90327c9cb109d736c40115684fd32f49e6b0.1612546384.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9bef90327c9cb109d736c40115684fd32f49e6b0.1612546384.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QhK5ZJAG;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Fri, Feb 05, 2021 at 06:34PM +0100, Andrey Konovalov wrote:
> Currently, krealloc() always calls ksize(), which unpoisons the whole
> object including the redzone. This is inefficient, as kasan_krealloc()
> repoisons the redzone for objects that fit into the same buffer.
> 
> This patch changes krealloc() instrumentation to use uninstrumented
> __ksize() that doesn't unpoison the memory. Instead, kasan_kreallos()
> is changed to unpoison the memory excluding the redzone.
> 
> For objects that don't fit into the old allocation, this patch disables
> KASAN accessibility checks when copying memory into a new object instead
> of unpoisoning it.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Clarification below.

> ---
>  mm/kasan/common.c | 12 ++++++++++--
>  mm/slab_common.c  | 20 ++++++++++++++------
>  2 files changed, 24 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7ea643f7e69c..a8a67dca5e55 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -476,7 +476,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  
>  	/*
>  	 * The object has already been unpoisoned by kasan_slab_alloc() for
> -	 * kmalloc() or by ksize() for krealloc().
> +	 * kmalloc() or by kasan_krealloc() for krealloc().
>  	 */
>  
>  	/*
> @@ -526,7 +526,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  
>  	/*
>  	 * The object has already been unpoisoned by kasan_alloc_pages() for
> -	 * alloc_pages() or by ksize() for krealloc().
> +	 * alloc_pages() or by kasan_krealloc() for krealloc().
>  	 */
>  
>  	/*
> @@ -554,8 +554,16 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  	if (unlikely(object == ZERO_SIZE_PTR))
>  		return (void *)object;
>  
> +	/*
> +	 * Unpoison the object's data.
> +	 * Part of it might already have been unpoisoned, but it's unknown
> +	 * how big that part is.
> +	 */
> +	kasan_unpoison(object, size);
> +
>  	page = virt_to_head_page(object);
>  
> +	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
>  	if (unlikely(!PageSlab(page)))
>  		return __kasan_kmalloc_large(object, size, flags);
>  	else
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index dad70239b54c..60a2f49df6ce 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1140,19 +1140,27 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
>  	void *ret;
>  	size_t ks;
>  
> -	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
> -		return NULL;
> -
> -	ks = ksize(p);
> +	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
> +	if (likely(!ZERO_OR_NULL_PTR(p))) {
> +		if (!kasan_check_byte(p))
> +			return NULL;

Just checking: Check byte returns true if the object is not tracked by KASAN, right? I.e. if it's a KFENCE object, kasan_check_byte() always returns true.

> +		ks = kfence_ksize(p) ?: __ksize(p);
> +	} else
> +		ks = 0;
>  
> +	/* If the object still fits, repoison it precisely. */
>  	if (ks >= new_size) {
>  		p = kasan_krealloc((void *)p, new_size, flags);
>  		return (void *)p;
>  	}
>  
>  	ret = kmalloc_track_caller(new_size, flags);
> -	if (ret && p)
> -		memcpy(ret, p, ks);
> +	if (ret && p) {
> +		/* Disable KASAN checks as the object's redzone is accessed. */
> +		kasan_disable_current();
> +		memcpy(ret, kasan_reset_tag(p), ks);
> +		kasan_enable_current();
> +	}
>  
>  	return ret;
>  }
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YCEW4SNDDERCWd7f%40elver.google.com.
