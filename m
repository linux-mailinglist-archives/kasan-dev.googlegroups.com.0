Return-Path: <kasan-dev+bncBCT4XGV33UIBBNHQZ7UAKGQEUY2SZAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B4F3857497
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 00:56:54 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id r142sf199675pfc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 15:56:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561589813; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJ3o8XHbe7t4gokXSNS2UYsMUGq4mXEdsgRde/Q3LQ9WqnUx/ksP5hvnPyc/BkpWbK
         CNt7unbGimApPL8nMA3mXDbynNco1KvoAGvM1m8C+vtuJL6UNDxSj7k0JSTj3zzc6+Th
         qJrk8y+zKdQfpOAw18hvD9fNoZHUYhuADQQJipgTmiJP5iR6GT+ZHgf+CHASjvOzMFwh
         1Ba9Gs14WK8ZIJbvOgzdW+fbwccRbaVPoL8Z7CEm3ToxnobzKLo9GrCSLqNNnZKlsBYE
         NCnO9Wlx7/6C/WpiWr5qt0XU5CF1AaKJh666PtOFBiyi5NLTOJV5q3MmLZMRQCiiDSIL
         UP0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KDRjddbOcaFIjhLYDIxtbCnVVt1EO9i5B+ETV2S7Ta8=;
        b=gxCRqNA/suVwCdPS2Bkt1ajnTvQxHr4DfFtAi0HJdR/SJuNeVjhQ6HdWae+ZtAGBcz
         ksXP/9tvv/WIWw/e/j/I4s7zvDbMYOWjRndN7Km1OLkoDWC3gj0eyWBOf+awHUcXz4ay
         THzDTTiEHp6H6NSijqXD/Q0MgAQxHiJ7Om8yFDnP4ciYtH1GOQKpmLs2fP10FeBxieJD
         dr32CRKgn7PdiiFeXZhAFDAmbK9tSHv5yWqqn1q5wx1s9EeGyUbtGljLSszQ1dv1bdyR
         KEB3SL4W3gJpupeDZCfr1ksd+gnfKMVyXEoV4s8AKq2MOYiTcBUggiozFQw1WXwhvhA7
         8E1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=U8i1ubLZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KDRjddbOcaFIjhLYDIxtbCnVVt1EO9i5B+ETV2S7Ta8=;
        b=JIgUqGCFttxiOMRj6hCGfQtRXWHEd+JgTq9Rg4VcnWU6vkW/p+fFrs8zBrBScV600l
         2VJhVnR0av4D5tZKC+rF501NTw816+WpUYPBF8SyfPwt53Dq4eBH/fKQO4IWMegsh9E0
         NmNGDPNT1+kNSmzUq3kmdcN+uLC4zSMyXUdDJCsMxeMCnEHWi8TPOcv30bRotMAYIbqk
         TwjB36EeZggYalWIz7NKcVqeICxG7+sgGIlE0XiZnBe9GfJAtIkmtS3XvgSchs8AC5Hs
         Pz3X/rdyYWl20/RuBPK3xyDU4m1BuP8WTqE0IRW0ll1o2LVMv3loHaUDf/Om6Da7foX3
         /r2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KDRjddbOcaFIjhLYDIxtbCnVVt1EO9i5B+ETV2S7Ta8=;
        b=tNjOAxO50lNcLfLgsDehhyI+f88COw3mYi/Ip/gTUgaLdkkGF9hUlwWpn/SpIwaLC9
         RIlMZVyRVZDpK68OUwPMAG152zs0BtjKcAR3Q1gyQYAn4wANp65U+LKRjoG341vjiLHa
         u7lcW1QFTm0JiVWRnqA+ZofLcvSVH5QpDKfS/4ZBQvNx0QMb8gUVfPh4HfLWTgBCke7b
         SRfbZ5kTqLf51Mt6+UcufbTk3Chl8bjyr95Xuectg9YfmcQwtyuqrsbOxYocas1iYXh+
         NpohQCx8ZRHICUQUdZXKgr2yKiTWxJhDeAkul2jCHkGNtY/0fvzZMQ+iTv4Kefb86fsM
         Lz8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVIEuhgIoIz/3kTi7r40banjyQwUV5bjy8Y8uXl9J3B8/S2lHLl
	ZsnPGfq3gLgcspfttPpJ3J8=
X-Google-Smtp-Source: APXvYqxbP8PnH0DnL+jhEyzZl1V4MVmdqxhyrNLY2Ux8lr4HTMP3RoSwh7wP7XYHBoe6GikNlxOvlA==
X-Received: by 2002:a17:90a:246f:: with SMTP id h102mr1841065pje.126.1561589812927;
        Wed, 26 Jun 2019 15:56:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8c:: with SMTP id m12ls1101369pls.0.gmail; Wed, 26
 Jun 2019 15:56:52 -0700 (PDT)
X-Received: by 2002:a17:902:b594:: with SMTP id a20mr613509pls.259.1561589812446;
        Wed, 26 Jun 2019 15:56:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561589812; cv=none;
        d=google.com; s=arc-20160816;
        b=O5iznmwXuimEbCPE9mRPw1dVLqBQyLNbrGYIpTvV/7vKfeAO1ltAWMMnOxrADa/cXh
         kToD0o3SqLF2h9TCpK6pwMouD5qn301/vTC/Kemm2PInEgAmm4wdOUyqatvN6bgpp3+S
         qEflM8xbaC/a/ByJQqW3lF+e1olXmG0KNk1T+5LXw+QHBOKQzNQZB5e9x2Lms+Cj+HLD
         np4E3AR0X4yOVZhx9TGBkCmk0is9r7ohtfpSA2kZVVv9CSNKY5Cvvligk8bLHvsTld5b
         CR2H1sPVWpsgKzHWklcLTbH+HGf71uYN5ucOclI0TxgzSlAX6A8aHwlQf1YP0jlb+oAx
         lGVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lYpkZPTX74T2ffIw2Dsub+OKE0abvghKdi68DMjPsYA=;
        b=vxgFiYNrJSrP1JaAV9/3fY9AGT0elyqQDDl2X18tdBI+RhygeFrHFUoGdg6emnS8Zr
         lLiw2n9hnUfOG8Nx+HESZ7Q0ipB2dbrcLHk2l0JlZ7PDMx3zMLXz2mZ01CzC4jsRstlD
         rurYGltkhUoRTntkC39En8NJ7/UlQoqdQzg7mUPP0o+cXuRHFYlB9Zsmesg8y0I15ueU
         ks7Vt3fRXXBsB1IC+ZUKIVYcHV3Vp6aA+/LJjJf0pfOo8i0ABuRwempTeuI4iKbe5Ijr
         NKKMlfxO0l/2wH6HFXhU9wYjyINlcGRYmPpKqJqiaDxfG7Qswkvb3G8vqf5spuLWUBan
         jpOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=U8i1ubLZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m93si126451pje.2.2019.06.26.15.56.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 15:56:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-223-200-170.hsd1.ca.comcast.net [73.223.200.170])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5E37B20665;
	Wed, 26 Jun 2019 22:56:51 +0000 (UTC)
Date: Wed, 26 Jun 2019 15:56:50 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, Christoph
 Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
 <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Mark Rutland
 <mark.rutland@arm.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v3 4/5] mm/slab: Refactor common ksize KASAN logic into
 slab_common.c
Message-Id: <20190626155650.c525aa7fad387e32be290b50@linux-foundation.org>
In-Reply-To: <20190626142014.141844-5-elver@google.com>
References: <20190626142014.141844-1-elver@google.com>
	<20190626142014.141844-5-elver@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=U8i1ubLZ;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 26 Jun 2019 16:20:13 +0200 Marco Elver <elver@google.com> wrote:

> This refactors common code of ksize() between the various allocators
> into slab_common.c: __ksize() is the allocator-specific implementation
> without instrumentation, whereas ksize() includes the required KASAN
> logic.
> 
> ...
>
>  /**
> - * ksize - get the actual amount of memory allocated for a given object
> - * @objp: Pointer to the object
> + * __ksize -- Uninstrumented ksize.
>   *
> - * kmalloc may internally round up allocations and return more memory
> - * than requested. ksize() can be used to determine the actual amount of
> - * memory allocated. The caller may use this additional memory, even though
> - * a smaller amount of memory was initially specified with the kmalloc call.
> - * The caller must guarantee that objp points to a valid object previously
> - * allocated with either kmalloc() or kmem_cache_alloc(). The object
> - * must not be freed during the duration of the call.
> - *
> - * Return: size of the actual memory used by @objp in bytes
> + * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
> + * safety checks as ksize() with KASAN instrumentation enabled.
>   */
> -size_t ksize(const void *objp)
> +size_t __ksize(const void *objp)
>  {
> -	size_t size;
> -
>  	BUG_ON(!objp);
>  	if (unlikely(objp == ZERO_SIZE_PTR))
>  		return 0;
>  
> -	size = virt_to_cache(objp)->object_size;
> -	/* We assume that ksize callers could use the whole allocated area,
> -	 * so we need to unpoison this area.
> -	 */
> -	kasan_unpoison_shadow(objp, size);
> -
> -	return size;
> +	return virt_to_cache(objp)->object_size;
>  }

This conflicts with Kees's "mm/slab: sanity-check page type when
looking up cache". 
https://ozlabs.org/~akpm/mmots/broken-out/mm-slab-sanity-check-page-type-when-looking-up-cache.patch

Here's what I ended up with:

/**
 * __ksize -- Uninstrumented ksize.
 *
 * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
 * safety checks as ksize() with KASAN instrumentation enabled.
 */
size_t __ksize(const void *objp)
{
	size_t size;
	struct kmem_cache *c;

	BUG_ON(!objp);
	if (unlikely(objp == ZERO_SIZE_PTR))
		return 0;

	c = virt_to_cache(objp);
	size = c ? c->object_size : 0;

	return size;
}
EXPORT_SYMBOL(__ksize);

> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1597,6 +1597,32 @@ void kzfree(const void *p)
>  }
>  EXPORT_SYMBOL(kzfree);
>  
> +/**
> + * ksize - get the actual amount of memory allocated for a given object
> + * @objp: Pointer to the object
> + *
> + * kmalloc may internally round up allocations and return more memory
> + * than requested. ksize() can be used to determine the actual amount of
> + * memory allocated. The caller may use this additional memory, even though
> + * a smaller amount of memory was initially specified with the kmalloc call.
> + * The caller must guarantee that objp points to a valid object previously
> + * allocated with either kmalloc() or kmem_cache_alloc(). The object
> + * must not be freed during the duration of the call.
> + *
> + * Return: size of the actual memory used by @objp in bytes
> + */
> +size_t ksize(const void *objp)
> +{
> +	size_t size = __ksize(objp);
> +	/*
> +	 * We assume that ksize callers could use whole allocated area,
> +	 * so we need to unpoison this area.
> +	 */
> +	kasan_unpoison_shadow(objp, size);
> +	return size;
> +}
> +EXPORT_SYMBOL(ksize);

That looks OK still.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626155650.c525aa7fad387e32be290b50%40linux-foundation.org.
For more options, visit https://groups.google.com/d/optout.
