Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG7J5KAAMGQES33JUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E578930DCD1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 15:35:07 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id v25sf6282486lfp.18
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 06:35:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612362907; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4pwGCQMpDgDdCeCValyrC7z21I5ePdJTtAuDNS5DcG99bvS6VfJShmDys2xTEhMFn
         fEY+FvSneTF1BztGLiitV1l2tcs7rH+BBqvYkU8gbvSioT+qCRCRM29tReGp3OTGsI+l
         jp0kAN0jifEgXWTOq74tpEKyrim3+ce/cjTB4mnYC+4ynVqF/M3ztfDlfs4cCbcS5beX
         DnS3V+jXOZXL1o+AUUe1HV8hjtakWpKqlBLohdYzbQUGlIiPYYQJyjtVuRg/J8zoJkIE
         /pkvub8vNxr1lyPiXGgbJGe9AUNHRHBoktSjj8+4p2xsUcbsUW5Ky6Hyfsxm+0bbzMs/
         66hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ELky7iuCCcfRpzwaaaXFZnM+ZxG4rrCxYC1UeGIPKFs=;
        b=gusjwQ2i+LnCssFEM+7RKUXEqey58MNIT2PqUViWlUd27At3LB1jC/10LWQddsQlk4
         JmiECcRmSgOVvACv/TvFX0tUPUR07MKqA05Wo+8c4UUNoHQROcbHbpuTpi/OBslqEqpY
         QkCkH66REyzygAT4nvjtSnWon3ekwRnmYi3nN3TZ7h7NNaAEzYghQz1eVawtdQr70rA7
         YfFS/VbSqeBVxah1GuZqKx18xkShT7ypZcK3uNwlxUsOL/OQvthC6XJT9w/GGgSAk66k
         XQ11s9Mf9rXzNKgnmj9VTQ4EYkiq8OODmhIy/oOxKSH+TtBOFbUr/Jl4jr9oLhMI8l9w
         WLNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=piNvFA2h;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ELky7iuCCcfRpzwaaaXFZnM+ZxG4rrCxYC1UeGIPKFs=;
        b=ezP69276VvhiOGUILSB3XRZaOdlbX1jd68LCZPnnkvH8Zg/QF3hE6vDu5iFpK2ecFQ
         LRTFh5F3X+OF6BxoDcVN+ZOGe/MkpBGEz4pIWIwp/pPORZeHrAQYhusOycfL6aXnA63w
         kA9WwYyI9N9Ulh2qTzGpavwcczHtESTCDljd6/WFLhS3ktVib9rFR6ImTykMiUiwIqi+
         VPcyQACennkEcFKegR8FbBjOyCYfzIkmKNEmkfyW5QyLFodhJSaiboQAJPQn9rZqT5na
         m+0V+yHrniSyLbsQotHe0+01U1TxW7IocH/xwpWy+PYscfZnNLTnYXAUb2T5E2YXYbJ0
         XDcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ELky7iuCCcfRpzwaaaXFZnM+ZxG4rrCxYC1UeGIPKFs=;
        b=bfJGhu3P2VWwttoF/6VdrZxd72OGVOYPKjNqYg/YrY5c0qrGaGL0/m+n6RzVNL383c
         nvMJ4YEn+vx9PFZcDYnDGxP6iEeoy8VkO8Cya25rtBie+6vF84nCCDFVMkntrh6DVVvg
         N+Uaq3SSZIkjXnQv3Co1DMvMKdDxkXieLgnMx+lifCK32gTHYZSoATbK7VbeDbKske7r
         idWK9lzs3KT0cTL4qeXxj0TxuVq8jCqUUgc59o/eX5QCeM/E7xLT1Qk/BO6rpVRZNIlM
         wMqZMjw/YDsQXfpWh4fHtmZXgGyVBeAzR52BpR83zNhf2H7CXHhjadULhu9fcVfLiwqt
         +mlQ==
X-Gm-Message-State: AOAM530zwrWlvEACc/YbQtnY2mVo2f1+O2srCnRYqP9ZwxDtO/V2D748
	SjUBUmopty8BIPnMPgxJbUE=
X-Google-Smtp-Source: ABdhPJxqxu66HqDWhdcR3SWjW66YMQMRwko1z1nekqh/PYUNb1+wN0RstrzM8yzp/VzqX9zkDvRWgA==
X-Received: by 2002:ac2:5a41:: with SMTP id r1mr1955744lfn.117.1612362907495;
        Wed, 03 Feb 2021 06:35:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5519:: with SMTP id j25ls431313lfk.2.gmail; Wed, 03 Feb
 2021 06:35:06 -0800 (PST)
X-Received: by 2002:a19:3fcc:: with SMTP id m195mr1885381lfa.459.1612362906363;
        Wed, 03 Feb 2021 06:35:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612362906; cv=none;
        d=google.com; s=arc-20160816;
        b=Gos7FmsGJ6iiOwCQ8GZ+FviyV8Exk5vAgYfPRL1DGn30pWaxI1xbVqJvI/ixt1Bduc
         eGHI9a54eNr1KAx06uPr05u4aE5ZhcQGzFDTs1vRK8i6AKmBbBcSjmDGcYpjovsT4VZt
         p410VbpiRLp7nIWxngZ4ouzYx4MeoVquXFMSlrRaDEMP+HFdqX24KduuzvJJlRkVNvtB
         zVkh2LT51hUFbyRbqG9CpIfLvDHUUGLNYScCLRGDk5P8cLMaA7UR9iXBCMR1b0YSjio5
         bGX6TV70hnB/aeLRHZu6KjUxejpuqa5uWSWaa13fQF0Q2oC2vUap9n2F4LBpBkDAUFgl
         HO+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=E4K/9sxU94RKYKEloT1K6toG7ncb4LzmnvyruO4aAFU=;
        b=hVg0c5CA3NPFAQFcoQP4qTWsp+DRwWBu6V30Dpwu7l6MsRyca0M/Q3tdoYfuc0lBDj
         l5BE+uZRZaLbjM6R4RUxjS8vw4KgpZz82a252h4TzBubUIb2iM489q7NIpmo1/khKzl3
         UAVIXCLrOuRjzhgVzVk1Rjwh52ySZJfqKTs50qvAT+EIJS9K1mPMBJpPPpuKv+mTXuFI
         QR620Lxbb84hheWNCsvA4VjIeMKxZtTP6P3HVON98N7/XrtrFtfB32rJD6CmgbO8n6Re
         kHyF31D4fCMMredWvnhjXdtT2Uj0qRjRTrCovDsd0Jhq+9om+rFWr+fzjY4sclN6V3/s
         pB7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=piNvFA2h;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id d7si113163ljj.6.2021.02.03.06.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 06:35:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id p15so24520300wrq.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 06:35:06 -0800 (PST)
X-Received: by 2002:a5d:6b45:: with SMTP id x5mr3763180wrw.415.1612362905963;
        Wed, 03 Feb 2021 06:35:05 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id i15sm2672462wmq.26.2021.02.03.06.35.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 06:35:05 -0800 (PST)
Date: Wed, 3 Feb 2021 15:34:59 +0100
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
Subject: Re: [PATCH 08/12] kasan, mm: optimize krealloc poisoning
Message-ID: <YBq0k2p5eudcY6bD@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <431c6cfa0ac8fb2b33d7ab561a64aa84c844d1a0.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <431c6cfa0ac8fb2b33d7ab561a64aa84c844d1a0.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=piNvFA2h;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
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
> ---
>  mm/kasan/common.c | 12 ++++++++++--
>  mm/slab_common.c  | 20 ++++++++++++++------
>  2 files changed, 24 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9c64a00bbf9c..a51d6ea580b0 100644
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
> index dad70239b54c..821f657d38b5 100644
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
> +		ks = __ksize(p);
> +	} else
> +		ks = 0;
>  

This unfortunately broke KFENCE:
https://syzkaller.appspot.com/bug?extid=e444e1006d07feef0ef3 + various
other false positives.

We need to use ksize() here, as __ksize() is unaware of KFENCE. Or
somehow add the same check here that ksize() uses to get the real object
size.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBq0k2p5eudcY6bD%40elver.google.com.
