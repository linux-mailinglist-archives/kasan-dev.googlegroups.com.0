Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVLQ2AAMGQEK4MC62I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B8CD62F7C4B
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:16:34 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id f20sf197491wmg.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:16:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716594; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0mU9AhfOCNpUFqkmv1AUU3YPy3GtoPCA4k8eETZPGKqN+fMAoyJJd+GIOdrbrRaUT
         8VUS/d4cSf1dl/2beJragCvDNgN+ZJ3H0C2bY4GPUh5EVDPVpLOFVX8o3mQcDv1Bvc8s
         H/CVuGLMt3p8R3zqyDkLVMtGk0BsUeidbOYvrjvt3Q0kKBwHtdA5FPAdo55INtPsRD95
         1Xo59NPLvwYtSS2rCCWENBJycFCAQDLh7QBkxVGg96VWWSMvIYm7db1YtRotf+Vv+cj1
         YIJyiDyo/FpRGD8QiFeQzD/t2IVicOp2YHIyO6YtcOgKDxKRUSjozwl5cbOLI9o6+Rat
         bERA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5j/+eZ68f+urnE16aH3yT1fUEc3NduKRMus08Xb4Od0=;
        b=yvYYpkygvECOk2c55kDuBJrbrK3qOYmwTXJfCu9rmw/Kkp58IOwad2m8aVcITfhA4Q
         h7fwhxcyGnQG5Pu92XxV/16Tkloqc33BC8bUSUK+zqSxKB6jtzB8TE5DiYYhMOQ+04+Q
         tD97dfr4tf0fF8jlGEfSl2p2jZy81ihLfGUPEIFEbM9HsoP3EmEtK/4jrzDan6QeIFuM
         4qAsgnmii39deOZ3DmpqAYcrDRwmg8pgYKy+YP1FFCU1h42+5eoisMubDzE7PX4WjJsS
         5J6EL5G3tURcwIBUaiBaHJYjT8wuMp+/lXF9wENCehloCivYGt3wh5y2RSM46dAayzZ0
         tDzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d6rRLMr4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5j/+eZ68f+urnE16aH3yT1fUEc3NduKRMus08Xb4Od0=;
        b=IPZkX8hFihG86hjhTrM7HkydTxPeKl/qTgvPwtJmP7E3TvEkZ+w/lK6HD16cAss72y
         g1Vm+/1YwkujH0YR2+kwDs2cCcA4DtzPNNcSGNN2JIS1qmFF9mPkNj+ma4rYizpgI1t5
         Q5UIVH2aecM3mW9hsJRaiIZp18E+k5nwK4YaI0PYoc+0NVydyoqG7gsaL9S8pBNkz1pO
         WJuQOIZixbSHAf/jYaqGJzUeOpQQVT/MqEnUke9qv4u+eS1TweL/XW1B5u5bnNjwVnnK
         j4d7x2xRT1zK2ztNyu2rLZ2Bs3/TmghKBkdUmfG6InIYjtjDIM6w4oAnw/JIgb1BNORJ
         aemg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5j/+eZ68f+urnE16aH3yT1fUEc3NduKRMus08Xb4Od0=;
        b=GXiwvZODsla1PxdGb30hzBuFOLHYehYmnKIX1obJtQ0hThATG3X2EAOSws0MCsttTr
         a4CAKRunsYdhsYSDOWyTimRYnF0L6kLGBskcfxrVYv38s+7k8jeInN/zafSrZZKBfkuH
         p4l7Eq8GIXwQXSw8YVwCIH5gu30SnMAerOFp9l50JauiZknMB0hLsPb/k0lXRRywjZkv
         6b8/ODMhq3Cv5006NCLA3ycnZ4/vFnZAK/lse9muRa5rtk6yMaDAMu0oLWD+cQE7luYu
         Yiwx0FP4gUp0MRCo5uqTKLkeIj6eIfoW6zMFaB5CiW7mkhb5p41zenIh+0Yculs/ZvQD
         iH+g==
X-Gm-Message-State: AOAM533hn7lTXp6/Lkm9Kt4SN85PoM08YGypG1a/SZnzV0XARBJDSVln
	2y6fcrQCcsAYS1Kx5m5h1h4=
X-Google-Smtp-Source: ABdhPJxkd54r4rCr88HC41WA8psZng/sHPBer/m8QTCQ+KETEw0u0DU4EIDI2yVsunZCC3r0j6/qCg==
X-Received: by 2002:a7b:c3d6:: with SMTP id t22mr8914224wmj.134.1610716594486;
        Fri, 15 Jan 2021 05:16:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:385:: with SMTP id 127ls2516577wmd.0.canary-gmail; Fri,
 15 Jan 2021 05:16:33 -0800 (PST)
X-Received: by 2002:a7b:c205:: with SMTP id x5mr9012333wmi.115.1610716593481;
        Fri, 15 Jan 2021 05:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716593; cv=none;
        d=google.com; s=arc-20160816;
        b=FYItfOVKY8RzMPN1KMsCQAujW6GWoQWdq/k9UGXC7K8DJVxU3s6XXlFgZvcux0ui/h
         qhtUkr/VrCl8PFI9GXqQx5Mx815YnCz8Eh49/DMD//cRj3xDPbKHL0Zful5jy+oDRTdL
         kD29iPm15+vSsQ5knabQbBg/k+wAaE5kKxMgg1VQPefl2Q+9wmnIfXTZYCFbQRqkmBkH
         IEucyQc1+/6hT/YAEeWAqF308Nbruptgy69jdc3EO+bpmBCkQ59UQ8yfz9br2AOq9c3b
         rudsylkjJ1qcTEAjkYcFuTTepZhYkUwgBcizjeoUFoeL1UXLrD3d9F8yYLKqZ3BCBy7O
         hl6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qEMRXLlUvyuq/GhhJdtp57CwP12NI88NDUm2Xo71cuA=;
        b=v8j2TXr7s9XpHyRWn1qVoPDrNXvS3qN3pMWFrJLeiISgz3Xc+iswTnZjfavUXHRfbW
         9StzS3FBo0r0KV/9+zuyp+KB88Ue2wtP/lrM4WTJEYQAiIR+TDYHBqKDfvFJEveHttR/
         UtG1/X9pLpcC0WbB89Wcs2XExrSc1e1i9F+LBzj4buM0SjPjluVKWnv9A9C5NvnsPUEe
         2ZG2Ho4N2crWZbuhe+TBFZm4pKU3lsiIhV8jeYDFBP4z7XbjoZC88FFuYQIUaExAkjDS
         YtCR7ilve+j8PDN43Qz0YE05oCsC0NmYeFK5lgg4HHboEgQKAg7aHLXeJn3rRZEikOa6
         1HsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d6rRLMr4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id y1si396005wrl.4.2021.01.15.05.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id i63so7329047wma.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:16:33 -0800 (PST)
X-Received: by 2002:a7b:cb09:: with SMTP id u9mr8794876wmj.61.1610716592906;
        Fri, 15 Jan 2021 05:16:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id s25sm15675814wrs.49.2021.01.15.05.16.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jan 2021 05:16:32 -0800 (PST)
Date: Fri, 15 Jan 2021 14:16:26 +0100
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
Subject: Re: [PATCH v3 14/15] kasan: add a test for kmem_cache_alloc/free_bulk
Message-ID: <YAGVqisrGwZfRRQU@elver.google.com>
References: <cover.1610652890.git.andreyknvl@google.com>
 <b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d6rRLMr4;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> Add a test for kmem_cache_alloc/free_bulk to make sure there are no
> false-positives when these functions are used.
> 
> Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 38 +++++++++++++++++++++++++++++++++-----
>  1 file changed, 33 insertions(+), 5 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index ab22a653762e..a96376aa7293 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -479,10 +479,11 @@ static void kmem_cache_oob(struct kunit *test)
>  {
>  	char *p;
>  	size_t size = 200;
> -	struct kmem_cache *cache = kmem_cache_create("test_cache",
> -						size, 0,
> -						0, NULL);
> +	struct kmem_cache *cache;
> +
> +	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
>  	p = kmem_cache_alloc(cache, GFP_KERNEL);
>  	if (!p) {
>  		kunit_err(test, "Allocation failed: %s\n", __func__);
> @@ -491,11 +492,12 @@ static void kmem_cache_oob(struct kunit *test)
>  	}
>  
>  	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
> +
>  	kmem_cache_free(cache, p);
>  	kmem_cache_destroy(cache);
>  }
>  
> -static void memcg_accounted_kmem_cache(struct kunit *test)
> +static void kmem_cache_accounted(struct kunit *test)
>  {
>  	int i;
>  	char *p;
> @@ -522,6 +524,31 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
>  	kmem_cache_destroy(cache);
>  }
>  
> +static void kmem_cache_bulk(struct kunit *test)
> +{
> +	struct kmem_cache *cache;
> +	size_t size = 200;
> +	char *p[10];
> +	bool ret;
> +	int i;
> +
> +	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +	ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, ARRAY_SIZE(p), (void **)&p);
> +	if (!ret) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		kmem_cache_destroy(cache);
> +		return;
> +	}
> +
> +	for (i = 0; i < ARRAY_SIZE(p); i++)
> +		p[i][0] = p[i][size - 1] = 42;
> +
> +	kmem_cache_free_bulk(cache, ARRAY_SIZE(p), (void **)&p);
> +	kmem_cache_destroy(cache);
> +}
> +
>  static char global_array[10];
>  
>  static void kasan_global_oob(struct kunit *test)
> @@ -961,7 +988,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kfree_via_page),
>  	KUNIT_CASE(kfree_via_phys),
>  	KUNIT_CASE(kmem_cache_oob),
> -	KUNIT_CASE(memcg_accounted_kmem_cache),
> +	KUNIT_CASE(kmem_cache_accounted),
> +	KUNIT_CASE(kmem_cache_bulk),
>  	KUNIT_CASE(kasan_global_oob),
>  	KUNIT_CASE(kasan_stack_oob),
>  	KUNIT_CASE(kasan_alloca_oob_left),
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YAGVqisrGwZfRRQU%40elver.google.com.
