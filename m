Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7RWD6QKGQEOL27D7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CBCC2AF8D1
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 20:17:39 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id u207sf1267648wmu.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 11:17:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605122259; cv=pass;
        d=google.com; s=arc-20160816;
        b=ONggIDCiFqx3yLMbfBVsVC583WnPjtnARmcKlI+/LuhoMtnP1S7Srw/zElbrAX3H4W
         rnXenEHGxWparu03Gy9/mgu/TI15X4A/lNwsctRtGx+2WzS3m274X/FVbScTEpo8nevJ
         NB8rutpFSBJuJgJao3jfecTd5ntJgX/zbodv4RouZ6gsUbjzZ5+/IK1dA9GinJzSxE+Y
         b1w8U4cUmC+65c4tq4NOhEv6/vY4OdUbjJu9B2T0E82tDX2/Q6nwlEVxUlF5W16U8vT/
         dnk19NxephOcad6M0oCuHUUnjEdIvOLcZfogVbwzhHPS/bDzrEslJeFUhp2jjf0BubWB
         +GjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MvoLm7fKelLqmNJRnrXaBDEwbY+zn6UfqXSfNb7rlow=;
        b=mFhYpZs6LcOTSXNZbgepraDkiH8CSUeacQ6i6YGuQTh3wNKsknajrVuvGp1gtdPJxo
         A50qjJsTEZa6GS793qJaD+ZGLxIUw7gv4YAZWDHBt0il0Q6+WvQNbQDK772KFQD1jugt
         FTc43n5+foZaLxsmydjaPW0kAh0HBB8APuzN1OsKikwvucBdFRPN11Nrm8f3sMLCLrfj
         AWZautylo/hRyueZuTsbGMELTDhOvQi2zoZoUsVBzpCIwPkttw8Rk3+sgZZQNShGWeX5
         u97iEKFBBOhuTH5TnawkcTfueSuOu7enKxGKEYYxnwXLeTigRGxwDmdIeHYe37dRINkL
         J0rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyMoM46i;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MvoLm7fKelLqmNJRnrXaBDEwbY+zn6UfqXSfNb7rlow=;
        b=HCc3ZM4U+T+C6pecEDIiurdaU8awR1Cm7EyTfYoUazDPSQ50HAdc4p5cOP2fTz9Rgb
         MLnJH4yx7Jj3794mXd/mgnPu1r4bim27yeMn4/0oG4WITh6URxA9IKU1+EixIILq9Q10
         F2OQWCV0H8Yl04N9UAkKT5S1BBDZknbChF0s8Vi+CDjlwEtdBSlS7lU6AbKmYeJT+5Sv
         wXowWB2zRZ5nPmx0fDooK1wkwr7dvN1+3pA7nRjv2PEcWvu6A5/JpYeskIIIA0fEjkXg
         GY3J1riuQqIpDxW2Au/0CJaIokyR2Y/ipG9KRgJ1GSop27rUuATydYB4YmG4W+BoE0mG
         XeAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MvoLm7fKelLqmNJRnrXaBDEwbY+zn6UfqXSfNb7rlow=;
        b=p+1TQkrEsTuJZiNDegdEzZJUeLsftXWfpwMa+fr4A2L4JGk+8/ERaKLhqLXHQdD6FZ
         vcp4wR323WolPWKzavOWSW11JntJQbiOykvWWlOlHmhMlw4KxBRluOxTbJqAlaRKi6Qs
         AG0MblblX2mzwQ+8Biok44f0zPiJc09AR2GPPfzMz1KcTcZ8UQW1uSks8M48IpXwtGZl
         5S8Kvhp8maXjRptMtIFPYttoGPKe/mEJPlYOrnXoHqu/WetOv0lpDGXCEVahT+0iRmJh
         1OZalhm4yiCXz625yFFaBCkUdNQcGKttP1gKJsJ7OrBWUQoAe+VjKvdsefv+KsuMzu8f
         fxbQ==
X-Gm-Message-State: AOAM5328THy9FGnKUZaCtJheTb8o3r0dfW0p5SG2us1cEgc8UYxTY26I
	r68GWNY6+vX3NoaebO9gjbA=
X-Google-Smtp-Source: ABdhPJzJVkDhJvcX910GfMQQyPGyA+o/DMqgfr6oyhSod8AkQLXovJCqoQCb5oVZhV/IQ3kPn8BQNQ==
X-Received: by 2002:adf:f9c4:: with SMTP id w4mr32721746wrr.64.1605122259279;
        Wed, 11 Nov 2020 11:17:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls745224wrp.1.gmail; Wed, 11 Nov
 2020 11:17:38 -0800 (PST)
X-Received: by 2002:adf:dccd:: with SMTP id x13mr2115642wrm.394.1605122258304;
        Wed, 11 Nov 2020 11:17:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605122258; cv=none;
        d=google.com; s=arc-20160816;
        b=Ia8OJE07XB7O+Q9YAA6ZoSDgWCI5ovbs/PJNZlAcUY0ZQKUF1OI1dtb1AO518YCWDY
         kmJHDCwl8xfS1k7zC9dUm+E7nuHkMkWNFB0lxRxdnOiNT1fp71wRwhWhS6nYIKwX4rmC
         IdS+aNCN6HB42xsq621xHcZ1jBpGuZ3cAnHR8DNLrXyr5a7Dh+44DrIzjGJX0zdZdUOF
         +Uxasw3SLGc9DG4OD+duUNcChckM4RnBQSZMCr4uyWKioWTQlg9roo/+k8kge2jyg1hh
         nDyauF69EJ8ft0vkHianxVOpKrTHZnWrk9Bwt29e+MXiNoZy+BSF43cIUGuUffzflO3E
         L1pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kMrBNTvUl7eFEy433Sc7HrH1xnZw22qMO0dPs+XlBag=;
        b=nQEj/DS0vkEX41l7A/pz/47ScaG72JhD24kPUMGv6PFPqXf2TZWwi962/FeqKBLASe
         cd8jrm5ZuNhvYk2MAu7c2mTw/ugZgZxVxxgiPLc3qageWpi9bTLU/Db4/wvJfOHMoDi3
         0oeYXUTPpwFpmtRdT1Kz1D25oEIoU/8NVu4qSkhas+UB//1XtTGRn6K/kNXEinsQwGwX
         eqUyq7CK1PXGe8sV/gUlWAjz5odoKMD3Rh/aWr4IlA8Hm89Q0qT50x619ukLpQqJmz03
         Ar98xEpnlFOOj33OqR52IloRJsyGxLS/VdJCGxWae/x6KzeWznTuDn9RG/BPc4jh8V2I
         3AjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyMoM46i;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id i1si108862wml.2.2020.11.11.11.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 11:17:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id l1so3603500wrb.9
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 11:17:38 -0800 (PST)
X-Received: by 2002:adf:93e1:: with SMTP id 88mr30294553wrp.37.1605122257781;
        Wed, 11 Nov 2020 11:17:37 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id b1sm3833382wmd.43.2020.11.11.11.17.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 11:17:36 -0800 (PST)
Date: Wed, 11 Nov 2020 20:17:31 +0100
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
Subject: Re: [PATCH v2 16/20] kasan: simplify assign_tag and set_tag calls
Message-ID: <20201111191731.GR517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <eae2f21f9e412b508783f72c687cb0b76c151440.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <eae2f21f9e412b508783f72c687cb0b76c151440.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JyMoM46i;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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
> set_tag() already ignores the tag for the generic mode, so just call it
> as is. Add a check for the generic mode to assign_tag(), and simplify its
> call in ____kasan_kmalloc().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
> ---
>  mm/kasan/common.c | 11 ++++++-----
>  1 file changed, 6 insertions(+), 5 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 69ab880abacc..40ff3ce07a76 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -238,6 +238,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  			bool init, bool keep_tag)
>  {
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		return 0xff;
> +

Hopefully the compiler is clever enough to start inlining this function.

>  	/*
>  	 * 1. When an object is kmalloc()'ed, two hooks are called:
>  	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
> @@ -280,8 +283,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  		__memset(alloc_meta, 0, sizeof(*alloc_meta));
>  	}
>  
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> -		object = set_tag(object, assign_tag(cache, object, true, false));
> +	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
> +	object = set_tag(object, assign_tag(cache, object, true, false));
>  
>  	return (void *)object;
>  }
> @@ -362,9 +365,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  				KASAN_GRANULE_SIZE);
>  	redzone_end = round_up((unsigned long)object + cache->object_size,
>  				KASAN_GRANULE_SIZE);
> -
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> -		tag = assign_tag(cache, object, false, keep_tag);
> +	tag = assign_tag(cache, object, false, keep_tag);
>  

The definition of 'tag' at the start of ____kasan_kmalloc() no longer
needs an initializer.

>  	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>  	kasan_unpoison_memory(set_tag(object, tag), size);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111191731.GR517454%40elver.google.com.
