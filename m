Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7EYWD6QKGQEPQCLLSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 796362AF5C6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:08:28 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id l5sf751386wrn.18
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:08:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605110908; cv=pass;
        d=google.com; s=arc-20160816;
        b=WkL9qK+AML1ggS3NcrnVSTv+o3Ss2B4gX/TA198VZwSkVSSWYuEeq3s8Fx9fKr2HRM
         sGG2XsTmh0XixdcW5dYidcBCJIXoQZp32NEAnJmUTbUI0G11v3KZkvNid94Uha6fDpWc
         0VXLaEk/Y/pa5daY8eKVt7RNGlKF+BI63AcEm9q8uH/lhkmJYVcjnnW6ztUnsiJW9Lnc
         GJxE/yxXppoBXnQ7d3e4SSak47vhOr8Tyo54kvXS499t+lHmUfhoWRAB2j8YTqynO4w6
         wCJf9m+OmDHca051q52KqVXgeLOXThTn2tlwSOmDby+bm7BgPt5v8EUTSQ23ojvRDY2r
         yeXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tQ9wbrsQuKdG+IRQEFLOkpzybk3UfRm2XBjkNVblonU=;
        b=ACqGSjHQHTTLQfnOlBCXGp7x+Rdym0MgvdweGETa7UUbCj8DI2QAP91ESLgeYXMNZQ
         OJonVvkabzGJTMFnM5S5BOiUTC/GxAhwWHbXBpcBk/LdgFvDnsozEFbjUobxgad/vdU0
         3/a6hcEJtGEis9MRm2FxOzs6iqZGcrLpHbjcgeyayjgCvHdsOw/zDTKBum/V/IqMvxVf
         aqPWHYKekIr/+zrys72I/HwEkuCYbWgrMCDDgh+9Z0wxDA+uFQWKBh+gjHuW+166dJW8
         ohK7cNHAyuzPXAap8IJHZrDFyhsB732jGduHOXyGamcoabp8uts5dyXyVQElT1yPrgFK
         5Sdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QM4oYuC5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tQ9wbrsQuKdG+IRQEFLOkpzybk3UfRm2XBjkNVblonU=;
        b=tVZyx+CuuaWONSigFT7uiCxteSIXZbvFuvoDoTpyeCFaq91fpjODy78/JLuC8+GPGX
         QJw7/lJN497vsmLggWrNnLBHdepzKVijnAUDeCMAJeyWsb6Ks32Sfe+GRxdKFTes/qga
         G1OuqGyn8yDB/WpDDsWrVVIfnnZk3i0RRgn32r823xm8sQZ8HMC0+D496okSDeNjx+pD
         9Ss+rx0+VMCZiW2p/FVLy4+tliItRvVPMpu9Kby4To3HFh6ZXNjlqFbbAHUow0qUe1Ms
         4HceeW3clGwJhcHhdwMaUrsxonY3a/l2VF37VSaWNvHtXddLH7icz+g+Lcmr96hd9MhQ
         3Njw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tQ9wbrsQuKdG+IRQEFLOkpzybk3UfRm2XBjkNVblonU=;
        b=Hn0hhB9RGo2165jcmPauFi7lrSCWOQGCKmNUO8OFysadlAVIiDgGuCtdGpjikQRC9+
         PEw+k6NMeeexXDXYmQM3cFnAQWzwNrMdwOU6Qkb26kiVkUp3+Ax9B0gJl9Arhce1rrh0
         Rc2pQspWfADuu2F5lWbzjcniY3L5sA2tBmbbMfaX/POzbaRFSfvotcnl0lkV1/vcKUBP
         neYN3/E5qT45mzKu0OMZhI2y4t2srTz2Ay9cD6nyuzXSP0Thtk2EeXj+0pWUaQCIH1Cm
         Xlzh/fK6YZa7pBcfDmR2P8L8Fu8vZzuAAfbr8maISYCh+5Om1cV1w3gb1jQAH+/bqSke
         T4Hw==
X-Gm-Message-State: AOAM530Sx9jOhjfc/DiL/+2RwGcs8XoHlwjLLJeOFNUi8+9kOZmpfnJ6
	vIU0hlnP9ybX+DX4Ob6bn6k=
X-Google-Smtp-Source: ABdhPJwDk6gWLNAsOFVQ+Ozre/dj4kYRQqQNfap+vN0iEJcWqa3v5Qt89sX3oIT7UxFdLR/O82jm6g==
X-Received: by 2002:a5d:5222:: with SMTP id i2mr32396732wra.247.1605110908223;
        Wed, 11 Nov 2020 08:08:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls178898wrc.2.gmail; Wed, 11 Nov
 2020 08:08:27 -0800 (PST)
X-Received: by 2002:a05:6000:10e:: with SMTP id o14mr31136927wrx.225.1605110907200;
        Wed, 11 Nov 2020 08:08:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605110907; cv=none;
        d=google.com; s=arc-20160816;
        b=Zb+iMuHSzaOftRfNQV6DeAvOkojA3zmavCSLS7U+ZMklKfDWXBZcE7T9bxs99xtVRO
         Z5GBp+p4Kf34W6I9MnauBl30G9Hviluf0c7FH63Zhbwh4GPcdFKXfaPu2MamBlDzt9/z
         73HKrh2EWbg6UCd3IQxdGlezqGRb3kmuCG0r++2ytAwMNmaLV+agpLe1pkieQlsz8wJ/
         69+AwMMlLAuXQTzGEQ4pUG3m6T0kSmcvHDzs2in/RPevred4hySAfIgUznNP1vRQlZ54
         734VaPK6YSgoKYOTsM5oX1D9hwu19KqJHnNNHgkYc+B5cBb19D++GgrP2/TRbHdEiRni
         UP2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JOTPMrM9cXc3gHfHHUUOqsLEtBpDW5NPaRavY4aCrIo=;
        b=UxUd1ITCcrzyJB+YtckJnyw5o/Ww0zmyuYuUE9DEoNQq6R0/ODOFohqHtViY2ubHlx
         FWGZrTFWUV/D+gOXcI1voAjcxpdnRPmpQ3EMu/i2TmfWOOOLOiFQIaGwocq+bNQMgjHW
         rt1FzCnGIm3u1ma8eyKSnbmCl9c+LJOSKA64BZUItmTEeKipfD8JfVizB9u4XE8OKkE3
         MOaHwv2R0meusKbC8Ggy1Krp6uPcYBP+4iPPF337o3XMx+NFzZRtJxEfNj+5EhTZgrE2
         qsSW9JXJAY2nSFw4WZmtQVvJYW4hpzKkSYAwFbFthm9be4RDyW1Ac0A678+lYIhTYfuc
         Y3qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QM4oYuC5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id t9si191162wmt.4.2020.11.11.08.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:08:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id r17so3074601wrw.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:08:27 -0800 (PST)
X-Received: by 2002:adf:a549:: with SMTP id j9mr16145230wrb.199.1605110906715;
        Wed, 11 Nov 2020 08:08:26 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id y10sm3052674wru.94.2020.11.11.08.08.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:08:25 -0800 (PST)
Date: Wed, 11 Nov 2020 17:08:20 +0100
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
Subject: Re: [PATCH v2 01/20] kasan: simplify quarantine_put call site
Message-ID: <20201111160819.GC517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <d7182392511522e5b3ab7b0c1c0933b4f5963ce0.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d7182392511522e5b3ab7b0c1c0933b4f5963ce0.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QM4oYuC5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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
> Move get_free_info() call into quarantine_put() to simplify the call site.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
> ---
>  mm/kasan/common.c     | 2 +-
>  mm/kasan/kasan.h      | 5 ++---
>  mm/kasan/quarantine.c | 3 ++-
>  3 files changed, 5 insertions(+), 5 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2bb0ef6da6bd..5712c66c11c1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  
>  	kasan_set_free_info(cache, object, tag);
>  
> -	quarantine_put(get_free_info(cache, object), cache);
> +	quarantine_put(cache, object);
>  
>  	return IS_ENABLED(CONFIG_KASAN_GENERIC);
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 21fe75c66f26..c2c40ec1544d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  
>  #if defined(CONFIG_KASAN_GENERIC) && \
>  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> -void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> +void quarantine_put(struct kmem_cache *cache, void *object);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
>  #else
> -static inline void quarantine_put(struct kasan_free_meta *info,
> -				struct kmem_cache *cache) { }
> +static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
>  static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 580ff5610fc1..a0792f0d6d0f 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
>  	qlist_init(q);
>  }
>  
> -void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> +void quarantine_put(struct kmem_cache *cache, void *object)
>  {
>  	unsigned long flags;
>  	struct qlist_head *q;
>  	struct qlist_head temp = QLIST_INIT;
> +	struct kasan_free_meta *info = get_free_info(cache, object);
>  
>  	/*
>  	 * Note: irq must be disabled until after we move the batch to the
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111160819.GC517454%40elver.google.com.
