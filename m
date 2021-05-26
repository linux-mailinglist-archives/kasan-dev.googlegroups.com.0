Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDV6XCCQMGQEJGBRZIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D273391494
	for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 12:12:31 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id 7-20020adf95070000b02901104ad3ef04sf160439wrs.16
        for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 03:12:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622023950; cv=pass;
        d=google.com; s=arc-20160816;
        b=KwQRDOmFF60tcL221X2P0RMlKhQmn+h8Ovf8shDPgrrl0SIggfoFy/YqyH6zVRCiZ7
         YDH3niYYR+oHhbQeG3bN6+qvYFmaPLiLEqL7rvcLKX57SsoUtObIVB+nuHjmTsNvsR//
         iA1h3+muvIkcllJGm+MErUSCimitNGW2Cf3A8ZPXEB8uPSlXQ/V2pFntxAlV9qip6Ahk
         T6i2KuhzZPQ+iAI5MRYnRLpuhvUf9Z29AKQVDm5Lwp48SpcVwK8ANKOjT59nm0GKr/G9
         agizp+qX4qfC4e3S5+7tdnpRPc8CK1PZqzzeneiGYyq3Ox29GZqEHJQdulPZoUE8dGSc
         zSkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jDl8wrNYUGfdWPuAQe9csolgodZ1CzPXqXNQyP2L6iY=;
        b=elQEbt/1QvSnznbnQT07mQEfnN+phLETYjXfPFLbOhfF0xu/6IDlRdevH2McqX4uy/
         uuV5TZeTr3wAnrGzU4IcSsBXX5ivENh5yQHzmlqW4Oz2sn0Z+7/Whevhkur+A1uq1O6b
         0XfAJ1dwbzbWXSFFAbMJm72QfV/M7KAYUfomolK8uqQTvnhM2SGek7hS+RcqF8yUQvpx
         VyMCPyblkgM7pmTssPf8aBeipMAUG9yeXVpnJ+Cco9EyVbKKvrvIR/SLE9ccOFdOPsNu
         55G7CAis200Uef4INplA5j/fAGZqICKmVMrvW8VsBZ9mBsxndbKBDLPR4/gUBQw2Xs9n
         13XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6C2fhuJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jDl8wrNYUGfdWPuAQe9csolgodZ1CzPXqXNQyP2L6iY=;
        b=gYJonldGnxOS0102MBGDY1o7XZMjVgJXjAy/+1HcIqEnxuNeC5p+o4nsdIDCzdosLF
         mED/SFwEdHnXxL3LVO6YvRAIH5mK08hUu+Q5CHphIs5XkcruRNuHoQJJy1yFNBLN9eKh
         jaZapLQsefQ80/xY5plkdluxziN9b9qQURmzjqmLDDfPbZsyJbOe0ZutuPCG6SAAtXN4
         7l+udqsJISwQgxmqQFG/G2ilZsPteGuLR3Z/FvLxjHgfwPqpt+viwDXcLoGQCfyVedLs
         H40orOpkMZm10duymHGA591lXVSQscojSVuIkwHsFGuI2Mw6ZydzAqcnM9KrsHjT244w
         ndHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jDl8wrNYUGfdWPuAQe9csolgodZ1CzPXqXNQyP2L6iY=;
        b=XXMbCM+K7tqzXX2AO34NtydJqfBa/SKlTsWbIKnO2dNOOCtcddi+pEMvBhEE9gVMKn
         Qj8nBnyog1E3B21hiOYmYY5KsrkJUiXtWbvH4YI5r3IgLsw+Gk3AmSh8jg+vQEqnx/7j
         cOHIMfDGfJaPwg6ZjXFucXJiiIxw9hSxcydXTgBIzpkRV161WReWBNsMJOLdczSVX+UU
         S6Czl29pV3zQD1qBO1t1kLnNSZd604aNFldGFWpAPX6mRIDdDLybiZBZunVyZMw2SNzx
         XQp5N3+kEKs90QalVd/H6YlpynPLFrt9Waq/FDG/U8grBVQ+SDCIa8jLixDx7TYXy5ka
         h8aA==
X-Gm-Message-State: AOAM530gGQv7b4hRO7hJKww+CCK1akI9MizvoeZIgZk0pelD4rSQPL9m
	gsDJ8t8k6EzHwm2Uw/R8i2M=
X-Google-Smtp-Source: ABdhPJwCEUDuemQ2vlKMBBosHimRzCp1k++izlJQuCarjV3mXZPR2/mQ8mUbJU/3xo7EUSPZMeo/gA==
X-Received: by 2002:a1c:bc07:: with SMTP id m7mr2624172wmf.179.1622023950760;
        Wed, 26 May 2021 03:12:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f52:: with SMTP id m18ls2996673wmq.0.canary-gmail;
 Wed, 26 May 2021 03:12:29 -0700 (PDT)
X-Received: by 2002:a05:600c:2e43:: with SMTP id q3mr11165879wmf.75.1622023949840;
        Wed, 26 May 2021 03:12:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622023949; cv=none;
        d=google.com; s=arc-20160816;
        b=UX0/DP6Tk0cpHk146/kIdHbzx/nLbwexBBPyXch/6m34Qnyrug9LPAJU8oJY53gCeD
         UYW4zD5rUYQ3CW1evaGpOWKKrABOiQLGbCcQt4woLxhkindr2Bfnkqmvz0gJUQB+y7yS
         5tpHlPUhc/eg94UjFm2rrAb7bbp7oaOPtSafL/g0TN2+ZiTClYgRHKE/SHD+LQMtJGOm
         c5RaT1nw6G2NUMaMYNgZQaZnNYFVu1LEujasJraM7XYCigAWItMI/mTwRsLkzHvZWbbC
         PGwmbPc0Xw71KMBjjXUb1+eg16QvX90e6uoYTmSzKoJ4LKgUKN1milBKVpHScazt5y5u
         hFCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ORUbrgb2hImgyzC/Ql6sac6MWYkFqD0t9FCM4LD49w4=;
        b=pjGIAw/isn4IbizM2iTb+qMxD8tUrTanMkSNYOTvrEsyzqKf1nDElSBMEHsQwqWsqS
         jbReIDV0YnHOS89JotQ+Mu9xAaL12mjVKkeqpyq/agA7TtM24Iy7hHm9xNRp7vjG5llA
         IqCM0pEtgJP0Dw2BZyVPQe5GGKk7h4xDbzlKqtd/vBCNXdzhPfFdBHN4mbdvdvUMztxF
         j22ZTQMkblhWkL84fsIi2KBUxyvg8ApxEnKyz9aaPd3eDBNhyMbDwzCfTkV5IOYGg5k6
         6TCHwqtNHpBuUeXap6BCYujM3TkdCDmZYGxGnz3WMqLLMq7J0M7VeYQ5ai2+BrEZgVbF
         4Jsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6C2fhuJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id t1si791428wrn.4.2021.05.26.03.12.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 May 2021 03:12:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 16so378687wmj.5
        for <kasan-dev@googlegroups.com>; Wed, 26 May 2021 03:12:29 -0700 (PDT)
X-Received: by 2002:a7b:c446:: with SMTP id l6mr2541346wmi.75.1622023949427;
        Wed, 26 May 2021 03:12:29 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:cd98:de82:208c:cbdb])
        by smtp.gmail.com with ESMTPSA id u18sm6717455wmj.15.2021.05.26.03.12.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 May 2021 03:12:28 -0700 (PDT)
Date: Wed, 26 May 2021 12:12:22 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/3] kasan: use separate (un)poison implementation for
 integrated init
Message-ID: <YK4fBogA/rzxEF1f@elver.google.com>
References: <cover.1620849613.git.pcc@google.com>
 <78af73393175c648b4eb10312825612f6e6889f6.1620849613.git.pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78af73393175c648b4eb10312825612f6e6889f6.1620849613.git.pcc@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l6C2fhuJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
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

On Wed, May 12, 2021 at 01:09PM -0700, Peter Collingbourne wrote:
[...] 
> +void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
> +void kasan_free_pages(struct page *page, unsigned int order);
> +
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
>  static inline bool kasan_enabled(void)
>  {
> +#ifdef CONFIG_KASAN
>  	return true;
> +#else
> +	return false;
> +#endif
>  }

Just

	return IS_ENABLED(CONFIG_KASAN);

>  static inline bool kasan_has_integrated_init(void)
> @@ -113,8 +113,30 @@ static inline bool kasan_has_integrated_init(void)
>  	return false;
>  }
>  
> +static __always_inline void kasan_alloc_pages(struct page *page,
> +					      unsigned int order, gfp_t flags)
> +{
> +	/* Only available for integrated init. */
> +	BUILD_BUG();
> +}
> +
> +static __always_inline void kasan_free_pages(struct page *page,
> +					     unsigned int order)
> +{
> +	/* Only available for integrated init. */
> +	BUILD_BUG();
> +}

This *should* always work, as long as the compiler optimizes everything
like we expect.

But: In this case, I think this is sign that the interface design can be
improved. Can we just make kasan_{alloc,free}_pages() return a 'bool
__must_check' to indicate if kasan takes care of init?

The variants here would simply return kasan_has_integrated_init().

That way, there'd be no need for the BUILD_BUG()s and the interface
becomes harder to misuse by design.

Also, given that kasan_{alloc,free}_pages() initializes memory, this is
an opportunity to just give them a better name. Perhaps

	/* Returns true if KASAN took care of initialization, false otherwise. */
	bool __must_check kasan_alloc_pages_try_init(struct page *page, unsigned int order, gfp_t flags);
	bool __must_check kasan_free_pages_try_init(struct page *page, unsigned int order);

[...]
> -	init = want_init_on_free();
> -	if (init && !kasan_has_integrated_init())
> -		kernel_init_free_pages(page, 1 << order);
> -	kasan_free_nondeferred_pages(page, order, init, fpi_flags);
> +	if (kasan_has_integrated_init()) {
> +		if (!skip_kasan_poison)
> +			kasan_free_pages(page, order);

I think kasan_free_pages() could return a bool, and this would become

	if (skip_kasan_poison || !kasan_free_pages(...)) {
		...

> +	} else {
> +		bool init = want_init_on_free();
> +
> +		if (init)
> +			kernel_init_free_pages(page, 1 << order);
> +		if (!skip_kasan_poison)
> +			kasan_poison_pages(page, order, init);
> +	}
>  
>  	/*
>  	 * arch_free_page() can make the page's contents inaccessible.  s390
> @@ -2324,8 +2324,6 @@ static bool check_new_pages(struct page *page, unsigned int order)
>  inline void post_alloc_hook(struct page *page, unsigned int order,
>  				gfp_t gfp_flags)
>  {
> -	bool init;
> -
>  	set_page_private(page, 0);
>  	set_page_refcounted(page);
>  
> @@ -2344,10 +2342,16 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	 * kasan_alloc_pages and kernel_init_free_pages must be
>  	 * kept together to avoid discrepancies in behavior.
>  	 */
> -	init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
> -	kasan_alloc_pages(page, order, init);
> -	if (init && !kasan_has_integrated_init())
> -		kernel_init_free_pages(page, 1 << order);
> +	if (kasan_has_integrated_init()) {
> +		kasan_alloc_pages(page, order, gfp_flags);

It looks to me that kasan_alloc_pages() could return a bool, and this
would become

	if (!kasan_alloc_pages(...)) {
		...

> +	} else {
> +		bool init =
> +			!want_init_on_free() && want_init_on_alloc(gfp_flags);
> +

[ No need for line-break (for cases like this the kernel is fine with up
to 100 cols if it improves readability). ]

> +		kasan_unpoison_pages(page, order, init);
> +		if (init)
> +			kernel_init_free_pages(page, 1 << order);
> +	}

Thoughts?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YK4fBogA/rzxEF1f%40elver.google.com.
