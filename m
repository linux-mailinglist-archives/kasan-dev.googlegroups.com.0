Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5MZWD6QKGQEQ6WBZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DF16A2AF5DB
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:10:29 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id t3sf602173lfk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:10:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111029; cv=pass;
        d=google.com; s=arc-20160816;
        b=fo/u4VCVFW9N/xIUfBY1qew3DG2Yh+GX6ulR0Q3nKmnAERorRgeSPz+CE+DkSGv04D
         sHVVlv1p51qHlwpc3noIDa3jzAkiZKsoaFmCjmuKlvPCIitCMlDUuUYrCQfivY4HuI1D
         cVWJcD4soimKS+o7iIMyBUMm4ymNiBUY9BkCd3S7wVCKVNQER191itE8+bRckKfpHfgf
         WLhPeKBv8NXAK8TyN1YEyh95LQbaiocjcynH5NN5phd4bwJZLCvuN1YX8z1Y6U/XPF91
         +n9sGIyWiharq8N+enaNs8MoyQ+eLtQbY7W4IzCGgk8nUuWfwoWLnpQG7PjHjL9Lf/Jt
         JoBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6jHrVv8XhwYin2Xz9JYk+FjF04oU61vhZmlq9r4/7aU=;
        b=pK+EwBCvZ7j5aDmj1MwgeZ7NuJFItHIF2NreWT5tu0VoksIn96cT5dVhiqz+IgboND
         N78oeZiPFzZpUxUGSF01cl34ZvjVOR4wTBwzKdx2DDNnWGRWDiy5BJWMdiRcNZemicQy
         LLQBoiGJ4Y5qFAgR2LIK63096R/YYMghEYJhHbV7OmTTsZYhVKABBkHj/2F8h2EuF8AM
         1S9E7QY6/H7KVXaRFDl8DK9xmzFLUE0SzmrZt/MFXpemBS2Jw9A9NjvxvTg5/GFqAcuR
         /4Vaq0E1RCDYVg/NxQ3GX4NsNKkC5l8hw14pICNTCbcJ/FLPm8U6Xzmrbn6RTYzbcfAH
         Nw8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S7eIjQJs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6jHrVv8XhwYin2Xz9JYk+FjF04oU61vhZmlq9r4/7aU=;
        b=kaDsjDny5B7/E9wlpwAX3zUKJyn/K2NgRKo/zPA5YAJjGnQzW3eSkKYIw/T10ySjaA
         Tb/oECwQ9QeRqbrU9VT3RiEOkZ9U1RjY2IejVdUe6I7aIxb3p84ldeKS1cCKwl6h0i18
         QMxRva3LU+z7vnaZbsBD0AAgnVKh/kDW3HaRgj2Kp8Gr9Efn0+laM1ifY4QMam10gqkc
         YmFbeDrVUa0WpIVwtkjmmz3I4tAT7xzR0WHzC9eXQO7Jqz/0Uy7jRu+hpbGPLnAOkAx5
         3fncGE4vw950ypbV8yqt/EOBmSY0B7sKcAlFAEQ7W8ntacTAX4XZv6bDPaszc7rc8Rmr
         Kb7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jHrVv8XhwYin2Xz9JYk+FjF04oU61vhZmlq9r4/7aU=;
        b=oqvnUfNx3rYU3KLfhCa/mU12DTS49BaW2dhu/+Inj4LfC4x3ucFbj35MJ/oEx4WJMV
         8ceFXGfKpPFW8Jz5mPzKUEMqvMoqWD4k8VZRB3rgCvZB+l8Hwtf1J1K5eTCYVsaft76h
         Jl79g6c06PHRCYsC8noY7o50haUF6ADAOVWlRaG3wbWIrPY5WjkywCtOopauy8FnX7R5
         u6m8DABXBNyDvqF6sCrZIo3JP+dXKOwLYzgelX9td7WnpN7G8A/WJ4vG4L3jyPYIpDMm
         GdBwYHYdYRdZGPZHejH83v4VirXEEfCykdyU3eRgoo7IMBfoRtGuVNOMVNLg+YgOPC15
         yfXQ==
X-Gm-Message-State: AOAM530uSCtNU4oUxaIwgL9NVPgMG+c2iomqU4iTGC20DlW4O8Wg0vmo
	czMouNZ7P8+LreVfvEDQrko=
X-Google-Smtp-Source: ABdhPJwsVCP6P9VZfgNJormLOHj9Aw2o9Gig/AFeDrHBBqmd9j1925sWyWWpYoeedEvtgGNMSDY15w==
X-Received: by 2002:a19:e20c:: with SMTP id z12mr8779783lfg.450.1605111029475;
        Wed, 11 Nov 2020 08:10:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls2172lfa.2.gmail; Wed, 11 Nov
 2020 08:10:28 -0800 (PST)
X-Received: by 2002:a19:fc03:: with SMTP id a3mr8377773lfi.472.1605111028274;
        Wed, 11 Nov 2020 08:10:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111028; cv=none;
        d=google.com; s=arc-20160816;
        b=HHxqL5+4JGVFUPu8TIGEGI9GDc7ukN8i4uohliw8wmdDmdUC6fH9LexEj2VUZerCX/
         ckamMumbY4ArHvugiZk0cQYwdwcb6PM40nMhxME+2qCa/9wMIJkfL8TzO+CMazQLpFrw
         +trIbZWYShrYQVrMoQ/s8RRin2v0oR4E8zbi8xhVS26kLgEbvJ5X8fEOT7S9mRBWddyR
         l1Ql+U2jA9uOLIAVz+nQ2K3HR3/ytIEH/9HcrKiklGKami0P9nSOC/Z3cNR4Z4pgx8i4
         PFT5wiSG6AJ7wBeHPfI0p2X1GROnKaFufAY4hd64sHdfz04nfR2cioBL4VW4SA3sUd2P
         Mm8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=u6Xd/aWnBK+33C9vA03cmc0xfNfCQ2wQSEufKCfSLLc=;
        b=tg8B/spPItNFYe/hyzhHXZBw49lUTrCxGHwtUCCCOswz07EP25+0jm08Zn9pRlaNDP
         CQH3txrU+qbUhF2ZG6yz5EWcd//+L1v1MaLNRaySX91VluA4MDgLJo16UCe7CHdBpfAl
         KjJMZxupVZ+zUWRsB+2sRorNmKSk4vq3DI1ivRLBDRaiUbYDq5g9aysZALrT+fJvnVRr
         1kEEG7Pf90ArtmY1ynXpVlLmYrUbdgFMCMkX+aIgGm3FEAle7XgldY7KmozDMU01xhr0
         YmZsjtI2O7SDvAFNJWEupKZ4azfUTtxCUco+h9C04o/SLRQD7j9YcjzBx8MeDJGywn1q
         G3Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S7eIjQJs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id v24si93438lfo.5.2020.11.11.08.10.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:10:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id r17so3081162wrw.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:10:28 -0800 (PST)
X-Received: by 2002:adf:f90f:: with SMTP id b15mr31148545wrr.343.1605111027687;
        Wed, 11 Nov 2020 08:10:27 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id h62sm2946698wrh.82.2020.11.11.08.10.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:10:26 -0800 (PST)
Date: Wed, 11 Nov 2020 17:10:20 +0100
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
Subject: Re: [PATCH v2 03/20] kasan: introduce set_alloc_info
Message-ID: <20201111161020.GE517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <5302e6d48429465259bd0868a7dc357290a2e8a5.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5302e6d48429465259bd0868a7dc357290a2e8a5.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S7eIjQJs;       spf=pass
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
> Add set_alloc_info() helper and move kasan_set_track() into it. This will
> simplify the code for one of the upcoming changes.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
> ---

Reviewed-by: Marco Elver <elver@google.com>

>  mm/kasan/common.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8fd04415d8f4..a880e5a547ed 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return __kasan_slab_free(cache, object, ip, true);
>  }
>  
> +static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> +{
> +	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> +}
> +
>  static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  				size_t size, gfp_t flags, bool keep_tag)
>  {
> @@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  		KASAN_KMALLOC_REDZONE);
>  
>  	if (cache->flags & SLAB_KASAN)
> -		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> +		set_alloc_info(cache, (void *)object, flags);
>  
>  	return set_tag(object, tag);
>  }
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111161020.GE517454%40elver.google.com.
