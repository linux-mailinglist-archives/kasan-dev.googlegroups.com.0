Return-Path: <kasan-dev+bncBCQJ32NM6AJBBL72WSXAMGQEIGXJD7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B49218555AC
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 23:22:40 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59a18ecf836sf227293eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:22:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707949359; cv=pass;
        d=google.com; s=arc-20160816;
        b=uNLezg7prkMX5Te9qc4zklwsmc28+9aU7CHQg80G5akLu9KJSirIfl0mPs3R/nH4Yc
         Gu0jlQ0fHxqRX4DVppHJNoDiBTuF9Qx+IS46mf3NSEhrV9nECwfeZOKrVeLOc/zp8qRa
         x2JW8Hjh8Ry81Z1asbFnbDShG+o7kIt+iwprNx8JF7hMjLKXDo9IP0tIgKPNB6Dvzcrf
         qn7LXiUOfBsmmXyX+db/W6FAn2Qmr/hPOz5yKuT3mHdsCPj48KX6yWGXaN8zXfUNHsfu
         bQo36ONOPwLDeNnWa2Ku9S8rQBxD8961qC8JSnuHh7EmyBg3+V+ee54gATxZVsaEe9Y2
         QIlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OgGCe+fNAK4wHowDyDBKl9/a0UILDH0LbeHVqTehyOg=;
        fh=geXee2WJqCPxmp63b6OZEneYCdzX/pBnSIRRV/zN/Mg=;
        b=0bo5cjf30PQ7LoNTVTTnbZjlJLsnpnXNO6/kKQIu+HNnlEGXf03QgGtVxSgFKZMwC3
         lKVdJgB4PHtblhGCNJ4E3awinXWxWcKBmI2Nf++U1tM0aN5WDR/t4WtTt3c1hx+6DNxQ
         Hd8ductBglLLksR+OetKeXIGNWSVjKJl2LY9WAUdKu2aRDqh36bVti0nwluCI8+Jh2Tc
         GOBke56Xqo4cZSYFj6xmfp/Vk/ui9ir7L9aD5OTK4ut+YipRf3PSYSJTXg2K8ZxjyU5Z
         RIcLS7Ss2CnoOI8AKrz/AG+cEAyw0QjIbxC1duCFtuei5O5/ZDXxBTNwVabJ9EXjGznP
         RI+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20230601.gappssmtp.com header.s=20230601 header.b=zuZXHFJB;
       spf=pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707949359; x=1708554159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OgGCe+fNAK4wHowDyDBKl9/a0UILDH0LbeHVqTehyOg=;
        b=Yd6TF79zYbW/i4WpxHn12dX2NtzIBlZTb7lf6SgiFvYKylYpvmxO45RPU55HoNPKFH
         tPDrVlLHiRuG+/D1QYsrCmIsYIXG/9VckO2OA1sN4+wls5Fsko8J7mz0kOO5VcnVH3gW
         M676bSGRA5VTm2SeMBkDYtrralLXos3Ce2YZlhLiNOFmjsIRoG1VrjiCx+zu7QGsxA9T
         EoqGLu7b5+IOHeqE0gQZSWwkrzNagbQD37RdlkotrbDTzMSEOFIdKDk+5X0aopfXJ96d
         UHtQuXZDwA0wuzM0OFwH0IJ08AdSlWD3W/bL/jCOH3uqRALP3shMI5AjylcCnnqiu3yc
         d/8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707949359; x=1708554159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OgGCe+fNAK4wHowDyDBKl9/a0UILDH0LbeHVqTehyOg=;
        b=wGJxTopXTdwe7BtvXlyvujhrT0y+os34f7Jf9Z4hQE0yZOUdHS+trticn6d7x4rY7p
         p6Jh1orXPC9Vmu4kPVtzd6R57TFXW4RVG8lYlHss84CHMeyuSzF8lMhqoITfF1bgekE7
         CRT8tzbTXX4MiZzK2xI96vqDVGdz9ufX3yuNvaNVy9A3QS1AIhINGR9I6Jr7hFJpf/Qj
         H0H/q75hTdrsYa+RBNV3n+dUv97Q3cbO7fISYdBlWXjxR9uy412MBGei4yPe3JXpjH77
         nAgOmH4DM/hn7on3tcpYn3ifsYqdUeY6NHN17sHISeOo/sqmXvmg3yIneQPqes3rela9
         X0pQ==
X-Forwarded-Encrypted: i=2; AJvYcCWNhRJuRmfYAL75moINFksA3DI6odwY5JIobLDnTbI9A2K8W7QY/x3i49cK9Q4DU2gXokwai0ijEg7M/7GROOJTuNzLDgkRWg==
X-Gm-Message-State: AOJu0YzpMKF/wvToPkgn7X4jimYkB3KAQmibp64aKydsAJwWILulwjtq
	ksmYguqCn0TTOFomyWnbPbzQJ8vXmnLARUqPzQ3njAyA12MZ2GAS
X-Google-Smtp-Source: AGHT+IFUhl+gU9ZZzkDGPs/FA0hXKK3mMnhy1OMKOGMe15Fkjx95RMeNKxrFWSNRlVjRoocUbLcfMA==
X-Received: by 2002:a4a:650d:0:b0:59d:28c9:bf97 with SMTP id y13-20020a4a650d000000b0059d28c9bf97mr76421ooc.1.1707949359591;
        Wed, 14 Feb 2024 14:22:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af08:0:b0:598:dc0d:33b6 with SMTP id w8-20020a4aaf08000000b00598dc0d33b6ls5212647oon.2.-pod-prod-03-us;
 Wed, 14 Feb 2024 14:22:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUXlFe3iPZrfRjL8Aaig7yTa29tYn6GnVnzuiRTM9YoJKi5ufm7t7YpQuCzGZPUvjHHUnarqbmN4hZtbdApBEMfvFED30IqM6rqtQ==
X-Received: by 2002:a05:6830:16c8:b0:6e2:c382:93c8 with SMTP id l8-20020a05683016c800b006e2c38293c8mr4062046otr.6.1707949358796;
        Wed, 14 Feb 2024 14:22:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707949358; cv=none;
        d=google.com; s=arc-20160816;
        b=IOpEP8oswn2aE+a+zZXNlCGNHwNwr0dGUDjT3j5Pr6tmzlgvNOtIt/xmYEeCQqyKkm
         +e0UJh1EYlOlpilC1fTbvcaRpW11FTLZYh+J30XUXKrRWrxAFz1sqmw/elbnQFx94w7f
         3OZbqJiP25nuVy6UfAHv8pvi1SByEP71m+OM+gzypSjrBGgRQiDMRG8yoWezB0k3hysI
         ifvitzQIf8uKNTWf7WZohwVSqXwhOVaQeziK2MdFsoVILkUek1qR521oJqfaQEx1avOP
         +Pr1lW+fBNG2jFAYlIj+AJTTAMUAhPc46DwYbjw88HP8bidwOlQcdiwi+U0TYGDuOEdl
         hUrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ln+OOvGmpFuiRMz6w7NK4oosvSzfGSRKkgDvCaci/QI=;
        fh=psGnW7iA6TfnuVwNaZFAJUAzS41vNX/oDdZeNY4UsiM=;
        b=O931n5Etyfs2IpK2AjiXsQ221MAlO5PBEwHhDuUy3Tq6gTxX0ABvXE/QOjwBcBo2wG
         5hUEJWXKBieMkVA4FHI2YCv2KUjrD4geHtAHiNS32wcFEvOtw4cT6SOzzk4lCn46QexB
         x9ss/ZPxVIEzZ/Ip+VwABB4H+i7Z3Do0Ajw4kPf31shDExu7bGs9jDjwdbmXrutxJoHY
         gBD6+SQBgAt0kbrL0qOC+IO58lhFKupg+p95GRy5dkjvEPEmx05Vq2dKJSm8DSIajv1y
         F8DIasmMTnXAHiMaoc/cGaUaHHh03heNpL5FC0LPmge7mFrPJqzM9zPa9/0IzBhh+sOQ
         tyGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20230601.gappssmtp.com header.s=20230601 header.b=zuZXHFJB;
       spf=pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id i23-20020a056830451700b006e2df32b368si7743otv.1.2024.02.14.14.22.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 14:22:38 -0800 (PST)
Received-SPF: pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-5ce942efda5so212519a12.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 14:22:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/7Xyefumw/i3c1gcV9vG2qsmpj8es6bUPR/xhZh4EjCxakwW6r8rpigsr/I/dykQY4BTQDEmB6jfE5+wQogH/MIa2uFctjTCfXA==
X-Received: by 2002:a05:6a20:d703:b0:19e:9b19:96c0 with SMTP id iz3-20020a056a20d70300b0019e9b1996c0mr191489pzb.7.1707949357817;
        Wed, 14 Feb 2024 14:22:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from dread.disaster.area (pa49-181-38-249.pa.nsw.optusnet.com.au. [49.181.38.249])
        by smtp.gmail.com with ESMTPSA id t29-20020a62d15d000000b006e0a55790easm9168222pfl.216.2024.02.14.14.22.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 14:22:36 -0800 (PST)
Received: from dave by dread.disaster.area with local (Exim 4.96)
	(envelope-from <david@fromorbit.com>)
	id 1raNeD-006ZVB-2T;
	Thu, 15 Feb 2024 09:22:33 +1100
Date: Thu, 15 Feb 2024 09:22:33 +1100
From: "'Dave Chinner' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 25/35] xfs: Memory allocation profiling fixups
Message-ID: <Zc09KRo7nMlSGpG6@dread.disaster.area>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-26-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-26-surenb@google.com>
X-Original-Sender: david@fromorbit.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fromorbit-com.20230601.gappssmtp.com header.s=20230601
 header.b=zuZXHFJB;       spf=pass (google.com: domain of david@fromorbit.com
 designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
X-Original-From: Dave Chinner <david@fromorbit.com>
Reply-To: Dave Chinner <david@fromorbit.com>
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

On Mon, Feb 12, 2024 at 01:39:11PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This adds an alloc_hooks() wrapper around kmem_alloc(), so that we can
> have allocations accounted to the proper callsite.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  fs/xfs/kmem.c |  4 ++--
>  fs/xfs/kmem.h | 10 ++++------
>  2 files changed, 6 insertions(+), 8 deletions(-)
> 
> diff --git a/fs/xfs/kmem.c b/fs/xfs/kmem.c
> index c557a030acfe..9aa57a4e2478 100644
> --- a/fs/xfs/kmem.c
> +++ b/fs/xfs/kmem.c
> @@ -8,7 +8,7 @@
>  #include "xfs_trace.h"
>  
>  void *
> -kmem_alloc(size_t size, xfs_km_flags_t flags)
> +kmem_alloc_noprof(size_t size, xfs_km_flags_t flags)
>  {
>  	int	retries = 0;
>  	gfp_t	lflags = kmem_flags_convert(flags);
> @@ -17,7 +17,7 @@ kmem_alloc(size_t size, xfs_km_flags_t flags)
>  	trace_kmem_alloc(size, flags, _RET_IP_);
>  
>  	do {
> -		ptr = kmalloc(size, lflags);
> +		ptr = kmalloc_noprof(size, lflags);
>  		if (ptr || (flags & KM_MAYFAIL))
>  			return ptr;
>  		if (!(++retries % 100))
> diff --git a/fs/xfs/kmem.h b/fs/xfs/kmem.h
> index b987dc2c6851..c4cf1dc2a7af 100644
> --- a/fs/xfs/kmem.h
> +++ b/fs/xfs/kmem.h
> @@ -6,6 +6,7 @@
>  #ifndef __XFS_SUPPORT_KMEM_H__
>  #define __XFS_SUPPORT_KMEM_H__
>  
> +#include <linux/alloc_tag.h>
>  #include <linux/slab.h>
>  #include <linux/sched.h>
>  #include <linux/mm.h>
> @@ -56,18 +57,15 @@ kmem_flags_convert(xfs_km_flags_t flags)
>  	return lflags;
>  }
>  
> -extern void *kmem_alloc(size_t, xfs_km_flags_t);
>  static inline void  kmem_free(const void *ptr)
>  {
>  	kvfree(ptr);
>  }
>  
> +extern void *kmem_alloc_noprof(size_t, xfs_km_flags_t);
> +#define kmem_alloc(...)			alloc_hooks(kmem_alloc_noprof(__VA_ARGS__))
>  
> -static inline void *
> -kmem_zalloc(size_t size, xfs_km_flags_t flags)
> -{
> -	return kmem_alloc(size, flags | KM_ZERO);
> -}
> +#define kmem_zalloc(_size, _flags)	kmem_alloc((_size), (_flags) | KM_ZERO)
>  
>  /*
>   * Zone interfaces
> -- 
> 2.43.0.687.g38aa6559b0-goog

These changes can be dropped - the fs/xfs/kmem.[ch] stuff is now
gone in linux-xfs/for-next.

-Dave.
-- 
Dave Chinner
david@fromorbit.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zc09KRo7nMlSGpG6%40dread.disaster.area.
